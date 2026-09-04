//! Applies one step of a staged transaction.
//!
//! [`Transaction<Staged>`](super::Transaction)'s `commit` decides *what* happens and in what
//! order. This module does one package's worth of it. This is where the typestate ends and the
//! work begins: everything here runs with the lock already held, the journal already written,
//! and the plan already verified. Nothing here re-checks any of that.
//!
//! The scriptlet ordering, the fake removal an upgrade performs before extracting anything, and
//! what a removal does with `%BACKUP%` are all libalpm's rules. Each is cited at the call site
//! that implements it.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use alpm_types::{PackageInstallReason, PackageValidation};
use piko_db::{EntryName, Limits};
use piko_db_write::{DbLock, LocalDbWriter};

use super::{Doomed, Patterns, Prepared, Replacement, Report, ScriptletRun};
use crate::{
    error::Result,
    exec::Runner,
    extract::{Ownership, PackageLimits},
    hash::MAX_BACKUP_BYTES,
    history::now,
    install::{Extraction, Filters},
    progress::Event,
    record::{self, InstallFacts},
    remove::{RemovalContext, RemovalDisposition, decide_removal},
    rootfs::RootDir,
    scriptlet,
};

/// Everything one install step needs, gathered so the function keeps a readable signature.
pub(super) struct InstallStep<'a> {
    pub(super) root: &'a RootDir,
    pub(super) dbpath: &'a Path,
    pub(super) lock: &'a DbLock,
    pub(super) package: &'a Prepared,
    pub(super) reason: PackageInstallReason,
    pub(super) ownership: Ownership,
    pub(super) limits: &'a PackageLimits,
    /// Paths the fake removal must leave alone because another step now owns them.
    pub(super) skip_remove: &'a BTreeSet<PathBuf>,
    /// `NoExtract`/`NoUpgrade`, obeyed by both the fake removal and the extraction.
    pub(super) patterns: &'a Patterns,
    /// `None` when scriptlets are turned off.
    pub(super) runner: Option<&'a Runner>,
}

/// Installs one package and records it in the database.
///
/// The scriptlet sequence follows `add.c`: `pre_install`/`pre_upgrade` before a byte is
/// extracted, `post_install`/`post_upgrade` after the database entry is written. Which of each
/// pair runs depends on whether a version was already installed, not on whether the version is
/// going up. That is what libalpm passes, and what `alpm-hooks(5)` means by "upgrade".
///
/// An upgrade also takes the old version apart first. See the fake removal below.
pub(super) fn install_step(
    step: &InstallStep<'_>,
    report: &mut Report,
    progress: &mut dyn FnMut(Event<'_>),
) -> Result<Extraction> {
    let old_version = step.replaced_version();
    let is_upgrade = old_version.is_some();

    if let (Some(runner), Some(script)) = (step.runner, step.package.script.as_deref()) {
        // From the archive, before extraction (`add.c:495`). The version comes from the
        // `.PKGINFO` that `verify` already parsed, so nothing is read twice.
        step.run_scriptlet(
            ScriptletCall {
                runner,
                script,
                kind: scriptlet::Kind::before_install(is_upgrade),
                version: &step.package.version.clone(),
                old_version: old_version.as_deref(),
            },
            report,
            progress,
        )?;
    }

    // The fake remove transaction runs at exactly libalpm's point in the sequence
    // (`add.c:508`): after `pre_upgrade`, before a single byte is extracted. Both edges
    // matter. Run it earlier and the scriptlet faces a half-dismantled package. Run it later
    // and it deletes the files the extraction just wrote.
    if let Some(old) = step.package.replaces.as_ref() {
        let (_, pacsaves) = remove_files(
            step.root,
            &Removal {
                files: &old.files,
                backups: &old.backups,
                skip_remove: step.skip_remove,
                replacement: Some(step.package.as_replacement()),
                patterns: step.patterns,
                // libalpm reads `ALPM_TRANS_FLAG_NOSAVE` here. `-S` has no way to set it.
                no_save: false,
            },
        );
        report.pacsaves.extend(pacsaves);
    }

    // The configured policy and the two packages' own `%BACKUP%` declarations, turned into
    // the predicates extraction asks. `old_backup_hash` is the load-bearing one. It is the
    // only baseline that distinguishes a config file the user edited from one they never
    // touched. Without it, every upgrade would silently overwrite the former.
    let old_backups = step.package.replaces.as_ref().map(|old| &old.backups);
    let filters = Filters {
        no_extract: &|path| step.patterns.skips(path),
        no_upgrade: &|path| step.patterns.preserves(path),
        old_backup_hash: &|path| old_backups.and_then(|backups| backups.get(path).cloned()),
        is_backup: &|path| step.package.backups.contains(path.to_string_lossy().as_ref()),
    };

    let extraction = crate::install::install(
        &step.package.path,
        step.root,
        &filters,
        step.ownership,
        step.limits,
    )?;

    // The `.PKGINFO` was parsed at verify time, so nothing here can refuse the package on its
    // own metadata. Refusing it here would happen after the payload above is already written.
    let entry = &step.package.entry;

    let facts = InstallFacts {
        install_date: now(),
        reason: step.reason,
        // This records what was actually done, not what was configured. A package accepted
        // because the policy asked for nothing gets `none`, same as one nobody checked.
        validation: vec![if step.package.validated {
            PackageValidation::Pgp
        } else {
            PackageValidation::None
        }],
    };

    let writer = LocalDbWriter::new(step.dbpath, step.lock, Limits::default())?;
    // The entry being replaced is the one installed **under this name**, whatever its version.
    // Removing only an entry with the *new* name and version leaves `foo-1.0.0-1` and
    // `foo-2.0.0-1` side by side after an upgrade, and the reader then reports the older of
    // the two.
    let previous = step.package.replaces.as_ref().map(|old| &old.entry);
    writer.replace_entry(previous, entry)?;

    // Staged rather than written one file at a time. An entry is three or four files, and
    // `write_record`/`write_raw` each pay an `fsync` of the data *and* of the directory. One
    // `EntryWrite` pays one directory `fsync` for the whole entry and overlaps the data ones.
    // Measured: 260 ms -> 113 ms for a 42-package upgrade on btrfs (`docs/perf-study.md`
    // §4.2). It also gives a stronger crash-safety property: no member of this entry becomes
    // visible until every member's data is durable, so an interruption cannot leave a new
    // `desc` beside an old `files`.
    let mut staged = writer.entry_write(entry);
    staged.record(&record::desc(&step.package.info, &step.package.raw, &facts))?;
    staged.record(&record::files(&extraction))?;

    // `.MTREE` and `.INSTALL` belong in the entry under their libalpm names
    // (`add.c:194`), not in the root.
    for (member, stored) in [(".MTREE", "mtree"), (".INSTALL", "install")] {
        if let Some(bytes) = extraction.metadata.get(member) {
            staged.raw(stored, bytes)?;
        }
    }
    staged.commit()?;

    if let (Some(runner), Some(script)) = (step.runner, step.package.script.as_deref()) {
        // `add.c:667` runs this from the copy now in the database entry. piko runs the same
        // bytes it just wrote there, so this is the same file without a second read.
        step.run_scriptlet(
            ScriptletCall {
                runner,
                script,
                kind: scriptlet::Kind::after_install(is_upgrade),
                version: &step.package.version.clone(),
                old_version: old_version.as_deref(),
            },
            report,
            progress,
        )?;
    }

    Ok(extraction)
}

/// One `.INSTALL` scriptlet function to run, gathered for the same reason [`InstallStep`] is.
struct ScriptletCall<'a> {
    runner: &'a Runner,
    script: &'a [u8],
    kind: scriptlet::Kind,
    version: &'a str,
    old_version: Option<&'a str>,
}

impl InstallStep<'_> {
    /// The version this install replaces, if any.
    fn replaced_version(&self) -> Option<String> {
        self.package.replaces.as_ref().map(|old| old.entry.version().to_string())
    }

    /// Runs one scriptlet function, recording the outcome and reporting it as it happens.
    fn run_scriptlet(
        &self,
        call: ScriptletCall<'_>,
        report: &mut Report,
        progress: &mut dyn FnMut(Event<'_>),
    ) -> Result<()> {
        let ScriptletCall { runner, script, kind, version, old_version } = call;
        if !scriptlet::declares(script, kind.as_str()) {
            return Ok(());
        }
        progress(Event::ScriptletStarted { package: &self.package.name, kind });
        let Some(outcome) =
            scriptlet::run(runner, self.root, script, kind, version, old_version, &mut |line| {
                progress(Event::ScriptletOutputLine { package: &self.package.name, kind, line });
            })?
        else {
            return Ok(());
        };
        progress(Event::ScriptletFinished { package: &self.package.name, kind, outcome: &outcome });
        report.scriptlets.push(ScriptletRun { package: self.package.name.clone(), kind, outcome });
        Ok(())
    }
}

/// Removes one installed package and its entry.
///
/// `skip_remove` names paths this same transaction has handed to another package. Deleting one
/// would remove a file the new owner has just installed and still claims. See
/// [`crate::conflict::Check::skip_remove`].
///
/// `pre_remove` runs before the first file goes, and `post_remove` runs after the entry is
/// gone, matching `remove.c:711` and `:731`. Both read the scriptlet from the database entry,
/// which is where the install put it. So `post_remove` is read *before* the entry is deleted.
///
/// Everything one removal step needs, mirroring [`InstallStep`].
#[derive(Clone, Copy)]
pub(super) struct RemoveStep<'a> {
    pub(super) root: &'a RootDir,
    pub(super) dbpath: &'a Path,
    pub(super) lock: &'a DbLock,
    /// The installed entry to take away.
    pub(super) entry: &'a EntryName,
    /// Its `%FILES%`, `%BACKUP%` and scriptlet, read at `verify`.
    pub(super) doomed: &'a Doomed,
    /// `-Rn`: suppress `.pacsave` files.
    pub(super) no_save: bool,
    /// Paths an install step in this same transaction now owns.
    pub(super) skip_remove: &'a BTreeSet<PathBuf>,
    /// `NoUpgrade` protects a file from removal too (`remove.c:592`).
    pub(super) patterns: &'a Patterns,
    /// `None` when scriptlets are turned off.
    pub(super) runner: Option<&'a Runner>,
}

pub(super) fn remove_step(
    step: &RemoveStep<'_>,
    report: &mut Report,
    progress: &mut dyn FnMut(Event<'_>),
) -> Result<(usize, Vec<PathBuf>)> {
    let &RemoveStep { root, dbpath, lock, entry, doomed, no_save, skip_remove, patterns, runner } =
        step;

    // Everything below was read at `verify`: that the entry exists, its `%FILES%`, its
    // `%BACKUP%`, and its scriptlet. So this function opens no database. That is what stops a
    // `-Rcs` of 35 packages from doing 35 full `readdir`s of the installed set.
    let script = doomed.script.as_deref();
    let version = entry.version().to_string();
    let run_scriptlet = |kind: scriptlet::Kind,
                         report: &mut Report,
                         progress: &mut dyn FnMut(Event<'_>)|
     -> Result<()> {
        let (Some(runner), Some(script)) = (runner, script) else { return Ok(()) };
        if !scriptlet::declares(script, kind.as_str()) {
            return Ok(());
        }
        let package = entry.name().to_string();
        progress(Event::ScriptletStarted { package: &package, kind });
        let Some(outcome) =
            scriptlet::run(runner, root, script, kind, &version, None, &mut |line| {
                progress(Event::ScriptletOutputLine { package: &package, kind, line });
            })?
        else {
            return Ok(());
        };
        progress(Event::ScriptletFinished { package: &package, kind, outcome: &outcome });
        report.scriptlets.push(ScriptletRun { package, kind, outcome });
        Ok(())
    };
    run_scriptlet(scriptlet::Kind::PreRemove, report, progress)?;

    let (touched, pacsaves) = remove_files(
        root,
        &Removal {
            files: &doomed.installed.files,
            backups: &doomed.installed.backups,
            skip_remove,
            // A real removal, so there is no `newpkg`. Nothing is spared for a successor.
            replacement: None,
            patterns,
            no_save,
        },
    );

    let writer = LocalDbWriter::new(dbpath, lock, Limits::default())?;
    writer.remove_entry(entry)?;
    run_scriptlet(scriptlet::Kind::PostRemove, report, progress)?;
    Ok((touched, pacsaves))
}

/// One package's files, and the rules that decide what happens to each.
///
/// Shared by the two callers `remove_package_files` (`remove.c:611`) has: a real removal, and
/// the fake one an upgrade runs first. The two differ only in `replacement`.
struct Removal<'a> {
    /// The paths to consider, in `%FILES%` order. The walk goes backwards through them.
    files: &'a [PathBuf],
    /// The removed package's `%BACKUP%` hashes — the baseline a `.pacsave` decision needs.
    backups: &'a BTreeMap<PathBuf, String>,
    /// Paths another step of this transaction has taken over.
    skip_remove: &'a BTreeSet<PathBuf>,
    /// The package taking this one's place, for an upgrade's fake removal.
    replacement: Option<Replacement<'a>>,
    /// The configured patterns. Only `NoUpgrade` is consulted (`remove.c:592`).
    patterns: &'a Patterns,
    /// Whether `.pacsave` files are suppressed (`-Rn`).
    no_save: bool,
}

/// Applies one package's file removals, returning how many paths were touched and the
/// `.pacsave` files created.
///
/// Every decision belongs to [`decide_removal`]. This function only asks the filesystem the
/// questions that function's inputs are made of, then does what it says.
fn remove_files(root: &RootDir, removal: &Removal<'_>) -> (usize, Vec<PathBuf>) {
    let mut touched = 0_usize;
    let mut pacsaves = Vec::new();

    // Reverse order, so a directory is considered only after everything inside it.
    for path in removal.files.iter().rev() {
        // Two spellings exist, and the difference is load-bearing. libalpm asks the
        // replacement's file list about the path *with* its trailing slash (`remove.c:487`),
        // and everything else about the path without it (`remove.c:453`).
        let spelled = path.to_string_lossy();
        let trimmed = trim_trailing_slash(path);
        let Ok(resolved) = root.resolve_parent(&trimmed) else { continue };
        let stripped = trimmed.to_string_lossy();

        let existing = crate::install::probe_existing(root, &trimmed);
        let recorded = removal.backups.get(&trimmed).cloned();
        let local_hash = recorded.as_ref().and_then(|_| {
            crate::hash::file_md5_at(resolved.dir(), resolved.name(), MAX_BACKUP_BYTES)
                .ok()
                .flatten()
                .map(|hash| hash.to_string())
        });

        let context = RemovalContext {
            existing,
            // This mirrors `should_skip_file`'s first clause. A file the user told piko never
            // to touch is not one a removal may delete either.
            no_upgrade: removal.patterns.preserves(&trimmed),
            in_skip_remove: removal.skip_remove.contains(&trimmed),
            replacement_keeps_it: removal.replacement.is_some_and(|new| new.keeps(&stripped)),
            replacement_ships_it: removal.replacement.is_some_and(|new| new.ships(&spelled)),
            old_backup_hash: recorded.as_deref(),
            local_hash: local_hash.as_deref(),
            no_save: removal.no_save,
            directory_has_other_owner: false,
        };

        match decide_removal(&context) {
            RemovalDisposition::Unlink => {
                let _ = rustix::fs::unlinkat(
                    resolved.dir(),
                    resolved.name(),
                    rustix::fs::AtFlags::empty(),
                );
                touched = touched.saturating_add(1);
            }
            RemovalDisposition::SaveAsPacsave => {
                let mut saved = resolved.name().to_os_string();
                saved.push(".pacsave");
                let _ = rustix::fs::renameat(
                    resolved.dir(),
                    resolved.name(),
                    resolved.dir(),
                    saved.as_os_str(),
                );
                pacsaves.push(PathBuf::from(format!("{}.pacsave", trimmed.display())));
                touched = touched.saturating_add(1);
            }
            RemovalDisposition::RemoveDirectoryIfEmpty => {
                // Failure is ordinary here: another package may still own something inside.
                let _ = rustix::fs::unlinkat(
                    resolved.dir(),
                    resolved.name(),
                    rustix::fs::AtFlags::REMOVEDIR,
                );
            }
            RemovalDisposition::Skip(_) => {}
        }
    }

    (touched, pacsaves)
}

/// A path without tar's trailing slash on directories.
fn trim_trailing_slash(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.strip_suffix('/').unwrap_or(&text))
}
