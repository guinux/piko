//! The transaction itself: a typestate that cannot be committed out of order.
//!
//! ```text
//! Transaction<Planned> --verify--> Transaction<Verified> --stage--> Transaction<Staged> --commit--> Report
//! ```
//!
//! libalpm enforces the same sequence with a runtime `ASSERT` on `trans->state`. It returns
//! `ALPM_ERR_TRANS_NOT_INITIALIZED` when a caller gets it wrong (`trans.c`). Here each step
//! consumes the previous value and returns the next. Getting it wrong does not compile.
//!
//! The states are not decoration. Each is a point where something is guaranteed:
//!
//! - **`Planned`** — the steps are known. Nothing has been read or written.
//! - **`Verified`** — every package the transaction needs has been located *and read*, every
//!   `.PKGINFO` is one piko can record, and every entry it will remove exists. The commit can
//!   still fail, but not for want of a package file or its metadata.
//! - **`Staged`** — the database lock is held and the journal is on disk and fsynced. This is
//!   the last state in which abandoning the transaction leaves the system untouched.
//! - committing consumes `Staged` and mutates.
//!
//! # This is where piko can change a real system
//!
//! Every other module reads, decides, or writes somewhere the caller named. This one is handed
//! a root and a dbpath and applies a whole plan to them. The tests here use a
//! `tempfile::TempDir` for both.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use alpm_pkginfo::PackageInfo;
use alpm_types::{PackageFileName, PackageInstallReason};
use piko_db::{EntryName, LocalDatabase, LocalPackage};
use piko_db_write::DbLock;
use piko_sig::{Keyring, Policy, Verdict};

use crate::{
    conflict::{self, Overwrite, WalkLimits, filelist::FileList},
    error::{Error, Result},
    exec::Runner,
    extract::{Ownership, PackageLimits},
    hook::{self, Hooks, When},
    install::Extraction,
    journal::{Intent, Journal},
    progress::{Event, StepOutcome, VerifyEvent},
    rootfs::RootDir,
    scriptlet::{self, MAX_SCRIPTLET_BYTES},
};

mod step;

use step::{InstallStep, RemoveStep, install_step, remove_step};

/// One thing a transaction will do.
#[derive(Clone, Debug)]
pub enum Step {
    /// Install a package file.
    Install {
        /// Which package, by cache file name.
        package: PackageFileName,
        /// Whether the user asked for it or a dependency pulled it in.
        reason: PackageInstallReason,
    },
    /// Remove an installed package.
    Remove {
        /// The installed entry, `<name>-<version>`.
        entry: EntryName,
        /// Whether to skip `.pacsave` files (`-Rn`).
        no_save: bool,
    },
}

impl Step {
    /// The journal line for this step.
    fn intent(&self) -> Intent {
        match self {
            Self::Install { package, .. } => Intent::Install { package: package.to_string() },
            Self::Remove { entry, .. } => Intent::Remove { entry: entry.as_str().to_owned() },
        }
    }
}

/// What a committed transaction did.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Packages installed, with what their extraction did.
    pub installed: Vec<(String, Extraction)>,
    /// Packages removed, and how many files each removal touched.
    pub removed: Vec<(String, usize)>,
    /// `.pacsave` files created, by path.
    pub pacsaves: Vec<PathBuf>,
    /// Every scriptlet function that ran, in order, with how it ended.
    ///
    /// A scriptlet that failed lands here rather than in an error. libalpm discards the return
    /// value at every call site, and piko matches that — see [`crate::scriptlet`]. Unlike
    /// libalpm, piko does not *drop* the outcome: what happened comes back to the caller.
    pub scriptlets: Vec<ScriptletRun>,
    /// Every hook that ran, before and after, in order.
    pub hooks: Vec<hook::Run>,
    /// Every hook file that could not be read or parsed, in the order they were met.
    ///
    /// Collected per phase rather than once up front — see [`run_hooks`]. A file broken for the
    /// whole transaction is reported twice, once for each phase that read the directory.
    /// libalpm does the same: `_alpm_hook_run` re-runs `_alpm_hook_validate` on every call, so
    /// pacman prints such a warning twice too.
    pub hook_problems: Vec<hook::Problem>,
}

/// One scriptlet function that piko ran.
#[derive(Clone, Debug)]
pub struct ScriptletRun {
    /// The package whose scriptlet it was.
    pub package: String,
    /// Which of the six functions.
    pub kind: scriptlet::Kind,
    /// How it ended.
    pub outcome: crate::exec::Outcome,
}

/// Steps are known; nothing has been touched.
#[derive(Debug)]
pub struct Planned {
    steps: Vec<Step>,
}

/// How package signatures are checked.
///
/// Defaulting to [`Verification::Disabled`] is a deliberate and uncomfortable choice. It keeps
/// this crate usable without a keyring (a chroot built from scratch has none), but it means a
/// caller who forgets to configure it installs unverified packages. The CLI therefore always
/// passes a real policy, taken from `pacman.conf`'s `SigLevel`, rather than relying on this
/// default.
#[derive(Debug, Default)]
pub enum Verification {
    /// Do not check signatures. `%VALIDATION%` will record `none`, truthfully.
    #[default]
    Disabled,
    /// Check every package against `keyring`, under `policy`.
    Enabled {
        /// The GnuPG keyring to verify against — pacman's is `/etc/pacman.d/gnupg`.
        keyring: Keyring,
        /// What the configured `SigLevel` demands of a package.
        policy: Policy,
    },
}

/// Verifies one package's detached signature, returning whether it was actually checked.
///
/// The distinction between "accepted having verified" and "accepted because the policy asked
/// for nothing" is not cosmetic. It is exactly what `%VALIDATION%` records. Conflating them
/// would write `pgp` into the database for a package nobody checked.
///
/// The policy applied is `policy_overrides`' entry for `file_name`, keyed by cache file name —
/// a repository's `SigLevel` can differ from another's. It falls back to
/// [`Verification::Enabled`]'s own `policy` when `file_name` has no more specific answer (in
/// current practice, only a candidate whose repository could not be resolved).
///
/// This is a free function rather than a method, because `piko install -w` verifies what it
/// downloaded without ever building a [`Transaction`]. libalpm checks under `-Sw` too:
/// `check_validity` (`sync.c:1275`) runs before `_alpm_sync_load`'s
/// `ALPM_TRANS_FLAG_DOWNLOADONLY` return. Sharing the function keeps the two answers from
/// drifting — the same reason [`Transaction::verify`] and the download path share
/// `Keyring::check` rather than each deciding what a missing `.sig` means.
///
/// # Errors
///
/// [`Error::SignatureUncheckable`] if the keyring could not answer at all, or
/// [`Error::SignatureRejected`] if it answered and the policy refuses the result.
pub fn check_signature(
    verification: &Verification,
    policy_overrides: &HashMap<String, Policy>,
    file_name: &PackageFileName,
    package: &Path,
) -> Result<bool> {
    let Verification::Enabled { keyring, policy } = verification else {
        return Ok(false);
    };
    let policy = policy_overrides.get(&file_name.to_string()).copied().unwrap_or(*policy);

    // `Keyring::check` owns the rule that a missing `.sig` is the policy's problem, not an
    // error. The repository-database check shares it, so the two cannot drift.
    let verdict = keyring.check(package, policy).map_err(|source| Error::SignatureUncheckable {
        package: package.to_path_buf(),
        reason: source.to_string(),
    })?;

    match verdict {
        Verdict::Accepted { verified } => Ok(verified),
        Verdict::Rejected(rejection) => Err(Error::SignatureRejected {
            package: package.to_path_buf(),
            reason: rejection.to_string(),
        }),
    }
}

/// One install step's package, with everything `verify` learned about it.
///
/// Gathered while the archive is open for conflict detection, rather than re-read at commit
/// time. The archive is decompressed once, and what a scriptlet runs is what was verified.
#[derive(Clone, Debug)]
struct Prepared {
    /// Where the package file is.
    path: PathBuf,
    /// Its `pkgname`, from the `.PKGINFO` already read.
    name: String,
    /// Its `pkgver`, likewise. The `pre_*` scriptlet needs it before extraction happens.
    version: String,
    /// The database entry it will become.
    ///
    /// Built at verify time, from [`Self::info`]. A name and version that do not form an entry
    /// mean the package cannot be recorded. That has to be known before anything is written.
    entry: EntryName,
    /// Its `.PKGINFO`, parsed.
    ///
    /// Parsed here rather than during the commit, and that placement is the point. Parsing it
    /// after [`crate::install::install`] has run would fail the step on a `.PKGINFO`
    /// `alpm-pkginfo` rejects, with the package's payload already written into the root.
    info: PackageInfo,
    /// Its `.PKGINFO` text, verbatim, which [`record::desc`] needs as well as the parse.
    raw: String,
    /// Whether its signature was actually checked.
    ///
    /// Carried rather than recomputed. This is what `%VALIDATION%` records. Re-deriving it at
    /// write time would let the database claim a verification that never happened.
    validated: bool,
    /// Its `.INSTALL`, if it ships one.
    script: Option<Vec<u8>>,
    /// Every path it ships, as its archive spells them.
    ///
    /// libalpm's `newpkg` file list. The fake removal consults it to decide what it must not
    /// delete.
    files: FileList,
    /// Every path it declares `backup =` in its `.PKGINFO`.
    ///
    /// Two things need it: extraction, to divert the path to a `.pacnew` rather than overwrite
    /// the user's copy, and the fake removal, to leave that copy alone.
    backups: BTreeSet<String>,
    /// The version already installed under this package's name, if any.
    ///
    /// Decides `pre_install` against `pre_upgrade`, supplies the scriptlet's second argument,
    /// names the entry the install must replace, drives the fake removal, and supplies the
    /// `%BACKUP%` baseline extraction compares against.
    replaces: Option<Superseded>,
}

impl Prepared {
    /// What this package ships, as a removal asks about it — libalpm's `newpkg`.
    const fn as_replacement(&self) -> Replacement<'_> {
        Replacement { files: &self.files, backups: &self.backups }
    }
}

/// The installed version an install replaces, read while its entry is still there.
///
/// This is libalpm's `oldpkg`. Carrying it is what lets [`install_step`] run the "fake remove
/// transaction" of `add.c:508` — `_alpm_remove_single_package(handle, oldpkg, newpkg, 0, 0)` —
/// which deletes the old version's files before the new version is extracted. Without it, a
/// package that drops a file between versions leaves that file on disk owned by nobody.
#[derive(Clone, Debug)]
struct Superseded {
    /// The installed entry, `<name>-<version>`.
    entry: EntryName,
    /// Its `%FILES%`, in database order — directories keep their trailing `/`.
    files: Vec<PathBuf>,
    /// Its `%BACKUP%` hashes, keyed by path.
    ///
    /// Two things need it, and they ask different questions. A `.pacsave` decision asks
    /// whether the user edited a file that is going away. Extraction asks what the *previous*
    /// package shipped, so it can tell an edited file from an untouched one.
    backups: BTreeMap<PathBuf, String>,
}

/// The `pacman.conf` path patterns a transaction obeys.
///
/// Shell globs, matched with [`piko_db::resolve::matches_any`] — the same function the hook
/// triggers use. That is the point. `NoExtract` decides both what extraction writes and what a
/// hook is told changed. Those two answers have to come from one matcher, or they will
/// eventually disagree about a `!` inversion.
///
/// This holds patterns rather than the predicates [`Filters`] takes, because this is the
/// *configured* policy, and it has to be handed on to [`hook::Summary`] as data. `Filters`
/// stays a predicate so a test can supply an exact answer instead of a pattern that has to be
/// right twice.
#[derive(Clone, Debug, Default)]
pub struct Patterns {
    /// `NoExtract`: never written, and therefore never owned.
    ///
    /// libalpm consults this in exactly two places — extraction (`add.c:224`) and the
    /// disk-space estimate. **Not** in conflict detection, so a `NoExtract` path is still
    /// checked for conflicts, and piko matches that.
    pub no_extract: Vec<String>,
    /// `NoUpgrade`: never overwritten; the packaged version lands beside it as `.pacnew`.
    ///
    /// Consulted by extraction (`add.c:303`) *and* by removal (`remove.c:592`). A file the
    /// user asked piko never to touch is not one a removal may delete either.
    pub no_upgrade: Vec<String>,
}

impl Patterns {
    /// Whether `path` is never extracted.
    fn skips(&self, path: &Path) -> bool {
        piko_db::resolve::matches_any(&self.no_extract, &path.to_string_lossy())
    }

    /// Whether `path` is never overwritten or removed.
    fn preserves(&self, path: &Path) -> bool {
        piko_db::resolve::matches_any(&self.no_upgrade, &path.to_string_lossy())
    }
}

/// What the package replacing a removed one ships — libalpm's `newpkg`.
#[derive(Clone, Copy, Debug)]
struct Replacement<'a> {
    files: &'a FileList,
    backups: &'a BTreeSet<String>,
}

impl Replacement<'_> {
    /// `should_skip_file`'s third clause (`remove.c:594`).
    ///
    /// The replacement ships this path *and* declares it a backup file. The user's copy stays
    /// where it is, and the packaged version lands beside it as a `.pacnew`. Deleting it here
    /// would throw away edits a moment before that happens.
    fn keeps(&self, stripped: &str) -> bool {
        self.backups.contains(stripped) && self.files.contains(stripped)
    }

    /// Whether the replacement ships the path exactly as spelled (`remove.c:487`).
    fn ships(&self, spelled: &str) -> bool {
        self.files.contains(spelled)
    }
}

/// Every package is available and verified, every entry to remove exists and is readable, and
/// no file is contested.
#[derive(Debug)]
pub struct Verified {
    steps: Vec<Step>,
    /// Located packages, parallel to the install steps.
    packages: Vec<Prepared>,
    /// Entries to be removed, parallel to the removal steps.
    removals: Vec<Doomed>,
    /// Paths a removal step must leave alone because an install step now owns them.
    skip_remove: std::collections::BTreeSet<PathBuf>,
    /// What the hooks will be asked about.
    ///
    /// Built here, before anything changes, because it describes the *old* state as much as
    /// the new one. An upgrade's `old_files` and a removal's file list are only readable while
    /// the packages are still installed.
    summary: hook::Summary,
}

/// The lock is held and the journal is written.
#[derive(Debug)]
pub struct Staged<'lock> {
    steps: Vec<Step>,
    packages: Vec<Prepared>,
    removals: Vec<Doomed>,
    skip_remove: std::collections::BTreeSet<PathBuf>,
    summary: hook::Summary,
    journal: Journal,
    lock: &'lock DbLock,
}

/// A transaction against one root and one database.
#[derive(Debug)]
pub struct Transaction<S> {
    root_path: PathBuf,
    dbpath: PathBuf,
    limits: PackageLimits,
    ownership: Ownership,
    overwrite: Overwrite,
    walk_limits: WalkLimits,
    verification: Verification,
    policy_overrides: HashMap<String, Policy>,
    patterns: Patterns,
    scriptlets: bool,
    hook_dirs: Vec<PathBuf>,
    state: S,
}

impl Transaction<Planned> {
    /// Plans `steps` against `root` and `dbpath`.
    #[must_use]
    pub fn new(root: &Path, dbpath: &Path, steps: Vec<Step>) -> Self {
        Self {
            root_path: root.to_path_buf(),
            dbpath: dbpath.to_path_buf(),
            limits: PackageLimits::default(),
            ownership: Ownership::FromArchive,
            overwrite: Overwrite::default(),
            walk_limits: WalkLimits::default(),
            verification: Verification::Disabled,
            policy_overrides: HashMap::new(),
            patterns: Patterns::default(),
            // Off by default, unlike pacman, for the same reason `--root` has no default: this
            // runs vendor shell code with piko's privileges. The CLI turns it on, so `piko
            // install` behaves like pacman. A library caller has to say so explicitly.
            scriptlets: false,
            hook_dirs: Vec::new(),
            state: Planned { steps },
        }
    }

    /// Runs each package's `.INSTALL` scriptlet at the six points libalpm does.
    ///
    /// Off by default — see [`Transaction::new`]. pacman's `--noscriptlet` is the CLI's way of
    /// turning it back off.
    #[must_use]
    pub const fn scriptlets(mut self, enabled: bool) -> Self {
        self.scriptlets = enabled;
        self
    }

    /// Runs the hooks found in `directories` before and after the transaction.
    ///
    /// The default is an empty list, which runs nothing. These are the configured `HookDir`s —
    /// **host** paths, not paths inside the root. See [`crate::hook`] for why that asymmetry is
    /// deliberate.
    ///
    /// The directories are taken rather than an already-collected [`Hooks`] **on purpose**. The
    /// set of hook files is read once per phase, at the moment that phase runs, so a hook file
    /// the transaction itself installs or deletes is seen exactly as libalpm sees it.
    #[must_use]
    pub fn hook_dirs(mut self, directories: Vec<PathBuf>) -> Self {
        self.hook_dirs = directories;
        self
    }

    /// Sets whether the archive's ownership is applied. Requires privilege when it is.
    #[must_use]
    pub const fn ownership(mut self, ownership: Ownership) -> Self {
        self.ownership = ownership;
        self
    }

    /// Sets the per-package bounds.
    #[must_use]
    pub const fn limits(mut self, limits: PackageLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Releases the paths `overwrite` accepts from file-conflict detection.
    ///
    /// pacman's `--overwrite`. It excuses a *file* whose owner disagrees, never a directory
    /// and never a path a package would replace with a directory — see
    /// [`conflict::decision::Resolution::Overwritten`].
    #[must_use]
    pub fn overwrite(mut self, overwrite: Overwrite) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Sets how package signatures are checked.
    ///
    /// Without this, nothing is verified and `%VALIDATION%` records `none` — see
    /// [`Verification`] for why that is the default and why the CLI never relies on it.
    #[must_use]
    pub fn verification(mut self, verification: Verification) -> Self {
        self.verification = verification;
        self
    }

    /// Overrides [`Transaction::verification`]'s policy for specific package files, keyed by
    /// cache file name (matching [`crate::source::CacheDirSource`]'s own key — `PackageFileName`
    /// has no `Hash` impl).
    ///
    /// A repository's `SigLevel` can differ from another's, unlike a database's single value.
    /// This is how a package is checked against the policy that actually governs *its*
    /// repository, rather than one value for the whole transaction. `verification`'s own
    /// `policy` remains the fallback for a file this map has no answer for.
    #[must_use]
    pub fn policy_overrides(mut self, overrides: HashMap<String, Policy>) -> Self {
        self.policy_overrides = overrides;
        self
    }

    /// Applies `pacman.conf`'s `NoExtract` and `NoUpgrade` patterns.
    ///
    /// The default is empty, which treats no path specially. The `NoExtract` half also reaches
    /// [`hook::Summary`], so hooks and extraction cannot disagree about what was written —
    /// which is why this is one setting rather than two.
    #[must_use]
    pub fn patterns(mut self, patterns: Patterns) -> Self {
        self.patterns = patterns;
        self
    }

    /// Verifies one package's detached signature, returning whether it was actually checked.
    ///
    /// Delegates to [`check_signature`], which is a free function so that a caller with no
    /// `Transaction` — `piko install -w`, which installs nothing — checks a package by the
    /// same rule this does.
    fn check_signature(&self, file_name: &PackageFileName, package: &Path) -> Result<bool> {
        check_signature(&self.verification, &self.policy_overrides, file_name, package)
    }

    /// Locates and reads every package, verifies its signature, checks every entry to be
    /// removed, and finds file conflicts.
    ///
    /// Doing this up front shortens the commit's failure modes. A missing package file, a
    /// `.PKGINFO` that cannot be recorded, or a file two packages both claim, is found before
    /// anything has changed, rather than half-way through. The check needs no lock of its own
    /// — the caller holds one by the time it matters — but it does read the local database. A
    /// `Verified` transaction is only as current as the moment it was verified.
    ///
    /// # Errors
    ///
    /// [`Error::NotAvailable`] if a package cannot be supplied, [`Error::UnusableSource`] if
    /// an entry to be removed is not installed or a package's `.PKGINFO` cannot be read, or
    /// [`Error::FileConflicts`] if the transaction would write a file it does not own.
    pub fn verify(
        self,
        source: &dyn crate::source::PackageSource,
    ) -> Result<Transaction<Verified>> {
        self.verify_with_progress(source, &mut |_| {})
    }

    /// As [`Transaction::verify`], reporting progress through `progress` as it runs.
    ///
    /// `progress` is the same narrow, deliberate exception to "diagnostics are returned, not
    /// logged" as [`Staged::commit_with_progress`] — see [`crate::progress`]'s documentation.
    /// It takes `FnMut` rather than `Fn` for the same reason `commit_with_progress` does: a
    /// caller driving a terminal UI needs a mutable borrow of whatever it draws with.
    ///
    /// # Errors
    ///
    /// As [`Transaction::verify`].
    pub fn verify_with_progress(
        self,
        source: &dyn crate::source::PackageSource,
        progress: &mut dyn FnMut(VerifyEvent),
    ) -> Result<Transaction<Verified>> {
        let local = LocalDatabase::open(self.dbpath.join("local"))
            .map_err(|error| Error::local_db(self.dbpath.join("local"), error))?;

        // Fetched up front, `ParallelDownloads` at a time, so the loop below finds every
        // package already in the cache. The verification order does not change: a download
        // that failed here is simply still missing, and `locate` reports it exactly where it
        // always did — see `PackageSource::prefetch`.
        let incoming: Vec<PackageFileName> = self
            .state
            .steps
            .iter()
            .filter_map(|step| match step {
                Step::Install { package, .. } => Some(package.clone()),
                Step::Remove { .. } => None,
            })
            .collect();
        source.prefetch(&incoming)?;

        let mut located = Vec::new();
        let mut removals = Vec::new();
        let mut doomed_entries: Vec<Doomed> = Vec::new();
        // The same list extraction obeys, handed to the hooks as data. A hook told a path
        // changed that `NoExtract` stopped anyone from writing would be a lie. The two answers
        // stay consistent only because they come from one setting and one matcher.
        let mut summary =
            hook::Summary { no_extract: self.patterns.no_extract.clone(), ..Default::default() };
        // Known up front, so `SignatureChecked` can report a total before this loop finishes a
        // single package. Signature checking hashes the whole file, and can be the slowest step
        // here for a large package.
        let total_installs =
            self.state.steps.iter().filter(|step| matches!(step, Step::Install { .. })).count();
        let mut signature_checked = 0_usize;
        for step in &self.state.steps {
            match step {
                Step::Install { package, .. } => {
                    let path = source.locate(package)?.path().to_path_buf();
                    // Runs before the archive is opened for any other purpose. A package that
                    // fails this is not read further, so a hostile archive gets no chance to
                    // exercise the extractor.
                    located.push((path.clone(), self.check_signature(package, &path)?));
                    signature_checked = signature_checked.saturating_add(1);
                    progress(VerifyEvent::SignatureChecked {
                        index: signature_checked,
                        total: total_installs,
                    });
                }
                Step::Remove { entry, .. } => {
                    let Some(package) = local.get(entry.name()) else {
                        return Err(Error::UnusableSource {
                            path: PathBuf::from(entry.as_str()),
                            reason: "not installed".to_owned(),
                        });
                    };
                    // Read here rather than left to the removal step, so the step needs no
                    // database of its own. Forcing the file list here also forces the backup
                    // list — see [`Doomed`].
                    let doomed = self::doomed(entry, package, self.scriptlets)?;
                    summary.removed.push(hook::trigger::Removed {
                        name: entry.name().to_string(),
                        files: spell(&doomed.installed.files),
                    });
                    removals.push(entry.name().to_string());
                    doomed_entries.push(doomed);
                }
            }
        }

        // Reading each archive is the only way to know what a package not yet installed will
        // write, and the only way to know whether its `.PKGINFO` is one piko can record.
        // pacman loads the same files for the same reason before its own check, so this is not
        // a cost piko added. One walk answers both questions.
        let mut verified_installs = 0_usize;
        let mut targets = Vec::with_capacity(located.len());
        let mut packages = Vec::with_capacity(located.len());
        for (path, validated) in located {
            let conflict::LoadedPackage { target, info, raw } =
                conflict::load_package(&path, &self.limits)?;
            let entry = self::entry_name(&path, &info)?;

            // The installed package of the same name, looked up once and used five ways. It
            // decides `pre_install` against `pre_upgrade`, supplies the scriptlet's `oldver`
            // argument, names the entry `install_step` has to replace, supplies the file list
            // its fake removal deletes, and supplies the `%BACKUP%` baseline extraction needs
            // to tell an edited config file from an untouched one.
            let replaces = superseded(local.get_str(&target.name))?;
            let old_files = replaces.as_ref().map(|old| spell(&old.files)).unwrap_or_default();

            summary.added.push(hook::trigger::Added {
                name: target.name.clone(),
                files: target.files.iter().map(str::to_owned).collect(),
                old_files,
                replaces_installed: replaces.is_some(),
            });
            packages.push(Prepared {
                path,
                name: target.name.clone(),
                version: target.version.clone(),
                entry,
                info,
                raw,
                validated,
                script: target.install_script.clone(),
                files: target.files.clone(),
                backups: target.backups.clone(),
                replaces,
            });
            targets.push(target);
            verified_installs = verified_installs.saturating_add(1);
            progress(VerifyEvent::PackageVerified {
                index: verified_installs,
                total: total_installs,
            });
        }

        let root = RootDir::open(&self.root_path)?;
        progress(VerifyEvent::ConflictCheckStarted);
        let check = conflict::check(
            &root,
            &local,
            &targets,
            &removals,
            &self.overwrite,
            &self.walk_limits,
        )?;
        if !check.is_clear() {
            return Err(Error::FileConflicts { conflicts: check.conflicts });
        }

        Ok(Transaction {
            root_path: self.root_path,
            dbpath: self.dbpath,
            limits: self.limits,
            ownership: self.ownership,
            overwrite: self.overwrite,
            walk_limits: self.walk_limits,
            verification: self.verification,
            policy_overrides: self.policy_overrides,
            patterns: self.patterns,
            scriptlets: self.scriptlets,
            hook_dirs: self.hook_dirs,
            state: Verified {
                steps: self.state.steps,
                packages,
                removals: doomed_entries,
                skip_remove: check.skip_remove,
                summary,
            },
        })
    }
}

/// The database entry a package will become, from its `.PKGINFO`.
///
/// Asked during [`Transaction::verify`], for the same reason the `.PKGINFO` is parsed there. A
/// name and version that do not form an entry mean the package cannot be recorded. That has to
/// be known before anything is written.
fn entry_name(package: &Path, info: &PackageInfo) -> Result<EntryName> {
    let (name, version) = match info {
        PackageInfo::V1(v1) => (&v1.pkgname, &v1.pkgver),
        PackageInfo::V2(v2) => (&v2.pkgname, &v2.pkgver),
    };
    EntryName::new(name, version).map_err(|error| Error::UnusableSource {
        path: package.to_path_buf(),
        reason: format!("its name and version do not form an entry: {error}"),
    })
}

/// A file list as a hook trigger compares it: plain strings, directories keeping their `/`.
fn spell(files: &[PathBuf]) -> Vec<String> {
    files.iter().map(|path| path.to_string_lossy().into_owned()).collect()
}

/// What an install has to take apart first, gathered while the old entry is still readable.
///
/// `None` when nothing of this name is installed. That is the ordinary fresh install.
///
/// # Errors
///
/// [`Error::UnreadableEntry`] if the installed entry exists but its `%FILES%` or `%BACKUP%`
/// cannot be read. Defaulting to an empty list is not an option here: the install is about to
/// delete that entry, so an empty list would leave every file it owned on disk with nothing
/// recording who put them there. That is the exact shape of the bug §57 records, in the one
/// place where it destroys data. Raising it at `verify` also keeps the promise `Verified`
/// makes: the commit does not fail for something that could have been read up front.
fn superseded(installed: Option<&LocalPackage>) -> Result<Option<Superseded>> {
    let Some(package) = installed else { return Ok(None) };
    // Unreachable in practice — the database produced this name and version by parsing a
    // directory name that `EntryName` itself accepted. Not worth an error of its own: without
    // an entry name there is no directory to remove and nothing to remove it from.
    let Ok(entry) = EntryName::new(package.name(), package.version()) else {
        return Ok(None);
    };
    self::installed_state(&entry, package).map(Some)
}

/// One installed entry's `%FILES%` and `%BACKUP%`, read while it is still on disk.
///
/// Shared by the two things that take an installed entry apart — an upgrade's fake removal and
/// a real removal — rather than written twice. This way the rule that neither list may be
/// defaulted cannot be applied in one place and skipped in the other. `remove_files` is one
/// function with two callers for the same reason.
///
/// # Errors
///
/// [`Error::UnreadableEntry`] if either list cannot be read.
fn installed_state(entry: &EntryName, package: &LocalPackage) -> Result<Superseded> {
    let files = package
        .file_list()
        .map_err(|error| Error::UnreadableEntry {
            entry: entry.as_str().to_owned(),
            reason: format!("its file list is unreadable: {error}"),
        })?
        .to_vec();
    let backups = package
        .backups()
        .map_err(|error| Error::UnreadableEntry {
            entry: entry.as_str().to_owned(),
            reason: format!("its backup list is unreadable: {error}"),
        })?
        .iter()
        .map(|backup| (backup.path.inner().to_path_buf(), backup.md5.to_string()))
        .collect();

    Ok(Superseded { entry: entry.clone(), files, backups })
}

/// Everything a removal step needs, read while the entry is still installed.
///
/// The mirror of [`Prepared`]. It exists to stop the local database being re-opened once per
/// removal step. The step only ever wants one entry, and opening a database to reach it means
/// a `readdir` of every installed package — ~1200 of them on this machine — repeated for every
/// package a `-Rcs` removes.
///
/// **This is a structural change, not a bug fix, and the difference is worth stating.** Moving
/// the `%BACKUP%` read from the step up to `verify` looks like it closes a hole in what
/// `Verified` promises, because the step used to read it *after* `pre_remove` had already run.
/// It does not close a hole: `%FILES%` and `%BACKUP%` are one `files` file behind a single
/// `Lazy<DbFiles>` in `LocalPackage`. Forcing the file list — which `verify` already did — had
/// always forced the backup list with it, so `backups()` could not fail where `file_list()`
/// had succeeded. See `a_malformed_backup_hash_makes_the_whole_entry_unreadable_at_verify`,
/// which pins that.
#[derive(Clone, Debug)]
struct Doomed {
    /// Its `%FILES%` and `%BACKUP%`, read exactly as an upgrade reads the version it replaces.
    installed: Superseded,
    /// Its `install` scriptlet, if it ships one and scriptlets are turned on.
    ///
    /// `post_remove` runs after the entry has been deleted, so the bytes have to be held
    /// somewhere regardless. Holding them from `verify` rather than from the top of the step
    /// removes the last reason that step had to open a database.
    script: Option<Vec<u8>>,
}

/// Reads what [`remove_step`] will need from an entry that is still on disk.
///
/// # Errors
///
/// [`Error::UnreadableEntry`] if `%FILES%` or `%BACKUP%` cannot be read. Neither may be
/// defaulted: an empty file list would delete the entry while leaving every file it owned on
/// disk with nothing recording who put them there.
fn doomed(entry: &EntryName, package: &LocalPackage, want_script: bool) -> Result<Doomed> {
    Ok(Doomed {
        installed: self::installed_state(entry, package)?,
        // Only when something will run it. A missing or unreadable scriptlet is not an error
        // either way — see [`read_entry_scriptlet`].
        script: want_script.then(|| read_entry_scriptlet(package.path())).flatten(),
    })
}

impl Transaction<Verified> {
    /// Writes the journal under the held lock, reaching the point of no return.
    ///
    /// `lock` must be the lock for this transaction's `dbpath`. The check belongs here rather
    /// than at the first write, because a lock over the wrong database protects nothing.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the journal cannot be written.
    pub fn stage(self, lock: &DbLock) -> Result<Transaction<Staged<'_>>> {
        let intents: Vec<Intent> = self.state.steps.iter().map(Step::intent).collect();
        let journal = Journal::begin(&self.dbpath, &self.root_path, &intents)?;

        Ok(Transaction {
            root_path: self.root_path,
            dbpath: self.dbpath,
            limits: self.limits,
            ownership: self.ownership,
            overwrite: self.overwrite,
            walk_limits: self.walk_limits,
            verification: self.verification,
            policy_overrides: self.policy_overrides,
            patterns: self.patterns,
            scriptlets: self.scriptlets,
            hook_dirs: self.hook_dirs,
            state: Staged {
                steps: self.state.steps,
                packages: self.state.packages,
                removals: self.state.removals,
                skip_remove: self.state.skip_remove,
                summary: self.state.summary,
                journal,
                lock,
            },
        })
    }
}

impl Transaction<Staged<'_>> {
    /// Abandons the transaction, removing the journal.
    ///
    /// Valid only because nothing has been mutated yet — which is exactly what the `Staged`
    /// state means.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the journal cannot be removed.
    pub fn abandon(self) -> Result<()> {
        self.state.journal.finish()
    }

    /// Applies every step, in order.
    ///
    /// # Errors
    ///
    /// Whatever the underlying step fails with. **The journal is deliberately left behind on
    /// failure.** A partly applied transaction is exactly the state it exists to record.
    /// Removing it would erase the only evidence.
    pub fn commit(self) -> Result<Report> {
        self.commit_with_progress(&mut |_| {})
    }

    /// As [`Staged::commit`], reporting progress through `progress` as it happens.
    ///
    /// `progress` is a narrow, deliberate exception to "diagnostics are returned, not logged"
    /// — see [`crate::progress`]'s documentation before treating this as license to add
    /// another one. It fires only for [`Step::Install`]/[`Step::Remove`], not for hooks, which
    /// already report through [`Report::hooks`]. It takes `FnMut` rather than `Fn`, because a
    /// caller printing a durable line per step needs a mutable borrow of whatever it writes to.
    ///
    /// # Errors
    ///
    /// As [`Staged::commit`].
    pub fn commit_with_progress(self, progress: &mut dyn FnMut(Event<'_>)) -> Result<Report> {
        let root = RootDir::open(&self.root_path)?;
        let mut state = self.state;
        let mut report = Report::default();
        let mut next_package = 0_usize;
        let mut next_removal = 0_usize;

        // Needed by scriptlets and hooks alike, and built even when neither will run. It only
        // resolves piko's own executable. Doing this before the first mutation means it fails
        // here rather than mid-transaction.
        let runner = Runner::new(&self.root_path)?;

        // Runs before anything changes. A `PreTransaction` hook with `AbortOnFail` that fails
        // stops the transaction here, with the system still untouched — which is the whole
        // reason that flag is `PreTransaction`-only.
        let aborted = self::run_hooks(
            &runner,
            &self.dbpath,
            &self.hook_dirs,
            When::PreTransaction,
            &state.summary,
            &mut report,
            progress,
        )?;
        if let Some(name) = aborted {
            // The journal is removed. Nothing was applied, so leaving one behind would make a
            // refused transaction look like an interrupted one.
            state.journal.finish()?;
            let output = report
                .hooks
                .last()
                .and_then(|run| run.outcome.as_ref())
                .map(|outcome| outcome.output.clone())
                .unwrap_or_default();
            return Err(Error::HookAborted { hook: name, output });
        }

        let total = state.steps.len();
        for (index, step) in state.steps.iter().enumerate() {
            // Peeked, not consumed. `next_package` still advances only inside the
            // `Step::Install` arm below.
            let replaces = match step {
                Step::Install { .. } => state
                    .packages
                    .get(next_package)
                    .and_then(|package| package.replaces.as_ref().map(|old| &old.entry)),
                Step::Remove { .. } => None,
            };
            progress(Event::StepStarted { index, total, step, replaces });
            match step {
                Step::Install { reason, .. } => {
                    let Some(package) = state.packages.get(next_package) else {
                        return Err(Error::UnusableSource {
                            path: PathBuf::new(),
                            reason: "verification did not locate this package".to_owned(),
                        });
                    };
                    next_package = next_package.saturating_add(1);
                    let pacsaves_before = report.pacsaves.len();
                    let extraction = self::install_step(
                        &InstallStep {
                            root: &root,
                            dbpath: &self.dbpath,
                            lock: state.lock,
                            package,
                            reason: *reason,
                            ownership: self.ownership,
                            limits: &self.limits,
                            skip_remove: &state.skip_remove,
                            patterns: &self.patterns,
                            runner: self.scriptlets.then_some(&runner),
                        },
                        &mut report,
                        progress,
                    )?;
                    state.journal.completed(index)?;
                    progress(Event::StepFinished {
                        step,
                        outcome: StepOutcome::Installed {
                            entry: &package.entry,
                            replaced: package.replaces.as_ref().map(|old| &old.entry),
                            extraction: &extraction,
                            pacsaves: report.pacsaves.get(pacsaves_before..).unwrap_or_default(),
                        },
                    });
                    report.installed.push((
                        package.path.file_name().unwrap_or_default().to_string_lossy().into_owned(),
                        extraction,
                    ));
                }
                Step::Remove { entry, no_save } => {
                    let Some(doomed) = state.removals.get(next_removal) else {
                        return Err(Error::UnusableSource {
                            path: PathBuf::from(entry.as_str()),
                            reason: "verification did not read this entry".to_owned(),
                        });
                    };
                    next_removal = next_removal.saturating_add(1);
                    let (touched, pacsaves) = self::remove_step(
                        &RemoveStep {
                            root: &root,
                            dbpath: &self.dbpath,
                            lock: state.lock,
                            entry,
                            doomed,
                            no_save: *no_save,
                            skip_remove: &state.skip_remove,
                            patterns: &self.patterns,
                            runner: self.scriptlets.then_some(&runner),
                        },
                        &mut report,
                        progress,
                    )?;
                    state.journal.completed(index)?;
                    progress(Event::StepFinished {
                        step,
                        outcome: StepOutcome::Removed { pacsaves: &pacsaves },
                    });
                    report.removed.push((entry.as_str().to_owned(), touched));
                    report.pacsaves.extend(pacsaves);
                }
            }
        }

        // `alpm-hooks(5)`: "PostTransaction hooks will not run if the transaction fails to
        // complete for any reason." So this runs after the loop, and the `?`s above skip it.
        // `AbortOnFail` is meaningless here and is ignored, as in libalpm.
        drop(self::run_hooks(
            &runner,
            &self.dbpath,
            &self.hook_dirs,
            When::PostTransaction,
            &state.summary,
            &mut report,
            progress,
        )?);

        state.journal.finish()?;
        Ok(report)
    }
}

/// Runs the hooks for one phase, appending each to `report`.
///
/// Returns the name of the hook that demands the transaction be abandoned, if one does.
///
/// # The hook files are read here, not once up front
///
/// `_alpm_hook_run` does its own `opendir`/`readdir` of every `HookDir` (`hook.c:536`). It runs
/// twice — before the transaction and after it (`trans.c:202` and `trans.c:238`). So the set of
/// hook files is whatever is on disk **at the moment the phase runs**, and the two phases can
/// legitimately see different sets.
///
/// That is not a minor detail. Arch ships each hook in the same package as the program it
/// runs — 31 of this machine's 46 hooks name an `Exec` their own package owns. A removal
/// deletes the hook file together with the binary, and the `PostTransaction` pass simply never
/// finds it. Only 8 of those 46 declare a `Depends`, so `Depends` is *not* what protects them.
/// Collecting the hook set once before the transaction would run a hook whose file and command
/// were both just deleted.
fn run_hooks(
    runner: &Runner,
    dbpath: &Path,
    hook_dirs: &[PathBuf],
    when: When,
    summary: &hook::Summary,
    report: &mut Report,
    progress: &mut dyn FnMut(Event<'_>),
) -> Result<Option<String>> {
    if hook_dirs.is_empty() {
        return Ok(None);
    }

    let (hooks, problems) = Hooks::collect(hook_dirs);
    report.hook_problems.extend(problems);

    let triggered = hooks.triggered(when, summary);
    if triggered.is_empty() {
        return Ok(None);
    }

    // Re-opened per phase rather than held. A `PostTransaction` hook's `Depends` must be
    // judged against the database as the transaction left it — exactly what
    // `_alpm_hook_run_hook` reads (`hook.c:505`) at the moment it runs.
    let local = LocalDatabase::open(dbpath.join("local"))
        .map_err(|error| Error::local_db(dbpath.join("local"), error))?;

    let total = triggered.len();
    progress(Event::HooksStarted { total });
    for (index, (hook, targets)) in triggered.into_iter().enumerate() {
        progress(Event::HookStarted {
            index,
            total,
            name: &hook.name,
            description: hook.description.as_deref(),
        });
        let run = hook::run(runner, &local, hook, &targets, &mut |line| {
            progress(Event::HookOutputLine { index, total, line });
        })?;
        let fatal = run.fatal.then(|| run.name.clone());
        progress(Event::HookFinished { index, total, run: &run });
        report.hooks.push(run);
        if let Some(name) = fatal {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

/// The `install` file inside a database entry, if it has one.
///
/// A missing scriptlet is the common case and not an error — `_alpm_runscriptlet` returns
/// success for a path it cannot read (`trans.c:346`). An unreadable one is treated the same
/// way. A removal must not be blocked by a file it is about to delete anyway.
fn read_entry_scriptlet(entry_path: &Path) -> Option<Vec<u8>> {
    let path = entry_path.join("install");
    piko_db::fs_util::read_capped_utf8(&path, piko_db::Limit::Desc, MAX_SCRIPTLET_BYTES)
        .ok()
        .map(String::into_bytes)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::source::CacheDirSource;

    /// A `.PKGINFO` for `foo` at `version`, declaring `backups` as `%BACKUP%` paths.
    fn pkginfo(version: &str, backups: &[&str]) -> String {
        let mut text = format!(
            "pkgname = foo\npkgbase = foo\npkgver = {version}\n\
             pkgdesc = An example package\nurl = https://example.org/\n\
             builddate = 1733737242\n\
             packager = Foobar McFooface <foobar@mcfooface.org>\n\
             size = 123\narch = x86_64\nlicense = MIT\n"
        );
        for path in backups {
            text.push_str(&format!("backup = {path}\n"));
        }
        text
    }

    /// A cache holding one synthetic package at version `1.0.0-1` with no backup files.
    fn cache_with_package(name: &str, payload: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write_package(dir.path(), name, "1.0.0-1", &[], payload);
        dir
    }

    /// Writes one synthetic `foo` package into `dir`.
    fn write_package(
        dir: &Path,
        name: &str,
        version: &str,
        backups: &[&str],
        payload: &[(&str, &[u8])],
    ) {
        let mut builder = tar::Builder::new(Vec::new());

        fn add(builder: &mut tar::Builder<Vec<u8>>, path: &str, contents: &[u8]) {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        fn add_dir(builder: &mut tar::Builder<Vec<u8>>, path: &str) {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Directory);
            header.set_cksum();
            builder.append_data(&mut header, path, &[][..]).unwrap();
        }

        add(&mut builder, ".PKGINFO", pkginfo(version, backups).as_bytes());
        // A real package lists every parent directory it owns exactly once. `alpm-db`'s
        // `files` reader requires both halves of that, so the fixture does too.
        let mut listed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (path, contents) in payload {
            let mut prefix = String::new();
            let parts: Vec<&str> = path.split('/').collect();
            for part in parts.iter().take(parts.len().saturating_sub(1)) {
                prefix.push_str(part);
                prefix.push('/');
                if listed.insert(prefix.clone()) {
                    add_dir(&mut builder, &prefix);
                }
            }
            add(&mut builder, path, contents);
        }
        std::fs::write(dir.join(name), builder.into_inner().unwrap()).unwrap();
    }

    /// A cache holding one package whose `.PKGINFO` is spelled out rather than generated.
    fn cache_with_raw_pkginfo(
        name: &str,
        pkginfo: &str,
        payload: &[(&str, &[u8])],
    ) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut add = |path: &str, contents: &[u8], is_dir: bool| {
            let mut header = tar::Header::new_gnu();
            header.set_mode(if is_dir { 0o755 } else { 0o644 });
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(contents.len() as u64);
            if is_dir {
                header.set_entry_type(tar::EntryType::Directory);
            }
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        };

        add(".PKGINFO", pkginfo.as_bytes(), false);
        for (path, contents) in payload {
            let mut prefix = String::new();
            let parts: Vec<&str> = path.split('/').collect();
            for part in parts.iter().take(parts.len().saturating_sub(1)) {
                prefix.push_str(part);
                prefix.push('/');
                add(&prefix.clone(), &[][..], true);
            }
            add(path, contents, false);
        }
        std::fs::write(dir.path().join(name), builder.into_inner().unwrap()).unwrap();
        dir
    }

    fn dbpath() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("local")).unwrap();
        std::fs::write(dir.path().join("local/ALPM_DB_VERSION"), "9\n").unwrap();
        dir
    }

    #[test]
    fn installs_a_package_and_records_it() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();

        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };

        let lock = DbLock::acquire(db.path()).unwrap();
        let report = Transaction::new(root.path(), db.path(), vec![step])
            .ownership(Ownership::Inherit)
            .verify(&source)
            .unwrap()
            .stage(&lock)
            .unwrap()
            .commit()
            .unwrap();

        assert_eq!(report.installed.len(), 1);
        assert_eq!(std::fs::read(root.path().join("usr/bin/foo")).unwrap(), b"binary");

        // The database entry is real: piko's own reader opens it.
        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        let package = local.get_str("foo").expect("the entry was not recorded");
        assert_eq!(package.version().to_string(), "1.0.0-1");
        assert_eq!(
            package.file_list().unwrap(),
            [PathBuf::from("usr/"), PathBuf::from("usr/bin/"), PathBuf::from("usr/bin/foo")]
        );

        // And the journal is gone, so nothing looks interrupted.
        assert!(crate::journal::read(db.path()).unwrap().is_none());
    }

    #[test]
    fn removes_a_package_and_its_files() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
        )
        .ownership(Ownership::Inherit)
        .verify(&source)
        .unwrap()
        .stage(&lock)
        .unwrap()
        .commit()
        .unwrap();

        let entry = EntryName::parse("foo-1.0.0-1").unwrap();
        Transaction::new(root.path(), db.path(), vec![Step::Remove { entry, no_save: false }])
            .verify(&source)
            .unwrap()
            .stage(&lock)
            .unwrap()
            .commit()
            .unwrap();

        assert!(!root.path().join("usr/bin/foo").exists());
        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        assert!(local.get_str("foo").is_none(), "the entry survived removal");
    }

    /// One bad `%BACKUP%` hash makes the whole entry unreadable, file list included.
    ///
    /// Not obvious, and worth pinning: `%FILES%` and `%BACKUP%` live in one `files` file, and
    /// `LocalPackage` parses it **once**, behind a single `Lazy<DbFiles>`. So `backups()`
    /// cannot fail unless `file_list()` fails too — they are the same parse — and the error a
    /// corrupt backup hash produces names the *file list*.
    ///
    /// That is why reading the backup list at `verify` rather than inside the removal step is a
    /// structural change and not a bug fix: forcing the file list, which `verify` already did,
    /// had always forced the backup list with it. This test is what proves that.
    ///
    /// The rest of the assertion checks *when* the refusal arrives: `verify` returns it, so
    /// `stage` is never reached and nothing has been touched.
    #[test]
    fn a_malformed_backup_hash_makes_the_whole_entry_unreadable_at_verify() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
        )
        .ownership(Ownership::Inherit)
        .verify(&source)
        .unwrap()
        .stage(&lock)
        .unwrap()
        .commit()
        .unwrap();

        // `%BACKUP%` lives in the entry's `files`, beside `%FILES%`, as `path<TAB>md5`.
        // A hash that is not one is what a corrupt entry looks like.
        let files = db.path().join("local/foo-1.0.0-1/files");
        let mut text = std::fs::read_to_string(&files).unwrap();
        text.push_str("\n%BACKUP%\netc/foo\tnot-a-hash\n");
        std::fs::write(&files, text).unwrap();

        let entry = EntryName::parse("foo-1.0.0-1").unwrap();
        let error =
            Transaction::new(root.path(), db.path(), vec![Step::Remove { entry, no_save: false }])
                .verify(&source)
                .unwrap_err();

        // The reason names the file list, not the backup list, because one parse produced both.
        let Error::UnreadableEntry { ref reason, .. } = error else {
            panic!("got {error:?}");
        };
        assert!(reason.contains("file list"), "{reason}");
        // Nothing was staged, so the package's files are all still there.
        assert!(root.path().join("usr/bin/foo").exists());
        assert!(crate::journal::read(db.path()).unwrap().is_none());
    }

    /// An unopenable local database keeps its cause typed, rather than stringified.
    ///
    /// This used to be an `Error::Io` carrying `io::Error::other(error.to_string())`. The
    /// message a user read was `failed to open <path>`. That named the wrong failure: a commit
    /// engine that cannot open the database has not failed at I/O in any way the
    /// `IoAction::Open` verb describes. Worse, the `piko_db::Error` underneath was gone for
    /// good, flattened into an opaque string no caller could match on at any depth.
    ///
    /// Asserted on shape rather than wording. The downcast is to `Box<piko_db::Error>`, not to
    /// `piko_db::Error`, because `#[source]` on a boxed field yields the box. See that
    /// variant's own documentation for why it is boxed at all.
    #[test]
    fn an_unopenable_local_database_keeps_its_cause_typed() {
        let cache = tempfile::tempdir().unwrap();
        let db = tempfile::tempdir().unwrap();
        // A `local` subdirectory that already holds something, but not `ALPM_DB_VERSION`.
        // A missing marker is tolerated on an empty or absent directory — see
        // `piko_db::local::schema_version::root_is_unpopulated` — so this needs an entry
        // besides the marker to still count as unreadable rather than a fresh database.
        let local = db.path().join("local");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(local.join("stray-file"), b"").unwrap();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let step = Step::Install {
            package: "absent-1.0.0-1-x86_64.pkg.tar.zst".parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let error =
            Transaction::new(root.path(), db.path(), vec![step]).verify(&source).unwrap_err();

        assert!(
            matches!(error, Error::LocalDatabaseUnreadable { .. }),
            "expected LocalDatabaseUnreadable, got {error:?}"
        );
        // The top line says what failed, and does not pretend it was an `open` syscall.
        let message = error.to_string();
        assert!(message.contains("local database"), "{message}");

        let cause = std::error::Error::source(&error).expect("the cause must survive");
        let db_error = cause
            .downcast_ref::<Box<piko_db::Error>>()
            .expect("the cause must still be a piko_db::Error, not an opaque string");
        // Its own message reaches the user unmerged, on its own `caused by:` line.
        assert!(db_error.to_string().contains("ALPM_DB_VERSION"), "{db_error}");
    }

    /// A missing package is caught before anything is touched.
    #[test]
    fn verification_fails_before_the_system_is_changed() {
        let cache = tempfile::tempdir().unwrap();
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let step = Step::Install {
            package: "absent-1.0.0-1-x86_64.pkg.tar.zst".parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let planned = Transaction::new(root.path(), db.path(), vec![step]);
        assert!(planned.verify(&source).is_err());
        // No journal, because staging never happened.
        assert!(crate::journal::read(db.path()).unwrap().is_none());
    }

    /// A `.PKGINFO` piko cannot record fails at `verify`, not half-way through the commit.
    ///
    /// This is a regression test with a history. The parse used to happen *after* `install`
    /// had extracted the payload. A `packager` line without an `<email>` then failed the
    /// transaction with the package's file already in the root and the journal already on
    /// disk. Both assertions below are the ones that used to fail.
    #[test]
    fn an_unrecordable_pkginfo_fails_before_the_root_is_touched() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let broken = pkginfo("1.0.0-1", &[])
            .replace("packager = Foobar McFooface <foobar@mcfooface.org>", "packager = test");
        let cache = cache_with_raw_pkginfo(name, &broken, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let error = Transaction::new(root.path(), db.path(), vec![step])
            .ownership(Ownership::Inherit)
            .verify(&source)
            .unwrap_err();

        assert!(
            matches!(&error, Error::UnusableSource { reason, .. }
                     if reason.contains(".PKGINFO is unreadable")),
            "got {error:?}"
        );
        assert!(!root.path().join("usr/bin/foo").exists(), "the payload was extracted anyway");
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "a journal was written");
    }

    /// `Staged` is the last point at which walking away costs nothing.
    #[test]
    fn abandoning_a_staged_transaction_leaves_no_trace() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        let staged = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
        )
        .verify(&source)
        .unwrap()
        .stage(&lock)
        .unwrap();

        assert!(crate::journal::read(db.path()).unwrap().is_some(), "staging writes a journal");
        staged.abandon().unwrap();

        assert!(crate::journal::read(db.path()).unwrap().is_none());
        assert!(!root.path().join("usr/bin/foo").exists());
    }

    /// The check is wired in, and it stops the transaction at `verify` — before the lock,
    /// before the journal, before a single byte is written.
    #[test]
    fn a_file_another_package_owns_stops_the_transaction() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/tool", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        // Another package already owns `usr/bin/tool`, and the file is really there.
        std::fs::create_dir_all(db.path().join("local/other-1.0.0-1")).unwrap();
        std::fs::write(
            db.path().join("local/other-1.0.0-1/files"),
            "%FILES%\nusr/\nusr/bin/\nusr/bin/tool\n",
        )
        .unwrap();
        std::fs::write(
            db.path().join("local/other-1.0.0-1/desc"),
            "%NAME%\nother\n\n%VERSION%\n1.0.0-1\n\n%ARCH%\nx86_64\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        std::fs::write(root.path().join("usr/bin/tool"), b"theirs").unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let error = Transaction::new(root.path(), db.path(), vec![step])
            .ownership(Ownership::Inherit)
            .verify(&source)
            .unwrap_err();

        let Error::FileConflicts { conflicts } = &error else {
            panic!("expected a file conflict, got {error:?}");
        };
        assert_eq!(conflicts.len(), 1, "{conflicts:?}");
        assert!(error.to_string().contains("usr/bin/tool"), "{error}");
        assert!(error.to_string().contains("other"), "{error}");

        // And the other package's file is untouched, which is the whole point.
        assert_eq!(std::fs::read(root.path().join("usr/bin/tool")).unwrap(), b"theirs");
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "nothing was staged");
    }

    /// `--overwrite` lets the same transaction through, and the file does change hands.
    #[test]
    fn overwrite_releases_the_same_transaction() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/tool", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        std::fs::create_dir_all(db.path().join("local/other-1.0.0-1")).unwrap();
        std::fs::write(
            db.path().join("local/other-1.0.0-1/files"),
            "%FILES%\nusr/\nusr/bin/\nusr/bin/tool\n",
        )
        .unwrap();
        std::fs::write(
            db.path().join("local/other-1.0.0-1/desc"),
            "%NAME%\nother\n\n%VERSION%\n1.0.0-1\n\n%ARCH%\nx86_64\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        std::fs::write(root.path().join("usr/bin/tool"), b"theirs").unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(root.path(), db.path(), vec![step])
            .ownership(Ownership::Inherit)
            .overwrite(Overwrite::new(|path| path == std::path::Path::new("usr/bin/tool")))
            .verify(&source)
            .unwrap()
            .stage(&lock)
            .unwrap()
            .commit()
            .unwrap();

        assert_eq!(std::fs::read(root.path().join("usr/bin/tool")).unwrap(), b"binary");
    }

    /// With verification on and no signature present, `Required` stops the transaction —
    /// before the lock, before the journal, before anything is written.
    #[test]
    fn an_unsigned_package_is_refused_when_signatures_are_required() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let keys = tempfile::tempdir().unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let error = Transaction::new(root.path(), db.path(), vec![step])
            .ownership(Ownership::Inherit)
            .verification(Verification::Enabled {
                keyring: Keyring::open(keys.path()).unwrap(),
                policy: Policy::for_package(piko_db::config::SigLevel::PACKAGE),
            })
            .verify(&source)
            .unwrap_err();

        assert!(matches!(error, Error::SignatureRejected { .. }), "got {error:?}");
        assert!(!root.path().join("usr/bin/foo").exists(), "nothing should have been written");
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "nothing was staged");
    }

    /// The same package under `Optional` installs, and records `none` rather than claiming a
    /// verification that did not happen.
    #[test]
    fn an_optional_policy_installs_and_records_that_nothing_was_verified() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let keys = tempfile::tempdir().unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
        )
        .ownership(Ownership::Inherit)
        .verification(Verification::Enabled {
            keyring: Keyring::open(keys.path()).unwrap(),
            policy: Policy::for_package(
                piko_db::config::SigLevel::PACKAGE | piko_db::config::SigLevel::PACKAGE_OPTIONAL,
            ),
        })
        .verify(&source)
        .unwrap()
        .stage(&lock)
        .unwrap()
        .commit()
        .unwrap();

        let text = std::fs::read_to_string(db.path().join("local/foo-1.0.0-1/desc")).unwrap();
        assert!(text.contains("%VALIDATION%\nnone\n"), "{text}");
    }

    /// A per-file override in `policy_overrides` is checked instead of `verification`'s own
    /// fallback `policy`. This proves a package can be held to a stricter policy than the
    /// transaction's default, the way one repository's `SigLevel` can differ from another's.
    #[test]
    fn a_policy_override_takes_precedence_over_the_fallback() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let keys = tempfile::tempdir().unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let error = Transaction::new(root.path(), db.path(), vec![step])
            .ownership(Ownership::Inherit)
            // The fallback would accept an unsigned package...
            .verification(Verification::Enabled {
                keyring: Keyring::open(keys.path()).unwrap(),
                policy: Policy::for_package(
                    piko_db::config::SigLevel::PACKAGE
                        | piko_db::config::SigLevel::PACKAGE_OPTIONAL,
                ),
            })
            // ...but this file's own override requires one.
            .policy_overrides(HashMap::from([(
                name.to_owned(),
                Policy::for_package(piko_db::config::SigLevel::PACKAGE),
            )]))
            .verify(&source)
            .unwrap_err();

        assert!(matches!(error, Error::SignatureRejected { .. }), "got {error:?}");
    }

    /// Installs `foo-<version>` from `cache` into `root`/`db`, and returns what it did.
    fn install_foo(cache: &Path, db: &Path, root: &Path, lock: &DbLock, version: &str) -> Report {
        let source = CacheDirSource::new([cache.to_path_buf()]).unwrap();
        Transaction::new(
            root,
            db,
            vec![Step::Install {
                package: format!("foo-{version}-x86_64.pkg.tar").parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
        )
        .ownership(Ownership::Inherit)
        .verify(&source)
        .unwrap()
        .stage(lock)
        .unwrap()
        .commit()
        .unwrap()
    }

    /// The fake remove transaction (`add.c:508`). A file the old version owned and the new one
    /// does not must go. Everything both ship survives, with the new content.
    ///
    /// Without this, the old file stayed on disk owned by nobody: the entry naming it had just
    /// been replaced.
    #[test]
    fn an_upgrade_deletes_the_files_the_new_version_drops() {
        let cache = tempfile::tempdir().unwrap();
        write_package(
            cache.path(),
            "foo-1.0.0-1-x86_64.pkg.tar",
            "1.0.0-1",
            &[],
            &[("usr/bin/foo", b"old"), ("usr/share/foo/dropped", b"gone soon")],
        );
        write_package(
            cache.path(),
            "foo-2.0.0-1-x86_64.pkg.tar",
            "2.0.0-1",
            &[],
            &[("usr/bin/foo", b"new")],
        );

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();

        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");
        assert!(root.path().join("usr/share/foo/dropped").exists());

        install_foo(cache.path(), db.path(), root.path(), &lock, "2.0.0-1");

        assert!(
            !root.path().join("usr/share/foo/dropped").exists(),
            "the dropped file was orphaned on disk"
        );
        // Its directory, which the new version does not ship either, went with it.
        assert!(!root.path().join("usr/share/foo").exists(), "the emptied directory stayed");
        // Everything both versions ship survives, holding the new content.
        assert_eq!(std::fs::read(root.path().join("usr/bin/foo")).unwrap(), b"new");
        assert!(root.path().join("usr/bin").is_dir(), "a shared directory was destroyed");

        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        let package = local.get_str("foo").expect("the new entry was not recorded");
        assert_eq!(package.version().to_string(), "2.0.0-1");
        assert_eq!(
            package.file_list().unwrap(),
            [PathBuf::from("usr/"), PathBuf::from("usr/bin/"), PathBuf::from("usr/bin/foo")]
        );
    }

    /// A backup file the new version still ships is left exactly where it is — no `.pacsave`,
    /// no deletion. `should_skip_file`'s third clause (`remove.c:594`). Removing it would
    /// throw away the user's edits a moment before the new copy lands beside them.
    #[test]
    fn an_upgrade_leaves_a_backup_file_the_new_version_still_ships() {
        let cache = tempfile::tempdir().unwrap();
        for version in ["1.0.0-1", "2.0.0-1"] {
            write_package(
                cache.path(),
                &format!("foo-{version}-x86_64.pkg.tar"),
                version,
                &["etc/foo.conf"],
                &[("etc/foo.conf", b"shipped")],
            );
        }

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();

        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");
        // The install recorded the hash of what it shipped, so this edit is detectable —
        // which is the whole point of `%BACKUP%`.
        std::fs::write(root.path().join("etc/foo.conf"), b"edited by the user").unwrap();

        let report = install_foo(cache.path(), db.path(), root.path(), &lock, "2.0.0-1");

        assert!(report.pacsaves.is_empty(), "{:?}", report.pacsaves);
        assert!(
            !root.path().join("etc/foo.conf.pacsave").exists(),
            "a .pacsave was created for a file the new version still manages"
        );
        // The user's edit survives untouched. The two versions ship the same bytes, so
        // `resolve_backup`'s second rule keeps what is there and drops the `.pacnew`.
        assert_eq!(std::fs::read(root.path().join("etc/foo.conf")).unwrap(), b"edited by the user");
        assert!(
            !root.path().join("etc/foo.conf.pacnew").exists(),
            "a redundant .pacnew was left behind"
        );
    }

    /// But a modified backup file the new version **drops** is saved rather than deleted.
    /// This is the one outcome with no recovery if it goes wrong.
    #[test]
    fn an_upgrade_saves_a_modified_backup_file_the_new_version_drops() {
        let cache = tempfile::tempdir().unwrap();
        write_package(
            cache.path(),
            "foo-1.0.0-1-x86_64.pkg.tar",
            "1.0.0-1",
            &["etc/foo.conf"],
            &[("etc/foo.conf", b"shipped"), ("usr/bin/foo", b"old")],
        );
        write_package(
            cache.path(),
            "foo-2.0.0-1-x86_64.pkg.tar",
            "2.0.0-1",
            &[],
            &[("usr/bin/foo", b"new")],
        );

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();

        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");
        std::fs::write(root.path().join("etc/foo.conf"), b"edited by the user").unwrap();

        let report = install_foo(cache.path(), db.path(), root.path(), &lock, "2.0.0-1");

        assert_eq!(report.pacsaves, [PathBuf::from("etc/foo.conf.pacsave")]);
        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf.pacsave")).unwrap(),
            b"edited by the user"
        );
        assert!(!root.path().join("etc/foo.conf").exists(), "the original was left behind");
    }

    /// A package whose archive lists a member twice still produces a usable entry.
    ///
    /// This covers the whole chain, because that is where the damage was: `install` claimed
    /// the path twice, `record::files` wrote both lines, and `alpm-db` then refused the
    /// `files` record — while the install reported **success**. The entry could never be read
    /// again, so the package could be neither removed nor upgraded. Both now refuse an
    /// unreadable entry rather than silently doing nothing.
    ///
    /// libalpm writes the duplicate and reads it back without complaint. This is piko staying
    /// inside what its own reader accepts, not a rule pacman also enforces.
    #[test]
    fn a_package_that_lists_a_member_twice_stays_manageable() {
        let cache = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let mut add = |path: &str, contents: &[u8], directory: bool| {
            let mut header = tar::Header::new_gnu();
            header.set_mode(if directory { 0o755 } else { 0o644 });
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(contents.len() as u64);
            if directory {
                header.set_entry_type(tar::EntryType::Directory);
            }
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        };
        add(".PKGINFO", pkginfo("1.0.0-1", &[]).as_bytes(), false);
        add("usr/", &[][..], true);
        add("usr/bin/", &[][..], true);
        add("usr/bin/foo", b"binary", false);
        add("usr/", &[][..], true);
        std::fs::write(
            cache.path().join("foo-1.0.0-1-x86_64.pkg.tar"),
            builder.into_inner().unwrap(),
        )
        .unwrap();

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();
        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");

        // This checks the record itself, because the assertion below would also pass on a
        // list that merely happens to parse.
        let text = std::fs::read_to_string(db.path().join("local/foo-1.0.0-1/files")).unwrap();
        assert_eq!(text.matches("usr/\n").count(), 1, "{text}");

        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        let package = local.get_str("foo").expect("the entry was not recorded");
        assert_eq!(
            package.file_list().expect("the entry piko wrote will not re-open"),
            [PathBuf::from("usr/"), PathBuf::from("usr/bin/"), PathBuf::from("usr/bin/foo")]
        );

        // It can actually be removed now, which is what an unreadable entry prevented.
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let entry = EntryName::parse("foo-1.0.0-1").unwrap();
        Transaction::new(root.path(), db.path(), vec![Step::Remove { entry, no_save: false }])
            .verify(&source)
            .unwrap()
            .stage(&lock)
            .unwrap()
            .commit()
            .unwrap();
        assert!(!root.path().join("usr/bin/foo").exists());
    }

    /// The headline case: a **fresh** install records `%BACKUP%`.
    ///
    /// `add.c:333`'s `if(backup)` sits outside the `notouch || needbackup` branch, so libalpm
    /// records a hash for every backup file it extracted — including one that was simply not
    /// on the system before. piko used to record none at all, because `install_step` passed
    /// `Filters::default()`, which left `is_backup` always false. See §82.
    #[test]
    fn a_fresh_install_records_the_backup_hash() {
        let cache = tempfile::tempdir().unwrap();
        write_package(
            cache.path(),
            "foo-1.0.0-1-x86_64.pkg.tar",
            "1.0.0-1",
            &["etc/foo.conf"],
            &[("etc/foo.conf", b"shipped"), ("usr/bin/foo", b"binary")],
        );

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();
        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");

        let expected = alpm_types::Md5Checksum::calculate_from(b"shipped").to_string();
        let text = std::fs::read_to_string(db.path().join("local/foo-1.0.0-1/files")).unwrap();
        assert!(text.contains(&format!("%BACKUP%\netc/foo.conf\t{expected}")), "{text}");

        // piko's own reader gives it back, which is what the next upgrade depends on.
        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        let backups = local.get_str("foo").unwrap().backups().unwrap().to_vec();
        assert_eq!(backups.len(), 1, "{backups:?}");
    }

    /// The case the whole `.pacnew` mechanism exists for: the user edited the file *and* the
    /// package changed it. Neither copy may be discarded, so both stay.
    #[test]
    fn an_upgrade_leaves_a_pacnew_when_the_user_and_the_package_both_changed_it() {
        let cache = tempfile::tempdir().unwrap();
        for (version, shipped) in [("1.0.0-1", &b"first"[..]), ("2.0.0-1", &b"second"[..])] {
            write_package(
                cache.path(),
                &format!("foo-{version}-x86_64.pkg.tar"),
                version,
                &["etc/foo.conf"],
                &[("etc/foo.conf", shipped)],
            );
        }

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();

        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");
        std::fs::write(root.path().join("etc/foo.conf"), b"edited by the user").unwrap();

        install_foo(cache.path(), db.path(), root.path(), &lock, "2.0.0-1");

        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf")).unwrap(),
            b"edited by the user",
            "the user's configuration was overwritten"
        );
        assert_eq!(std::fs::read(root.path().join("etc/foo.conf.pacnew")).unwrap(), b"second");
        // `%BACKUP%` records what the *package* shipped, not what is on disk. It is the
        // baseline the next upgrade compares against, not a description of the file.
        let expected = alpm_types::Md5Checksum::calculate_from(b"second").to_string();
        let text = std::fs::read_to_string(db.path().join("local/foo-2.0.0-1/files")).unwrap();
        assert!(text.contains(&expected), "{text}");
    }

    /// A `NoExtract` path is never written, never owned, and never reported to a hook.
    ///
    /// The last of the three is why this is one change. A hook told a path changed that
    /// nothing was allowed to write would be a lie.
    #[test]
    fn a_no_extract_path_is_absent_from_the_root_the_entry_and_the_hooks() {
        let cache = tempfile::tempdir().unwrap();
        write_package(
            cache.path(),
            "foo-1.0.0-1-x86_64.pkg.tar",
            "1.0.0-1",
            &[],
            &[("usr/bin/foo", b"binary"), ("usr/share/locale/de.mo", b"translation")],
        );

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let patterns =
            Patterns { no_extract: vec!["usr/share/locale/*".to_owned()], no_upgrade: Vec::new() };
        let verified = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: "foo-1.0.0-1-x86_64.pkg.tar".parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
        )
        .ownership(Ownership::Inherit)
        .patterns(patterns.clone())
        .verify(&source)
        .unwrap();

        // The hooks are told the same list extraction obeys, from the same setting.
        assert_eq!(verified.state.summary.no_extract, patterns.no_extract);

        verified.stage(&lock).unwrap().commit().unwrap();

        assert!(!root.path().join("usr/share/locale/de.mo").exists(), "it was written anyway");
        assert!(root.path().join("usr/bin/foo").exists());
        let text = std::fs::read_to_string(db.path().join("local/foo-1.0.0-1/files")).unwrap();
        assert!(!text.contains("de.mo"), "the entry claims a file that is not there:\n{text}");
    }

    /// A `NoUpgrade` path is never overwritten and never removed.
    ///
    /// This checks both halves, because libalpm consults the same list in two places —
    /// `add.c:303` and `should_skip_file` (`remove.c:592`). Wiring only the first would let
    /// `remove` delete the very file the directive protects.
    #[test]
    fn a_no_upgrade_path_is_neither_overwritten_nor_removed() {
        let cache = tempfile::tempdir().unwrap();
        for version in ["1.0.0-1", "2.0.0-1"] {
            write_package(
                cache.path(),
                &format!("foo-{version}-x86_64.pkg.tar"),
                version,
                // Declared `%BACKUP%` *as well*, which is the sharp case. Without it, the
                // three-way rule has no original to compare against and keeps both anyway, so
                // the test would pass even with `NoUpgrade` ignored.
                &["etc/foo.conf"],
                &[("etc/foo.conf", version.as_bytes())],
            );
        }

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let patterns =
            Patterns { no_extract: Vec::new(), no_upgrade: vec!["etc/foo.conf".to_owned()] };

        let install = |version: &str| {
            Transaction::new(
                root.path(),
                db.path(),
                vec![Step::Install {
                    package: format!("foo-{version}-x86_64.pkg.tar").parse().unwrap(),
                    reason: PackageInstallReason::Explicit,
                }],
            )
            .ownership(Ownership::Inherit)
            .patterns(patterns.clone())
            .verify(&source)
            .unwrap()
            .stage(&lock)
            .unwrap()
            .commit()
            .unwrap()
        };

        install("1.0.0-1");
        // Deliberately *not* edited. `%BACKUP%` now records what 1.0.0-1 shipped, so the
        // three-way rule would find `original == local`, conclude the user never touched it,
        // and install the new version — which is exactly what `NoUpgrade` forbids. libalpm
        // never gets there: `notouch` is decided first, and no hash is compared (`add.c:303`).
        install("2.0.0-1");

        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf")).unwrap(),
            b"1.0.0-1",
            "NoUpgrade did not protect the installed file"
        );
        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf.pacnew")).unwrap(),
            b"2.0.0-1",
            "the packaged version should be waiting beside it"
        );

        // The removal leaves it too.
        let entry = EntryName::parse("foo-2.0.0-1").unwrap();
        Transaction::new(root.path(), db.path(), vec![Step::Remove { entry, no_save: false }])
            .patterns(patterns)
            .verify(&source)
            .unwrap()
            .stage(&lock)
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf")).unwrap(),
            b"1.0.0-1",
            "the removal deleted a file NoUpgrade protects"
        );
    }

    /// An install as a dependency records `%REASON%`, matching pacman.
    #[test]
    fn a_dependency_install_records_its_reason() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Depend,
            }],
        )
        .ownership(Ownership::Inherit)
        .verify(&source)
        .unwrap()
        .stage(&lock)
        .unwrap()
        .commit()
        .unwrap();

        let text = std::fs::read_to_string(db.path().join("local/foo-1.0.0-1/desc")).unwrap();
        assert!(text.contains("%REASON%\n1\n"), "{text}");
    }
}
