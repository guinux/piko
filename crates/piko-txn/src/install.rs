//! Installs one package into a root.
//!
//! This module composes the other modules. It adds no rules of its own:
//!
//! 1. [`crate::extract::archive::walk`] reads the members.
//! 2. [`crate::extract::decision::decide`] decides what to do with each member.
//! 3. [`crate::extract::apply`] applies the decision, through [`crate::rootfs`].
//! 4. [`crate::extract::backup`] resolves the `.pacnew` of any backup file.
//!
//! The result is an [`Extraction`]: a record of what actually landed. The local database
//! entry is written from this record. Nothing here writes to the database. That is
//! `piko-db-write`'s job, in a later step.
//!
//! # Scope
//!
//! This installs a package's *payload* only. It does not run scriptlets, check for file
//! conflicts against other packages, or verify signatures. Each of these is a later
//! milestone. Each is deliberately absent, not stubbed: a stub that silently succeeds is
//! worse than a missing feature.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read as _,
    path::{Path, PathBuf},
};

use alpm_types::Md5Checksum;

use crate::{
    error::Result,
    extract::{
        Ownership,
        apply::{Applied, apply},
        archive::{self, Member, MemberKind, PackageLimits},
        backup::{self, BackupOutcome},
        decision::{Disposition, EntryContext, Existing, PacnewReason, SkipReason, decide},
    },
    rootfs::RootDir,
};

/// Which paths a transaction treats specially.
///
/// `NoExtract` and `NoUpgrade` are `pacman.conf` directives that hold shell-glob patterns.
/// They arrive here already resolved into predicates, not as patterns. This crate needs no
/// opinion on glob syntax, and a caller can supply any policy it likes — including, in
/// tests, an exact list.
pub struct Filters<'a> {
    /// Paths never to extract at all.
    pub no_extract: &'a dyn Fn(&Path) -> bool,
    /// Paths never to overwrite. The packaged version lands as `.pacnew`.
    pub no_upgrade: &'a dyn Fn(&Path) -> bool,
    /// The hash the currently installed package recorded for a backup path, if any.
    ///
    /// `None` for a fresh install. During an upgrade, this is the old package's `%BACKUP%`
    /// hash. It is the baseline that distinguishes an edited config file from an untouched
    /// one.
    pub old_backup_hash: &'a dyn Fn(&Path) -> Option<String>,
    /// Whether the *new* package declares a path as a backup file.
    pub is_backup: &'a dyn Fn(&Path) -> bool,
}

impl std::fmt::Debug for Filters<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filters").finish_non_exhaustive()
    }
}

impl Default for Filters<'_> {
    /// Filters that treat nothing specially: extract everything, back up nothing.
    fn default() -> Self {
        Self {
            no_extract: &|_| false,
            no_upgrade: &|_| false,
            old_backup_hash: &|_| None,
            is_backup: &|_| false,
        }
    }
}

/// What happened to one payload member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Written to its intended path.
    Written,
    /// Skipped, and why.
    Skipped(crate::extract::decision::SkipReason),
    /// A backup file, resolved against the user's copy.
    Backup(BackupOutcome),
}

/// A record of what an installation actually did.
///
/// The local database entry is written from this record. So `owned` is the set of paths
/// the package *has* on this system. That set is not quite the archive's list, and not
/// quite the set of writes that happened. A `NoExtract` path is dropped: the file is
/// genuinely not there. A directory that already existed is kept: it is there, and a file
/// list missing a parent directory is one `alpm-db` refuses to re-read.
#[derive(Clone, Debug, Default)]
pub struct Extraction {
    /// Every payload path, in archive order, with what happened to it.
    ///
    /// One entry exists per archive **member**. A member listed twice appears twice: that
    /// is what the archive said, and what extraction did. [`Extraction::owned`] is the set
    /// form.
    pub outcomes: Vec<(PathBuf, Outcome)>,
    /// Paths that are now owned by the package, in archive order, each **once**.
    ///
    /// The uniqueness is not decoration. `%FILES%` is written from this list, and `alpm-db`
    /// refuses a `files` record that repeats a path. A duplicated archive member would
    /// otherwise produce an entry piko cannot read back.
    pub owned: Vec<PathBuf>,
    /// `%BACKUP%` hashes to record, keyed by path.
    pub backup_hashes: BTreeMap<PathBuf, Md5Checksum>,
    /// Metadata members (`.PKGINFO`, `.MTREE`, `.INSTALL`, …) and their contents.
    ///
    /// piko captures these rather than extracting them: they belong in the database entry,
    /// not in the root. libalpm does the same, redirecting them in `extract_db_file`
    /// (`add.c:194`).
    pub metadata: BTreeMap<String, Vec<u8>>,
    /// Paths whose hash could not be computed during backup resolution.
    pub unreadable: Vec<PathBuf>,
}

/// Largest metadata member piko holds in memory.
///
/// `.MTREE` for a large package runs to a few hundred kilobytes, so this limit is generous.
/// Metadata is buffered because it is written to the database entry after the walk, and the
/// archive stream cannot be rewound.
const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;

/// Installs the package at `package` into `root`.
///
/// # Errors
///
/// Returns [`crate::Error`] if the archive cannot be read, a path escapes the root, or a
/// write fails. A refusal — a directory in the way of a file — stops the installation. This
/// matches libalpm (`add.c:290`).
pub fn install(
    package: &Path,
    root: &RootDir,
    filters: &Filters<'_>,
    ownership: Ownership,
    limits: &PackageLimits,
) -> Result<Extraction> {
    let mut result = Extraction::default();
    // Backup files need a second pass. The `.pacnew` can only be resolved once it exists,
    // which needs the archive stream to have moved on.
    let mut pending_backups: Vec<(PathBuf, Option<String>, bool)> = Vec::new();
    // What `owned` already holds, so a repeated archive member is claimed once. See `claim`.
    let mut claimed: BTreeSet<PathBuf> = BTreeSet::new();
    // Backup files with no `.pacnew` to resolve against, as `(owned path, file to hash)`.
    // The two differ only under `NoUpgrade`, where what the package shipped is the `.pacnew`.
    let mut pending_hashes: Vec<(PathBuf, PathBuf)> = Vec::new();

    archive::walk(package, limits, |member, contents| {
        if member.kind == MemberKind::Metadata {
            capture_metadata(member, contents, &mut result);
            return Ok(());
        }

        let existing = probe(root, &member.path)?;
        let old_hash = (filters.old_backup_hash)(&member.path);
        let context = EntryContext {
            entry: member.entry,
            existing,
            // Every member being walked *is* the package's file list. piko derives the file
            // list from the archive, not from a separately loaded `%FILES%`. So libalpm's
            // "not in file list" case (`add.c:208`) cannot arise here.
            in_file_list: true,
            no_extract: (filters.no_extract)(&member.path),
            no_upgrade: (filters.no_upgrade)(&member.path),
            old_backup_hash: old_hash.as_deref(),
            new_is_backup: (filters.is_backup)(&member.path),
        };

        let disposition = decide(&context);
        // Parent directories a package did not list must still exist for the write to land.
        if !matches!(disposition, Disposition::Skip(_)) {
            create_parents(root, &member.path)?;
        }

        match apply(root, member, contents, &disposition, ownership)? {
            Applied::Written => {
                result.outcomes.push((member.path.clone(), Outcome::Written));
                claim(&mut result, &mut claimed, &member.path);
                // `add.c:333`'s `if(backup)` sits *outside* the `notouch || needbackup`
                // branch. So a backup file that was simply not there before — every backup
                // file in a fresh install — is still recorded. piko hashes it after the
                // walk, like the `.pacnew` cases below, to avoid interrupting the archive
                // stream.
                if context.new_is_backup {
                    pending_hashes.push((member.path.clone(), member.path.clone()));
                }
            }
            Applied::Skipped => {
                let Disposition::Skip(reason) = disposition else {
                    // `apply` only reports `Skipped` for a `Skip` disposition.
                    return Ok(());
                };
                // A directory that was already there is still one the package ships, so it
                // belongs in `%FILES%`. Only `NoExtract` makes a path genuinely absent from
                // the system, and therefore not the package's.
                //
                // This matters beyond neatness. `alpm-db` refuses a file list whose entries
                // have no listed parent. Omitting a shared directory produces an entry that
                // will not re-open, and every package installed after the first into a
                // given tree hits this. `remove` then cannot read what it owns.
                if reason == SkipReason::DirectoryExists {
                    claim(&mut result, &mut claimed, &member.path);
                }
                result.outcomes.push((member.path.clone(), Outcome::Skipped(reason)));
            }
            Applied::WrittenAsPacnew { reason, is_new } => {
                // The package owns the path either way. Whichever copy wins, the entry is
                // one of this package's files.
                claim(&mut result, &mut claimed, &member.path);

                // The two reasons are *not* interchangeable. Treating them as one was a
                // latent bug here, unreachable only because `no_upgrade` was hardcoded
                // false. Under `NoUpgrade`, libalpm sets `notouch` and never compares a
                // hash (`add.c:303`). The installed file is never replaced, so the
                // `.pacnew` is final. Running the three-way resolution on it would rename
                // the `.pacnew` over the very file the directive exists to protect.
                match reason {
                    PacnewReason::Backup { .. } => {
                        pending_backups.push((member.path.clone(), old_hash, is_new));
                    }
                    PacnewReason::NoUpgrade => {
                        let pacnew = pacnew_path(&member.path);
                        if context.new_is_backup {
                            pending_hashes.push((member.path.clone(), pacnew.clone()));
                        }
                        result.outcomes.push((
                            member.path.clone(),
                            Outcome::Backup(BackupOutcome::KeptBoth { pacnew }),
                        ));
                    }
                }
            }
        }
        Ok(())
    })?;

    for (path, old_hash, is_new) in pending_backups {
        let resolution = backup::resolve(root, &path, old_hash.as_deref(), is_new)?;
        if resolution.unreadable {
            result.unreadable.push(path.clone());
        }
        if let Some(hash) = resolution.recorded_hash {
            result.backup_hashes.insert(path.clone(), hash);
        }
        result.outcomes.push((path, Outcome::Backup(resolution.outcome)));
    }

    // Backup files with nothing to resolve against: `%BACKUP%` still records what the
    // package shipped. The *next* upgrade reads this back as its only baseline for telling
    // an edited file from an untouched one.
    for (owned, on_disk) in pending_hashes {
        match backup::hash_of(root, &on_disk) {
            Some(hash) => {
                result.backup_hashes.insert(owned, hash);
            }
            None => result.unreadable.push(owned),
        }
    }

    Ok(result)
}

/// `<path>.pacnew`, the name [`apply`] diverts an entry to.
fn pacnew_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(crate::extract::apply::PACNEW_SUFFIX);
    PathBuf::from(name)
}

/// Records that the package owns `path`, ignoring a repeat.
///
/// # Why a set and not a list
///
/// Nothing between a package file and here rejects an archive that lists the same member
/// twice. `tar` allows it. [`archive::walk`] counts members, not distinct paths.
/// Extraction happily writes the second copy over the first. libalpm allows it too:
/// nothing in `add_entry_to_files_list` (`be_package.c:385`) or `_alpm_local_db_write`
/// (`be_local.c:1104`) deduplicates, and its own `%FILES%` reader (`be_local.c:861`)
/// appends without complaint. A duplicated member round-trips through pacman unnoticed.
///
/// `alpm-db` is stricter. It refuses such a `files` record outright
/// (`InvalidFilesPaths { "Duplicate paths:" }`). piko must therefore not write one: the
/// install would *succeed*, but the entry it left behind could never be read again. The
/// package could then be neither removed nor upgraded — both now refuse an unreadable
/// entry rather than silently doing nothing.
///
/// Deduplicating loses nothing. A path stated twice is the same claim twice. Every
/// consumer on both sides treats the list as a set.
fn claim(result: &mut Extraction, claimed: &mut BTreeSet<PathBuf>, path: &Path) {
    if claimed.insert(path.to_path_buf()) {
        result.owned.push(path.to_path_buf());
    }
}

/// Buffers a metadata member for the database entry.
fn capture_metadata(member: &Member, contents: &mut dyn std::io::Read, into: &mut Extraction) {
    let name = member.path.to_string_lossy().into_owned();
    let mut buffer = Vec::new();
    // A metadata member too large to buffer is dropped, not treated as a failed install. It
    // is not payload, and the entry is still usable without, say, a `.CHANGELOG`.
    let mut limited = contents.take(MAX_METADATA_BYTES as u64);
    if std::io::Read::read_to_end(&mut limited, &mut buffer).is_ok() {
        into.metadata.insert(name, buffer);
    }
}

/// What is at `path` inside `root`, from an `lstat` that follows nothing.
///
/// Public as [`probe_existing`] because removal asks the same question of the same paths.
pub fn probe_existing(root: &RootDir, path: &Path) -> Existing {
    probe(root, path).unwrap_or(Existing::Absent)
}

/// What is at `path` inside `root`, from an `lstat` that follows nothing.
fn probe(root: &RootDir, path: &Path) -> Result<Existing> {
    let Ok(resolved) = root.resolve_parent(path) else {
        // The parent does not exist yet, so nothing can be at the path.

        return Ok(Existing::Absent);
    };
    match rustix::fs::statat(resolved.dir(), resolved.name(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
    {
        Ok(stat) => Ok(
            if rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory
            {
                Existing::Directory
            } else {
                Existing::Other
            },
        ),
        Err(_) => Ok(Existing::Absent),
    }
}

/// Creates the directories leading to `path`.
fn create_parents(root: &RootDir, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| p.components().next().is_some()) {
        // `create_dir_all` resolves the parent of what it is given, so it is handed a
        // notional child to make it create `parent` itself.
        root.create_dir_all(&parent.join("x"))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// Builds an uncompressed package tarball.
    fn package(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> (tempfile::TempDir, PathBuf) {
        let mut builder = tar::Builder::new(Vec::new());
        build(&mut builder);
        let bytes = builder.into_inner().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pkg.tar");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    fn header(mode: u32) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(0);
        header
    }

    fn file(builder: &mut tar::Builder<Vec<u8>>, name: &str, contents: &[u8]) {
        let mut h = header(0o644);
        h.set_size(contents.len() as u64);
        h.set_cksum();
        builder.append_data(&mut h, name, contents).unwrap();
    }

    /// A directory member, spelled with the trailing slash a real package archive carries.
    fn dir(builder: &mut tar::Builder<Vec<u8>>, name: &str) {
        let mut h = header(0o755);
        h.set_size(0);
        h.set_entry_type(tar::EntryType::Directory);
        h.set_cksum();
        builder.append_data(&mut h, name, &[][..]).unwrap();
    }

    fn root() -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = RootDir::open(dir.path()).unwrap();
        (dir, root)
    }

    fn run(pkg: &Path, root: &RootDir, filters: &Filters<'_>) -> Extraction {
        install(pkg, root, filters, Ownership::Inherit, &PackageLimits::default()).unwrap()
    }

    #[test]
    fn installs_a_payload_and_records_what_it_owns() {
        let (_keep, pkg) = package(|b| {
            file(b, ".PKGINFO", b"pkgname = foo");
            file(b, "usr/bin/foo", b"binary");
            file(b, "etc/foo.conf", b"setting = 1");
        });
        let (dir, root) = root();

        let result = run(&pkg, &root, &Filters::default());

        assert_eq!(std::fs::read(dir.path().join("usr/bin/foo")).unwrap(), b"binary");
        assert_eq!(result.owned, [PathBuf::from("usr/bin/foo"), PathBuf::from("etc/foo.conf")]);
        // Metadata is captured for the database entry, not written into the root.
        assert_eq!(result.metadata.get(".PKGINFO").unwrap(), b"pkgname = foo");
        assert!(!dir.path().join(".PKGINFO").exists());
    }

    /// A member listed twice is owned once, because `%FILES%` is a set.
    ///
    /// `tar` allows a repeated member and libalpm records the repeat, but `alpm-db` refuses a
    /// `files` record that has one — so writing it would leave an entry piko cannot read back.
    /// `outcomes` still reports both members: two were processed, and that is what happened.
    #[test]
    fn a_member_listed_twice_is_owned_once() {
        let (_keep, pkg) = package(|b| {
            dir(b, "usr/");
            dir(b, "usr/bin/");
            file(b, "usr/bin/foo", b"first");
            // Both kinds repeat: a directory that is skipped the second time, and a file that
            // is written over the first copy.
            dir(b, "usr/");
            file(b, "usr/bin/foo", b"second");
        });
        let (dir_handle, root) = root();

        let result = run(&pkg, &root, &Filters::default());

        assert_eq!(
            result.owned,
            [PathBuf::from("usr/"), PathBuf::from("usr/bin/"), PathBuf::from("usr/bin/foo")]
        );
        assert_eq!(result.outcomes.len(), 5, "{:?}", result.outcomes);
        // Last member wins, as it does for tar and for libalpm.
        assert_eq!(std::fs::read(dir_handle.path().join("usr/bin/foo")).unwrap(), b"second");
    }

    /// A `NoExtract` path is not written and is *not* owned — the package does not have that
    /// file on this system, so its `files` entry must not claim it.
    #[test]
    fn a_no_extract_path_is_neither_written_nor_owned() {
        let (_keep, pkg) = package(|b| {
            file(b, "usr/bin/foo", b"binary");
            file(b, "usr/share/locale/de.mo", b"translation");
        });
        let (dir, root) = root();

        let skip = |p: &Path| p.starts_with("usr/share/locale");
        let filters = Filters { no_extract: &skip, ..Filters::default() };
        let result = run(&pkg, &root, &filters);

        assert!(!dir.path().join("usr/share/locale/de.mo").exists());
        assert_eq!(result.owned, [PathBuf::from("usr/bin/foo")]);
        assert!(matches!(
            result.outcomes.get(1),
            Some((_, Outcome::Skipped(crate::extract::decision::SkipReason::NoExtract)))
        ));
    }

    /// The second package into a shared tree must still claim the directories it ships.
    ///
    /// Its directories are already there, so extraction skips them — but the package does own
    /// them, pacman records them, and `alpm-db` refuses to re-read a file list whose entries
    /// have no listed parent. Dropping them made every package after the first produce a
    /// database entry that would not open, which `remove` then could not act on.
    #[test]
    fn a_directory_that_already_exists_is_still_owned() {
        let (_keep, pkg) = package(|b| {
            dir(b, "usr/");
            dir(b, "usr/bin/");
            file(b, "usr/bin/second", b"binary");
        });
        let (dir_handle, root) = root();
        // Something else got here first.
        std::fs::create_dir_all(dir_handle.path().join("usr/bin")).unwrap();

        let result = run(&pkg, &root, &Filters::default());

        assert_eq!(
            result.owned,
            [PathBuf::from("usr/"), PathBuf::from("usr/bin/"), PathBuf::from("usr/bin/second")],
            "a pre-existing directory the package ships must stay in its file list"
        );
        // And it is still reported as skipped, because nothing was written for it.
        assert!(matches!(
            result.outcomes.first(),
            Some((_, Outcome::Skipped(crate::extract::decision::SkipReason::DirectoryExists)))
        ));
    }

    /// The distinction that must survive: `NoExtract` is not the same as "already there".
    #[test]
    fn a_no_extract_directory_is_not_owned() {
        let (_keep, pkg) = package(|b| {
            dir(b, "usr/");
            dir(b, "usr/share/locale/");
        });
        let (dir_handle, root) = root();
        std::fs::create_dir_all(dir_handle.path().join("usr/share/locale")).unwrap();

        let skip = |p: &Path| p.starts_with("usr/share/locale");
        let filters = Filters { no_extract: &skip, ..Filters::default() };
        let result = run(&pkg, &root, &filters);

        assert_eq!(result.owned, [PathBuf::from("usr/")]);
    }

    #[test]
    fn creates_parent_directories_a_package_did_not_list() {
        let (_keep, pkg) = package(|b| file(b, "usr/share/doc/foo/README", b"docs"));
        let (dir, root) = root();

        run(&pkg, &root, &Filters::default());
        assert_eq!(std::fs::read(dir.path().join("usr/share/doc/foo/README")).unwrap(), b"docs");
    }

    /// A fresh install of a backup file just writes it: there is nothing to preserve.
    #[test]
    fn a_backup_file_with_nothing_installed_is_written_directly() {
        let (_keep, pkg) = package(|b| file(b, "etc/foo.conf", b"packaged"));
        let (dir, root) = root();

        let yes = |_: &Path| true;
        let filters = Filters { is_backup: &yes, ..Filters::default() };
        let result = run(&pkg, &root, &filters);

        assert_eq!(std::fs::read_to_string(dir.path().join("etc/foo.conf")).unwrap(), "packaged");
        assert!(!dir.path().join("etc/foo.conf.pacnew").exists());
        assert_eq!(result.owned, [PathBuf::from("etc/foo.conf")]);
    }

    /// An upgrade over a file the user edited must keep their copy and leave a `.pacnew`.
    #[test]
    fn an_edited_backup_file_keeps_the_users_copy() {
        let (_keep, pkg) = package(|b| file(b, "etc/foo.conf", b"new packaged"));
        let (dir, root) = root();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/foo.conf"), b"user edited").unwrap();

        let original = Md5Checksum::calculate_from(b"original shipped").to_string();
        let hash = move |_: &Path| Some(original.clone());
        let yes = |_: &Path| true;
        let filters = Filters { old_backup_hash: &hash, is_backup: &yes, ..Filters::default() };
        let result = run(&pkg, &root, &filters);

        assert_eq!(
            std::fs::read_to_string(dir.path().join("etc/foo.conf")).unwrap(),
            "user edited"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("etc/foo.conf.pacnew")).unwrap(),
            "new packaged"
        );
        // The recorded hash is the package's, so the next upgrade has a baseline.
        assert_eq!(
            result.backup_hashes.get(Path::new("etc/foo.conf")).unwrap().to_string(),
            Md5Checksum::calculate_from(b"new packaged").to_string()
        );
        assert!(matches!(
            result.outcomes.last(),
            Some((_, Outcome::Backup(BackupOutcome::KeptBoth { .. })))
        ));
    }

    /// An untouched config file is upgraded in place, with no `.pacnew` left behind.
    #[test]
    fn an_untouched_backup_file_is_upgraded_in_place() {
        let (_keep, pkg) = package(|b| file(b, "etc/foo.conf", b"new packaged"));
        let (dir, root) = root();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/foo.conf"), b"original shipped").unwrap();

        let original = Md5Checksum::calculate_from(b"original shipped").to_string();
        let hash = move |_: &Path| Some(original.clone());
        let yes = |_: &Path| true;
        let filters = Filters { old_backup_hash: &hash, is_backup: &yes, ..Filters::default() };
        run(&pkg, &root, &filters);

        assert_eq!(
            std::fs::read_to_string(dir.path().join("etc/foo.conf")).unwrap(),
            "new packaged"
        );
        assert!(!dir.path().join("etc/foo.conf.pacnew").exists());
    }

    /// `NoUpgrade` never replaces the installed file, whatever the hashes say.
    #[test]
    fn a_no_upgrade_path_always_lands_as_pacnew() {
        let (_keep, pkg) = package(|b| file(b, "etc/foo.conf", b"packaged"));
        let (dir, root) = root();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/foo.conf"), b"local").unwrap();

        let yes = |_: &Path| true;
        let filters = Filters { no_upgrade: &yes, ..Filters::default() };
        run(&pkg, &root, &filters);

        assert_eq!(std::fs::read_to_string(dir.path().join("etc/foo.conf")).unwrap(), "local");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("etc/foo.conf.pacnew")).unwrap(),
            "packaged"
        );
    }

    /// A directory in the way of a file stops the installation.
    #[test]
    fn a_directory_in_the_way_fails_the_install() {
        let (_keep, pkg) = package(|b| file(b, "usr/thing", b"payload"));
        let (dir, root) = root();
        std::fs::create_dir_all(dir.path().join("usr/thing")).unwrap();

        let err = install(
            &pkg,
            &root,
            &Filters::default(),
            Ownership::Inherit,
            &PackageLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::ExtractionRefused { .. }), "got {err:?}");
    }

    /// Rewrites the member name in a tar header, fixing the checksum.
    ///
    /// `tar::Builder` refuses to emit a `..` path, which is the correct behaviour for a
    /// well-behaved writer and useless for testing a hostile archive. A real attacker writes
    /// the bytes directly, so the test does too.
    fn rename_first_member(bytes: &mut [u8], name: &str) {
        let header = bytes.get_mut(..512).expect("a tar header is 512 bytes");
        header.get_mut(..100).expect("name field").fill(0);
        let field = header.get_mut(..name.len()).expect("name fits");
        field.copy_from_slice(name.as_bytes());

        // The checksum is computed with its own field read as spaces.
        header.get_mut(148..156).expect("checksum field").fill(b' ');
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        let text = format!("{sum:06o}\0 ");
        header.get_mut(148..156).expect("checksum field").copy_from_slice(text.as_bytes());
    }

    /// Confinement holds at this layer too, not only in `rootfs`'s own tests — and against a
    /// hand-crafted archive rather than one a library was willing to produce.
    #[test]
    fn a_traversing_member_fails_the_install() {
        let mut builder = tar::Builder::new(Vec::new());
        file(&mut builder, "aa/escape", b"payload");
        let mut bytes = builder.into_inner().unwrap();
        rename_first_member(&mut bytes, "../escape");

        let keep = tempfile::tempdir().unwrap();
        let pkg = keep.path().join("evil.pkg.tar");
        std::fs::write(&pkg, &bytes).unwrap();
        let (_dir, root) = root();

        let err = install(
            &pkg,
            &root,
            &Filters::default(),
            Ownership::Inherit,
            &PackageLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::UnsafeArchivePath { .. }), "got {err:?}");
        // And nothing landed beside the root, which is where `../escape` aimed.
        assert!(!_dir.path().parent().unwrap().join("escape").exists());
    }
}
