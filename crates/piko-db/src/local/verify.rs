//! Comparing an installed package's owned files against its `ALPM-MTREE` data.
//!
//! This is the equivalent of `pacman -Qkk`. It checks existence, type, ownership, mode,
//! modification time, size, SHA-256 digest and symlink targets, reusing
//! `alpm_mtree::mtree::v2::Path`'s own
//! [`equals_path`](alpm_mtree::mtree::v2::Path::equals_path) rather than re-deriving that
//! comparison. Layered on top is pacman's own `-Qkk` policy:
//!
//! - A `%BACKUP%` file's timestamp, size or digest is allowed to differ — an edited config
//!   file is expected to. A failure to even compute the comparison is not softened.
//! - A directory's modification time is not checked at all.
//! - A missing file matching `NoExtract` is not reported.
//! - `.INSTALL`/`.CHANGELOG` entries are compared against the local database entry, not the
//!   installation root.
//! - Every other dot-prefixed mtree entry (`.BUILDINFO`, `.PKGINFO`, the `mtree` data itself)
//!   is skipped entirely. These belong to piko's own database and are never extracted under
//!   the installation root.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use alpm_common::InputPath;
use alpm_mtree::mtree::{path_validation_error::PathValidationError, v2};

use crate::{
    error::{Error, SharedError},
    local::package::LocalPackage,
    resolve,
};

/// The db-recorded name of a package's install scriptlet, once the `./` mtree prefix and the
/// leading dot pacman keeps are both accounted for. See `check.c`'s special-casing of
/// `.INSTALL`/`.CHANGELOG`, mirrored here.
const INSTALL_MTREE_NAME: &str = ".INSTALL";
/// As [`INSTALL_MTREE_NAME`], for the package's changelog.
const CHANGELOG_MTREE_NAME: &str = ".CHANGELOG";

/// One file that disagreed with the package's `ALPM-MTREE` data.
#[derive(Debug)]
pub struct FileProblem {
    /// The path relative to the installation root (or, for `.INSTALL`/`.CHANGELOG`, relative
    /// to the database entry) that disagreed.
    pub path: PathBuf,
    /// What disagreed about it. Reuses `alpm_mtree`'s own error and message instead of
    /// re-deriving the comparison it already performed.
    pub error: PathValidationError,
    /// Whether `path` is one of the package's `%BACKUP%` entries.
    ///
    /// A `true` here does not mean the disagreement is ignorable in general — only
    /// [`FileProblem::is_error`] knows which [`PathValidationError`] variants a backup file is
    /// allowed to disagree on.
    pub backup: bool,
}

impl FileProblem {
    /// Whether this disagreement should count as a failure.
    ///
    /// `false` only for a `%BACKUP%` file's own timestamp, size or digest actually
    /// *disagreeing*. `pacman -Qkk` expects an edited config file to differ there. A failure
    /// to even compute the comparison (`CreateHashDigest`, e.g. permission denied reading a
    /// root-only backup file) is not softened. `check_file_cksum` (`check.c`) returns an
    /// error unconditionally when it cannot calculate a checksum at all; it only softens an
    /// actual mismatch once both sides are computed. Every other disagreement, backup file or
    /// not, is a failure: a backup file must still be the right type, owner and mode, and
    /// must still exist.
    #[must_use]
    pub fn is_error(&self) -> bool {
        if !self.backup {
            return true;
        }
        !matches!(
            self.error,
            PathValidationError::PathTimeMismatch { .. }
                | PathValidationError::PathSizeMismatch { .. }
                | PathValidationError::PathDigestMismatch { .. }
        )
    }
}

/// The result of [`LocalPackage::verify_files`] for one package with an `mtree` file.
#[derive(Debug)]
pub struct FileCheckReport {
    /// How many files the package's `mtree` data records, mirroring `pacman -Qkk`'s "N total
    /// files". Counts every entry it walks, whether or not a problem was found on it.
    pub total: usize,
    /// Every disagreement found. More than one may share a `path` (e.g. both a mode and an
    /// ownership mismatch on the same file).
    pub problems: Vec<FileProblem>,
}

impl FileCheckReport {
    /// How many distinct files have at least one [`FileProblem::is_error`] problem. This is
    /// `pacman -Qkk`'s "altered files" count: it counts a file once, no matter how many of
    /// its checks failed.
    #[must_use]
    pub fn altered_files(&self) -> usize {
        self.problems
            .iter()
            .filter(|problem| problem.is_error())
            .map(|problem| problem.path.as_path())
            .collect::<HashSet<_>>()
            .len()
    }
}

impl LocalPackage {
    /// Compares every file this package owns against its `ALPM-MTREE` data — the equivalent of
    /// `pacman -Qkk`.
    ///
    /// `Ok(None)` means this package has no `mtree` file to check against, matching `-Qkk`'s
    /// own "no mtree file" case rather than treating it as a failure.
    ///
    /// `no_extract` is `NoExtract` from `pacman.conf`, matched the same way `--overwrite`
    /// patterns are ([`resolve::matches_any`]). A missing file matching one of these
    /// patterns is not reported at all, mirroring `alpm_option_match_noextract`.
    ///
    /// # Errors
    ///
    /// If the `mtree` file cannot be read or parsed, or if `root` is not an absolute path.
    pub fn verify_files(
        &self,
        root: &Path,
        no_extract: &[String],
    ) -> std::result::Result<Option<FileCheckReport>, SharedError> {
        let Some(mtree) = self.mtree()? else {
            return Ok(None);
        };
        let entries = match mtree {
            alpm_mtree::Mtree::V1(entries) | alpm_mtree::Mtree::V2(entries) => entries,
        };

        let backups: HashSet<&Path> =
            self.backups()?.iter().map(|entry| entry.path.inner()).collect();

        let mut problems = Vec::new();
        let mut total = 0_usize;
        for entry in entries {
            let Ok(normalized) = entry.as_normalized_path() else {
                // A malformed mtree path is `equals_path`'s own concern once compared. Skip
                // here instead of duplicating its error reporting.
                continue;
            };

            if normalized == Path::new(INSTALL_MTREE_NAME)
                || normalized == Path::new(CHANGELOG_MTREE_NAME)
            {
                total = total.saturating_add(1);
                self.verify_dbfile_entry(entry, normalized, &mut problems)?;
                continue;
            }

            if normalized.to_string_lossy().starts_with('.') {
                // The package's own metadata (`.BUILDINFO`, `.PKGINFO`, the `mtree` data
                // itself) is recorded in mtree but was never extracted under `root`. pacman's
                // own `-Qkk` does not check these either: `check.c` skips any dot-prefixed
                // entry other than `.INSTALL`/`.CHANGELOG` before it is even counted.
                continue;
            }

            total = total.saturating_add(1);
            self.verify_root_entry(entry, normalized, root, no_extract, &backups, &mut problems)?;
        }

        Ok(Some(FileCheckReport { total, problems }))
    }

    /// Verifies a `.INSTALL`/`.CHANGELOG` mtree entry against the database entry's own
    /// lowercase file, not the installation root. Mirrors `check.c`'s redirection to
    /// `<dbpath>/local/<pkg>-<ver>/{install,changelog}`.
    fn verify_dbfile_entry(
        &self,
        entry: &v2::Path,
        normalized: &Path,
        problems: &mut Vec<FileProblem>,
    ) -> std::result::Result<(), SharedError> {
        let name =
            if normalized == Path::new(INSTALL_MTREE_NAME) { "install" } else { "changelog" };

        let mut rewritten = entry.clone();
        let mtree_path = PathBuf::from("./").join(name);
        match &mut rewritten {
            v2::Path::Directory(dir) => dir.path = mtree_path,
            v2::Path::File(file) => file.path = mtree_path,
            v2::Path::Link(link) => link.path = mtree_path,
        }

        let input = InputPath::new(self.path(), Path::new(name)).map_err(|source| {
            Error::InvalidVerifyRoot { path: self.path().to_path_buf(), source }
        })?;
        if let Err(errors) = rewritten.equals_path(&input) {
            problems.extend(errors.into_iter().map(|error| FileProblem {
                path: PathBuf::from(name),
                error,
                backup: false,
            }));
        }
        Ok(())
    }

    /// Verifies one ordinary mtree entry against the installation root.
    fn verify_root_entry(
        &self,
        entry: &v2::Path,
        normalized: &Path,
        root: &Path,
        no_extract: &[String],
        backups: &HashSet<&Path>,
        problems: &mut Vec<FileProblem>,
    ) -> std::result::Result<(), SharedError> {
        let on_disk = root.join(normalized);

        // A symlink where mtree expects a directory or a regular file must never be followed.
        // `Directory`/`File::equals_path` resolve metadata with `Path::metadata`, which
        // follows a symlink, and a `File` match would go on to open and hash whatever the
        // symlink points at. Reporting the type mismatch here, without ever calling
        // `equals_path`, keeps piko from reading a file it was never asked to.
        if !matches!(entry, v2::Path::Link(_))
            && let Ok(metadata) = std::fs::symlink_metadata(&on_disk)
            && metadata.file_type().is_symlink()
        {
            let error = if matches!(entry, v2::Path::Directory(_)) {
                PathValidationError::PathNotADir { mtree_path: entry.to_path_buf(), path: on_disk }
            } else {
                PathValidationError::PathNotAFile { mtree_path: entry.to_path_buf(), path: on_disk }
            };
            problems.push(FileProblem { path: normalized.to_path_buf(), error, backup: false });
            return Ok(());
        }

        let input = InputPath::new(root, normalized)
            .map_err(|source| Error::InvalidVerifyRoot { path: root.to_path_buf(), source })?;
        let Err(errors) = entry.equals_path(&input) else {
            return Ok(());
        };

        let is_backup = backups.contains(normalized);
        for error in errors {
            match &error {
                PathValidationError::PathMissing { .. }
                    if resolve::matches_any(no_extract, &normalized.to_string_lossy()) =>
                {
                    // NoExtract. pacman does not report this file at all.
                }
                PathValidationError::PathTimeMismatch { .. }
                    if matches!(entry, v2::Path::Directory(_)) =>
                {
                    // Directory mtimes drift under ordinary filesystem traffic; `-Qkk` does
                    // not check them.
                }
                _ => problems.push(FileProblem {
                    path: normalized.to_path_buf(),
                    error,
                    backup: is_backup,
                }),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::{
        fs::Metadata,
        os::unix::fs::{MetadataExt, symlink},
    };

    use tempfile::TempDir;

    use super::*;
    use crate::{
        UnknownSectionPolicy,
        entry_name::EntryName,
        fixture::{DbFixture, MINIMAL_DESC_V1, MINIMAL_FILES},
        limits::Limits,
    };

    /// Four bytes used as every test file's body. Their SHA-256 digest is [`CONTENT_SHA256`].
    const CONTENT: &[u8] = b"test";
    const CONTENT_SHA256: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn package_at(db: &DbFixture, entry: &str) -> LocalPackage {
        LocalPackage::new(
            EntryName::parse(entry).unwrap(),
            db.path().join(entry),
            Limits::default(),
            UnknownSectionPolicy::default(),
        )
    }

    fn write_file(root: &Path, rel: &str, contents: &[u8]) -> Metadata {
        let full = root.join(rel);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(&full, contents).unwrap();
        std::fs::metadata(&full).unwrap()
    }

    fn write_dir(root: &Path, rel: &str) -> Metadata {
        let full = root.join(rel);
        std::fs::create_dir_all(&full).unwrap();
        std::fs::metadata(&full).unwrap()
    }

    fn write_symlink(root: &Path, rel: &str, target: &str) -> Metadata {
        let full = root.join(rel);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        symlink(target, &full).unwrap();
        std::fs::symlink_metadata(&full).unwrap()
    }

    fn file_stanza(rel: &str, meta: &Metadata, size: u64, sha256: &str) -> String {
        format!(
            "./{rel} type=file uid={} gid={} mode={:o} time={}.0 size={size} \
             sha256digest={sha256}\n",
            meta.uid(),
            meta.gid(),
            meta.mode() & 0o7777,
            meta.mtime()
        )
    }

    fn dir_stanza(rel: &str, meta: &Metadata) -> String {
        format!(
            "./{rel} type=dir uid={} gid={} mode={:o} time={}.0\n",
            meta.uid(),
            meta.gid(),
            meta.mode() & 0o7777,
            meta.mtime()
        )
    }

    fn link_stanza(rel: &str, meta: &Metadata, target: &str) -> String {
        format!(
            "./{rel} type=link uid={} gid={} mode={:o} time={}.0 link={target}\n",
            meta.uid(),
            meta.gid(),
            meta.mode() & 0o7777,
            meta.mtime()
        )
    }

    fn package_with_mtree(entry: &str, mtree_body: &str) -> (DbFixture, LocalPackage) {
        let db = DbFixture::new();
        db.package(entry)
            .desc(MINIMAL_DESC_V1)
            .files(MINIMAL_FILES)
            .mtree(&format!("#mtree\n{mtree_body}"))
            .build();
        let pkg = package_at(&db, entry);
        (db, pkg)
    }

    #[test]
    fn a_package_with_no_mtree_is_reported_as_having_none() {
        let root = TempDir::new().unwrap();
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).files(MINIMAL_FILES).build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        assert!(pkg.verify_files(root.path(), &[]).unwrap().is_none());
    }

    #[test]
    fn a_consistent_file_reports_no_problems() {
        let root = TempDir::new().unwrap();
        let meta = write_file(root.path(), "usr/bin/foo", CONTENT);
        let stanza = file_stanza("usr/bin/foo", &meta, CONTENT.len() as u64, CONTENT_SHA256);
        let (_db, pkg) = package_with_mtree("foo-1.0.0-1", &stanza);

        let report = pkg.verify_files(root.path(), &[]).unwrap().unwrap();
        assert_eq!(report.total, 1);
        assert!(report.problems.is_empty(), "got {:?}", report.problems);
    }

    #[test]
    fn a_missing_file_is_a_hard_error() {
        let root = TempDir::new().unwrap();
        // `usr/bin/foo` is never written, so it does not exist under `root`.
        let meta = write_dir(root.path(), "usr/bin");
        let mut stanza = dir_stanza("usr/bin", &meta);
        stanza.push_str(&file_stanza("usr/bin/foo", &meta, 4, CONTENT_SHA256));
        let (_db, pkg) = package_with_mtree("foo-1.0.0-1", &stanza);

        let report = pkg.verify_files(root.path(), &[]).unwrap().unwrap();
        assert_eq!(report.altered_files(), 1);
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.is_error() && matches!(p.error, PathValidationError::PathMissing { .. }))
        );
    }

    #[test]
    fn an_altered_regular_file_is_a_hard_error() {
        let root = TempDir::new().unwrap();
        let meta = write_file(root.path(), "usr/bin/foo", CONTENT);
        // The mtree record's size differs from what is actually on disk.
        let stanza = file_stanza("usr/bin/foo", &meta, 999, CONTENT_SHA256);
        let (_db, pkg) = package_with_mtree("foo-1.0.0-1", &stanza);

        let report = pkg.verify_files(root.path(), &[]).unwrap().unwrap();
        assert_eq!(report.altered_files(), 1);
        assert!(report.problems.iter().any(
            |p| p.is_error() && matches!(p.error, PathValidationError::PathSizeMismatch { .. })
        ));
    }

    #[test]
    fn buildinfo_and_pkginfo_entries_are_not_checked_or_counted() {
        let root = TempDir::new().unwrap();
        // Neither is ever extracted under `root`. If piko checked them like ordinary root
        // entries, both would report as missing. This was a real bug, caught against a live
        // system: `piko check pacman` reported ".BUILDINFO"/".PKGINFO" as missing, where
        // `pacman -Qkk pacman` reports nothing for them at all, and excludes them from its
        // own total-files count.
        let stanza = "./.BUILDINFO type=file uid=0 gid=0 mode=644 time=1.0 size=1 \
                       sha256digest=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n\
                       ./.PKGINFO type=file uid=0 gid=0 mode=644 time=1.0 size=1 \
                       sha256digest=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n";
        let (_db, pkg) = package_with_mtree("foo-1.0.0-1", stanza);

        let report = pkg.verify_files(root.path(), &[]).unwrap().unwrap();
        assert_eq!(report.total, 0);
        assert!(report.problems.is_empty(), "got {:?}", report.problems);
    }

    #[test]
    fn a_backup_file_that_cannot_be_hashed_is_still_a_hard_error() {
        // pacman's own `check_file_cksum` (`check.c`) returns an error unconditionally when
        // it cannot even calculate a checksum. It only softens an actual mismatch once both
        // sides were computed. This was a real divergence, caught against a live system:
        // `piko check audit` under-counted altered files by one relative to
        // `pacman -Qkk audit`, because `CreateHashDigest` was wrongly included in the
        // softened set for backup files.
        let problem = FileProblem {
            path: PathBuf::from("etc/foo.conf"),
            error: PathValidationError::CreateHashDigest {
                path: PathBuf::from("/etc/foo.conf"),
                source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            },
            backup: true,
        };
        assert!(problem.is_error());
    }

    #[test]
    fn an_altered_backup_file_is_reported_but_not_an_error() {
        let root = TempDir::new().unwrap();
        let meta = write_file(root.path(), "etc/foo.conf", CONTENT);
        let stanza = file_stanza("etc/foo.conf", &meta, 999, CONTENT_SHA256);

        let files_body = "\
%FILES%
etc/
etc/foo.conf

%BACKUP%
etc/foo.conf\td41d8cd98f00b204e9800998ecf8427e
";
        let db = DbFixture::new();
        db.package("foo-1.0.0-1")
            .desc(MINIMAL_DESC_V1)
            .files(files_body)
            .mtree(&format!("#mtree\n{stanza}"))
            .build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        let report = pkg.verify_files(root.path(), &[]).unwrap().unwrap();
        assert_eq!(report.altered_files(), 0, "a backup file's size mismatch is not a failure");
        assert!(!report.problems.is_empty(), "the mismatch is still reported");
        assert!(report.problems.iter().all(|p| !p.is_error()));
    }

    #[test]
    fn a_missing_file_matching_no_extract_is_not_reported_at_all() {
        let root = TempDir::new().unwrap();
        let meta = write_dir(root.path(), "usr/bin");
        let mut stanza = dir_stanza("usr/bin", &meta);
        stanza.push_str(&file_stanza("usr/bin/foo", &meta, 4, CONTENT_SHA256));
        let (_db, pkg) = package_with_mtree("foo-1.0.0-1", &stanza);

        let report = pkg.verify_files(root.path(), &["usr/bin/foo".to_owned()]).unwrap().unwrap();
        assert!(report.problems.is_empty(), "got {:?}", report.problems);
    }

    #[test]
    fn a_directory_modification_time_is_never_checked() {
        let root = TempDir::new().unwrap();
        let meta = write_dir(root.path(), "usr/bin");
        // The time recorded in mtree is stale, unlike the file's real mtime.
        let mut stanza = format!(
            "./usr/bin type=dir uid={} gid={} mode={:o} time=1.0\n",
            meta.uid(),
            meta.gid(),
            meta.mode() & 0o7777
        );
        stanza.push_str(&file_stanza("usr/bin/foo", &meta, 0, CONTENT_SHA256));
        // The file itself is also missing, to have one confirmed problem to compare against.
        // The directory's own stale time must not add a second one.
        let (_db, pkg) = package_with_mtree("foo-1.0.0-1", &stanza);

        let report = pkg.verify_files(root.path(), &[]).unwrap().unwrap();
        assert!(
            report
                .problems
                .iter()
                .all(|p| !matches!(p.error, PathValidationError::PathTimeMismatch { .. })),
            "got {:?}",
            report.problems
        );
    }

    #[test]
    fn a_symlink_swapped_in_for_a_file_is_a_type_mismatch_not_a_followed_read() {
        let root = TempDir::new().unwrap();
        // piko must never open this secret, even indirectly.
        let secret = write_file(root.path(), "etc/secret", b"do not read me");
        let _ = secret;
        let meta = write_symlink(root.path(), "usr/bin/foo", "/etc/secret");
        // mtree expects a regular file at this path, not a symlink.
        let stanza = file_stanza("usr/bin/foo", &meta, 4, CONTENT_SHA256);
        let (_db, pkg) = package_with_mtree("foo-1.0.0-1", &stanza);

        let report = pkg.verify_files(root.path(), &[]).unwrap().unwrap();
        assert_eq!(report.altered_files(), 1);
        assert!(
            report
                .problems
                .iter()
                .any(|p| matches!(p.error, PathValidationError::PathNotAFile { .. })),
            "got {:?}",
            report.problems
        );
    }

    #[test]
    fn a_symlink_with_a_different_target_is_a_hard_error() {
        let root = TempDir::new().unwrap();
        let meta = write_symlink(root.path(), "usr/bin/foo", "/usr/bin/bar");
        // The mtree record's link target differs from what is actually on disk.
        let stanza = link_stanza("usr/bin/foo", &meta, "/usr/bin/baz");
        let (_db, pkg) = package_with_mtree("foo-1.0.0-1", &stanza);

        let report = pkg.verify_files(root.path(), &[]).unwrap().unwrap();
        assert_eq!(report.altered_files(), 1);
        assert!(
            report
                .problems
                .iter()
                .any(|p| matches!(p.error, PathValidationError::PathSymlinkMismatch { .. })),
            "got {:?}",
            report.problems
        );
    }

    #[test]
    fn install_scriptlet_entries_are_checked_against_the_database_entry() {
        let db = DbFixture::new();
        let pkg_dir = db.path().join("foo-1.0.0-1");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("install"), "true\n").unwrap();
        let meta = std::fs::metadata(pkg_dir.join("install")).unwrap();
        // sha256("true\n")
        let sha256 = "a17fcf0a2f50e2d495e4f90ce263410edc183add6c62699a2facbccf60410f74";
        let stanza = file_stanza(".INSTALL", &meta, 5, sha256);
        db.package("foo-1.0.0-1")
            .desc(MINIMAL_DESC_V1)
            .files(MINIMAL_FILES)
            .mtree(&format!("#mtree\n{stanza}"))
            .build();
        let pkg = package_at(&db, "foo-1.0.0-1");
        let root = TempDir::new().unwrap();

        let report = pkg.verify_files(root.path(), &[]).unwrap().unwrap();
        assert!(report.problems.is_empty(), "got {:?}", report.problems);
    }
}
