//! The audited filesystem core.
//!
//! Every byte this crate reads off disk passes through [`read_capped`]. The hardening lives
//! in one place, so it can be reviewed on its own. The `MetadataFile` convenience
//! constructors from `alpm-common` (`from_file`) are deliberately never used: they call
//! `read_to_string` on a path with no bound and no file-type check.
//!
//! Three properties are enforced here:
//!
//! 1. **No symlink traversal.** A metadata file is opened with `O_NOFOLLOW`. A symlink
//!    planted in an entry directory cannot redirect a read outside the database.
//! 2. **No blocking on non-files.** The open uses `O_NONBLOCK`, and the descriptor is
//!    `fstat`ed before any read. Without this, opening a FIFO blocks until a writer
//!    appears, and reading `/dev/zero` never terminates.
//! 3. **No unbounded reads.** Reads stop one byte past the configured limit and report
//!    [`Error::LimitExceeded`] instead of returning truncated data.
//!
//! # Public surface
//!
//! Most of this module is crate-private. A small, deliberate part is public: `piko-db-write`
//! lives in another crate and must not reimplement the audited door. A second, unaudited path
//! to the filesystem is exactly what this module exists to prevent. Export only what a caller
//! outside the crate has a demonstrated need for. Extend it when a real need appears, not in
//! advance.

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, IoAction, Result},
    limits::Limit,
};

/// Opens `path` for reading without following a final symlink and without blocking.
fn open_no_follow(path: &Path) -> Result<File> {
    let mut options = File::options();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    options.open(path).map_err(|source| Error::io(path, IoAction::Open, source))
}

/// Fails unless `file` is a regular file.
///
/// An `fstat` catches a FIFO, socket, device node or directory before an unbounded read
/// would.
pub(crate) fn ensure_regular_file(file: &File, path: &Path) -> Result<std::fs::Metadata> {
    let metadata = file.metadata().map_err(|source| Error::io(path, IoAction::Metadata, source))?;
    if !metadata.is_file() {
        return Err(Error::NotARegularFile { path: path.to_path_buf() });
    }
    Ok(metadata)
}

/// Opens `path` for reading, following a final symlink but never blocking.
///
/// Unlike [`open_no_follow`], this **does** follow a symlink. It exists for repository
/// archives. The path is a single file the caller names explicitly (e.g. `core.db`), not one
/// of many enumerated directory entries. The [alpm-repo-db] spec itself documents
/// `repo.db -> repo.db.tar.gz` as the normal server-side layout, so refusing to follow it
/// would break the documented access path for no security benefit. The `O_NONBLOCK` plus
/// `fstat` check still applies: a FIFO or device node named like an archive still cannot hang
/// the process or be read as if it were one.
///
/// [alpm-repo-db]: https://alpm.archlinux.page/specifications/alpm-repo-db.7.html
pub(crate) fn open_following_symlinks(path: &Path) -> Result<File> {
    let mut options = File::options();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }

    let file = options.open(path).map_err(|source| Error::io(path, IoAction::Open, source))?;
    ensure_regular_file(&file, path)?;
    Ok(file)
}

/// Reads `path` in full, refusing anything that is not a regular file and anything larger
/// than `max` bytes.
///
/// `limit` names the bound in the resulting error; it carries no behaviour.
///
/// # Errors
///
/// - [`Error::Io`] if the path cannot be opened, stat'ed or read.
/// - [`Error::NotARegularFile`] if it is a directory, FIFO, socket, device node or symlink.
/// - [`Error::LimitExceeded`] if the contents exceed `max` bytes.
pub(crate) fn read_capped(path: &Path, limit: Limit, max: u64) -> Result<Vec<u8>> {
    let file = open_no_follow(path)?;
    let metadata = ensure_regular_file(&file, path)?;

    // Reading one byte past the limit distinguishes "exactly at the limit" from "truncated".
    // An oversized file is reported, never silently accepted short.
    let ceiling = max.saturating_add(1);
    let mut buffer = Vec::with_capacity(hint_capacity(metadata.len(), max));
    file.take(ceiling)
        .read_to_end(&mut buffer)
        .map_err(|source| Error::io(path, IoAction::Read, source))?;

    if buffer.len() as u64 > max {
        return Err(Error::LimitExceeded { path: path.to_path_buf(), limit, max });
    }

    Ok(buffer)
}

/// Reads `path` in full and decodes it as UTF-8.
///
/// # Errors
///
/// As [`read_capped`], plus [`Error::NotUtf8`] if the contents are not valid UTF-8.
pub fn read_capped_utf8(path: &Path, limit: Limit, max: u64) -> Result<String> {
    let bytes = read_capped(path, limit, max)?;
    decode(path, bytes)
}

/// Reads `path` in full and decodes it as UTF-8, **following a final symlink**.
///
/// Exposes the [`open_following_symlinks`] door for alpm `.hook` files. `alpm-hooks(5)`
/// documents disabling a hook by shadowing it with a symlink to `/dev/null`. Refusing to
/// follow that symlink would break the feature instead of protecting anything: a hook
/// directory is host configuration named by `pacman.conf`, not a package-controlled entry
/// directory, and the file is one of an enumerated set whose whole population is trusted the
/// same way.
///
/// The rest of the door is unchanged: `O_NONBLOCK`, an `fstat` that refuses anything but a
/// regular file, and a bounded read. A FIFO planted in a hook directory still cannot hang the
/// process. The caller distinguishes [`Error::NotARegularFile`] and decides what a non-file
/// means for it. For hooks it means "no content", exactly what `/dev/null` would have
/// yielded.
///
/// # Errors
///
/// As [`read_capped`], except that a final symlink is resolved rather than refused.
pub fn read_capped_utf8_following(path: &Path, limit: Limit, max: u64) -> Result<String> {
    let file = open_following_symlinks(path)?;
    let metadata = ensure_regular_file(&file, path)?;

    let ceiling = max.saturating_add(1);
    let mut buffer = Vec::with_capacity(hint_capacity(metadata.len(), max));
    file.take(ceiling)
        .read_to_end(&mut buffer)
        .map_err(|source| Error::io(path, IoAction::Read, source))?;
    if buffer.len() as u64 > max {
        return Err(Error::LimitExceeded { path: path.to_path_buf(), limit, max });
    }

    decode(path, buffer)
}

/// Decodes bytes read from `path` as UTF-8.
fn decode(path: &Path, bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes)
        .map_err(|error| Error::NotUtf8 { path: path.to_path_buf(), source: error.utf8_error() })
}

/// Chooses a starting allocation from the stat'ed size.
///
/// The stat'ed size is untrusted, so it only ever shrinks the allocation. It never grows it
/// past the limit. A file claiming to be huge must not make piko allocate that much up front.
fn hint_capacity(reported: u64, max: u64) -> usize {
    let bounded = reported.min(max).min(1024 * 1024);
    usize::try_from(bounded).unwrap_or(0)
}

/// Returns `true` if `path` is a directory and not a symlink to one.
///
/// libalpm's equivalent (`is_dir` in `be_local.c`) uses a following `stat`. A symlink
/// pointing at a directory is accepted there as a database entry. piko does not follow it: an
/// entry directory that is a symlink is a redirection primitive with no legitimate use.
///
/// # Errors
///
/// [`Error::Io`] if the path cannot be stat'ed for a reason other than not existing.
pub fn is_real_directory(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(Error::io(path, IoAction::Metadata, source)),
    }
}

/// Returns `true` if `path` exists, without following a final symlink.
pub fn exists_no_follow(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Joins `directory` and `component`, where `component` is a single path component.
pub(crate) fn join(directory: &Path, component: &str) -> PathBuf {
    directory.join(component)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn write(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        path
    }

    #[test]
    fn reads_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "desc", b"%NAME%\nfoo\n");
        let contents = read_capped(&path, Limit::Desc, 1024).unwrap();
        assert_eq!(contents, b"%NAME%\nfoo\n");
    }

    #[test]
    fn accepts_an_empty_file() {
        // Seven packages on a real system ship a zero-byte `files` file.
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "files", b"");
        assert!(read_capped(&path, Limit::Files, 1024).unwrap().is_empty());
    }

    #[test]
    fn accepts_a_file_exactly_at_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "desc", &[b'x'; 16]);
        assert_eq!(read_capped(&path, Limit::Desc, 16).unwrap().len(), 16);
    }

    /// Truncating would misreport a package's contents. The read must fail instead.
    #[test]
    fn refuses_a_file_one_byte_over_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "desc", &[b'x'; 17]);
        let err = read_capped(&path, Limit::Desc, 16).unwrap_err();
        assert!(
            matches!(err, Error::LimitExceeded { limit: Limit::Desc, max: 16, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn refuses_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir");
        std::fs::create_dir(&path).unwrap();
        let err = read_capped(&path, Limit::Desc, 1024).unwrap_err();
        // A directory fails at `open` on Linux (EISDIR) rather than at the stat check.
        // Either rejection is acceptable; silently succeeding is not.
        assert!(matches!(err, Error::Io { .. } | Error::NotARegularFile { .. }), "got {err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = write(dir.path(), "target", b"secret");
        let link = dir.path().join("desc");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = read_capped(&link, Limit::Desc, 1024).unwrap_err();
        assert!(matches!(err, Error::Io { action: IoAction::Open, .. }), "got {err:?}");
    }

    #[test]
    fn reports_invalid_utf8_with_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "desc", &[0xff, 0xfe]);
        let err = read_capped_utf8(&path, Limit::Desc, 1024).unwrap_err();
        assert!(matches!(err, Error::NotUtf8 { .. }), "got {err:?}");
        assert!(err.to_string().contains("desc"));
    }

    #[cfg(unix)]
    #[test]
    fn open_following_symlinks_follows_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = write(dir.path(), "core.db.tar.gz", b"archive bytes");
        let link = dir.path().join("core.db");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut file = open_following_symlinks(&link).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"archive bytes");
    }

    #[test]
    fn open_following_symlinks_refuses_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = open_following_symlinks(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Io { .. } | Error::NotARegularFile { .. }), "got {err:?}");
    }

    #[test]
    fn missing_files_report_their_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent");
        let err = read_capped(&path, Limit::Desc, 1024).unwrap_err();
        assert!(matches!(err, Error::Io { action: IoAction::Open, .. }), "got {err:?}");
        assert!(err.to_string().contains("absent"));
    }

    #[cfg(unix)]
    #[test]
    fn is_real_directory_rejects_a_symlink_to_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(is_real_directory(&real).unwrap());
        assert!(!is_real_directory(&link).unwrap(), "a symlinked entry must not be followed");
    }

    #[test]
    fn is_real_directory_reports_false_for_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_real_directory(&dir.path().join("absent")).unwrap());
    }

    /// A capacity hint is a performance detail. It must never be driven by an untrusted
    /// size, or a sparse file claiming to be terabytes would abort the process.
    #[test]
    fn capacity_hint_never_exceeds_the_limit() {
        assert_eq!(hint_capacity(u64::MAX, 16), 16);
        assert_eq!(hint_capacity(8, 1024), 8);
        assert_eq!(hint_capacity(u64::MAX, u64::MAX), 1024 * 1024);
    }
}
