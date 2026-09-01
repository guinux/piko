//! Hashing installed files, for the backup comparison.
//!
//! pacman records a backup file's MD5 in the local database. It compares that hash against the
//! file on disk to decide whether the user edited it. piko must compute the same digest to
//! interoperate: the recorded hashes come from pacman, and piko compares its own hashes against
//! them. So "MD5 is weak" is not a reason to choose a different algorithm here. MD5 is not a
//! security primitive in this context — it only answers "did these bytes change" against a
//! value pacman wrote.
//!
//! The digest comes from `alpm_types::Md5Checksum`, not from `md-5` directly. The official
//! crate already exposes it and is already in the dependency graph.

use std::{ffi::OsStr, os::fd::AsFd, path::Path};

use alpm_types::Md5Checksum;
use rustix::fs::{AtFlags, Mode, OFlags};

use crate::error::{Error, IoAction, Result};

/// Largest file that will be hashed for a backup comparison.
///
/// `Checksum::calculate_from` takes the whole input as a slice, so the read must be capped
/// somewhere. 64 MiB is far beyond any real configuration file. The bound exists so a package
/// declaring `usr/lib/firmware.bin` as a `%BACKUP%` entry cannot make piko read it into memory.
/// It does not constrain legitimate use.
pub const MAX_BACKUP_BYTES: u64 = 64 * 1024 * 1024;

/// Computes the MD5 of `name` inside `dir`.
///
/// Returns `Ok(None)` when the file is simply not there. That is an ordinary state, not a
/// failure — for example a backup file the user deleted.
///
/// # Errors
///
/// [`Error::Io`] if the file exists but cannot be read, or
/// [`Error::PackageLimitExceeded`] if it is larger than `max`.
///
/// # Treat a failure as *unknown*, never as *unchanged*
///
/// Both an `Err` and an `Ok(None)` mean piko does not know what the file contains. A caller
/// must map both to `None` when feeding [`crate::extract::decision::resolve_backup`] or
/// [`crate::remove::decide_removal`]. Never map either to a hash that happens to be convenient.
/// Those functions rely on an unknown hash keeping the user's file, and that safety depends on
/// the unknown actually arriving as unknown. libalpm gets this wrong in `remove.c:536`: there,
/// an uncomputable hash compares equal to the recorded one, and the file gets deleted.
pub fn file_md5_at(dir: &impl AsFd, name: &OsStr, max: u64) -> Result<Option<Md5Checksum>> {
    // `O_NOFOLLOW`: a backup path that has become a symlink must not be followed out of the
    // root to hash something else.
    //
    // `O_NONBLOCK`: opening a FIFO for reading blocks until a writer appears. Without this
    // flag, a backup path that is a FIFO hangs the package manager forever. The file-type
    // check below runs after the open, far too late to help. This is the same reasoning as
    // `piko_db::fs_util::open_no_follow`.
    let fd = match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(source) => return Err(io(name, IoAction::Open, source)),
    };

    let stat = rustix::fs::fstat(&fd).map_err(|source| io(name, IoAction::Metadata, source))?;
    // Only a regular file has contents worth comparing. `O_NOFOLLOW` rules out a symlink here,
    // but a FIFO or device node could still reach this point, and reading one would block or
    // never end.
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(Error::UnusableSource {
            path: Path::new(name).to_path_buf(),
            reason: "not a regular file".to_owned(),
        });
    }

    let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
    if size > max {
        return Err(Error::PackageLimitExceeded {
            path: Path::new(name).to_path_buf(),
            limit: "backup file size",
            max,
        });
    }

    let mut file = std::fs::File::from(fd);
    let mut contents = Vec::with_capacity(usize::try_from(size.min(max)).unwrap_or(0));
    // Reading one byte past the cap distinguishes "exactly at the limit" from "truncated". This
    // is the same idiom as piko-db's `fs_util::read_capped`. A file that grew between the stat
    // and the read must not be silently hashed short.
    {
        use std::io::Read as _;
        file.by_ref()
            .take(max.saturating_add(1))
            .read_to_end(&mut contents)
            .map_err(|source| Error::io(Path::new(name), IoAction::Read, source))?;
    }
    if contents.len() as u64 > max {
        return Err(Error::PackageLimitExceeded {
            path: Path::new(name).to_path_buf(),
            limit: "backup file size",
            max,
        });
    }

    Ok(Some(Md5Checksum::calculate_from(&contents)))
}

/// Reports whether `name` exists inside `dir`, without following a symlink.
pub fn exists_at(dir: &impl AsFd, name: &OsStr) -> bool {
    rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).is_ok()
}

/// Wraps a `rustix` error against a bare name.
fn io(name: &OsStr, action: IoAction, source: rustix::io::Errno) -> Error {
    Error::io(Path::new(name), action, source.into())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::rootfs::RootDir;

    fn root() -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = RootDir::open(dir.path()).unwrap();
        (dir, root)
    }

    fn hash_of(root: &RootDir, name: &str) -> Result<Option<Md5Checksum>> {
        let resolved = root.resolve_parent(Path::new(name)).unwrap();
        file_md5_at(resolved.dir(), resolved.name(), MAX_BACKUP_BYTES)
    }

    /// The digest must be the one pacman would have recorded. Pin it against a known MD5,
    /// not only against itself.
    #[test]
    fn computes_the_standard_md5() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("f"), b"abc").unwrap();
        assert_eq!(
            hash_of(&root, "f").unwrap().unwrap().to_string(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn hashes_an_empty_file() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("f"), b"").unwrap();
        assert_eq!(
            hash_of(&root, "f").unwrap().unwrap().to_string(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    /// Absence is an ordinary state, not a failure.
    #[test]
    fn a_missing_file_is_none_not_an_error() {
        let (_dir, root) = root();
        assert!(hash_of(&root, "absent").unwrap().is_none());
    }

    #[test]
    fn refuses_a_file_over_the_limit() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("f"), vec![b'x'; 100]).unwrap();

        let resolved = root.resolve_parent(Path::new("f")).unwrap();
        let err = file_md5_at(resolved.dir(), resolved.name(), 10).unwrap_err();
        assert!(
            matches!(err, Error::PackageLimitExceeded { limit: "backup file size", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn accepts_a_file_exactly_at_the_limit() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("f"), vec![b'x'; 10]).unwrap();
        let resolved = root.resolve_parent(Path::new("f")).unwrap();
        assert!(file_md5_at(resolved.dir(), resolved.name(), 10).unwrap().is_some());
    }

    /// A backup path replaced by a symlink must not be followed to hash something else.
    #[cfg(unix)]
    #[test]
    fn refuses_to_follow_a_symlink() {
        let (dir, root) = root();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret");
        std::fs::write(&secret, b"secret").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("f")).unwrap();

        assert!(hash_of(&root, "f").is_err());
    }

    /// Reading a FIFO would block forever.
    #[cfg(unix)]
    #[test]
    fn refuses_a_non_regular_file() {
        let (dir, root) = root();
        let fifo = dir.path().join("f");
        let path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // `mkfifo` via rustix keeps `unsafe_code = forbid` intact.
        rustix::fs::mknodat(
            rustix::fs::CWD,
            path.as_c_str(),
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();

        let err = hash_of(&root, "f").unwrap_err();
        assert!(matches!(err, Error::UnusableSource { .. }), "got {err:?}");
    }

    #[test]
    fn exists_reports_presence_without_following() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("here"), b"x").unwrap();
        let resolved = root.resolve_parent(Path::new("here")).unwrap();
        assert!(exists_at(resolved.dir(), resolved.name()));

        let absent = root.resolve_parent(Path::new("gone")).unwrap();
        assert!(!exists_at(absent.dir(), absent.name()));
    }
}
