//! The `db.lck` database lock.
//!
//! Interoperability dictates everything here, not what a lock "should" be. pacman and piko
//! must not both believe they hold the database. piko therefore reproduces
//! `_alpm_handle_lock` (`handle.c:119`) exactly, including the parts that are arguably
//! defects — see [`DbLock::acquire`]. `docs/locking.md` records the full derivation.

use std::{
    fs::File,
    path::{Path, PathBuf},
};

use crate::error::{Error, IoAction, Result};

/// The lock file's name, inside the database path.
///
/// This sits beside `local/`, not inside it: the path is `<dbpath>/db.lck`, fixed at
/// `alpm.c:41,67`. It is not a directory, so [`crate::LocalDatabase`]'s scan skips it without
/// needing a special case.
pub const LOCK_FILE: &str = "db.lck";

/// An acquired database lock.
///
/// Held for the duration of a write. Dropping it releases the lock. Prefer
/// [`DbLock::release`] where the caller can act on a failure, because a [`Drop`] cannot
/// report one.
///
/// # Not a `flock`
///
/// The lock is pure file *existence*, so it is **not** released when the process dies. A
/// crashed piko or pacman leaves a stale `db.lck` that a human must remove, exactly as
/// pacman's own error message instructs. This is deliberately not "improved" into an advisory
/// `flock`. An `flock` would be invisible to pacman, and two package managers writing the same
/// database concurrently is far worse than a stale file.
#[derive(Debug)]
pub struct DbLock {
    path: PathBuf,
    /// Kept open for the lifetime of the lock, mirroring libalpm's `handle->lockfd`.
    ///
    /// Nothing is ever written to it. Holding the descriptor makes the lock's lifetime visible
    /// to `lsof`-style tooling, matching what libalpm does.
    _file: File,
}

impl DbLock {
    /// Acquires `<dbpath>/db.lck`, failing immediately if another process holds it.
    ///
    /// The open is `O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC` with mode `0000`. The parent
    /// directory is created first. Both steps mirror `_alpm_handle_lock` (`handle.c:127`,
    /// `handle.c:139`). `O_EXCL` makes this atomic and makes it fail fast: there is no retry
    /// and no timeout, only `EINTR` is resumed.
    ///
    /// Mode `0000` is intentional. The file is never read or written, only created and
    /// unlinked, so it needs no permissions at all. A root-owned unreadable file is also a
    /// clearer signal than an empty readable one.
    ///
    /// # Errors
    ///
    /// - [`Error::DatabaseLocked`] if the lock file already exists. This is the expected
    ///   failure, not an exceptional one: another package manager is running, or a previous
    ///   one crashed.
    /// - [`Error::Io`] if the directory cannot be created or the file cannot be opened for
    ///   any other reason.
    pub fn acquire(dbpath: &Path) -> Result<Self> {
        let path = dbpath.join(LOCK_FILE);

        // libalpm creates the lock file's directory before opening it. A fresh `--dbpath` is
        // therefore usable without the caller preparing it first.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|source| Error::io(parent, IoAction::CreateDir, source))?;
        }

        let mut options = File::options();
        // `create_new` is O_CREAT | O_EXCL. Rust already opens with O_CLOEXEC.
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o000);
        }

        loop {
            return match options.open(&path) {
                Ok(file) => Ok(Self { path, _file: file }),
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    Err(Error::DatabaseLocked { path })
                }
                // libalpm retries only this failure. Every other failure is reported.
                Err(source) if source.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(source) => Err(Error::io(&path, IoAction::Create, source)),
            };
        }
    }

    /// The path of the lock file being held.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Releases the lock, reporting a failure to remove the file.
    ///
    /// A lock file that has already vanished counts as **success**, not an error: something
    /// else removed it, the database is no longer locked, and that is what the caller wanted.
    /// libalpm reaches the same conclusion by a different route, downgrading `ENOENT` to a
    /// warning in `_alpm_handle_unlock` (`handle.c:165`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the lock file exists but cannot be removed.
    pub fn release(self) -> Result<()> {
        // This takes the path out before `self` drops, so `Drop` does not try again.
        let path = self.path.clone();
        // `_file` closes here. libalpm likewise closes before unlinking.
        drop(self);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Error::io(&path, IoAction::Remove, source)),
        }
    }
}

impl Drop for DbLock {
    /// Best-effort release.
    ///
    /// A failure here cannot be reported. That is the whole reason [`DbLock::release`]
    /// exists. Leaving the file behind is the safe direction to fail in: a stale lock stops
    /// the next writer, while a lock wrongly believed released would let two run at once.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    #[test]
    fn acquires_and_releases() {
        let dir = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(dir.path()).unwrap();
        assert!(dir.path().join(LOCK_FILE).exists());
        lock.release().unwrap();
        assert!(!dir.path().join(LOCK_FILE).exists());
    }

    #[test]
    fn refuses_a_second_holder() {
        let dir = tempfile::tempdir().unwrap();
        let _held = DbLock::acquire(dir.path()).unwrap();
        let err = DbLock::acquire(dir.path()).unwrap_err();
        assert!(matches!(err, Error::DatabaseLocked { .. }), "got {err:?}");
    }

    /// libalpm's `ASSERT(handle->lockfd < 0, return 0)` makes a re-lock a no-op rather than a
    /// recursive acquisition. piko has no handle to re-enter, so the equivalent statement has
    /// two parts: the guard is not reacquirable while alive (the test above), and dropping it
    /// makes the lock available again.
    #[test]
    fn dropping_the_guard_releases() {
        let dir = tempfile::tempdir().unwrap();
        drop(DbLock::acquire(dir.path()).unwrap());
        assert!(!dir.path().join(LOCK_FILE).exists());
        // It is reacquirable, so the drop really did release rather than merely close.
        DbLock::acquire(dir.path()).unwrap().release().unwrap();
    }

    /// A stale lock file is the documented consequence of not using `flock`. It must block
    /// acquisition even though no process holds it. That is the interoperable behavior, and
    /// "improving" it would silently diverge from pacman.
    #[test]
    fn a_stale_lock_file_still_blocks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LOCK_FILE), b"").unwrap();
        let err = DbLock::acquire(dir.path()).unwrap_err();
        assert!(matches!(err, Error::DatabaseLocked { .. }), "got {err:?}");
    }

    /// Releasing a lock whose file already vanished is success. The post-condition the
    /// caller asked for already holds.
    #[test]
    fn releasing_a_vanished_lock_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join(LOCK_FILE)).unwrap();
        lock.release().unwrap();
    }

    #[test]
    fn creates_a_missing_database_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("var/lib/pacman");
        let lock = DbLock::acquire(&nested).unwrap();
        assert!(nested.join(LOCK_FILE).exists());
        lock.release().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_lock_file_has_mode_0000() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(dir.path()).unwrap();
        let mode = std::fs::metadata(lock.path()).unwrap().permissions().mode();
        // This masks to only the permission bits; `mode()` also carries the file-type bits.
        assert_eq!(mode & 0o777, 0o000, "mode was {:o}", mode & 0o777);
        lock.release().unwrap();
    }

    /// The error names the path. "Unable to lock database" without one is exactly the
    /// message users cannot act on.
    #[test]
    fn the_error_names_the_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let _held = DbLock::acquire(dir.path()).unwrap();
        let message = DbLock::acquire(dir.path()).unwrap_err().to_string();
        assert!(message.contains(LOCK_FILE), "{message}");
    }
}
