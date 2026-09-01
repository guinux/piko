//! Error types for the local database writer.
//!
//! This is a separate enum from [`piko_db::Error`], for the same reason `piko-txn` keeps its
//! own: a reader fails to *understand* something, a writer fails to *change* something. A
//! caller distinguishing "the database is corrupt" from "another package manager holds the
//! lock" should not have to match on variants of one type to do it.
//!
//! Reads performed on the way to a write — validating `ALPM_DB_VERSION`, loading a `desc` to
//! rewrite one section of it — go through `piko-db` and arrive here as [`Error::Read`].

use std::{fmt, path::PathBuf};

/// A [`Result`](std::result::Result) with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The filesystem operation that failed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum IoAction {
    /// Creating a file.
    Create,
    /// Creating a directory.
    CreateDir,
    /// Writing to an open file.
    Write,
    /// Renaming a file over another.
    Rename,
    /// Removing a file.
    Remove,
    /// Opening a file or directory.
    Open,
    /// Querying or changing a path's metadata.
    Metadata,
    /// Flushing a file or directory to stable storage.
    Sync,
}

impl IoAction {
    /// The verb phrase used in error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::CreateDir => "create directory",
            Self::Write => "write",
            Self::Rename => "rename onto",
            Self::Remove => "remove",
            Self::Open => "open",
            Self::Metadata => "stat",
            Self::Sync => "flush to disk",
        }
    }
}

impl fmt::Display for IoAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error produced while writing a local database.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A filesystem operation failed.
    #[error("failed to {action} {}", path.display())]
    Io {
        /// The path the operation was attempted on.
        path: PathBuf,
        /// The operation that was attempted.
        action: IoAction,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// Another process holds the database lock, or a previous one left it behind.
    ///
    /// The message repeats pacman's own advice. The lock is existence-based, not
    /// `flock`-based (see [`crate::DbLock`]), so a crash leaves a lock file that only a human
    /// can clear. Naming the file to remove turns a mystery into an actionable error.
    #[error(
        "unable to lock the database at {}; if no package manager is running, remove it",
        path.display()
    )]
    DatabaseLocked {
        /// The lock file that could not be created.
        path: PathBuf,
    },

    /// A writer was handed a lock belonging to a different database path.
    ///
    /// This is checked rather than assumed because the failure it prevents is silent: the
    /// write would succeed against an unlocked database, while a lock is dutifully held over
    /// an unrelated one.
    #[error("the lock at {} does not belong to the database at {}", lock.display(), dbpath.display())]
    WrongLock {
        /// The lock file that was presented.
        lock: PathBuf,
        /// The database path being written.
        dbpath: PathBuf,
    },

    /// A `desc` or `files` file is not a well-formed list of `%SECTION%` blocks.
    ///
    /// Only the writer produces this. The reader is deliberately more permissive: it tolerates
    /// sections it does not recognize, so a database written by a newer pacman stays readable.
    /// A *rewrite* cannot be permissive, because anything it fails to represent is something
    /// it would drop on the way back out.
    #[error("failed to represent {} for rewriting", path.display())]
    Record {
        /// The path that could not be represented.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: crate::record::RecordError,
    },

    /// A read performed on the way to a write failed.
    #[error(transparent)]
    Read(#[from] piko_db::Error),
}

impl Error {
    /// Builds an [`Error::Io`] for `path`.
    pub(crate) fn io(path: impl Into<PathBuf>, action: IoAction, source: std::io::Error) -> Self {
        Self::Io { path: path.into(), action, source }
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
    fn error_is_send_sync_static() {
        const fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Error>();
    }

    #[test]
    fn io_errors_name_the_path_and_the_action() {
        let err = Error::io(
            "/var/lib/pacman/local/foo-1-1/desc",
            IoAction::Write,
            std::io::Error::from(std::io::ErrorKind::StorageFull),
        );
        assert_eq!(err.to_string(), "failed to write /var/lib/pacman/local/foo-1-1/desc");
    }

    /// A read failure keeps its own message; this layer must not retitle it.
    #[test]
    fn a_read_failure_passes_through_transparently() {
        let inner = piko_db::Error::NotARegularFile { path: PathBuf::from("/x/desc") };
        let message = inner.to_string();
        let wrapped = Error::from(inner);
        assert_eq!(wrapped.to_string(), message);
    }
}
