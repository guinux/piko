//! Errors from downloading and refreshing.

use std::path::PathBuf;

/// A [`Result`](std::result::Result) with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Something went wrong fetching or installing a database.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Every configured server failed.
    ///
    /// Carries what each server said. A single "could not download core.db" turns into a
    /// support thread: one mirror 404s, another times out, a third serves HTML from a captive
    /// portal, and the user needs to see which.
    #[error(
        "could not download {file} from any of {} server(s):\n  {}",
        attempts.len(),
        attempts.iter().map(|(url, why)| format!("{url}: {why}")).collect::<Vec<_>>().join("\n  ")
    )]
    AllServersFailed {
        /// The file that was wanted, e.g. `core.db`.
        file: String,
        /// Each server tried, in order, and why it did not work.
        attempts: Vec<(String, String)>,
    },

    /// A repository has no server to download from.
    #[error("repository {repo} has no Server configured")]
    NoServers {
        /// The repository name.
        repo: String,
    },

    /// A batch was asked to fetch the same file twice.
    ///
    /// Refused rather than deduplicated. `<destination>.new` is derived from the destination
    /// alone, so two transfers to one destination would race to write the same atomic-write
    /// temporary from two threads.
    /// Silently collapsing the duplicate would hide a caller bug that only shows up as a
    /// corrupted download under load.
    #[error("{file} was listed more than once in a single batch")]
    DuplicateTarget {
        /// The file named twice.
        file: String,
    },

    /// The download exceeded the size bound.
    ///
    /// A mirror is not trusted to be honest about how much it will send, so the bound is
    /// enforced against what actually arrives rather than against `Content-Length`.
    #[error("{file} exceeds the {max} byte download limit")]
    TooLarge {
        /// The file being downloaded.
        file: String,
        /// The configured maximum.
        max: u64,
    },

    /// The server answered with a body of zero bytes.
    ///
    /// A repository database or a package archive is a compressed tarball. It is never
    /// legitimately empty. This variant exists because installing an empty body once
    /// truncated a working database to nothing. Nothing is written for an empty body now,
    /// either way.
    #[error("the download of {file} was empty (nothing was written)")]
    EmptyDownload {
        /// The file that came back empty.
        file: String,
    },

    /// The downloaded database did not satisfy the repository's `SigLevel`.
    ///
    /// The live database is untouched. This is raised before anything is renamed into place.
    #[error("the downloaded {file} was rejected: {reason} (the existing database is unchanged)")]
    SignatureRejected {
        /// The file that was rejected.
        file: String,
        /// Which rule refused it.
        reason: String,
    },

    /// The downloaded database could not be checked at all.
    ///
    /// Kept separate from [`Error::SignatureRejected`] for the same reason `piko-txn` keeps
    /// them separate: one means distrust the mirror, the other means fix the keyring.
    #[error("cannot check the signature of the downloaded {file}: {reason}")]
    SignatureUncheckable {
        /// The file that could not be checked.
        file: String,
        /// What went wrong.
        reason: String,
    },

    /// A filesystem operation failed.
    #[error("failed to {action} {}", path.display())]
    Io {
        /// The path involved.
        path: PathBuf,
        /// What was being attempted.
        action: &'static str,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// Installing a downloaded file failed.
    #[error(transparent)]
    Install(#[from] piko_db_write::Error),

    /// A [`crate::Cancel`] was requested while a download was in progress.
    ///
    /// Raised from inside the streaming loop, the same place as [`Error::TooLarge`], as soon
    /// as the request is noticed rather than only between whole files. The temporary being
    /// written stays uncommitted and is removed on drop. Nothing changed on disk.
    #[error("the download was cancelled")]
    Cancelled,
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

    /// The whole point of collecting attempts is that they reach the user.
    #[test]
    fn a_failed_download_names_every_server_it_tried() {
        let error = Error::AllServersFailed {
            file: "core.db".to_owned(),
            attempts: vec![
                ("https://a.example/core.db".to_owned(), "404 Not Found".to_owned()),
                ("https://b.example/core.db".to_owned(), "timed out".to_owned()),
            ],
        };
        let message = error.to_string();
        assert!(message.contains("a.example"), "{message}");
        assert!(message.contains("timed out"), "{message}");
    }

    /// A rejection has to say the system was left alone, or the user's next move is to panic
    /// about a half-updated database that does not exist.
    #[test]
    fn a_rejection_says_the_existing_database_is_intact() {
        let error = Error::SignatureRejected {
            file: "core.db".to_owned(),
            reason: "the signature is invalid".to_owned(),
        };
        assert!(error.to_string().contains("unchanged"), "{error}");
    }
}
