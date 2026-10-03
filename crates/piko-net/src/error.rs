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
    /// support thread. One mirror 404s, another times out, a third serves HTML from a captive
    /// portal. The user needs to see which.
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

    /// A repository's `SigLevel` asks for a signature check, and the keyring cannot be used.
    ///
    /// [`crate::RefreshTargets::new`] returns this before any download. Failing open here
    /// would install every database unverified the day the keyring broke.
    #[error("a repository's SigLevel requires a signature check, and the keyring cannot be used")]
    KeyringUnusable {
        /// Why the keyring could not be opened.
        #[source]
        source: piko_sig::Error,
    },

    /// A batch was asked to fetch the same file twice.
    ///
    /// Refused rather than deduplicated. `<destination>.new` is derived from the destination
    /// alone. So two transfers to one destination would race to write the same atomic-write
    /// temporary from two threads.
    /// Silently collapsing the duplicate would hide a caller bug that only shows up as a
    /// corrupted download under load.
    #[error("{file} was listed more than once in a single batch")]
    DuplicateTarget {
        /// The file named twice.
        file: String,
    },

    /// A refresh was handed a lock belonging to a different database path.
    ///
    /// The lock must be `<dbpath>/db.lck` for the `<dbpath>` whose `sync` directory is written.
    /// Any other lock leaves that directory unlocked, which nothing else would report.
    #[error(
        "the lock at {} does not belong to the database that holds {}",
        lock.display(),
        sync_dir.display()
    )]
    WrongLock {
        /// The lock file that was presented.
        lock: PathBuf,
        /// The sync directory being written.
        sync_dir: PathBuf,
    },

    /// The download exceeded the size bound.
    ///
    /// A mirror is not trusted to be honest about how much it will send. So the bound is
    /// enforced against what actually arrives, not against `Content-Length`.
    #[error("{file} exceeds the {max} byte download limit")]
    TooLarge {
        /// The file being downloaded.
        file: String,
        /// The configured maximum.
        max: u64,
    },

    /// A package download went past the size its repository database declares.
    ///
    /// The declared size is `%CSIZE%`. The transfer is refused while it arrives, before the
    /// checksum could say anything, so a mirror cannot fill the cache with bytes nobody asked
    /// for.
    #[error("{file} is larger than the {declared} bytes its repository declares")]
    LargerThanDeclared {
        /// The file being downloaded.
        file: String,
        /// `%CSIZE%`.
        declared: u64,
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
    /// them separate. One means distrust the mirror. The other means fix the keyring.
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
    /// Raised from inside the streaming loop, the same place as [`Error::TooLarge`]. It fires
    /// as soon as the request is noticed, not only between whole files. The temporary being
    /// written stays uncommitted and is removed on drop. Nothing changed on disk.
    #[error("the download was cancelled")]
    Cancelled,

    /// The download sandbox could not run a request.
    ///
    /// The helper could not be started, the download user does not exist, or the kernel refused
    /// a restriction. Every server would fail the same way, so no other server is tried. Nothing
    /// was downloaded.
    #[error("the download sandbox failed: {reason}")]
    Sandbox {
        /// What went wrong.
        reason: String,
    },
}

impl Error {
    /// Whether this error stops a whole transfer, rather than one server's attempt.
    pub(crate) const fn stops_every_server(&self) -> bool {
        matches!(self, Self::Cancelled | Self::Sandbox { .. })
    }
}

/// Text a server or the download helper wrote, escaped before it reaches a terminal. The rule
/// is shared with every other crate: see [`fn@piko_db::printable`].
pub(crate) use piko_db::printable;

/// `text` with the user information taken out of every URL in it: the `user:password@` in
/// front of a host.
///
/// libalpm names a server by its host alone, with the user information dropped
/// (`curl_gethost`, `dload.c:307`). A `Server` can carry a password, and ureq sends it as HTTP
/// basic authentication. Text that an error holds reaches a terminal, and from there a log or a
/// bug report. So every URL piko-net puts in an error, a note or a reason goes through this
/// first, and so does every message ureq or the download helper returns.
///
/// An authority ends at the first `/`, `?`, `#`, quote, angle bracket or white space after
/// `://`. The user information is everything up to its last `@`, the same split the `http`
/// loopback test and the per-host failure count make.
#[must_use]
pub fn without_credentials(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains("://") {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut shown = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find("://") {
        let Some((before, after)) = rest.split_at_checked(index.saturating_add(3)) else { break };
        shown.push_str(before);
        let end = after
            .find(|c: char| {
                matches!(c, '/' | '?' | '#' | '"' | '\'' | '<' | '>' | '`') || c.is_whitespace()
            })
            .unwrap_or(after.len());
        let Some((authority, tail)) = after.split_at_checked(end) else {
            rest = after;
            break;
        };
        shown.push_str(authority.rsplit_once('@').map_or(authority, |(_, host)| host));
        rest = tail;
    }
    shown.push_str(rest);
    std::borrow::Cow::Owned(shown)
}

/// Renders `error` followed by every cause in its chain, joined by `": "`.
///
/// Use this where an error becomes text, as in the attempts of [`Error::AllServersFailed`].
/// The message of an [`Error::Io`] names the action and the path only, and its source carries
/// the reason. A reporter that walks the chain prints that reason. `to_string` alone drops it,
/// and the user then reads "failed to download <url>" with no reason at all.
pub(crate) fn with_causes(error: &dyn std::error::Error) -> String {
    use std::fmt::Write as _;

    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let _ = write!(text, ": {cause}");
        source = cause.source();
    }
    text
}

/// The reason one server failed, as one attempt of [`Error::AllServersFailed`] records it.
///
/// Each attempt is already listed under its URL, without credentials. An [`Error::Io`] about
/// that same URL names it again in its message, so only its causes are kept. An error about
/// another file keeps its whole message, because which file failed is the information. The
/// `.sig` fetched beside a download is the usual case.
pub(crate) fn attempt_reason(url: &str, error: &Error) -> String {
    match error {
        Error::Io { path, source, .. } if path.as_os_str() == &*without_credentials(url) => {
            with_causes(source)
        }
        other => with_causes(other),
    }
}

#[cfg(test)]
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

    /// An attempt stored as text keeps the reason that the source of an `Io` error carries.
    #[test]
    fn with_causes_keeps_the_whole_chain() {
        let error = Error::Io {
            path: "http://a.example/core.db".into(),
            action: "download",
            source: std::io::Error::other("io: Connection reset by peer"),
        };
        assert_eq!(
            with_causes(&error),
            "failed to download http://a.example/core.db: io: Connection reset by peer"
        );
        assert_eq!(with_causes(&Error::Cancelled), "the download was cancelled");
    }

    /// An attempt names its URL once. An error about another file still names that file.
    #[test]
    fn attempt_reason_drops_only_the_repeated_url() {
        let url = "http://a.example/core.db";
        let reset = |path: &str| Error::Io {
            path: path.into(),
            action: "download",
            source: std::io::Error::other("io: Connection reset by peer"),
        };
        assert_eq!(attempt_reason(url, &reset(url)), "io: Connection reset by peer");
        assert_eq!(
            attempt_reason(url, &reset("http://a.example/core.db.sig")),
            "failed to download http://a.example/core.db.sig: io: Connection reset by peer"
        );
        let empty = Error::EmptyDownload { file: "core.db".to_owned() };
        assert_eq!(attempt_reason(url, &empty), empty.to_string());
    }

    /// A rejection has to say the system was left alone. Otherwise the user's next move is to
    /// panic about a half-updated database that does not exist.
    /// A server URL loses its user information and keeps everything else, as `curl_gethost`
    /// drops it.
    #[test]
    fn a_url_loses_its_credentials() {
        assert_eq!(
            without_credentials("https://user:secret@mirror.example:8443/core/os/x86_64/core.db"),
            "https://mirror.example:8443/core/os/x86_64/core.db"
        );
        // The host follows the last `@`, as the loopback test reads it.
        assert_eq!(
            without_credentials("https://a@b:c@mirror.example/x"),
            "https://mirror.example/x"
        );
        assert_eq!(without_credentials("https://mirror.example/x@y"), "https://mirror.example/x@y");
    }

    /// Every URL in a message loses its credentials, and the text around them stays.
    #[test]
    fn every_url_in_a_message_loses_its_credentials() {
        assert_eq!(
            without_credentials(
                "error sending request for url (https://u:p@a.example/core.db): \
                 redirected to 'https://v:q@b.example/core.db'"
            ),
            "error sending request for url (https://a.example/core.db): \
             redirected to 'https://b.example/core.db'"
        );
        assert_eq!(without_credentials("connection reset by peer"), "connection reset by peer");
    }

    /// An attempt about its own URL keeps only the causes once the path lost its credentials.
    #[test]
    fn attempt_reason_matches_the_url_without_its_credentials() {
        let url = "https://user:secret@a.example/core.db";
        let error = Error::Io {
            path: without_credentials(url).as_ref().into(),
            action: "download",
            source: std::io::Error::other("unexpected HTTP status 404"),
        };
        assert_eq!(attempt_reason(url, &error), "unexpected HTTP status 404");
    }

    #[test]
    fn a_rejection_says_the_existing_database_is_intact() {
        let error = Error::SignatureRejected {
            file: "core.db".to_owned(),
            reason: "the signature is invalid".to_owned(),
        };
        assert!(error.to_string().contains("unchanged"), "{error}");
    }
}
