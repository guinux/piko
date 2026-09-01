//! Errors from signature verification.

use std::path::PathBuf;

/// A [`Result`](std::result::Result) with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Something went wrong while verifying, as opposed to a file simply failing verification.
///
/// The distinction is the point of this type. "This package's signature is untrusted" is not
/// an error. It is [`crate::decision::Verdict::Rejected`], an answer the caller asked for. An
/// error here means piko could not get an answer. The two must never be conflated: treating a
/// broken keyring as a failed signature would refuse valid packages, and treating it as a pass
/// would install unverified ones.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The keyring directory cannot be used.
    #[error("the keyring at {} cannot be used: {reason}", home.display())]
    KeyringUnusable {
        /// The GnuPG home directory that was tried.
        home: PathBuf,
        /// Why it could not be used.
        reason: String,
    },

    /// GnuPG could not carry out an operation.
    ///
    /// Carries GPGME's message as text rather than its error type. The type is not `Send`,
    /// and a caller that wants to react to a specific code should read a
    /// [`crate::decision::Verdict`] instead.
    #[error("failed to {action} {}: {message}", path.display())]
    Gpgme {
        /// The file involved.
        path: PathBuf,
        /// What was being attempted.
        action: &'static str,
        /// What GnuPG said.
        ///
        /// Text, not GPGME's error type. That type is not `Send`, and a caller wanting to
        /// react to a specific code should read a [`crate::decision::Verdict`].
        message: String,
    },
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// A transaction hands errors between threads. A bound that is not asserted is one that
    /// quietly disappears. This is also why `Gpgme` carries a `String`.
    #[test]
    fn error_is_send_sync_static() {
        const fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Error>();
    }

    #[test]
    fn a_keyring_error_names_the_directory() {
        let error = Error::KeyringUnusable {
            home: PathBuf::from("/etc/pacman.d/gnupg"),
            reason: "not a directory".to_owned(),
        };
        assert!(error.to_string().contains("/etc/pacman.d/gnupg"), "{error}");
    }
}
