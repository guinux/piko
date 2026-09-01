//! Errors from administering a keyring.
//!
//! A separate enum from [`piko_sig::Error`], for the same reason `piko-db-write` keeps its
//! own: a verifier fails to *understand* something, an administrator fails to *change*
//! something. A caller distinguishing "the keyring is unreadable" from "that key is not in the
//! keyring" should not have to match on variants of one type built for a different job.

use std::path::PathBuf;

/// A [`Result`](std::result::Result) with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Something went wrong administering a keyring.
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
    /// Carries GPGME's message as text rather than its error type, for the same reason
    /// `piko_sig::Error::Gpgme` does: the type is not `Send`.
    #[error("failed to {action} {}: {message}", path.display())]
    Gpgme {
        /// The file or key involved.
        path: PathBuf,
        /// What was being attempted.
        action: &'static str,
        /// What GnuPG said.
        message: String,
    },

    /// An operation that needs piko's local signing key found none.
    #[error("the keyring at {} has no piko master key; run `piko-key init` first", home.display())]
    NoMasterKey {
        /// The keyring directory that was searched.
        home: PathBuf,
    },

    /// An operation named a key that is not in the keyring.
    #[error("the key {keyid} is not in the keyring at {}", home.display())]
    KeyNotFound {
        /// The keyring directory that was searched.
        home: PathBuf,
        /// The key identifier (fingerprint or short ID) that was not found.
        keyid: String,
    },

    /// A `populate` source file (`<name>.gpg`, `-trusted`, or `-revoked`) could not be used.
    #[error("failed to use keyring file {}: {reason}", path.display())]
    PopulateFile {
        /// The file that could not be used.
        path: PathBuf,
        /// Why.
        reason: String,
    },
}

impl From<piko_sig::Error> for Error {
    /// [`piko_sig::open_context`] is the one function this crate calls into `piko-sig` for.
    /// Its only failure mode is [`piko_sig::Error::KeyringUnusable`], so the conversion is
    /// total in practice; a future verification-only variant reaching here becomes
    /// [`Error::Gpgme`] rather than losing the message.
    fn from(source: piko_sig::Error) -> Self {
        match source {
            piko_sig::Error::KeyringUnusable { home, reason } => {
                Error::KeyringUnusable { home, reason }
            }
            other => Error::Gpgme {
                path: PathBuf::new(),
                action: "open the keyring",
                message: other.to_string(),
            },
        }
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

    /// This crate's errors cross the same thread boundary `piko-txn` already relies on for
    /// `piko_sig::Error`; the bound must hold here too.
    #[test]
    fn error_is_send_sync_static() {
        const fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Error>();
    }

    #[test]
    fn a_no_master_key_error_names_the_keyring() {
        let error = Error::NoMasterKey { home: PathBuf::from("/etc/pacman.d/gnupg") };
        assert!(error.to_string().contains("/etc/pacman.d/gnupg"), "{error}");
        assert!(error.to_string().contains("piko-key init"), "{error}");
    }
}
