//! Errors from administering a keyring.
//!
//! A separate enum from [`piko_sig::Error`], for the same reason `piko-db-write` keeps its
//! own. A verifier fails to *understand* something. An administrator fails to *change*
//! something. A caller must be able to tell "the keyring is unreadable" from "that key is not
//! in the keyring". Matching on variants of one type built for a different job should not be
//! what it takes.

use std::path::PathBuf;

/// A [`Result`](std::result::Result) with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The GnuPG operation an [`Error::Gpgme`] names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Operation {
    /// Allocating a buffer GnuPG writes into.
    AllocateBuffer,
    /// Creating a configuration file of the keyring.
    CreateConfFile,
    /// Creating a file of the keyring.
    CreateKeyringFile,
    /// Creating the keyring directory.
    CreateKeyringDir,
    /// Deleting a key.
    Delete,
    /// Disabling a key.
    Disable,
    /// Generating the master key.
    GenerateMasterKey,
    /// Importing keys.
    Import,
    /// Listing the keys of the keyring.
    ListKeys,
    /// Signing a key locally with the master key.
    LocallySign,
    /// Opening a configuration file of the keyring.
    OpenConfFile,
    /// Opening the keyring.
    OpenKeyring,
    /// Reading a file.
    Read,
    /// Reading one key of a key listing.
    ReadKey,
    /// Reading a configuration file of the keyring.
    ReadConfFile,
    /// Reading the fingerprint of a key.
    ReadFingerprint,
    /// Removing the expiry date of the master key.
    RemoveMasterKeyExpiry,
    /// Searching for the master key.
    SearchMasterKey,
    /// Selecting the master key as the signer.
    SelectSigner,
    /// Setting the permissions of a configuration file of the keyring.
    SetConfFileMode,
    /// Setting the permissions of a file of the keyring.
    SetKeyringFileMode,
    /// Setting how GnuPG lists keys.
    SetKeyListMode,
    /// Choosing an ownertrust level the trust menu offers.
    SetOwnertrustLevel,
    /// Setting the ownertrust of a key.
    SetOwnertrust,
    /// Setting the permissions of the keyring directory.
    SetKeyringDirMode,
    /// Setting the permissions of the trust database.
    SetTrustDbMode,
    /// Using a file of the keyring.
    UseKeyringFile,
    /// Writing a configuration file of the keyring.
    WriteConfFile,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AllocateBuffer => "allocate a scratch buffer",
            Self::CreateConfFile => "create a keyring configuration file",
            Self::CreateKeyringFile => "create a keyring file",
            Self::CreateKeyringDir => "create the keyring directory",
            Self::Delete => "delete",
            Self::Disable => "disable",
            Self::GenerateMasterKey => "generate the master key",
            Self::Import => "import",
            Self::ListKeys => "list keys in",
            Self::LocallySign => "locally sign",
            Self::OpenConfFile => "open a keyring configuration file",
            Self::OpenKeyring => "open the keyring",
            Self::Read => "read",
            Self::ReadKey => "read a key from",
            Self::ReadConfFile => "read a keyring configuration file",
            Self::ReadFingerprint => "read the fingerprint of",
            Self::RemoveMasterKeyExpiry => "remove the master key's expiry date",
            Self::SearchMasterKey => "search for the master key",
            Self::SelectSigner => "select the master key as signer",
            Self::SetConfFileMode => "set a keyring configuration file's permissions",
            Self::SetKeyringFileMode => "set a keyring file's permissions",
            Self::SetKeyListMode => "set key list mode for",
            Self::SetOwnertrustLevel => "set ownertrust",
            Self::SetOwnertrust => "set ownertrust on",
            Self::SetKeyringDirMode => "set the keyring directory's permissions",
            Self::SetTrustDbMode => "set the trust database's permissions",
            Self::UseKeyringFile => "use a keyring file",
            Self::WriteConfFile => "write a keyring configuration file",
        })
    }
}

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
        action: Operation,
        /// What GnuPG said.
        message: String,
    },

    /// An operation that needs piko's local signing key found none.
    #[error("the keyring at {} has no piko master key; run `piko key init` first", home.display())]
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

    /// A delete would also have deleted a secret key, and the caller did not allow that.
    ///
    /// The message names the flag, not the GPGME failure. [`Error::NoMasterKey`] names
    /// `piko key init` for the same reason: the caller's next step is the useful part. GPGME
    /// reports `GPG_ERR_CONFLICT` here, which says nothing about that next step.
    #[error(
        "the key {keyid} in the keyring at {} has a secret key; pass --secret to delete it too",
        home.display()
    )]
    SecretKeyRefused {
        /// The keyring directory.
        home: PathBuf,
        /// The key that was not deleted.
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
    /// This crate calls two functions of `piko-sig` to open a keyring:
    /// `piko_sig::ensure_trusted_keyring` and `piko_sig::open_context`. Their only failure
    /// mode is [`piko_sig::Error::KeyringUnusable`], so the conversion is total in practice. A
    /// future verification-only variant reaching here becomes [`Error::Gpgme`] rather than
    /// losing the message.
    fn from(source: piko_sig::Error) -> Self {
        match source {
            piko_sig::Error::KeyringUnusable { home, reason } => {
                Error::KeyringUnusable { home, reason }
            }
            other => Error::gpgme(PathBuf::new(), Operation::OpenKeyring, other),
        }
    }
}

impl Error {
    /// An [`Error::Gpgme`] that carries `source`'s message.
    pub(crate) fn gpgme(
        path: impl Into<PathBuf>,
        action: Operation,
        source: impl std::fmt::Display,
    ) -> Self {
        Self::Gpgme { path: path.into(), action, message: source.to_string() }
    }
}

#[cfg(test)]
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
        assert!(error.to_string().contains("piko key init"), "{error}");
    }
}
