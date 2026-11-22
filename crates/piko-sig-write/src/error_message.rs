//! The [`Message`] of each error this crate returns, for a frontend that renders it in the
//! language of its user.
//!
//! Each message renders in English exactly as the type's `Display` writes it. The tests below
//! build one value of every variant and compare the two.
//!
//! What GnuPG says stays English.

use piko_i18n::{Localize, Message};

use crate::error::{Error, Operation};

impl Localize for Error {
    fn message(&self) -> Message {
        match self {
            Self::KeyringUnusable { home, reason } => Message::new("sig-error-keyring-unusable")
                .arg("home", home.display().to_string())
                .arg("reason", reason.as_str()),
            Self::Gpgme { path, action, message } => Message::new("sig-error-gpgme")
                .arg("action", action.message())
                .arg("path", path.display().to_string())
                .arg("message", message.as_str()),
            Self::NoMasterKey { home } => {
                Message::new("sig-error-no-master-key").arg("home", home.display().to_string())
            }
            Self::KeyNotFound { home, keyid } => Message::new("sig-error-key-not-found")
                .arg("keyid", keyid.as_str())
                .arg("home", home.display().to_string()),
            Self::SecretKeyRefused { home, keyid } => Message::new("sig-error-secret-key-refused")
                .arg("keyid", keyid.as_str())
                .arg("home", home.display().to_string()),
            Self::PopulateFile { path, reason } => Message::new("sig-error-populate-file")
                .arg("path", path.display().to_string())
                .arg("reason", reason.as_str()),
        }
    }
}

impl Localize for Operation {
    fn message(&self) -> Message {
        Message::new(match self {
            Self::AllocateBuffer => "sig-admin-op-allocate-buffer",
            Self::CreateConfFile => "sig-admin-op-create-conf-file",
            Self::CreateKeyringFile => "sig-admin-op-create-keyring-file",
            Self::CreateKeyringDir => "sig-admin-op-create-keyring-dir",
            Self::Delete => "sig-admin-op-delete",
            Self::Disable => "sig-admin-op-disable",
            Self::GenerateMasterKey => "sig-admin-op-generate-master-key",
            Self::Import => "sig-admin-op-import",
            Self::ListKeys => "sig-admin-op-list-keys",
            Self::LocallySign => "sig-admin-op-locally-sign",
            Self::OpenConfFile => "sig-admin-op-open-conf-file",
            Self::OpenKeyring => "sig-admin-op-open-keyring",
            Self::Read => "sig-admin-op-read",
            Self::ReadKey => "sig-admin-op-read-key",
            Self::ReadConfFile => "sig-admin-op-read-conf-file",
            Self::ReadFingerprint => "sig-admin-op-read-fingerprint",
            Self::RemoveMasterKeyExpiry => "sig-admin-op-remove-master-key-expiry",
            Self::SearchMasterKey => "sig-admin-op-search-master-key",
            Self::SelectSigner => "sig-admin-op-select-signer",
            Self::SetConfFileMode => "sig-admin-op-set-conf-file-mode",
            Self::SetKeyringFileMode => "sig-admin-op-set-keyring-file-mode",
            Self::SetKeyListMode => "sig-admin-op-set-key-list-mode",
            Self::SetOwnertrustLevel => "sig-admin-op-set-ownertrust-level",
            Self::SetOwnertrust => "sig-admin-op-set-ownertrust",
            Self::SetKeyringDirMode => "sig-admin-op-set-keyring-dir-mode",
            Self::SetTrustDbMode => "sig-admin-op-set-trust-db-mode",
            Self::UseKeyringFile => "sig-admin-op-use-keyring-file",
            Self::WriteConfFile => "sig-admin-op-write-conf-file",
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use piko_i18n::{Catalog, Language, Placeables};

    use super::*;

    fn home() -> PathBuf {
        PathBuf::from("/etc/pacman.d/gnupg")
    }

    /// One value of every variant of [`Error`], with arguments distinct from each other, so a
    /// message that swaps two variables renders differently from `Display`.
    fn every_error() -> Vec<Error> {
        let mut errors = vec![
            Error::KeyringUnusable { home: home(), reason: "not a directory".to_owned() },
            Error::NoMasterKey { home: home() },
            Error::KeyNotFound { home: home(), keyid: "0123456789ABCDEF".to_owned() },
            Error::SecretKeyRefused { home: home(), keyid: "0123456789ABCDEF".to_owned() },
            Error::PopulateFile {
                path: PathBuf::from("/usr/share/pacman/keyrings/archlinux.gpg"),
                reason: "it is not a regular file".to_owned(),
            },
        ];
        errors.extend(
            [
                Operation::AllocateBuffer,
                Operation::CreateConfFile,
                Operation::CreateKeyringFile,
                Operation::CreateKeyringDir,
                Operation::Delete,
                Operation::Disable,
                Operation::GenerateMasterKey,
                Operation::Import,
                Operation::ListKeys,
                Operation::LocallySign,
                Operation::OpenConfFile,
                Operation::OpenKeyring,
                Operation::Read,
                Operation::ReadKey,
                Operation::ReadConfFile,
                Operation::ReadFingerprint,
                Operation::RemoveMasterKeyExpiry,
                Operation::SearchMasterKey,
                Operation::SelectSigner,
                Operation::SetConfFileMode,
                Operation::SetKeyringFileMode,
                Operation::SetKeyListMode,
                Operation::SetOwnertrustLevel,
                Operation::SetOwnertrust,
                Operation::SetKeyringDirMode,
                Operation::SetTrustDbMode,
                Operation::UseKeyringFile,
                Operation::WriteConfFile,
            ]
            .map(|action| Error::Gpgme {
                path: home(),
                action,
                message: "bad data".to_owned(),
            }),
        );
        // A match with no wildcard arm: a new variant fails to compile here until it has a
        // sample above.
        for error in &errors {
            match error {
                Error::KeyringUnusable { .. }
                | Error::Gpgme { .. }
                | Error::NoMasterKey { .. }
                | Error::KeyNotFound { .. }
                | Error::SecretKeyRefused { .. }
                | Error::PopulateFile { .. } => {}
            }
        }
        errors
    }

    #[test]
    fn the_english_catalog_renders_each_error_as_display_does() {
        let catalog = Catalog::new(Language::English, Placeables::Plain);
        for error in every_error() {
            assert_eq!(catalog.try_format(&error.message()), Ok(error.to_string()));
        }
    }

    #[test]
    fn every_language_renders_each_error() {
        for language in Language::ALL {
            let catalog = Catalog::new(*language, Placeables::Plain);
            for error in every_error() {
                let rendered = catalog.try_format(&error.message());
                assert!(rendered.is_ok(), "{language:?}: {rendered:?}");
            }
        }
    }
}
