//! The [`Message`] of each error this crate returns, and of each [`Rejection`], for a frontend
//! that renders it in the language of its user.
//!
//! Each message renders in English exactly as the type's `Display` writes it. The tests below
//! build one value of every variant and compare the two.
//!
//! What GnuPG says stays English.

use piko_i18n::{Arg, Localize, Message};

use crate::decision::Rejection;
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
        }
    }
}

impl Localize for Operation {
    fn message(&self) -> Message {
        Message::new(match self {
            Self::ReadSignature => "sig-op-read-signature",
            Self::ReadSignatureOf => "sig-op-read-signature-of",
            Self::ReadSignedFile => "sig-op-read-signed-file",
            Self::Verify => "sig-op-verify",
            Self::LookUpSigningKey => "sig-op-look-up-signing-key",
        })
    }
}

/// The key a rejection names: its fingerprint, or a phrase for a key with none.
fn key(fingerprint: Option<&String>) -> Arg {
    fingerprint.map_or_else(|| Message::new("sig-unnamed-key").into(), Arg::from)
}

impl Localize for Rejection {
    fn message(&self) -> Message {
        match self {
            Self::MissingRequired => Message::new("sig-rejection-missing-required"),
            Self::MarginalTrust { fingerprint } => {
                Message::new("sig-rejection-marginal-trust").arg("key", key(fingerprint.as_ref()))
            }
            Self::UnknownTrust { fingerprint } => {
                Message::new("sig-rejection-unknown-trust").arg("key", key(fingerprint.as_ref()))
            }
            Self::NeverTrust { fingerprint } => {
                Message::new("sig-rejection-never-trust").arg("key", key(fingerprint.as_ref()))
            }
            Self::SignatureExpired => Message::new("sig-rejection-signature-expired"),
            Self::KeyUnknown { fingerprint } => {
                Message::new("sig-rejection-key-unknown").arg("key", key(fingerprint.as_ref()))
            }
            Self::KeyDisabled { fingerprint } => {
                Message::new("sig-rejection-key-disabled").arg("key", key(fingerprint.as_ref()))
            }
            Self::KeyRevoked { fingerprint } => {
                Message::new("sig-rejection-key-revoked").arg("key", key(fingerprint.as_ref()))
            }
            Self::WeakDigest { fingerprint, algorithm } => {
                Message::new("sig-rejection-weak-digest")
                    .arg("key", key(fingerprint.as_ref()))
                    .arg("algorithm", *algorithm)
            }
            Self::WeakKey { fingerprint, algorithm, bits } => {
                Message::new("sig-rejection-weak-key")
                    .arg("key", key(fingerprint.as_ref()))
                    .arg("algorithm", *algorithm)
                    .arg("bits", *bits)
            }
            Self::Invalid => Message::new("sig-rejection-invalid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use piko_i18n::{Catalog, Language, Placeables};

    use super::*;

    /// One value of every variant of [`Error`] and of [`Rejection`], with arguments distinct
    /// from each other, so a message that swaps two variables renders differently from
    /// `Display`.
    fn every_message() -> Vec<(String, Message)> {
        let mut errors = vec![Error::KeyringUnusable {
            home: PathBuf::from("/etc/pacman.d/gnupg"),
            reason: "not a directory".to_owned(),
        }];
        errors.extend(
            [
                Operation::ReadSignature,
                Operation::ReadSignatureOf,
                Operation::ReadSignedFile,
                Operation::Verify,
                Operation::LookUpSigningKey,
            ]
            .map(|action| Error::Gpgme {
                path: PathBuf::from("/a/core.db"),
                action,
                message: "bad data".to_owned(),
            }),
        );
        let named = || Some("0123456789ABCDEF".to_owned());
        let mut rejections = vec![
            Rejection::MissingRequired,
            Rejection::SignatureExpired,
            Rejection::Invalid,
            Rejection::WeakKey { fingerprint: named(), algorithm: "RSA", bits: 1024 },
        ];
        for fingerprint in [named(), None] {
            rejections.extend([
                Rejection::MarginalTrust { fingerprint: fingerprint.clone() },
                Rejection::UnknownTrust { fingerprint: fingerprint.clone() },
                Rejection::NeverTrust { fingerprint: fingerprint.clone() },
                Rejection::KeyUnknown { fingerprint: fingerprint.clone() },
                Rejection::KeyDisabled { fingerprint: fingerprint.clone() },
                Rejection::KeyRevoked { fingerprint: fingerprint.clone() },
                Rejection::WeakDigest { fingerprint: fingerprint.clone(), algorithm: "SHA1" },
            ]);
        }
        // A match with no wildcard arm: a new variant fails to compile here until it has a
        // sample above.
        for error in &errors {
            match error {
                Error::KeyringUnusable { .. } | Error::Gpgme { .. } => {}
            }
        }
        for rejection in &rejections {
            match rejection {
                Rejection::MissingRequired
                | Rejection::MarginalTrust { .. }
                | Rejection::UnknownTrust { .. }
                | Rejection::NeverTrust { .. }
                | Rejection::SignatureExpired
                | Rejection::KeyUnknown { .. }
                | Rejection::KeyDisabled { .. }
                | Rejection::KeyRevoked { .. }
                | Rejection::WeakDigest { .. }
                | Rejection::WeakKey { .. }
                | Rejection::Invalid => {}
            }
        }
        let mut all: Vec<(String, Message)> =
            errors.iter().map(|each| (each.to_string(), each.message())).collect();
        all.extend(rejections.iter().map(|each| (each.to_string(), each.message())));
        all
    }

    #[test]
    fn the_english_catalog_renders_each_error_as_display_does() {
        let catalog = Catalog::new(Language::English, Placeables::Plain);
        for (display, message) in every_message() {
            assert_eq!(catalog.try_format(&message), Ok(display));
        }
    }

    #[test]
    fn every_language_renders_each_error() {
        for language in Language::ALL {
            let catalog = Catalog::new(*language, Placeables::Plain);
            for (_, message) in every_message() {
                let rendered = catalog.try_format(&message);
                assert!(rendered.is_ok(), "{language:?}: {rendered:?}");
            }
        }
    }
}
