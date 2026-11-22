//! The [`Message`] of each error this crate returns, for a frontend that renders it in the
//! language of its user.
//!
//! Each message renders in English exactly as the type's `Display` writes it. The tests below
//! build one value of every variant and compare the two.
//!
//! A reason a server, the download helper or GnuPG wrote stays English. It is quoted as it is.

use piko_i18n::{Arg, Localize, Message};

use crate::error::{Error, IoAction, Uncheckable};

impl Localize for Error {
    fn message(&self) -> Message {
        match self {
            Self::AllServersFailed { file, attempts } => {
                let attempts = attempts.iter().map(|(url, reason)| {
                    Message::new("net-attempt")
                        .arg("url", url.as_str())
                        .arg("reason", reason.as_str())
                });
                Message::new("net-error-all-servers-failed")
                    .arg("file", file.as_str())
                    .arg("count", attempts.len())
                    .arg("list", Arg::list(attempts, "net-join-lines"))
            }
            Self::NoServers { repo } => {
                Message::new("net-error-no-servers").arg("repo", repo.as_str())
            }
            Self::KeyringUnusable { .. } => Message::new("net-error-keyring-unusable"),
            Self::DuplicateTarget { file } => {
                Message::new("net-error-duplicate-target").arg("file", file.as_str())
            }
            Self::WrongLock { lock, sync_dir } => Message::new("net-error-wrong-lock")
                .arg("lock", lock.display().to_string())
                .arg("sync_dir", sync_dir.display().to_string()),
            Self::TooLarge { file, max } => {
                Message::new("net-error-too-large").arg("file", file.as_str()).arg("max", *max)
            }
            Self::LargerThanDeclared { file, declared } => {
                Message::new("net-error-larger-than-declared")
                    .arg("file", file.as_str())
                    .arg("declared", *declared)
            }
            Self::EmptyDownload { file } => {
                Message::new("net-error-empty-download").arg("file", file.as_str())
            }
            Self::SignatureRejected { file, reason } => {
                Message::new("net-error-signature-rejected")
                    .arg("file", file.as_str())
                    .arg("reason", reason.message())
            }
            Self::SignatureUncheckable { file, reason } => {
                Message::new("net-error-signature-uncheckable")
                    .arg("file", file.as_str())
                    .arg("reason", reason.message())
            }
            Self::Io { path, action, .. } => {
                let id = match action {
                    IoAction::Download => "net-error-io-download",
                    IoAction::Create => "net-error-io-create",
                    IoAction::ReadDownload => "net-error-io-read-download",
                    IoAction::WriteDownload => "net-error-io-write-download",
                };
                Message::new(id).arg("path", path.display().to_string())
            }
            Self::Install(error) => error.message(),
            Self::Cancelled => Message::new("net-error-cancelled"),
            Self::Sandbox { reason } => {
                Message::new("net-error-sandbox").arg("reason", reason.as_str())
            }
        }
    }
}

impl Localize for Uncheckable {
    fn message(&self) -> Message {
        match self {
            Self::Unreachable { url, reason } => Message::new("net-uncheckable-unreachable")
                .arg("url", url.as_str())
                .arg("reason", reason.as_str()),
            Self::Status { url, status } => Message::new("net-uncheckable-status")
                .arg("url", url.as_str())
                .arg("status", status.to_string()),
            Self::Empty { url } => Message::new("net-uncheckable-empty").arg("url", url.as_str()),
            Self::NoKeyring => Message::new("net-uncheckable-no-keyring"),
            Self::Keyring(error) => error.message(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use piko_i18n::{Catalog, Language, Placeables};

    use super::*;

    fn io(action: IoAction) -> Error {
        Error::Io {
            path: PathBuf::from("https://a.example/core.db"),
            action,
            source: std::io::ErrorKind::NotFound.into(),
        }
    }

    fn uncheckable(reason: Uncheckable) -> Error {
        Error::SignatureUncheckable { file: "core.db".to_owned(), reason }
    }

    /// One value of every variant of [`Error`], with arguments distinct from each other, so a
    /// message that swaps two variables renders differently from `Display`.
    fn every_error() -> Vec<Error> {
        let attempt = |url: &str, reason: &str| (url.to_owned(), reason.to_owned());
        let errors = vec![
            Error::AllServersFailed {
                file: "core.db".to_owned(),
                attempts: vec![attempt("https://a.example/core.db", "404 Not Found")],
            },
            Error::AllServersFailed {
                file: "core.db".to_owned(),
                attempts: vec![
                    attempt("https://a.example/core.db", "404 Not Found"),
                    attempt("https://b.example/core.db", "timed out"),
                    attempt("https://c.example/core.db", "reset"),
                ],
            },
            Error::NoServers { repo: "core".to_owned() },
            Error::KeyringUnusable {
                source: piko_sig::Error::KeyringUnusable {
                    home: PathBuf::from("/etc/pacman.d/gnupg"),
                    reason: "missing".to_owned(),
                },
            },
            Error::DuplicateTarget { file: "core.db".to_owned() },
            Error::WrongLock {
                lock: PathBuf::from("/a/db.lck"),
                sync_dir: PathBuf::from("/b/sync"),
            },
            Error::TooLarge { file: "core.db".to_owned(), max: 1024 },
            Error::LargerThanDeclared { file: "foo.pkg.tar.zst".to_owned(), declared: 2048 },
            Error::EmptyDownload { file: "core.db".to_owned() },
            Error::SignatureRejected {
                file: "core.db".to_owned(),
                reason: piko_sig::Rejection::KeyUnknown { fingerprint: Some("ABCD".to_owned()) },
            },
            uncheckable(Uncheckable::Unreachable {
                url: "https://a.example/core.db.sig".to_owned(),
                reason: "timed out".to_owned(),
            }),
            uncheckable(Uncheckable::Status {
                url: "https://a.example/core.db.sig".to_owned(),
                status: 500,
            }),
            uncheckable(Uncheckable::Empty { url: "https://a.example/core.db.sig".to_owned() }),
            uncheckable(Uncheckable::NoKeyring),
            uncheckable(Uncheckable::Keyring(piko_sig::Error::KeyringUnusable {
                home: PathBuf::from("/etc/pacman.d/gnupg"),
                reason: "missing".to_owned(),
            })),
            io(IoAction::Download),
            io(IoAction::Create),
            io(IoAction::ReadDownload),
            io(IoAction::WriteDownload),
            Error::Install(piko_db_write::Error::Read(piko_db::Error::NotARegularFile {
                path: PathBuf::from("/a"),
            })),
            Error::Cancelled,
            Error::Sandbox { reason: "no user".to_owned() },
        ];
        // A match with no wildcard arm: a new variant fails to compile here until it has a
        // sample above.
        for error in &errors {
            match error {
                Error::AllServersFailed { .. }
                | Error::NoServers { .. }
                | Error::KeyringUnusable { .. }
                | Error::DuplicateTarget { .. }
                | Error::WrongLock { .. }
                | Error::TooLarge { .. }
                | Error::LargerThanDeclared { .. }
                | Error::EmptyDownload { .. }
                | Error::SignatureRejected { .. }
                | Error::SignatureUncheckable { .. }
                | Error::Io { .. }
                | Error::Install(_)
                | Error::Cancelled
                | Error::Sandbox { .. } => {}
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
