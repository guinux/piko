//! The [`Message`] of each error this crate returns, for a frontend that renders it in the
//! language of its user.
//!
//! Each message renders in English exactly as the type's `Display` writes it. The tests below
//! build one value of every variant and compare the two.

use piko_i18n::{Localize, Message};

use crate::error::{Error, IoAction};
use crate::record::{RecordError, Unrepresentable};

impl Localize for Error {
    fn message(&self) -> Message {
        match self {
            Self::Io { path, action, .. } => {
                let id = match action {
                    IoAction::Create => "dbw-error-io-create",
                    IoAction::CreateDir => "dbw-error-io-create-dir",
                    IoAction::Write => "dbw-error-io-write",
                    IoAction::Rename => "dbw-error-io-rename",
                    IoAction::Remove => "dbw-error-io-remove",
                    IoAction::Open => "dbw-error-io-open",
                    IoAction::Metadata => "dbw-error-io-stat",
                    IoAction::Sync => "dbw-error-io-sync",
                };
                Message::new(id).arg("path", path.display().to_string())
            }
            Self::DatabaseLocked { path } => {
                Message::new("dbw-error-database-locked").arg("path", path.display().to_string())
            }
            Self::WrongLock { lock, dbpath } => Message::new("dbw-error-wrong-lock")
                .arg("lock", lock.display().to_string())
                .arg("dbpath", dbpath.display().to_string()),
            Self::TemporaryReplaced { path } => {
                Message::new("dbw-error-temporary-replaced").arg("path", path.display().to_string())
            }
            Self::Record { path, .. } => {
                Message::new("dbw-error-record").arg("path", path.display().to_string())
            }
            Self::InvalidMemberName { name } => {
                Message::new("dbw-error-invalid-member-name").arg("name", format!("{name:?}"))
            }
            Self::Read(error) => error.message(),
        }
    }
}

impl Localize for RecordError {
    fn message(&self) -> Message {
        match self {
            Self::ValueOutsideSection { line, content } => {
                Message::new("dbw-record-value-outside-section")
                    .arg("line", line.to_string())
                    .arg("content", format!("{content:?}"))
            }
            Self::DuplicateSection { keyword, line } => {
                Message::new("dbw-record-duplicate-section")
                    .arg("keyword", keyword.as_str())
                    .arg("line", line.to_string())
            }
            Self::InvalidKeyword { keyword } => {
                Message::new("dbw-record-invalid-keyword").arg("keyword", format!("{keyword:?}"))
            }
            Self::UnrepresentableValue { keyword, value, reason } => {
                Message::new("dbw-record-unrepresentable-value")
                    .arg("keyword", keyword.as_str())
                    .arg("value", format!("{value:?}"))
                    .arg("reason", reason.message())
            }
        }
    }
}

impl Localize for Unrepresentable {
    fn message(&self) -> Message {
        Message::new(match self {
            Self::Empty => "dbw-unrepresentable-empty",
            Self::LineBreak => "dbw-unrepresentable-line-break",
            Self::Nul => "dbw-unrepresentable-nul",
            Self::SectionHeader => "dbw-unrepresentable-section-header",
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use piko_i18n::{Catalog, Language, Placeables};

    use super::*;

    fn path() -> PathBuf {
        PathBuf::from("/var/lib/pacman/local/foo-1-1/desc")
    }

    /// One value of every variant of [`Error`] and of [`RecordError`], with arguments distinct
    /// from each other, so a message that swaps two variables renders differently from
    /// `Display`.
    fn every_message() -> Vec<(String, Message)> {
        let actions = [
            IoAction::Create,
            IoAction::CreateDir,
            IoAction::Write,
            IoAction::Rename,
            IoAction::Remove,
            IoAction::Open,
            IoAction::Metadata,
            IoAction::Sync,
        ];
        let mut errors: Vec<Error> = actions
            .into_iter()
            .map(|action| Error::io(path(), action, std::io::ErrorKind::NotFound.into()))
            .collect();
        let mut records = vec![
            RecordError::ValueOutsideSection { line: 1, content: "x".to_owned() },
            RecordError::DuplicateSection { keyword: "NAME".to_owned(), line: 5 },
            RecordError::InvalidKeyword { keyword: "a%b".to_owned() },
        ];
        records.extend(
            [
                Unrepresentable::Empty,
                Unrepresentable::LineBreak,
                Unrepresentable::Nul,
                Unrepresentable::SectionHeader,
            ]
            .map(|reason| RecordError::UnrepresentableValue {
                keyword: "DESC".to_owned(),
                value: "a\nb".to_owned(),
                reason,
            }),
        );
        errors.extend([
            Error::DatabaseLocked { path: PathBuf::from("/var/lib/pacman/db.lck") },
            Error::WrongLock { lock: PathBuf::from("/a/db.lck"), dbpath: PathBuf::from("/b") },
            Error::TemporaryReplaced { path: path() },
            Error::Record {
                path: path(),
                source: RecordError::DuplicateSection { keyword: "NAME".to_owned(), line: 5 },
            },
            Error::InvalidMemberName { name: "../x".to_owned() },
            Error::Read(piko_db::Error::NotARegularFile { path: path() }),
        ]);
        // A match with no wildcard arm: a new variant fails to compile here until it has a
        // sample above.
        for error in &errors {
            match error {
                Error::Io { .. }
                | Error::DatabaseLocked { .. }
                | Error::WrongLock { .. }
                | Error::TemporaryReplaced { .. }
                | Error::Record { .. }
                | Error::InvalidMemberName { .. }
                | Error::Read(_) => {}
            }
        }
        let mut all: Vec<(String, Message)> =
            errors.iter().map(|each| (each.to_string(), each.message())).collect();
        all.extend(records.iter().map(|each| (each.to_string(), each.message())));
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
