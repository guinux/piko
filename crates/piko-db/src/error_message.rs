//! The [`Message`] of each error this crate returns, for a frontend that renders it in the
//! language of its user.
//!
//! Each message renders in English exactly as the type's `Display` writes it. The tests below
//! build one value of every variant and compare the two.

use piko_i18n::{Localize, Message};

use crate::compression::Unsupported;
use crate::error::{Error, IoAction};
use crate::fs_util::Distrust;
use crate::limits::Limit;
use crate::local::SchemaVersionError;
use crate::repo::RepoNameError;

impl Localize for Error {
    fn message(&self) -> Message {
        match self {
            Self::Io { path, action, .. } => {
                let id = match action {
                    IoAction::Open => "db-error-io-open",
                    IoAction::Read => "db-error-io-read",
                    IoAction::Metadata => "db-error-io-stat",
                    IoAction::ReadDir => "db-error-io-read-dir",
                    IoAction::Decompress => "db-error-io-decompress",
                };
                Message::new(id).arg("path", path.display().to_string())
            }
            Self::LimitExceeded { path, limit, max } => Message::new("db-error-limit-exceeded")
                .arg("path", path.display().to_string())
                .arg("limit", limit.message())
                .arg("max", *max),
            Self::Untrusted { path, distrust } => Message::new("db-error-untrusted")
                .arg("path", path.display().to_string())
                .arg("distrust", distrust.message()),
            Self::NotARegularFile { path } => {
                Message::new("db-error-not-a-regular-file").arg("path", path.display().to_string())
            }
            Self::NotUtf8 { path, .. } => {
                Message::new("db-error-not-utf8").arg("path", path.display().to_string())
            }
            Self::SchemaVersion(error) => error.message(),
            Self::TooManyEntries { path, max } => Message::new("db-error-too-many-entries")
                .arg("path", path.display().to_string())
                .arg("max", *max),
            Self::TooManyRelations { path, max } => Message::new("db-error-too-many-relations")
                .arg("path", path.display().to_string())
                .arg("max", *max),
            Self::TooManyPaths { path, max } => Message::new("db-error-too-many-paths")
                .arg("path", path.display().to_string())
                .arg("max", *max),
            Self::TooManyEntryPaths { path, entry, max } => {
                Message::new("db-error-too-many-entry-paths")
                    .arg("path", path.display().to_string())
                    .arg("entry", entry.as_str())
                    .arg("max", *max)
            }
            Self::TooManySolvables { max } => {
                Message::new("db-error-too-many-solvables").arg("max", *max)
            }
            Self::TooManyClauses { max } => {
                Message::new("db-error-too-many-clauses").arg("max", *max)
            }
            Self::SolveBudgetExhausted { max } => {
                Message::new("db-error-solve-budget-exhausted").arg("max", *max)
            }
            Self::SolveInconsistent { clause } => {
                Message::new("db-error-solve-inconsistent").arg("clause", clause.to_string())
            }
            Self::PlanLocalDescUnreadable { name, .. } => {
                Message::new("db-error-plan-local-desc").arg("name", name.to_string())
            }
            Self::UpdateLocalDescUnreadable { name, .. } => {
                Message::new("db-error-update-local-desc").arg("name", name.to_string())
            }
            Self::PlanRepoDependsUnreadable { name, .. } => {
                Message::new("db-error-plan-repo-depends").arg("name", name.to_string())
            }
            Self::DescFields { path, .. } => {
                Message::new("db-error-desc-fields").arg("path", path.display().to_string())
            }
            Self::RepoDescFields { package, .. } => {
                Message::new("db-error-repo-desc-fields").arg("package", package.to_string())
            }
            Self::Files { path, .. } | Self::Mtree { path, .. } => {
                Message::new("db-error-parse").arg("path", path.display().to_string())
            }
            Self::InvalidVerifyRoot { path, .. } => {
                Message::new("db-error-invalid-verify-root").arg("path", path.display().to_string())
            }
            Self::UnsafeMtreePath { mtree, entry } => Message::new("db-error-unsafe-mtree-path")
                .arg("mtree", mtree.display().to_string())
                .arg("entry", entry.display().to_string()),
            Self::UnrecognisedArchiveName { path } => {
                Message::new("db-error-archive-name").arg("path", path.display().to_string())
            }
            // The refusal is the caller's own error. It is quoted as it renders: this crate
            // cannot know its type.
            Self::ArchiveRefused { source } => {
                Message::new("db-error-quoted").arg("text", source.to_string())
            }
            Self::UnsupportedCompression { path, format } => {
                Message::new("db-error-unsupported-compression")
                    .arg("path", path.display().to_string())
                    .arg("format", format.message())
            }
            Self::FilesUnavailable { repo } => {
                Message::new("db-error-files-unavailable").arg("repo", repo.to_string())
            }
            Self::RepoDescUnparsable { entry, .. } => {
                Message::new("db-error-repo-desc-unparsable").arg("entry", entry.as_str())
            }
            Self::FilesMissingForPackage { name } => {
                Message::new("db-error-files-missing").arg("name", name.to_string())
            }
            Self::FilesVersionSkew { name, db_version, files_version } => {
                Message::new("db-error-files-version-skew")
                    .arg("name", name.to_string())
                    .arg("db_version", db_version.to_string())
                    .arg("files_version", files_version.to_string())
            }
            Self::ForeignPackage { name } => {
                Message::new("db-error-foreign-package").arg("name", name.to_string())
            }
            Self::ConfigDirectiveOutsideSection { path, line } => {
                Message::new("db-error-config-outside-section")
                    .arg("path", path.display().to_string())
                    .arg("line", line.to_string())
            }
            Self::ConfigInvalidDirective { path, line, directive, value, reason } => {
                Message::new("db-error-config-invalid-value")
                    .arg("path", path.display().to_string())
                    .arg("line", line.to_string())
                    .arg("directive", directive.as_str())
                    .arg("value", value.as_str())
                    .arg("reason", reason.as_str())
            }
            Self::ConfigPathUnresolved { path, line, directive, value, source } => {
                Message::new("db-error-config-path-unresolved")
                    .arg("path", path.display().to_string())
                    .arg("line", line.to_string())
                    .arg("directive", directive.as_str())
                    .arg("value", value.as_str())
                    .arg("reason", source.to_string())
            }
            Self::ConfigIncludeDepthExceeded { path, line } => {
                Message::new("db-error-config-include-depth")
                    .arg("path", path.display().to_string())
                    .arg("line", line.to_string())
            }
            Self::ConfigInvalidRepoName { path, line, name, .. } => {
                Message::new("db-error-config-invalid-repo-name")
                    .arg("path", path.display().to_string())
                    .arg("line", line.to_string())
                    .arg("name", name.as_str())
            }
        }
    }
}

impl Localize for Limit {
    fn message(&self) -> Message {
        Message::new(match self {
            Self::Desc => "db-limit-desc",
            Self::Files => "db-limit-files",
            Self::MtreeCompressed => "db-limit-mtree-compressed",
            Self::MtreeInflated => "db-limit-mtree-inflated",
            Self::SchemaVersion => "db-limit-schema-version",
            Self::RepoCompressed => "db-limit-repo-compressed",
            Self::RepoInflated => "db-limit-repo-inflated",
            Self::RepoEntry => "db-limit-repo-entry",
            Self::RepoExtension => "db-limit-repo-extension",
            Self::PacmanConf => "db-limit-pacman-conf",
            Self::Hook => "db-limit-hook",
            Self::MountTable => "db-limit-mount-table",
            Self::Journal => "db-limit-journal",
            Self::KeyringList => "db-limit-keyring-list",
            Self::TimeZone => "db-limit-time-zone",
        })
    }
}

impl Localize for Distrust {
    fn message(&self) -> Message {
        match self {
            Self::ForeignOwner { uid } => {
                Message::new("db-distrust-foreign-owner").arg("uid", uid.to_string())
            }
            Self::GroupOrOtherWritable { mode } => {
                Message::new("db-distrust-writable").arg("mode", format!("{mode:04o}"))
            }
        }
    }
}

impl Localize for Unsupported {
    fn message(&self) -> Message {
        Message::new(match self {
            Self::Xz => "db-compression-xz",
            Self::Bzip2 => "db-compression-bzip2",
            Self::Compress => "db-compression-compress",
            Self::Lrzip => "db-compression-lrzip",
            Self::Lz4 => "db-compression-lz4",
            Self::Lzip => "db-compression-lzip",
            Self::Lzop => "db-compression-lzop",
            Self::Unrecognized => "db-compression-unrecognized",
        })
    }
}

impl Localize for SchemaVersionError {
    fn message(&self) -> Message {
        match self {
            Self::Missing { path } => Message::new("db-schema-missing").arg("path", path.as_str()),
            Self::Malformed { contents } => {
                Message::new("db-schema-malformed").arg("contents", format!("{contents:?}"))
            }
            Self::Unsupported { found, expected } => Message::new("db-schema-unsupported")
                .arg("found", found.to_string())
                .arg("expected", expected.to_string()),
        }
    }
}

impl Localize for RepoNameError {
    fn message(&self) -> Message {
        match self {
            Self::Empty => Message::new("db-repo-name-empty"),
            Self::DisallowedCharacter { name, found } => Message::new("db-repo-name-disallowed")
                .arg("name", format!("{name:?}"))
                .arg("found", format!("{found:?}")),
            Self::LeadingDash { name } => {
                Message::new("db-repo-name-leading-dash").arg("name", format!("{name:?}"))
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use alpm_types::{FullVersion, Name};
    use piko_i18n::{Catalog, Language, Placeables};

    use super::*;
    use crate::eager::DescFieldError;
    use crate::meta::files::FilesError;
    use crate::repo::RepoName;

    fn path() -> PathBuf {
        PathBuf::from("/var/lib/pacman/local/foo-1-1/desc")
    }

    fn name() -> Name {
        "foo".parse().unwrap()
    }

    fn io_error() -> std::io::Error {
        std::io::Error::from(std::io::ErrorKind::NotFound)
    }

    fn desc_field() -> Box<DescFieldError> {
        Box::new(DescFieldError::MissingSection { section: "NAME" })
    }

    fn shared() -> crate::error::SharedError {
        Arc::new(Error::NotARegularFile { path: path() })
    }

    /// One value of every variant of [`Error`], with arguments distinct from each other, so a
    /// message that swaps two variables renders differently from `Display`.
    fn every_error() -> Vec<Error> {
        let actions = [
            IoAction::Open,
            IoAction::Read,
            IoAction::Metadata,
            IoAction::ReadDir,
            IoAction::Decompress,
        ];
        let mut errors: Vec<Error> = actions
            .into_iter()
            .map(|action| Error::Io { path: path(), action, source: io_error() })
            .collect();
        errors.extend([
            Error::LimitExceeded { path: path(), limit: Limit::Desc, max: 1024 },
            Error::Untrusted { path: path(), distrust: Distrust::ForeignOwner { uid: 1000 } },
            Error::Untrusted {
                path: path(),
                distrust: Distrust::GroupOrOtherWritable { mode: 0o666 },
            },
            Error::NotARegularFile { path: path() },
            Error::NotUtf8 {
                path: path(),
                source: String::from_utf8(vec![0xff]).unwrap_err().utf8_error(),
            },
            Error::SchemaVersion(SchemaVersionError::Missing { path: "/db".to_owned() }),
            Error::SchemaVersion(SchemaVersionError::Malformed { contents: "x\n".to_owned() }),
            Error::SchemaVersion(SchemaVersionError::Unsupported { found: 8, expected: 9 }),
            Error::TooManyEntries { path: path(), max: 3 },
            Error::TooManyRelations { path: path(), max: 3 },
            Error::TooManyPaths { path: path(), max: 3 },
            Error::TooManyEntryPaths { path: path(), entry: "foo-1-1".to_owned(), max: 3 },
            Error::TooManySolvables { max: 3 },
            Error::TooManyClauses { max: 3 },
            Error::SolveBudgetExhausted { max: 3 },
            Error::SolveInconsistent { clause: 12_345 },
            Error::PlanLocalDescUnreadable { name: name(), source: shared() },
            Error::UpdateLocalDescUnreadable { name: name(), source: shared() },
            Error::PlanRepoDependsUnreadable { name: name(), source: shared() },
            Error::DescFields { path: path(), source: desc_field() },
            Error::RepoDescFields { package: name(), source: desc_field() },
            Error::Files {
                path: path(),
                source: FilesError::UnknownSection { keyword: "X".to_owned(), line: 2 },
            },
            Error::Mtree {
                path: path(),
                source: alpm_mtree::Error::AlpmCommon(alpm_common::Error::NotADirectory {
                    path: path(),
                }),
            },
            Error::InvalidVerifyRoot {
                path: path(),
                source: alpm_common::Error::NotADirectory { path: path() },
            },
            Error::UnsafeMtreePath { mtree: path(), entry: PathBuf::from("../etc/shadow") },
            Error::UnrecognisedArchiveName { path: path() },
            Error::ArchiveRefused { source: "the signature is invalid".into() },
            Error::UnsupportedCompression { path: path(), format: Unsupported::Xz },
            Error::FilesUnavailable { repo: RepoName::parse("core").unwrap() },
            Error::RepoDescUnparsable { entry: "foo-1-1".to_owned(), source: desc_field() },
            Error::FilesMissingForPackage { name: name() },
            Error::FilesVersionSkew {
                name: name(),
                db_version: Box::new("1.0-1".parse::<FullVersion>().unwrap()),
                files_version: Box::new("2.0-1".parse::<FullVersion>().unwrap()),
            },
            Error::ForeignPackage { name: name() },
            Error::ConfigDirectiveOutsideSection { path: path(), line: 7 },
            Error::ConfigInvalidDirective {
                path: path(),
                line: 7,
                directive: "SigLevel".to_owned(),
                value: "Sometimes".to_owned(),
                reason: "unknown option".to_owned(),
            },
            Error::ConfigPathUnresolved {
                path: path(),
                line: 7,
                directive: "RootDir".to_owned(),
                value: "/nowhere".to_owned(),
                source: io_error(),
            },
            Error::ConfigIncludeDepthExceeded { path: path(), line: 7 },
            Error::ConfigInvalidRepoName {
                path: path(),
                line: 7,
                name: "a/b".to_owned(),
                source: RepoNameError::Empty,
            },
        ]);
        // A match with no wildcard arm: a new variant fails to compile here until it has a
        // sample above.
        for error in &errors {
            match error {
                Error::Io { .. }
                | Error::LimitExceeded { .. }
                | Error::Untrusted { .. }
                | Error::NotARegularFile { .. }
                | Error::NotUtf8 { .. }
                | Error::SchemaVersion(_)
                | Error::TooManyEntries { .. }
                | Error::TooManyRelations { .. }
                | Error::TooManyPaths { .. }
                | Error::TooManyEntryPaths { .. }
                | Error::TooManySolvables { .. }
                | Error::TooManyClauses { .. }
                | Error::SolveBudgetExhausted { .. }
                | Error::SolveInconsistent { .. }
                | Error::PlanLocalDescUnreadable { .. }
                | Error::UpdateLocalDescUnreadable { .. }
                | Error::PlanRepoDependsUnreadable { .. }
                | Error::DescFields { .. }
                | Error::RepoDescFields { .. }
                | Error::Files { .. }
                | Error::Mtree { .. }
                | Error::InvalidVerifyRoot { .. }
                | Error::UnsafeMtreePath { .. }
                | Error::UnrecognisedArchiveName { .. }
                | Error::ArchiveRefused { .. }
                | Error::UnsupportedCompression { .. }
                | Error::FilesUnavailable { .. }
                | Error::RepoDescUnparsable { .. }
                | Error::FilesMissingForPackage { .. }
                | Error::FilesVersionSkew { .. }
                | Error::ForeignPackage { .. }
                | Error::ConfigDirectiveOutsideSection { .. }
                | Error::ConfigInvalidDirective { .. }
                | Error::ConfigPathUnresolved { .. }
                | Error::ConfigIncludeDepthExceeded { .. }
                | Error::ConfigInvalidRepoName { .. } => {}
            }
        }
        errors
    }

    /// Every value whose message is a word or a sentence of its own.
    fn every_part() -> Vec<(String, Message)> {
        let limits = [
            Limit::Desc,
            Limit::Files,
            Limit::MtreeCompressed,
            Limit::MtreeInflated,
            Limit::SchemaVersion,
            Limit::RepoCompressed,
            Limit::RepoInflated,
            Limit::RepoEntry,
            Limit::RepoExtension,
            Limit::PacmanConf,
            Limit::Hook,
            Limit::MountTable,
            Limit::Journal,
            Limit::KeyringList,
            Limit::TimeZone,
        ];
        let formats = [
            Unsupported::Xz,
            Unsupported::Bzip2,
            Unsupported::Compress,
            Unsupported::Lrzip,
            Unsupported::Lz4,
            Unsupported::Lzip,
            Unsupported::Lzop,
            Unsupported::Unrecognized,
        ];
        let names = [
            RepoNameError::Empty,
            RepoNameError::DisallowedCharacter { name: "a/b".to_owned(), found: '/' },
            RepoNameError::LeadingDash { name: "-core".to_owned() },
        ];
        let mut all: Vec<(String, Message)> =
            limits.iter().map(|each| (each.to_string(), each.message())).collect();
        all.extend(formats.iter().map(|each| (each.to_string(), each.message())));
        all.extend(names.iter().map(|each| (each.to_string(), each.message())));
        all.extend(every_error().iter().map(|each| (each.to_string(), each.message())));
        all
    }

    #[test]
    fn the_english_catalog_renders_each_error_as_display_does() {
        let catalog = Catalog::new(Language::English, Placeables::Plain);
        for (display, message) in every_part() {
            assert_eq!(catalog.try_format(&message).as_deref(), Ok(display.as_str()));
        }
    }

    #[test]
    fn every_language_renders_each_error() {
        for language in Language::ALL {
            let catalog = Catalog::new(*language, Placeables::Plain);
            for (_, message) in every_part() {
                let rendered = catalog.try_format(&message);
                assert!(rendered.is_ok(), "{language:?}: {rendered:?}");
            }
        }
    }
}
