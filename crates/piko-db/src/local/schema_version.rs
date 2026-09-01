//! The `ALPM_DB_VERSION` schema version file.
//!
//! A local database records its format version in a top-level `ALPM_DB_VERSION` file
//! holding a single numeric line. Version `9` has been current since pacman 4.2.0 (2014).
//!
//! Like libalpm, piko requires an **exact** match. A database written by an older or a newer
//! implementation is refused rather than read on a guess. Unlike libalpm, piko never creates
//! the file — this layer is read-only. Fabricating a version marker for a database of
//! unknown actual layout would paper over corruption instead of reporting it.
//!
//! A missing file is still tolerated, not by this module but by [`super::database`], when
//! [`root_is_unpopulated`] says the directory is empty or absent — the same "nothing to
//! misread" boundary libalpm's own bootstrap uses. Creating the file on disk stays
//! `piko-db-write`'s job, the first time something actually gets written.

use std::path::Path;

use crate::{
    error::{Error, IoAction, Result},
    fs_util,
    limits::{Limit, Limits},
};

/// The `alpm-db` schema version this crate implements.
pub const ALPM_DB_VERSION: u32 = 9;

/// The name of the schema version file inside a database directory.
pub const ALPM_DB_VERSION_FILE: &str = "ALPM_DB_VERSION";

/// Why a database's schema version is unusable.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SchemaVersionError {
    /// The `ALPM_DB_VERSION` file does not exist.
    #[error("{path} does not contain an {ALPM_DB_VERSION_FILE} file")]
    Missing {
        /// The database directory that lacks the file.
        path: String,
    },

    /// The file exists but does not hold a bare number.
    #[error("{ALPM_DB_VERSION_FILE} contains {contents:?}, which is not a version number")]
    Malformed {
        /// The file's contents, truncated for display.
        contents: String,
    },

    /// The version is well-formed but not the one this crate implements.
    #[error(
        "database schema version is {found}, but piko implements version {expected}; \
         run pacman-db-upgrade or use a matching piko release"
    )]
    Unsupported {
        /// The version found on disk.
        found: u32,
        /// The version this crate implements.
        expected: u32,
    },
}

/// Reads and validates `<root>/ALPM_DB_VERSION`.
///
/// # Errors
///
/// - [`Error::SchemaVersion`] if the file is missing, malformed, or holds a version other
///   than [`ALPM_DB_VERSION`].
/// - [`Error::Io`] or [`Error::LimitExceeded`] if the file cannot be read.
pub fn check(root: &Path, limits: &Limits) -> Result<u32> {
    let path = fs_util::join(root, ALPM_DB_VERSION_FILE);

    if !fs_util::exists_no_follow(&path) {
        return Err(SchemaVersionError::Missing { path: root.display().to_string() }.into());
    }

    let contents =
        fs_util::read_capped_utf8(&path, Limit::SchemaVersion, limits.get(Limit::SchemaVersion))?;

    parse(&contents).map_err(Error::from)
}

/// Parses the contents of an `ALPM_DB_VERSION` file.
///
/// libalpm reads this with `fscanf("%zu")`, which skips leading whitespace and ignores
/// whatever follows the digits. So libalpm accepts `"9 lol"`. piko requires the whole file,
/// once trimmed, to be the number — trailing content after a version marker is not
/// tolerated.
fn parse(contents: &str) -> std::result::Result<u32, SchemaVersionError> {
    let trimmed = contents.trim();
    let found = trimmed
        .parse::<u32>()
        .map_err(|_| SchemaVersionError::Malformed { contents: truncate(trimmed) })?;

    if found == ALPM_DB_VERSION {
        Ok(found)
    } else {
        Err(SchemaVersionError::Unsupported { found, expected: ALPM_DB_VERSION })
    }
}

/// Whether `root` is a database nobody has written into yet: it does not exist, or it exists
/// and is completely empty.
///
/// [`check`] cannot decide this on its own — telling "not yet created" from "corrupted" needs
/// a directory listing, which the success path has no reason to do. This mirrors libalpm's own
/// `local_db_validate` (`be_local.c:466`): its `readdir` loop bootstraps a fresh
/// `ALPM_DB_VERSION` only when the directory holds nothing else, and refuses otherwise. Any
/// entry at all — even one unrelated to the database format, like a stray file left by another
/// tool — disqualifies it there, and does here too.
///
/// # Errors
///
/// [`Error::Io`] if `root` exists but cannot be listed for a reason other than not existing.
pub fn root_is_unpopulated(root: &Path) -> Result<bool> {
    match std::fs::read_dir(root) {
        Ok(mut entries) => Ok(entries.next().is_none()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(source) => Err(Error::io(root, IoAction::ReadDir, source)),
    }
}

/// Shortens untrusted contents so a hostile file cannot flood an error message.
fn truncate(contents: &str) -> String {
    const MAX: usize = 32;
    match contents.char_indices().nth(MAX) {
        Some((index, _)) => {
            let head = contents.get(..index).unwrap_or_default();
            format!("{head}…")
        }
        None => contents.to_owned(),
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

    #[test]
    fn accepts_the_current_version() {
        assert_eq!(parse("9").unwrap(), 9);
        assert_eq!(parse("9\n").unwrap(), 9, "the real file ends with a newline");
        assert_eq!(parse("  9  \n").unwrap(), 9);
    }

    /// Both directions must fail. Reading a newer database on a guess is how a package
    /// manager corrupts a system it does not understand.
    #[test]
    fn refuses_other_versions() {
        for (contents, expected) in [("8", 8_u32), ("10", 10), ("0", 0)] {
            let err = parse(contents).unwrap_err();
            assert!(
                matches!(err, SchemaVersionError::Unsupported { found, .. } if found == expected),
                "{contents:?} gave {err:?}"
            );
        }
    }

    /// libalpm accepts `"9 lol"` because of how `fscanf` works. piko does not.
    #[test]
    fn refuses_malformed_contents() {
        for contents in ["", "nine", "9 lol", "9.0", "-9", "٩"] {
            assert!(
                matches!(parse(contents), Err(SchemaVersionError::Malformed { .. })),
                "{contents:?} should be malformed, got {:?}",
                parse(contents)
            );
        }
    }

    /// The file's contents are untrusted and end up in an error message.
    #[test]
    fn truncates_long_contents_in_error_messages() {
        let long = "x".repeat(10_000);
        let err = parse(&long).unwrap_err();
        assert!(err.to_string().len() < 200, "error message was not truncated");
    }

    #[test]
    fn truncate_is_char_boundary_safe() {
        let text = "é".repeat(100);
        assert!(truncate(&text).ends_with('…'));
    }

    #[test]
    fn check_reports_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let err = check(dir.path(), &Limits::default()).unwrap_err();
        assert!(
            matches!(err, Error::SchemaVersion(SchemaVersionError::Missing { .. })),
            "got {err:?}"
        );
    }

    #[test]
    fn check_reads_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(ALPM_DB_VERSION_FILE), "9\n").unwrap();
        assert_eq!(check(dir.path(), &Limits::default()).unwrap(), ALPM_DB_VERSION);
    }
}
