//! Local database reading — the installed-package database at `<dbpath>/local`.
//!
//! One directory per installed package, named `<name>-<version>`, holding `desc`, `files`
//! and usually a gzipped `mtree`. See [alpm-db].
//!
//! Unlike a repository archive, the local database supports random access. Each entry is a
//! directory, so [`LocalDatabase::open`] learns the whole package set from `readdir` alone
//! and reads no file at all. This is what makes the lazy loading in [`LocalPackage`] worthwhile.
//! `piko list` never opens a `desc`. `piko files` opens only the `files` of the packages it
//! is asked about.
//!
//! # What is *not* here
//!
//! Three things this database uses are shared with [`crate::repo`] and therefore live one
//! level up, not in this module:
//!
//! - [`EntryName`](crate::entry_name::EntryName) — both formats name things
//!   `<name>-<version>`, and the repository reader parses archive members with it.
//! - [`crate::desc_compat`] — the unknown-section policy. Only the *view* over a parsed local
//!   `desc` is local, and that is [`desc::DescView`].
//! - [`MatchKind`](crate::search::MatchKind) — so a search ranks hits identically whichever
//!   database answered.
//!
//! Keeping them shared rather than duplicating them is deliberate. The repository module is
//! organised the same way for the same reason.
//!
//! [alpm-db]: https://alpm.archlinux.page/specifications/alpm-db.7.html

pub(crate) mod database;
pub(crate) mod desc;
pub(crate) mod package;
pub(crate) mod schema_version;
pub(crate) mod search;
pub(crate) mod verify;

pub use database::{LocalDatabase, OpenOptions};

pub use database::Diagnostic;
pub use desc::DescView;
pub use package::LocalPackage;
pub use package::{EagerView, Inconsistency};
pub use schema_version::SchemaVersionError;
pub use schema_version::{
    ALPM_DB_VERSION, ALPM_DB_VERSION_FILE, check_schema_version, root_is_unpopulated,
};
pub use verify::FileCheckReport;
pub use verify::FileProblem;
