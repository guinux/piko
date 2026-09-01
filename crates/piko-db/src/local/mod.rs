//! Local database reading — the installed-package database at `<dbpath>/local`.
//!
//! One directory per installed package, named `<name>-<version>`, holding `desc`, `files`
//! and usually a gzipped `mtree`. See [alpm-db].
//!
//! Unlike a repository archive, the local database supports random access. Each entry is a
//! directory, so [`LocalDatabase::open`] learns the whole package set from `readdir` alone
//! and reads no file at all. This is what makes the lazy loading in [`package`] worthwhile.
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
//! - [`crate::desc_compat`] — the unknown-section filter and its policy. Only the *view* over
//!   a parsed local `desc` is local, and that is [`desc_compat::DescView`].
//! - [`MatchKind`](crate::search::MatchKind) — so a search ranks hits identically whichever
//!   database answered.
//!
//! Keeping them shared rather than duplicating them is deliberate. The repository module is
//! organised the same way for the same reason.
//!
//! [alpm-db]: https://alpm.archlinux.page/specifications/alpm-db.7.html

pub mod database;
pub mod desc_compat;
pub mod package;
pub mod schema_version;
pub mod search;
pub mod verify;

pub use database::{Diagnostic, LocalDatabase, OpenOptions};
pub use desc_compat::DescView;
pub use package::{EagerView, Inconsistency, LocalPackage};
pub use schema_version::{ALPM_DB_VERSION, ALPM_DB_VERSION_FILE, SchemaVersionError};
pub use search::LocalSearchHit;
pub use verify::{FileCheckReport, FileProblem};
