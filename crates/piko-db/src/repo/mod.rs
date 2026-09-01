//! Repository (sync) database reading — the `alpm-repo-db` format.
//!
//! A repository database is a compressed tar archive, one per repository (`core.db`,
//! `extra.db`, …). Each holds a `<name>-<version>/desc` entry per package. The
//! _default with files_ variant also holds a sibling `<name>-<version>/files` entry. See
//! [alpm-repo-db].
//!
//! Unlike the local database, a repository archive has no random access: gzip-over-tar must
//! be walked front to back. [`RepoDatabase::open_repo`] therefore prefers the smaller
//! `<repo>.db` archive and defers file lists to `<repo>.files`. It loads that archive in full
//! only when [`RepoPackage::file_list`] is actually called — the requirement this module
//! exists to satisfy. See [`files_arena`] for why that deferred load is keyed by name and
//! version rather than by position.
//!
//! [alpm-repo-db]: https://alpm.archlinux.page/specifications/alpm-repo-db.7.html

#[cfg_attr(test, allow(unreachable_pub))]
pub(crate) mod archive;
mod desc_compat;
mod eager;
mod files_arena;
mod package;
mod repo_name;
mod search;

pub mod database;

pub use crate::eager::DescFieldError;
pub use crate::search::MatchKind;
pub use database::{FileListEntry, RepoDatabase, RepoDiagnostic, RepoOpenOptions, Variant};
pub use desc_compat::RepoDescView;
pub use package::RepoPackage;
pub use repo_name::{RepoName, RepoNameError};
pub use search::SearchHit;
