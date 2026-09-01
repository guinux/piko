//! Readers for the local and repository [ALPM] databases, and the transaction planner that
//! reasons over both.
//!
//! ALPM based systems (Arch Linux and derivatives) track installed packages in a **local
//! database** (a directory tree, usually `/var/lib/pacman/local`) and track available
//! packages in one **repository database** per configured repository (a compressed archive,
//! such as `core.db`). [`local`] reads the former, [`repo`] reads the latest. [`solve`] turns
//! a request ("install `foo`", "remove `bar`", sysupgrade) into a [`solve::Plan`] against both
//! at once.
//!
//! [ALPM]: https://alpm.archlinux.page/specifications/
//!
//! # Design
//!
//! - **Directory names are the source of truth** for the local database, matching pacman. A
//!   single `read_dir` call yields every installed package's name and version; no file needs
//!   to open for that alone. See [`entry_name`].
//! - **Metadata files are lazy-loaded and their failures are cached**, never silently emptied.
//!   `desc`, `files`, and `mtree` load on first access. A package with a corrupt `desc` keeps
//!   reporting that error on every later access, rather than looking like a package with no
//!   dependencies. See [`Lazy`].
//! - **Every disk read is bounded** by a configurable [`Limits`], including archive member
//!   counts and decompressed sizes. Anything that is not a regular file (a FIFO, a device
//!   node, a symlink pointing outside the entry) is rejected rather than opened. See
//!   [`fs_util`].
//! - **`LocalDatabase`/`LocalPackage` and `RepoDatabase`/`RepoPackage` are `Send + Sync`.**
//!   Reads after construction need no lock.
//! - **Scan problems are data, not log lines.** This crate calls no `log`/`tracing` macro.
//!   Diagnostics ([`local::Diagnostic`], [`repo::RepoDiagnostic`]) and per-package problems
//!   ([`local::Inconsistency`]) accumulate in memory, bounded by
//!   [`Limits::max_diagnostics`], and the caller decides how to present them.
//! - **`unsafe` is forbidden workspace-wide.**
//!
//! # Example
//!
//! ```rust,no_run
//! use piko_db::LocalDatabase;
//!
//! let db = LocalDatabase::open("/var/lib/pacman/local")?;
//!
//! // Free: comes from the directory name alone.
//! for pkg in db.iter() {
//!     println!("{} {}", pkg.name(), pkg.version());
//! }
//!
//! // Lazy: reads and parses `desc` on this first call only.
//! if let Some(pkg) = db.iter().next() {
//!     let desc = pkg.desc()?;
//!     println!("{}", desc.description());
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

// The two database formats. Each is self-contained.
pub mod local;
pub mod repo;

// Vocabulary and machinery both of them share.
pub mod config;
pub mod desc_compat;
pub mod eager;
pub mod entry_name;
pub mod error;
pub mod fs_util;
pub mod lazy;
pub mod limits;
pub mod search;

// Answers that need both databases at once.
pub mod resolve;
pub mod solve;
pub mod updates;

mod depcmp;
mod diagnostics;

#[cfg(any(test, feature = "fixture"))]
pub mod fixture;

pub use desc_compat::{UnknownSection, UnknownSectionPolicy};
pub use eager::DescFieldError;
pub use entry_name::{EntryName, EntryNameError};
pub use error::{Error, IoAction, Result, SharedError};
pub use lazy::Lazy;
pub use limits::{Limit, Limits};
pub use local::{
    ALPM_DB_VERSION, DescView, Diagnostic, EagerView, FileCheckReport, FileProblem, Inconsistency,
    LocalDatabase, LocalPackage, LocalSearchHit, OpenOptions,
};
pub use resolve::{IgnoreList, Resolved, SyncRepo, SyncRepos};
pub use search::{LocalOrRepo, MatchKind, resolve_installed_or_repo};
pub use updates::Update;
