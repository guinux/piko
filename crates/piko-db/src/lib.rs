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
//!   to open for that alone. See [`EntryName`].
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
//! # Feature flags
//!
//! - **`fixture`** *(off by default)* — exposes the `fixture` module, a builder for throwaway
//!   database trees in a `tempfile::TempDir`. Integration tests and downstream crates turn it
//!   on; nothing in a normal build needs it, and it pulls in `tempfile`. The module is absent
//!   from a default build, so this names it rather than linking it. It is a helper for this
//!   workspace's tests, and is not part of the stable interface.
//!
//! # Stability
//!
//! Each public item has one path. A domain module holds its items, and its submodules are
//! private. A submodule stays public when it is a domain of its own: one grammar
//! ([`meta::section`], [`meta::kv`], [`config::ini`]), one file ([`meta::files`]), or one
//! question ([`repo::freshness`]).
//!
//! An item hidden from this documentation is there for this workspace's tests. It is one step
//! of a pipeline that a public function already runs, and it is not part of the stable
//! interface.
//!
//! Three rules say which types a later release can extend without a breaking change:
//!
//! - **A result, a report, a diagnostic or a failure is `#[non_exhaustive]`.** A later release
//!   can add a variant or a field. Match it with a wildcard arm.
//! - **A decision, and a closed set, are exhaustive.** A new variant changes what every caller
//!   must do, so it must break the build of each caller. Examples: [`solve::Step`],
//!   [`repo::freshness::Comparison`], [`repo::Variant`].
//! - **An input struct is exhaustive, with public fields.** It has a `Default` when a default
//!   value means something, as for options and limits. Change one field with the struct
//!   update syntax, as in `Limits { max_entries: 8, ..Limits::default() }`. An added field
//!   keeps that expression valid.
//!
//! # Example
//!
//! ```rust,no_run
//! use piko_db::local::LocalDatabase;
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

// docs.rs sets this cfg (see `[package.metadata.docs.rs]`), and it is nightly-only. On any
// stable build the attribute expands to nothing, so this costs the MSRV nothing.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

// The two database formats. Each is self-contained.
pub mod local;
pub mod repo;

// Vocabulary and machinery both of them share.
pub mod comparable;
pub mod compression;
pub mod config;
pub mod desc_compat;
mod eager;
mod entry_name;
mod error;
pub mod fs_util;
pub mod glob;
pub mod groups;
mod lazy;
mod limits;
pub mod meta;
mod printable;
pub mod search;

// Answers that need both databases at once.
pub mod resolve;
pub mod solve;
pub mod updates;

mod depcmp;
mod diagnostics;

// A test helper for this workspace's own tests. It is not part of the stable interface.
#[cfg(any(test, feature = "fixture"))]
#[doc(hidden)]
pub mod fixture;

pub use eager::DescFieldError;
pub use entry_name::{EntryName, EntryNameError};
pub use error::SharedError;
pub use error::{Error, IoAction, Result};
pub use lazy::Lazy;
pub use limits::{Limit, Limits};
pub use printable::{excerpt, printable, printable_lines, printable_path};
