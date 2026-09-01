//! Writes the alpm-db local package database.
//!
//! This is a separate crate from `piko-db`, not a module inside it, so a reader cannot link a
//! writer. `piko list` and `piko why` have no legitimate need for [`LocalDbWriter`]. A crate
//! boundary turns that from a code-review question into a compile error. `piko-txn` already
//! applies the same rule one layer up.
//!
//! The dependency runs one way. This crate reads through `piko-db` for the `ALPM_DB_VERSION`
//! check, and for loading a `desc` to rewrite one section of it. `piko-db` never references
//! this crate. Those reads go through `piko_db::fs_util`, the audited door, instead of a
//! second path of this crate's own. A writer that reimplemented the symlink and size checks
//! would be exactly the unaudited second door that module exists to prevent.
//!
//! Two rules the reader does not need:
//!
//! 1. **A write is atomic or it did not happen.** Every file is written to a temporary
//!    sibling, fsynced, and renamed over its target, with the directory fsynced afterwards.
//!    libalpm uses a plain `fopen("w")` with no temporary file, no `rename`, no `fsync`, and
//!    does not check `fclose` (`be_local.c:988`). An interrupted pacman can leave a truncated
//!    `desc` that no longer parses. See [`LocalDbWriter`].
//!
//! 2. **A rewrite changes only what it was asked to change.** Round-tripping a `desc` through
//!    `alpm-db`'s parsed types loses information. Measured against the 1158 entries on the
//!    machine this was developed against, it rewrites 105 `%URL%` values, reorders
//!    `%REASON%`/`%GROUPS%` in 20 entries, and drops 3 `%BACKUP%` entries outright. The writer
//!    therefore keeps its own raw-preserving representation; see [`Record`].
//!
//! [`DbLock`] handles concurrency. It is byte-compatible with pacman's `db.lck`, not with any
//! better locking scheme. `docs/locking.md` explains why that constraint is not negotiable.

pub mod atomic;
pub mod error;
mod local;
mod lock;
mod record;

pub use atomic::AtomicFile;
pub use error::{Error, IoAction, Result};
pub use local::{EntryWrite, LocalDbWriter};
pub use lock::{DbLock, LOCK_FILE};
pub use record::{Record, RecordError, RecordKind, Section};
