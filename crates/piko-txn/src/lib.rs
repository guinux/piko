//! The commit engine. It turns a planned transaction into a changed system.
//!
//! The pure `decision` halves stay separate from anything that writes. That is what makes
//! libalpm's per-entry rules reviewable — see [`extract::decision`], [`conflict::decision`],
//! and [`hook::trigger`].
//!
//! # Nothing here writes to a real system in tests
//!
//! Every test writes into a `tempfile::TempDir`. The real cache and the real database stay
//! read-only inputs, and that stays true as the destructive parts land.

pub mod conflict;
pub mod error;
pub mod exec;
pub mod extract;
pub mod hash;
pub mod hook;
pub mod install;
pub mod journal;
pub mod plan;
pub mod progress;
pub mod record;
pub mod remove;
pub mod rootfs;
pub mod scriptlet;
pub mod source;
pub mod transaction;

pub use conflict::{Blocker, Check, FileConflict, filelist::FileList};
pub use error::{Error, Result};
pub use extract::{BackupAction, Disposition, EntryContext};
pub use install::{Extraction, Filters, install};
pub use plan::{
    DownloadOnlyOutcome, download_only, download_targets, install_steps, verification_from,
};
pub use remove::{RemovalContext, RemovalDisposition, decide_removal, pacsave_rotation};
pub use rootfs::{Resolved, RootDir, UnsafePath};
pub use source::{
    CacheDirSource, DownloadDir, DownloadTarget, DownloadingSource, Location, PackageSource,
    RejectedCacheDir, RejectionReason, Skipped, select_download_dir,
};
pub use transaction::{Patterns, Report, Step, Transaction};
