//! The commit engine. It turns a planned transaction into a changed system.
//!
//! This is the only crate in the workspace that can modify a machine. Every other one reads,
//! decides, or writes where its caller pointed it. A [`Transaction`] is handed a root and a
//! `dbpath` and applies a whole [`solve::Plan`](piko_db::solve::Plan)'s worth of work to them:
//! extraction, file-conflict detection, `.pacnew`/`.pacsave` resolution, scriptlets, hooks, the
//! local-database write, and the two history records.
//!
//! # The order is the safety property
//!
//! [`transaction`] is a typestate. Each step consumes the previous value, so the sequence is
//! not something a caller can get wrong at run time:
//!
//! ```text
//! Transaction<Planned> --verify--> Transaction<Verified> --stage--> Transaction<Staged> --commit--> Report
//! ```
//!
//! Every state is a point where something is guaranteed, and the guarantees are what make the
//! ordering worth enforcing:
//!
//! - **`Planned`** — the steps are known. Nothing has been read or written.
//! - **`Verified`** — every package is located *and read*, every `.PKGINFO` parses, every entry
//!   to be removed exists, and no step would write a file another package owns. All of this
//!   happens before anything is written, never part-way through a commit.
//! - **`Staged`** — the `db.lck` lock is held and the journal is on disk and fsynced. This is
//!   the last state in which dropping the transaction leaves the system untouched.
//! - committing consumes `Staged` and mutates.
//!
//! libalpm enforces the same sequence with a runtime `ASSERT` on `trans->state`, returning
//! `ALPM_ERR_TRANS_NOT_INITIALIZED` when a caller gets it wrong (`trans.c`). Here it does not
//! compile.
//!
//! # Design
//!
//! - **A pure decision, separately from the write that applies it.** [`extract::decision`],
//!   [`conflict::decision`] and [`hook::trigger`] are functions over values. That is what makes
//!   libalpm's per-entry rules reviewable and testable without a root to write into.
//! - **Nothing verifies twice, and nothing verifies in two places.** Signature checking lives
//!   in [`Transaction::verify`], reached through a [`PackageSource`] — a package named on the
//!   command line takes exactly the route a downloaded one does. libalpm instead validates in
//!   `alpm_pkg_load` and then skips `check_validity` four times over.
//! - **A path is resolved inside the root, never against the host.** [`rootfs`] opens each
//!   component with `openat`, so a symlink planted in the root cannot redirect a write outside
//!   it. [`UnsafePath`] is what a refusal looks like.
//! - **Destructive behavior is opt-in.** Scriptlets, hooks and history recording are all off in
//!   [`Transaction::new`], because running vendor shell code with piko's privileges is the
//!   CLI's decision to make, not a library default.
//! - **An interruption is detectable.** [`journal`] records intent before each step and
//!   completion after it. It does not make the step reversible — see the crate's known gaps.
//! - **Diagnostics are returned, never logged**, as everywhere else in the workspace. A failed
//!   scriptlet, an unreadable hook file and a `pacman.log` that cannot be written all come back
//!   on [`Report`] rather than failing the transaction or printing anything.
//!
//! # Nothing here writes to a real system in tests
//!
//! Every test writes into a `tempfile::TempDir`. The real cache and the real database stay
//! read-only inputs.
//!
//! # Example
//!
//! Installing one package file that already sits in a cache directory. `verify` reads it and
//! checks it against the rest of the system; `stage` takes the database lock; only `commit`
//! writes.
//!
//! ```rust,no_run
//! use std::path::{Path, PathBuf};
//!
//! use piko_txn::{CacheDirSource, Step, Transaction};
//! use piko_db_write::DbLock;
//! use alpm_types::{PackageFileName, PackageInstallReason};
//!
//! let root = Path::new("/");
//! let dbpath = Path::new("/var/lib/pacman");
//!
//! let steps = vec![Step::Install {
//!     package: "tree-2.2.1-1-x86_64.pkg.tar.zst".parse::<PackageFileName>()?,
//!     reason: PackageInstallReason::Explicit,
//! }];
//!
//! let source = CacheDirSource::new([PathBuf::from("/var/cache/pacman/pkg")])?;
//!
//! // Reads every package and runs file-conflict detection. Nothing is written yet.
//! let verified = Transaction::new(root, dbpath, steps).verify(&source)?;
//!
//! // Takes `db.lck` and fsyncs the journal. Dropping here still changes nothing.
//! let lock = DbLock::acquire(dbpath)?;
//! let report = verified.stage(&lock)?.commit()?;
//!
//! for (package, extraction) in &report.installed {
//!     println!("{package}: {} files", extraction.owned.len());
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod conflict;
pub mod error;
pub mod exec;
pub mod extract;
pub mod file_target;
pub mod hash;
pub mod history;
pub mod hook;
pub mod install;
pub mod journal;
pub mod pkginfo;
pub mod plan;
pub mod progress;
pub mod record;
pub mod remove;
pub mod rootfs;
pub mod scriptlet;
pub mod source;
pub mod target;
pub mod transaction;

pub use conflict::{Blocker, Check, FileConflict, filelist::FileList};
pub use error::{Error, Result};
pub use extract::{BackupAction, Disposition, EntryContext};
pub use file_target::FileTarget;
pub use history::{Action, LocalOffset, Recording};
pub use install::{Extraction, Filters, install};
pub use plan::{
    DownloadOnlyOutcome, download_only, download_targets, install_steps, verification_from,
};
pub use remove::{RemovalContext, RemovalDisposition, decide_removal, pacsave_rotation};
pub use rootfs::{Resolved, RootDir, UnsafePath};
pub use source::{
    CacheDirSource, DownloadDir, DownloadTarget, DownloadingSource, FileSource, Location,
    PackageSource, RejectedCacheDir, RejectionReason, Skipped, select_download_dir,
};
pub use target::{TargetKind, classify};
pub use transaction::{Patterns, Report, Step, Transaction};
