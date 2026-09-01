//! Extracts a package into an installation root.
//!
//! This module splits deliberately into a part that decides and a part that acts:
//!
//! - [`decision`] is pure. Every rule libalpm applies per entry — the six-case
//!   filesystem/package matrix, `NoExtract`, `NoUpgrade`, and the three-way backup
//!   comparison — is a function from values to values. All of it can be enumerated in
//!   tests without a filesystem, an archive, or a package.
//! - The writing half acts on those decisions through [`crate::rootfs`], so that no decision
//!   can be applied outside the root.
//!
//! libalpm interleaves the two in `extract_single_file` (`add.c:191`). That is why its
//! carefully written matrix comment is hard to check against its implementation.

pub mod apply;
pub mod archive;
pub mod backup;
pub mod decision;

pub use apply::{Applied, Ownership, apply};
pub use archive::{Member, MemberKind, PackageLimits, walk};
pub use backup::{BackupOutcome, Resolution};
pub use decision::{
    BackupAction, Disposition, EntryContext, EntryKind, Existing, PacnewReason, RefuseReason,
    SkipReason, decide, resolve_backup,
};
