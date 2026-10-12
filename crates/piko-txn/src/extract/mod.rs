//! Extracts a package into an installation root.
//!
//! This module splits deliberately into a part that decides and a part that acts:
//!
//! - `decision` is pure. Every rule libalpm applies per entry is a function from values to
//!   values. That covers the six-case filesystem/package matrix, `NoExtract`, `NoUpgrade`,
//!   and the three-way backup comparison. All of it can be enumerated in tests without a
//!   filesystem, an archive, or a package.
//! - The writing half acts on those decisions through [`crate::rootfs`], so that no decision
//!   can be applied outside the root.
//!
//! libalpm interleaves the two in `extract_single_file` (`add.c:191`). That is why its
//! carefully written matrix comment is hard to check against its implementation.

pub(crate) mod apply;
pub(crate) mod archive;
pub(crate) mod backup;
pub(crate) mod decision;

pub use apply::{Ownership, apply};

pub use apply::{Applied, XattrProblem};

pub use apply::XattrRefusal;

pub use archive::{Link, Member, MemberKind, PackageLimits, walk};
pub use archive::{LinkKind, Xattr};
pub use backup::Resolution;
pub use backup::{BackupOutcome, resolve};
pub use decision::Existing;
#[doc(hidden)]
pub use decision::resolve_backup;
pub use decision::{BackupAction, EntryContext, PacnewReason, RefuseReason, SkipReason};
pub use decision::{Disposition, EntryKind, decide};
