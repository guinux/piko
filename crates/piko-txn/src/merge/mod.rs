//! The `.pacnew` and `.pacsave` files a transaction leaves behind, and what to do with them.
//!
//! A transaction that meets an edited configuration file keeps both copies. The package's
//! version lands beside the user's as `<path>.pacnew` ([`crate::extract`]), or the user's is
//! kept as `<path>.pacsave` when the package goes away ([`crate::remove`]). Neither is the
//! final state. Someone has to look at the pair and decide.
//!
//! This module is the half of that job a front end must not re-derive. It finds the pending
//! files, says how each pair compares, picks the base for a three-way merge, names the
//! programs to run and the order of their arguments, and carries out the answer.
//!
//! # What stays outside
//!
//! Starting a program, holding a terminal, and asking a question are a front end's. So is the
//! temporary file a merge program writes into: this module hands back bytes.
//!
//! # pacman has no counterpart
//!
//! libalpm creates these files and reports them through `ALPM_EVENT_PACNEW_CREATED` and
//! `ALPM_EVENT_PACSAVE_CREATED`. It keeps nothing. The resolution lives in `pacdiff`, a shell
//! script shipped separately from pacman. That script recovers the list by scanning
//! `%BACKUP%`, then asks `pacman -Qoq` one file at a time for the owning package. The scan
//! here answers both questions at once, because it starts from the package rather than from
//! the file.
//!
//! # Paths
//!
//! Every path in this module is root-relative, the way `%BACKUP%` spells it (`etc/foo.conf`),
//! with no leading separator. That is the spelling [`crate::RootDir`] resolves, and the one a
//! package archive uses for the same file. A caller that displays one joins the root itself. A
//! caller never *acts* on a joined path: every write goes through a [`crate::Resolved`], so the
//! directory acted in is the object that was checked.

use std::path::PathBuf;

use alpm_types::{FullVersion, Name};

pub mod action;
pub mod base;
pub mod program;
pub mod scan;

pub use self::{
    action::{Action, Outcome, apply, remove_if_identical},
    base::{BaseCandidate, BaseLimits, extract_member, find_base},
    program::{
        DEFAULT_DIFFPROG, DEFAULT_MERGEPROG, Invocation, parse_program, review_diff,
        three_way_diff, three_way_merge, two_way_diff,
    },
    scan::{Scan, ScanLimits, scan},
};

/// The suffix a package manager gives the version it kept.
pub const PACNEW_SUFFIX: &str = ".pacnew";
/// The suffix a package manager gives the version the user had.
pub const PACSAVE_SUFFIX: &str = ".pacsave";

/// Which suffix a pending file carries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PendingKind {
    /// `<path>.pacnew`: what the package ships, beside what the user has.
    Pacnew,
    /// `<path>.pacsave`: what the user had, kept when the package stopped shipping it.
    Pacsave,
    /// `<path>.pacsave.N`: an older `.pacsave` that a later removal rotated out of the way.
    NumberedPacsave(u32),
}

impl PendingKind {
    /// The suffix, spelled as it is on disk.
    #[must_use]
    pub fn suffix(self) -> String {
        match self {
            Self::Pacnew => PACNEW_SUFFIX.to_owned(),
            Self::Pacsave => PACSAVE_SUFFIX.to_owned(),
            Self::NumberedPacsave(number) => format!("{PACSAVE_SUFFIX}.{number}"),
        }
    }

    /// The word that names this kind: `pacnew`, `pacsave`, `pacsave.2`.
    #[must_use]
    pub fn label(self) -> String {
        self.suffix().trim_start_matches('.').to_owned()
    }

    /// Whether a merge against this file means anything.
    ///
    /// A numbered `.pacsave` is a historical copy. The package that shipped its counterpart
    /// rotated it aside two versions ago, so there is no current version to merge it with.
    #[must_use]
    pub const fn is_mergeable(self) -> bool {
        matches!(self, Self::Pacnew | Self::Pacsave)
    }
}

/// How a pending file compares with the installed file it belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// The installed file is not there.
    TargetMissing,
    /// The two files hold the same bytes, so the pending one carries nothing.
    Identical,
    /// The two files differ, so a decision is needed.
    Differs,
    /// One of the two could not be read: a symlink, a device node, or over the cap.
    ///
    /// No destructive action is offered for this verdict. [`Problem::Uncomparable`] says which
    /// file and why. An unreadable pair is never reported as [`Verdict::Identical`], because
    /// that verdict deletes a file without asking.
    Unreadable,
}

/// One pending file, and what is known about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pending {
    /// The pending file itself, root-relative.
    pub pacfile: PathBuf,
    /// The installed file it belongs to, root-relative.
    pub target: PathBuf,
    /// Which suffix `pacfile` carries.
    pub kind: PendingKind,
    /// The installed package whose `%BACKUP%` declared `target`.
    pub package: Name,
    /// That package's installed version.
    ///
    /// This is the upper bound a three-way base sits below. See [`find_base`].
    pub installed_version: FullVersion,
    /// How the pair compares.
    pub verdict: Verdict,
}

/// Why one candidate could not be examined.
///
/// Returned rather than logged, as everywhere else in the workspace. A scan that met a problem
/// still returns everything it found.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Problem {
    /// A package's backup list could not be read, so none of its files were examined.
    #[error("{package}'s backup list cannot be read: {reason}")]
    UnreadableEntry {
        /// The package.
        package: String,
        /// What the database reader said.
        reason: String,
    },
    /// A pair exists but could not be compared.
    #[error("{} cannot be compared: {reason}", path.display())]
    Uncomparable {
        /// The pending file.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// A path did not resolve inside the root, so nothing was listed for it.
    #[error("{} cannot be resolved inside the root: {reason}", path.display())]
    OutsideRoot {
        /// The path, as `%BACKUP%` spells it.
        path: PathBuf,
        /// What the resolution said.
        reason: String,
    },
    /// A directory could not be listed, so its numbered `.pacsave` files were not found.
    ///
    /// The plain `.pacnew` and `.pacsave` files in that directory are still found. They are
    /// tested by name rather than by listing, so a directory too large to list does not hide
    /// the two kinds that can be merged.
    #[error("{} cannot be listed: {reason}", path.display())]
    UnlistableDirectory {
        /// The directory, root-relative.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// A `.pacsave.N` file carries a number piko will not act on.
    ///
    /// The number must fit in a `u32` and must render back to the same digits. `.pacsave.01`
    /// fails the second test: read as `1`, it would make a rotation rename `.pacsave.1` to
    /// `.pacsave.2` while leaving `.pacsave.01` in place, with two files claiming one rank.
    #[error("{} does not carry a usable .pacsave number", path.display())]
    UnusableNumber {
        /// The file, root-relative.
        path: PathBuf,
    },
}
