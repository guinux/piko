//! Decides whether a path that already exists on the filesystem blocks an installation.
//!
//! This module answers CHECK 2 of `_alpm_db_find_fileconflicts` (`conflict.c:477-678`). For
//! every path a package is about to install that already exists, it decides whether something
//! legitimate explains it. libalpm sets a `resolved_conflict` flag from six places spread over
//! 180 lines. Three of those places also mutate transaction state and advance the loop cursor.
//!
//! Here the six explanations are an enum, and the answer is a pure function.
//! [`crate::extract::decision`] takes the same approach: rules this consequential need to be
//! readable side by side. libalpm folds two extra effects into the same code — adding to
//! `skip_remove`, and skipping ahead over a directory's contents. Those stay the driver's job,
//! not this function's. [`Resolution`] carries enough information for the driver to know when
//! they apply.
//!
//! # The asymmetry that matters
//!
//! A missed explanation costs a false conflict: piko refuses a transaction pacman would have
//! run, and the user is inconvenienced. A missed conflict costs a file that belonged to
//! another package. The rules below are transcribed completely rather than reduced to the
//! common cases. Anything this function cannot establish resolves to [`Verdict::Conflict`].

use crate::extract::decision::Existing;

/// Why an existing path turns out not to block the installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resolution {
    /// Nothing is at the path after all.
    NotPresent,
    /// The package ships a directory, and a directory is already there.
    ///
    /// This is the ordinary case: every package that installs into `usr/bin/` ships `usr/bin/`.
    DirectoryAlreadyThere,
    /// The installed version of this same package owns the path as a file, and the new
    /// version ships a directory there.
    ///
    /// `conflict.c:533`. The file belongs to this package, so replacing it with a directory
    /// is an upgrade, not a collision.
    FileBecomesDirectory,
    /// A package this transaction removes owns the path.
    ///
    /// `conflict.c:552`. The path will be gone before the new package needs the space.
    RemovedByTransaction,
    /// Another package in this transaction owns the path today and is giving it up.
    ///
    /// `conflict.c:575`. The file changes hands between two packages that are both being
    /// upgraded. The driver must add the path to `skip_remove`. Otherwise the outgoing
    /// package's removal deletes the file its new owner just installed.
    ChangesOwner {
        /// The package that owns it now.
        from: String,
    },
    /// Everything inside the directory belongs to packages this transaction removes.
    ///
    /// `conflict.c:613`. The directory will be empty by the time it is needed.
    DirectoryEmptiedByTransaction,
    /// The path is unowned, and the new package declares it a backup file.
    ///
    /// `conflict.c:645`. This is a configuration file the user created by hand before
    /// installing the package that manages it. libalpm adopts it rather than refusing, and
    /// the `.pacnew` machinery then protects its contents.
    AdoptedBackupFile,
    /// An `--overwrite` pattern matches the path.
    ///
    /// `conflict.c:661`. Never applies to a directory: `--overwrite` releases piko from
    /// protecting a file, and extraction refuses a directory in the way regardless.
    Overwritten,
}

/// Whether an existing path blocks the installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// It does, and the transaction must not proceed.
    Conflict,
    /// It does not, for this reason.
    Resolved(Resolution),
}

impl Verdict {
    /// Whether the path changes owner, and from which package.
    ///
    /// The driver uses this to build `skip_remove`. Nothing else needs to match on the
    /// resolution.
    #[must_use]
    pub fn changes_owner_from(&self) -> Option<&str> {
        match self {
            Self::Resolved(Resolution::ChangesOwner { from }) => Some(from),
            _ => None,
        }
    }

    /// Whether the driver should skip the entries nested under this path.
    ///
    /// libalpm advances its loop cursor past a directory's contents in three of the six
    /// branches (`conflict.c:542`, `:564`, `:602`), and only when the package ships the path
    /// as a directory. In each case, the reason the directory is acceptable also covers
    /// everything inside it. Checking those separately would report conflicts the resolution
    /// has already answered.
    #[must_use]
    pub const fn skips_directory_contents(&self) -> bool {
        matches!(
            self,
            Self::Resolved(
                Resolution::FileBecomesDirectory
                    | Resolution::RemovedByTransaction
                    | Resolution::ChangesOwner { .. }
            )
        )
    }
}

/// Everything the decision depends on.
///
/// Every field is a question the driver has already answered against the filesystem or the
/// local database. This lets the rules below read as plain rules.
#[derive(Clone, Debug)]
pub struct FilesystemContext<'a> {
    /// Whether the package ships this path as a directory (it ends in `/`).
    pub package_says_directory: bool,
    /// What is at the path now, from an `lstat` that follows nothing.
    pub existing: Existing,
    /// Whether the path is a directory once symlinks are followed.
    ///
    /// Distinct from `existing == Existing::Directory`, which is deliberately blind to a
    /// symlink. Both fields are needed. This one answers "is a directory already there",
    /// which a symlink to a directory satisfies. `existing` answers "what object is literally
    /// at this path", which decides whether extraction would destroy something.
    ///
    /// libalpm gets this for free, by accident. It stats the path with the trailing slash
    /// still on (`conflict.c:511`). A trailing slash makes `lstat` resolve the final symlink
    /// and fail with `ENOTDIR` unless the result is a directory. Measured on this machine:
    /// `lstat("d/regular/")` fails, and `lstat("symlink-to-dir/")` succeeds and reports a
    /// directory.
    pub resolves_to_directory: bool,
    /// Whether the installed version of this same package lists the path as a file.
    ///
    /// `None` when no version of the package is installed.
    pub old_version_owns_file: bool,
    /// Whether a package this transaction removes owns the path.
    pub owned_by_removal: bool,
    /// The other package in this transaction that owns the path today, if any.
    pub changing_owner_from: Option<&'a str>,
    /// For a directory: whether everything inside it belongs to packages that are going away.
    ///
    /// The driver computes this only when it has to, because answering it means walking the
    /// directory. It stands for libalpm's whole `conflict.c:613-642` block, including its
    /// precondition that the directory's owners are a subset of what is being removed.
    pub directory_emptied_by_transaction: bool,
    /// Whether the new package declares the path a backup file.
    pub new_is_backup: bool,
    /// Whether any installed package owns the path.
    pub owned_by_anyone: bool,
    /// Whether an `--overwrite` pattern matches the path.
    pub overwrite: bool,
}

/// Decides whether an existing path blocks the installation.
///
/// The order matches libalpm's and is observable. A path can satisfy several of these rules at
/// once, and which one is reported determines whether the driver skips ahead and whether it
/// records a `skip_remove`. Do not reorder them to read more nicely.
#[must_use]
pub fn decide(context: &FilesystemContext<'_>) -> Verdict {
    // libalpm reaches this code only after `llstat` succeeds (`conflict.c:515`).
    if context.existing == Existing::Absent {
        return Verdict::Resolved(Resolution::NotPresent);
    }

    if context.package_says_directory {
        // A symlink to a directory counts: the package wants a directory there and finds one.
        // This is where piko and libalpm agree by different means. See the field's
        // documentation above.
        if context.resolves_to_directory {
            return Verdict::Resolved(Resolution::DirectoryAlreadyThere);
        }
        // A directory landing where this same package used to keep a file. This check runs
        // before the removal and owner-change rules, which is why it sits inside this branch.
        if context.old_version_owns_file {
            return Verdict::Resolved(Resolution::FileBecomesDirectory);
        }
    }

    if context.owned_by_removal {
        return Verdict::Resolved(Resolution::RemovedByTransaction);
    }

    if let Some(from) = context.changing_owner_from {
        return Verdict::Resolved(Resolution::ChangesOwner { from: from.to_owned() });
    }

    if context.existing == Existing::Directory && context.directory_emptied_by_transaction {
        return Verdict::Resolved(Resolution::DirectoryEmptiedByTransaction);
    }

    if context.new_is_backup && !context.owned_by_anyone {
        return Verdict::Resolved(Resolution::AdoptedBackupFile);
    }

    // `--overwrite` is the last resort. It never applies to a directory on disk: libalpm
    // guards this branch with `!S_ISDIR(lsbuf.st_mode)` (`conflict.c:661`).
    if context.existing != Existing::Directory && context.overwrite {
        return Verdict::Resolved(Resolution::Overwritten);
    }

    Verdict::Conflict
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// A context in which nothing explains the path. Each test then states only its own rule.
    fn context(existing: Existing) -> FilesystemContext<'static> {
        FilesystemContext {
            package_says_directory: false,
            existing,
            resolves_to_directory: existing == Existing::Directory,
            old_version_owns_file: false,
            owned_by_removal: false,
            changing_owner_from: None,
            directory_emptied_by_transaction: false,
            new_is_backup: false,
            owned_by_anyone: false,
            overwrite: false,
        }
    }

    /// The default case, and the reason this check exists: an unowned file is in the way, and
    /// nothing explains it.
    #[test]
    fn an_unexplained_file_is_a_conflict() {
        assert_eq!(decide(&context(Existing::Other)), Verdict::Conflict);
    }

    #[test]
    fn an_absent_path_is_never_a_conflict() {
        let mut ctx = context(Existing::Absent);
        ctx.owned_by_anyone = true;
        assert_eq!(decide(&ctx), Verdict::Resolved(Resolution::NotPresent));
    }

    #[test]
    fn a_shared_directory_is_not_a_conflict() {
        let mut ctx = context(Existing::Directory);
        ctx.package_says_directory = true;
        assert_eq!(decide(&ctx), Verdict::Resolved(Resolution::DirectoryAlreadyThere));
    }

    /// A symlink to a directory satisfies a package that ships a directory. Deciding this on
    /// `existing` alone would report a conflict on every `usr/lib/foo -> ../bar` layout the
    /// distribution relies on.
    #[test]
    fn a_symlink_to_a_directory_satisfies_a_packaged_directory() {
        let mut ctx = context(Existing::Other);
        ctx.package_says_directory = true;
        ctx.resolves_to_directory = true;
        assert_eq!(decide(&ctx), Verdict::Resolved(Resolution::DirectoryAlreadyThere));
    }

    /// A plain file where the package wants a directory is a conflict. This is the case
    /// libalpm's `ENOTDIR` hides from itself. Nothing owns the file, nothing removes it, and
    /// extraction would replace it (case 4 of the extraction matrix), so it must be reported
    /// here.
    #[test]
    fn a_packaged_directory_over_a_plain_file_is_a_conflict() {
        let mut ctx = context(Existing::Other);
        ctx.package_says_directory = true;
        assert_eq!(decide(&ctx), Verdict::Conflict);
    }

    /// An upgrade that turns one of its own files into a directory.
    #[test]
    fn a_file_this_package_owned_may_become_a_directory() {
        let mut ctx = context(Existing::Other);
        ctx.package_says_directory = true;
        ctx.old_version_owns_file = true;
        let verdict = decide(&ctx);
        assert_eq!(verdict, Verdict::Resolved(Resolution::FileBecomesDirectory));
        assert!(verdict.skips_directory_contents());
    }

    /// The same rule must not fire for a file. It is guarded by `pfile_isdir`
    /// (`conflict.c:522`). Without that guard, an ordinary upgrade of any file would resolve
    /// here instead of falling through to the rules below it.
    #[test]
    fn the_file_becomes_directory_rule_needs_the_package_to_ship_a_directory() {
        let mut ctx = context(Existing::Other);
        ctx.old_version_owns_file = true;
        assert_eq!(decide(&ctx), Verdict::Conflict);
    }

    #[test]
    fn a_path_this_transaction_removes_is_not_a_conflict() {
        let mut ctx = context(Existing::Other);
        ctx.owned_by_removal = true;
        assert_eq!(decide(&ctx), Verdict::Resolved(Resolution::RemovedByTransaction));
    }

    /// The rule with a side effect. The outgoing package must be stopped from deleting the
    /// file its new owner installs. `changes_owner_from` feeds exactly that.
    #[test]
    fn a_file_changing_hands_records_who_had_it() {
        let mut ctx = context(Existing::Other);
        ctx.changing_owner_from = Some("oldpkg");
        let verdict = decide(&ctx);
        assert_eq!(
            verdict,
            Verdict::Resolved(Resolution::ChangesOwner { from: "oldpkg".to_owned() })
        );
        assert_eq!(verdict.changes_owner_from(), Some("oldpkg"));
    }

    #[test]
    fn a_directory_left_empty_by_the_transaction_is_not_a_conflict() {
        let mut ctx = context(Existing::Directory);
        ctx.directory_emptied_by_transaction = true;
        assert_eq!(decide(&ctx), Verdict::Resolved(Resolution::DirectoryEmptiedByTransaction));
    }

    /// A config file the user wrote before installing the package that manages it.
    #[test]
    fn an_unowned_backup_file_is_adopted() {
        let mut ctx = context(Existing::Other);
        ctx.new_is_backup = true;
        assert_eq!(decide(&ctx), Verdict::Resolved(Resolution::AdoptedBackupFile));
    }

    /// Adoption applies only to an unowned file. If another package owns it, this is a genuine
    /// collision, and being a backup file does not excuse it.
    #[test]
    fn a_backup_file_owned_by_another_package_is_still_a_conflict() {
        let mut ctx = context(Existing::Other);
        ctx.new_is_backup = true;
        ctx.owned_by_anyone = true;
        assert_eq!(decide(&ctx), Verdict::Conflict);
    }

    #[test]
    fn overwrite_releases_a_file() {
        let mut ctx = context(Existing::Other);
        ctx.overwrite = true;
        assert_eq!(decide(&ctx), Verdict::Resolved(Resolution::Overwritten));
    }

    /// `--overwrite` does not apply to a directory on disk. Extraction refuses a file over a
    /// directory regardless of what the user asked for. Resolving it here would only move the
    /// failure later, and report it worse.
    #[test]
    fn overwrite_does_not_release_a_directory() {
        let mut ctx = context(Existing::Directory);
        ctx.overwrite = true;
        assert_eq!(decide(&ctx), Verdict::Conflict);
    }

    /// The ordering is observable. A path that is both removed by this transaction and
    /// changing owner must report the removal, because that branch records no `skip_remove`.
    /// Reversing them would suppress a removal libalpm performs.
    #[test]
    fn removal_is_reported_before_a_change_of_owner() {
        let mut ctx = context(Existing::Other);
        ctx.owned_by_removal = true;
        ctx.changing_owner_from = Some("oldpkg");
        let verdict = decide(&ctx);
        assert_eq!(verdict, Verdict::Resolved(Resolution::RemovedByTransaction));
        assert_eq!(verdict.changes_owner_from(), None);
    }

    /// Only the three branches libalpm skips ahead from say so.
    #[test]
    fn only_three_resolutions_skip_a_directorys_contents() {
        let skipping = [
            Resolution::FileBecomesDirectory,
            Resolution::RemovedByTransaction,
            Resolution::ChangesOwner { from: "x".to_owned() },
        ];
        let not_skipping = [
            Resolution::NotPresent,
            Resolution::DirectoryAlreadyThere,
            Resolution::DirectoryEmptiedByTransaction,
            Resolution::AdoptedBackupFile,
            Resolution::Overwritten,
        ];
        for resolution in skipping {
            assert!(
                Verdict::Resolved(resolution.clone()).skips_directory_contents(),
                "{resolution:?}"
            );
        }
        for resolution in not_skipping {
            assert!(
                !Verdict::Resolved(resolution.clone()).skips_directory_contents(),
                "{resolution:?}"
            );
        }
        assert!(!Verdict::Conflict.skips_directory_contents());
    }
}
