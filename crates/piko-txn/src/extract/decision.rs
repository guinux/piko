//! Decides what to do with a single archive entry, before anything is written.
//!
//! libalpm makes these decisions inline in `extract_single_file` (`add.c:191`), interleaved
//! with the extraction itself. The outcome lives in local `int` flags (`notouch`,
//! `needbackup`, `isnewfile`) and reaches the user through callbacks fired mid-loop. That is
//! why the rules are hard to review: the matrix in the comment at `add.c:232` is authored
//! carefully, then implemented across sixty lines that also do I/O.
//!
//! Here the decisions are pure functions returning values. Tests can enumerate every cell of
//! the matrix and every ordering of the three hashes, without a filesystem, an archive, or a
//! package. The code that acts on them stays small enough to review on its own. This is the
//! same split that makes `piko_db::solve::Plan` a value rather than a callback tape.

/// What the archive says an entry is.
///
/// This is only the distinction libalpm draws: `S_ISDIR(entrymode)` or not. A symlink, a
/// device node, and a regular file are all handled identically at this stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    /// A directory.
    Directory,
    /// A regular file, symlink, device node or anything else.
    Other,
}

/// What is at the destination right now.
///
/// This comes from an `lstat`, matching libalpm's `llstat` (`add.c:247`). So a symlink *to* a
/// directory is [`Existing::Other`], not [`Existing::Directory`]. That distinction is
/// load-bearing: it is what makes replacing a symlink with a real file an ordinary overwrite
/// rather than the refused "file replacing directory" case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Existing {
    /// Nothing is there.
    Absent,
    /// A directory.
    Directory,
    /// A regular file, symlink, device node or anything else.
    Other,
}

/// Why an entry is being extracted next to the existing file instead of over it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacnewReason {
    /// The path matches a `NoUpgrade` pattern, so the installed file is never replaced.
    ///
    /// The `.pacnew` is final in this case: there is no hash comparison and no chance of it
    /// being renamed into place.
    NoUpgrade,
    /// The path is a backup file, so the user may have edited it.
    ///
    /// Whether the `.pacnew` survives is decided afterwards by [`resolve_backup`].
    Backup {
        /// The hash the *old* package recorded for this file, if it had one.
        ///
        /// `None` means the file became a backup file only in the new package, libalpm's
        /// "allow adding backup files retroactively" (`add.c:311`). There is then no original
        /// to compare against, which changes what [`resolve_backup`] can conclude.
        original_hash: Option<String>,
    },
}

/// Why an entry cannot be extracted at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefuseReason {
    /// A directory is in the way of a non-directory. Case 5 of the matrix.
    ///
    /// libalpm refuses this outright (`add.c:290`) rather than removing the directory, and so
    /// does piko. The directory may hold files belonging to other packages, or to nobody.
    DirectoryInTheWay,
}

/// Why an entry is being skipped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkipReason {
    /// The path matches a `NoExtract` pattern.
    NoExtract,
    /// The directory already exists, so there is nothing to create. Case 6.
    DirectoryExists,
    /// The archive contains an entry the package's own file list does not mention.
    ///
    /// libalpm warns and skips (`add.c:208`). Treating the file list as authoritative over the
    /// archive is the same principle as the local database's directory-name-wins rule.
    NotInFileList,
}

/// What to do with an entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Extract it over the destination.
    Extract,
    /// Extract it to `<destination>.pacnew`.
    ExtractAsPacnew(PacnewReason),
    /// Do not extract it.
    Skip(SkipReason),
    /// Refuse, and fail the transaction.
    Refuse(RefuseReason),
}

/// Everything the decision depends on, so the matrix reads as a matrix.
#[derive(Clone, Debug)]
pub struct EntryContext<'a> {
    /// What the archive says the entry is.
    pub entry: EntryKind,
    /// What is at the destination.
    pub existing: Existing,
    /// Whether the package's own file list mentions this path.
    pub in_file_list: bool,
    /// Whether the path matches a `NoExtract` pattern.
    pub no_extract: bool,
    /// Whether the path matches a `NoUpgrade` pattern.
    pub no_upgrade: bool,
    /// The hash the currently installed package recorded for this path, if it is one of its
    /// backup files.
    pub old_backup_hash: Option<&'a str>,
    /// Whether the *new* package lists this path as a backup file.
    pub new_is_backup: bool,
}

/// Decides what to do with one entry.
///
/// The matrix, transcribed from the comment at `add.c:232`, with the filesystem down the
/// side and the package across the top:
///
/// | | file/node | directory |
/// |---|---|---|
/// | **absent** | 1 extract | 2 extract |
/// | **file/node** | 3 overwrite, or back up | 4 overwrite |
/// | **directory** | 5 refuse | 6 skip |
///
/// The order of the checks matters and is libalpm's: `NoExtract` wins over everything, then
/// the matrix, and only in case 3 do `NoUpgrade` and the backup rules apply.
#[must_use]
pub fn decide(context: &EntryContext<'_>) -> Disposition {
    // The archive is not authoritative about what the package contains; the file list is.
    if !context.in_file_list {
        return Disposition::Skip(SkipReason::NotInFileList);
    }
    if context.no_extract {
        return Disposition::Skip(SkipReason::NoExtract);
    }

    match (context.existing, context.entry) {
        // Cases 1 and 2: nothing is there, so nothing needs deciding.
        (Existing::Absent, _) => Disposition::Extract,
        // Case 6: the directory is already there. Its mode may differ from the package's.
        // libalpm warns about that and does not correct it; that is a diagnostic for the
        // caller, not a decision, so it is not modelled here.
        (Existing::Directory, EntryKind::Directory) => {
            Disposition::Skip(SkipReason::DirectoryExists)
        }
        // Case 5: a file may not replace a directory.
        (Existing::Directory, EntryKind::Other) => {
            Disposition::Refuse(RefuseReason::DirectoryInTheWay)
        }
        // Case 4: a directory may replace a file.
        (Existing::Other, EntryKind::Directory) => Disposition::Extract,
        // Case 3, the only interesting one.
        (Existing::Other, EntryKind::Other) => {
            if context.no_upgrade {
                return Disposition::ExtractAsPacnew(PacnewReason::NoUpgrade);
            }
            // The old package's record comes first. It is what makes "has the user edited
            // this?" answerable at all.
            if let Some(hash) = context.old_backup_hash {
                return Disposition::ExtractAsPacnew(PacnewReason::Backup {
                    original_hash: Some(hash.to_owned()),
                });
            }
            if context.new_is_backup {
                // "allow adding backup files retroactively" (`add.c:311`).
                return Disposition::ExtractAsPacnew(PacnewReason::Backup { original_hash: None });
            }
            Disposition::Extract
        }
    }
}

/// What to do with a `.pacnew` that was extracted for a backup file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupAction {
    /// Rename the `.pacnew` over the installed file.
    InstallNew,
    /// Keep the installed file as it is.
    KeepExisting {
        /// Whether the `.pacnew` should be removed.
        ///
        /// This applies only when this extraction created it. An existing `.pacnew` from an
        /// earlier upgrade is left alone. Deleting a file the user may still be merging from
        /// would destroy their work.
        remove_pacnew: bool,
    },
    /// Keep both, and tell the user a `.pacnew` is waiting.
    KeepBoth,
}

/// Resolves a backup file three ways, from `add.c:351-404`.
///
/// The three hashes are the corners of the problem:
///
/// - `local` — what is on disk now, which the user may have edited;
/// - `packaged` — what the new package ships;
/// - `original` — what the *old* package shipped, recorded in its `%BACKUP%`.
///
/// The comparisons answer, in order: is the user already running what we are about to
/// install; has the file not changed between the two packages; has the user left it
/// untouched. Only when all three miss is the decision handed to the user as a `.pacnew`.
///
/// `original` is `None` for a file that became a backup file only in the new package. The
/// middle two questions are then unanswerable, and anything other than an exact match with
/// what is already installed must become a `.pacnew`. Piko cannot tell an edited file from an
/// unedited one without a baseline, and guessing wrong overwrites the user's work.
#[must_use]
pub fn resolve_backup(
    local: Option<&str>,
    packaged: Option<&str>,
    original: Option<&str>,
    pacnew_is_new: bool,
) -> BackupAction {
    // This uses `a.is_some() && a == b` rather than a let-chain: let-chains are stable only
    // from Rust 1.88, and the workspace MSRV is 1.85. The guard is load-bearing either way. It
    // stops two *unreadable* files (both `None`) from comparing equal.
    if local.is_some() && local == packaged {
        // The user already has exactly this content. libalpm still installs, to get the
        // timestamps right. The rename is harmless because the bytes are identical.
        return BackupAction::InstallNew;
    }
    if original.is_some() && original == packaged {
        // The file did not change between the two packages, so whatever is on disk is either
        // the user's edit or the same thing. Either way, leave it.
        return BackupAction::KeepExisting { remove_pacnew: pacnew_is_new };
    }
    if original.is_some() && original == local {
        // The user has not touched it, so it is safe to move forward.
        return BackupAction::InstallNew;
    }
    BackupAction::KeepBoth
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// A context with nothing unusual set, so each test states only what it is about.
    fn context(entry: EntryKind, existing: Existing) -> EntryContext<'static> {
        EntryContext {
            entry,
            existing,
            in_file_list: true,
            no_extract: false,
            no_upgrade: false,
            old_backup_hash: None,
            new_is_backup: false,
        }
    }

    #[test]
    fn case_1_and_2_extract_into_empty_space() {
        for entry in [EntryKind::Other, EntryKind::Directory] {
            assert_eq!(decide(&context(entry, Existing::Absent)), Disposition::Extract);
        }
    }

    #[test]
    fn case_3_overwrites_an_ordinary_file() {
        assert_eq!(decide(&context(EntryKind::Other, Existing::Other)), Disposition::Extract);
    }

    #[test]
    fn case_4_lets_a_directory_replace_a_file() {
        assert_eq!(decide(&context(EntryKind::Directory, Existing::Other)), Disposition::Extract);
    }

    /// The one case that fails the transaction. The directory may contain files owned by
    /// something else, so piko does not remove it.
    #[test]
    fn case_5_refuses_to_replace_a_directory_with_a_file() {
        assert_eq!(
            decide(&context(EntryKind::Other, Existing::Directory)),
            Disposition::Refuse(RefuseReason::DirectoryInTheWay)
        );
    }

    #[test]
    fn case_6_skips_an_existing_directory() {
        assert_eq!(
            decide(&context(EntryKind::Directory, Existing::Directory)),
            Disposition::Skip(SkipReason::DirectoryExists)
        );
    }

    /// A symlink is `Existing::Other`, so replacing one is case 3 rather than case 5. If
    /// `lstat` were a `stat`, a symlink to a directory would be refused instead. That is why
    /// the distinction is spelled out on `Existing`.
    #[test]
    fn a_symlink_to_a_directory_is_overwritten_not_refused() {
        assert_eq!(decide(&context(EntryKind::Other, Existing::Other)), Disposition::Extract);
    }

    #[test]
    fn no_extract_wins_over_every_case() {
        for existing in [Existing::Absent, Existing::Directory, Existing::Other] {
            for entry in [EntryKind::Other, EntryKind::Directory] {
                let mut ctx = context(entry, existing);
                ctx.no_extract = true;
                assert_eq!(
                    decide(&ctx),
                    Disposition::Skip(SkipReason::NoExtract),
                    "{entry:?} over {existing:?}"
                );
            }
        }
    }

    /// The file list is authoritative over the archive, and that check comes first. An entry
    /// that is not in the list is skipped even where it would otherwise be refused.
    #[test]
    fn an_entry_missing_from_the_file_list_is_skipped_before_anything_else() {
        let mut ctx = context(EntryKind::Other, Existing::Directory);
        ctx.in_file_list = false;
        assert_eq!(decide(&ctx), Disposition::Skip(SkipReason::NotInFileList));
    }

    #[test]
    fn no_upgrade_diverts_to_pacnew() {
        let mut ctx = context(EntryKind::Other, Existing::Other);
        ctx.no_upgrade = true;
        assert_eq!(decide(&ctx), Disposition::ExtractAsPacnew(PacnewReason::NoUpgrade));
    }

    /// `NoUpgrade` is checked before the backup rules, so it wins even for a backup file.
    #[test]
    fn no_upgrade_wins_over_backup() {
        let mut ctx = context(EntryKind::Other, Existing::Other);
        ctx.no_upgrade = true;
        ctx.old_backup_hash = Some("abc");
        ctx.new_is_backup = true;
        assert_eq!(decide(&ctx), Disposition::ExtractAsPacnew(PacnewReason::NoUpgrade));
    }

    #[test]
    fn a_backup_file_carries_the_old_packages_hash() {
        let mut ctx = context(EntryKind::Other, Existing::Other);
        ctx.old_backup_hash = Some("abc");
        assert_eq!(
            decide(&ctx),
            Disposition::ExtractAsPacnew(PacnewReason::Backup {
                original_hash: Some("abc".to_owned())
            })
        );
    }

    /// "allow adding backup files retroactively": the new package declares it a backup file
    /// and the old one did not, so there is no original to compare against.
    #[test]
    fn a_newly_declared_backup_file_has_no_original() {
        let mut ctx = context(EntryKind::Other, Existing::Other);
        ctx.new_is_backup = true;
        assert_eq!(
            decide(&ctx),
            Disposition::ExtractAsPacnew(PacnewReason::Backup { original_hash: None })
        );
    }

    /// Backup rules only apply to case 3. A backup file that is not currently present is
    /// simply extracted.
    #[test]
    fn backup_rules_do_not_apply_when_nothing_is_installed() {
        let mut ctx = context(EntryKind::Other, Existing::Absent);
        ctx.old_backup_hash = Some("abc");
        ctx.new_is_backup = true;
        assert_eq!(decide(&ctx), Disposition::Extract);
    }

    #[test]
    fn backup_installs_when_the_user_already_has_the_new_content() {
        assert_eq!(
            resolve_backup(Some("new"), Some("new"), Some("old"), true),
            BackupAction::InstallNew
        );
    }

    #[test]
    fn backup_keeps_the_users_file_when_the_package_did_not_change_it() {
        assert_eq!(
            resolve_backup(Some("edited"), Some("same"), Some("same"), true),
            BackupAction::KeepExisting { remove_pacnew: true }
        );
    }

    /// A `.pacnew` that was already there is the user's, possibly half-merged. Only one this
    /// extraction created may be removed.
    #[test]
    fn backup_does_not_remove_a_pacnew_it_did_not_create() {
        assert_eq!(
            resolve_backup(Some("edited"), Some("same"), Some("same"), false),
            BackupAction::KeepExisting { remove_pacnew: false }
        );
    }

    #[test]
    fn backup_upgrades_a_file_the_user_never_touched() {
        assert_eq!(
            resolve_backup(Some("old"), Some("new"), Some("old"), true),
            BackupAction::InstallNew
        );
    }

    /// The case the whole `.pacnew` mechanism exists for: the user edited the file *and* the
    /// package changed it. Neither version can be discarded, so the user decides.
    #[test]
    fn backup_keeps_both_when_all_three_differ() {
        assert_eq!(
            resolve_backup(Some("edited"), Some("new"), Some("old"), true),
            BackupAction::KeepBoth
        );
    }

    /// Without an original, an edited file is indistinguishable from an unedited one, so the
    /// only safe answers are "identical" or "let the user decide".
    #[test]
    fn backup_without_an_original_only_installs_on_an_exact_match() {
        assert_eq!(
            resolve_backup(Some("same"), Some("same"), None, true),
            BackupAction::InstallNew
        );
        assert_eq!(resolve_backup(Some("edited"), Some("new"), None, true), BackupAction::KeepBoth);
    }

    /// An unreadable local file must never be treated as matching anything.
    #[test]
    fn backup_with_no_local_hash_keeps_both() {
        assert_eq!(resolve_backup(None, Some("new"), Some("old"), true), BackupAction::KeepBoth);
    }

    /// Two *absent* hashes must not compare equal. Comparing the `Option`s without the
    /// `is_some` guard would make every unhashable file look like an exact match and
    /// silently overwrite it.
    #[test]
    fn backup_treats_missing_hashes_as_unknown_not_as_equal() {
        assert_eq!(resolve_backup(None, None, None, true), BackupAction::KeepBoth);
        assert_eq!(resolve_backup(None, None, Some("old"), true), BackupAction::KeepBoth);
        assert_eq!(resolve_backup(Some("local"), None, None, true), BackupAction::KeepBoth);
    }

    /// The ordering of the three comparisons is libalpm's, and it is observable: when the
    /// local file matches both the package and the original, the first rule wins and the
    /// file is installed rather than left alone. The outcomes agree on the bytes, so this
    /// pins the behaviour rather than the reasoning.
    #[test]
    fn the_comparison_order_matches_libalpm_when_all_three_agree() {
        assert_eq!(
            resolve_backup(Some("same"), Some("same"), Some("same"), true),
            BackupAction::InstallNew
        );
    }
}
