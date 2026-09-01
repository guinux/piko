//! Decides what to do with a single file when a package is removed.
//!
//! This mirrors [`crate::extract::decision`], and is pure for the same reason: libalpm decides
//! this inline in `unlink_file` (`remove.c:441`) while also doing the unlinking, so the rules
//! and their application cannot be reviewed apart. Here they are values instead.
//!
//! The rules matter more than their size suggests. A removal that gets one wrong deletes
//! configuration the user edited, with no copy anywhere.

use crate::extract::decision::Existing;

/// Why a file is left alone during removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemovalSkipReason {
    /// The path matches a `NoUpgrade` pattern.
    NoUpgrade,
    /// The transaction's `skip_remove` list names it.
    ///
    /// libalpm populates this during an upgrade so that files the replacement package also
    /// ships are not removed and immediately recreated (`remove.c:593`).
    SkipRemove,
    /// A replacement package ships this same path as one of its backup files.
    ///
    /// Removing it would throw away the user's edits a moment before the new package's version
    /// is laid down beside them as a `.pacnew`.
    ReplacementKeepsIt,
    /// A replacement package ships this same directory.
    ///
    /// Only a directory reaches this variant. `unlink_file` keeps a directory the new package
    /// also ships (`remove.c:487`), rather than removing it and letting extraction recreate it.
    ReplacementShipsIt,
    /// Nothing is at the path.
    NotPresent,
}

/// What to do with one of a removed package's files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemovalDisposition {
    /// Delete it.
    Unlink,
    /// Rename it to `<path>.pacsave`, rotating any existing ones first.
    ///
    /// See [`pacsave_rotation`].
    SaveAsPacsave,
    /// Try to remove the directory, which succeeds only if it is empty.
    ///
    /// libalpm calls `rmdir` and treats failure as ordinary (`remove.c:521`). A directory that
    /// still holds files belonging to something else must stay.
    RemoveDirectoryIfEmpty,
    /// Leave it.
    Skip(RemovalSkipReason),
}

/// Everything a removal decision depends on.
#[derive(Clone, Debug)]
pub struct RemovalContext<'a> {
    /// What is at the path, from an `lstat`.
    pub existing: Existing,
    /// Whether the path matches a `NoUpgrade` pattern.
    pub no_upgrade: bool,
    /// Whether the transaction's `skip_remove` list names it.
    pub in_skip_remove: bool,
    /// Whether a replacement package ships this path as a backup file it also owns.
    pub replacement_keeps_it: bool,
    /// Whether a replacement package ships this path exactly as spelled.
    ///
    /// Only consulted for a directory. That is the only case libalpm consults it for. A *file*
    /// both versions ship is deliberately unlinked here and written again by the extraction
    /// that follows. A directory is kept instead, so its mode and ownership are not destroyed
    /// and recreated for nothing.
    pub replacement_ships_it: bool,
    /// The hash the package being removed recorded for this path, if it is a backup file.
    pub old_backup_hash: Option<&'a str>,
    /// The hash of what is on disk now, or `None` if it could not be computed.
    pub local_hash: Option<&'a str>,
    /// Whether the transaction was asked not to create `.pacsave` files (`-Rn`).
    pub no_save: bool,
    /// Whether another installed package also owns this directory.
    ///
    /// Only consulted for a directory. libalpm walks the whole local database to answer this
    /// (`remove.c:495`).
    pub directory_has_other_owner: bool,
}

/// Decides what to do with one file of a package being removed.
///
/// The order follows libalpm: the skip checks of `should_skip_file` (`remove.c:591`) come
/// first, then existence, then the directory case, then the backup case.
#[must_use]
pub fn decide_removal(context: &RemovalContext<'_>) -> RemovalDisposition {
    if context.no_upgrade {
        return RemovalDisposition::Skip(RemovalSkipReason::NoUpgrade);
    }
    if context.in_skip_remove {
        return RemovalDisposition::Skip(RemovalSkipReason::SkipRemove);
    }
    if context.replacement_keeps_it {
        return RemovalDisposition::Skip(RemovalSkipReason::ReplacementKeepsIt);
    }

    match context.existing {
        Existing::Absent => RemovalDisposition::Skip(RemovalSkipReason::NotPresent),
        Existing::Directory => {
            if context.replacement_ships_it {
                // `remove.c:487`. Checked before the ownership question, as libalpm does.
                RemovalDisposition::Skip(RemovalSkipReason::ReplacementShipsIt)
            } else if context.directory_has_other_owner {
                // Another package's file list claims it. It is not this package's to remove,
                // even if it happens to be empty right now.
                RemovalDisposition::Skip(RemovalSkipReason::SkipRemove)
            } else {
                RemovalDisposition::RemoveDirectoryIfEmpty
            }
        }
        Existing::Other => {
            let Some(recorded) = context.old_backup_hash else {
                // Not a backup file: nothing to preserve.
                return RemovalDisposition::Unlink;
            };
            if context.no_save {
                return RemovalDisposition::Unlink;
            }
            // Unchanged since it was installed, so a copy would preserve nothing.
            if context.local_hash == Some(recorded) {
                return RemovalDisposition::Unlink;
            }
            RemovalDisposition::SaveAsPacsave
        }
    }
}

/// The renames that make room for a new `<path>.pacsave`, in the order they must happen.
///
/// Each pair is `(from_suffix, to_suffix)`, applied to the file's path. The order is
/// descending, so no rename ever overwrites a file a later one still needs:
/// `.pacsave.2` → `.pacsave.3`, then `.pacsave.1` → `.pacsave.2`, then `.pacsave` →
/// `.pacsave.1`. Transcribed from `shift_pacsave` (`remove.c:347`).
///
/// `existing_numbers` are the `N`s of the `<path>.pacsave.N` files already present.
/// `plain_exists` says whether a bare `<path>.pacsave` is there.
///
/// # Only what exists is renamed
///
/// libalpm takes the *highest* `N`, then loops down through every integer, renaming
/// `.pacsave.{i-1}` to `.pacsave.{i}` whether or not the source is there, ignoring the
/// failures. It does that because `log_max` is all it kept. This function is handed the whole
/// set instead, so it renames only the files that actually exist.
///
/// The outcome is identical: the renames libalpm issues for absent files do nothing. But the
/// work here is bounded by how many `.pacsave` files there *are*, not by the largest number
/// one of them is *named after*. That difference is not cosmetic. `N` is parsed out of a
/// filename, so it is attacker-influenced. A single `foo.pacsave.4000000000` sitting in `/etc`
/// costs libalpm four billion `rename` syscalls.
#[must_use]
pub fn pacsave_rotation(existing_numbers: &[u32], plain_exists: bool) -> Vec<(String, String)> {
    let mut numbers: Vec<u32> = existing_numbers.to_vec();
    numbers.sort_unstable();
    numbers.dedup();

    let mut renames = Vec::new();
    // Descending order, so each `.pacsave.N` moves only after `.pacsave.{N+1}` has vacated.
    let mut immovable: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for number in numbers.iter().rev().copied() {
        // `.pacsave.{u32::MAX}` has nowhere to go, and then neither does the one below it.
        // Moving that one up would overwrite a file that is staying put.
        match number.checked_add(1) {
            Some(next) if !immovable.contains(&next) => {
                renames.push((format!(".pacsave.{number}"), format!(".pacsave.{next}")));
            }
            _ => {
                immovable.insert(number);
            }
        }
    }

    if plain_exists && !immovable.contains(&1) {
        renames.push((".pacsave".to_owned(), ".pacsave.1".to_owned()));
    }
    renames
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn context(existing: Existing) -> RemovalContext<'static> {
        RemovalContext {
            existing,
            no_upgrade: false,
            in_skip_remove: false,
            replacement_keeps_it: false,
            replacement_ships_it: false,
            old_backup_hash: None,
            local_hash: None,
            no_save: false,
            directory_has_other_owner: false,
        }
    }

    #[test]
    fn an_ordinary_file_is_unlinked() {
        assert_eq!(decide_removal(&context(Existing::Other)), RemovalDisposition::Unlink);
    }

    #[test]
    fn an_absent_file_is_nothing_to_do() {
        assert_eq!(
            decide_removal(&context(Existing::Absent)),
            RemovalDisposition::Skip(RemovalSkipReason::NotPresent)
        );
    }

    #[test]
    fn a_directory_is_removed_only_if_it_is_empty() {
        assert_eq!(
            decide_removal(&context(Existing::Directory)),
            RemovalDisposition::RemoveDirectoryIfEmpty
        );
    }

    #[test]
    fn a_directory_another_package_owns_is_left_alone() {
        let mut ctx = context(Existing::Directory);
        ctx.directory_has_other_owner = true;
        assert!(matches!(decide_removal(&ctx), RemovalDisposition::Skip(_)));
    }

    /// An upgrade's fake removal keeps a directory the new version also ships, rather than
    /// removing it and having extraction put it straight back.
    #[test]
    fn a_directory_the_replacement_ships_is_kept() {
        let mut ctx = context(Existing::Directory);
        ctx.replacement_ships_it = true;
        assert_eq!(
            decide_removal(&ctx),
            RemovalDisposition::Skip(RemovalSkipReason::ReplacementShipsIt)
        );
    }

    /// But a *file* both versions ship is unlinked. libalpm's `should_skip_file`
    /// (`remove.c:589`) tests the replacement's backup list, not its file list. So the old
    /// copy goes, and the extraction that follows writes the new one.
    #[test]
    fn a_file_the_replacement_ships_is_still_unlinked() {
        let mut ctx = context(Existing::Other);
        ctx.replacement_ships_it = true;
        assert_eq!(decide_removal(&ctx), RemovalDisposition::Unlink);
    }

    /// An unmodified config file has nothing worth preserving, so it is deleted rather than
    /// littering the system with a `.pacsave` identical to what was shipped.
    #[test]
    fn an_unmodified_backup_file_is_unlinked() {
        let mut ctx = context(Existing::Other);
        ctx.old_backup_hash = Some("abc");
        ctx.local_hash = Some("abc");
        assert_eq!(decide_removal(&ctx), RemovalDisposition::Unlink);
    }

    /// The case the whole mechanism exists for.
    #[test]
    fn a_modified_backup_file_is_saved() {
        let mut ctx = context(Existing::Other);
        ctx.old_backup_hash = Some("abc");
        ctx.local_hash = Some("edited");
        assert_eq!(decide_removal(&ctx), RemovalDisposition::SaveAsPacsave);
    }

    /// **Divergence from libalpm.** `remove.c:536` reads
    /// `int cmp = filehash ? strcmp(filehash, backup->hash) : 0;`. When the hash cannot be
    /// computed, `cmp` is 0, meaning "unchanged", and libalpm *deletes* the file. piko treats
    /// an unknown hash as modified and saves it instead. Deleting a config file that could not
    /// be read is the one outcome with no recovery.
    #[test]
    fn a_backup_file_whose_hash_is_unknown_is_saved_not_deleted() {
        let mut ctx = context(Existing::Other);
        ctx.old_backup_hash = Some("abc");
        ctx.local_hash = None;
        assert_eq!(decide_removal(&ctx), RemovalDisposition::SaveAsPacsave);
    }

    /// `-Rn`: the user asked for no `.pacsave` files, and that beats the modification check.
    #[test]
    fn no_save_unlinks_even_a_modified_backup_file() {
        let mut ctx = context(Existing::Other);
        ctx.old_backup_hash = Some("abc");
        ctx.local_hash = Some("edited");
        ctx.no_save = true;
        assert_eq!(decide_removal(&ctx), RemovalDisposition::Unlink);
    }

    #[test]
    fn the_skip_checks_come_before_everything() {
        for (field, reason) in [
            (
                &mut RemovalContext { no_upgrade: true, ..context(Existing::Other) },
                RemovalSkipReason::NoUpgrade,
            ),
            (
                &mut RemovalContext { in_skip_remove: true, ..context(Existing::Other) },
                RemovalSkipReason::SkipRemove,
            ),
            (
                &mut RemovalContext { replacement_keeps_it: true, ..context(Existing::Other) },
                RemovalSkipReason::ReplacementKeepsIt,
            ),
        ] {
            // Even a modified backup file, which would otherwise be saved.
            field.old_backup_hash = Some("abc");
            field.local_hash = Some("edited");
            assert_eq!(decide_removal(field), RemovalDisposition::Skip(reason));
        }
    }

    #[test]
    fn rotation_of_a_lone_pacsave() {
        assert_eq!(pacsave_rotation(&[], true), [(".pacsave".to_owned(), ".pacsave.1".to_owned())]);
    }

    #[test]
    fn rotation_with_nothing_present_renames_nothing() {
        assert!(pacsave_rotation(&[], false).is_empty());
    }

    /// Descending order is the whole point. Doing it the other way round would copy
    /// `.pacsave.1` over `.pacsave.2` and lose a generation.
    #[test]
    fn rotation_runs_from_the_top_down() {
        assert_eq!(
            pacsave_rotation(&[1, 2], true),
            [
                (".pacsave.2".to_owned(), ".pacsave.3".to_owned()),
                (".pacsave.1".to_owned(), ".pacsave.2".to_owned()),
                (".pacsave".to_owned(), ".pacsave.1".to_owned()),
            ]
        );
    }

    /// No rename may target a name that a later rename still reads from.
    #[test]
    fn rotation_never_overwrites_a_source_it_still_needs() {
        let renames = pacsave_rotation(&[1, 2, 3, 4], true);
        for (index, (_, target)) in renames.iter().enumerate() {
            for (source, _) in renames.iter().skip(index.saturating_add(1)) {
                assert_ne!(target, source, "{target} is clobbered before it is read");
            }
        }
    }

    /// A gap does not compress the sequence. `.pacsave.5` becomes `.pacsave.6`, and the
    /// absent 1..4 are simply not renamed. libalpm would issue five no-op renames to reach the
    /// same state.
    #[test]
    fn rotation_skips_gaps_instead_of_walking_them() {
        assert_eq!(
            pacsave_rotation(&[5], true),
            [
                (".pacsave.5".to_owned(), ".pacsave.6".to_owned()),
                (".pacsave".to_owned(), ".pacsave.1".to_owned()),
            ]
        );
    }

    /// The number comes from a filename, so it is attacker-influenced. Work must scale with
    /// how many `.pacsave` files exist, not with what they are named.
    #[test]
    fn rotation_work_is_bounded_by_file_count_not_by_the_number_in_the_name() {
        let renames = pacsave_rotation(&[4_000_000_000], true);
        assert_eq!(renames.len(), 2, "{renames:?}");
        assert_eq!(
            renames.first(),
            Some(&(".pacsave.4000000000".to_owned(), ".pacsave.4000000001".to_owned()))
        );
    }

    /// `.pacsave.{u32::MAX}` cannot be shifted up, so it stays. Nothing may be renamed on top
    /// of it.
    #[test]
    fn rotation_refuses_to_clobber_a_file_that_cannot_move() {
        assert!(pacsave_rotation(&[u32::MAX], false).is_empty());
        assert!(
            pacsave_rotation(&[u32::MAX - 1, u32::MAX], false).is_empty(),
            "the one below an immovable file must not be moved onto it"
        );
        // The blockage does not propagate past a gap. MAX-3 has somewhere to go.
        assert_eq!(
            pacsave_rotation(&[u32::MAX - 3, u32::MAX], false),
            [(format!(".pacsave.{}", u32::MAX - 3), format!(".pacsave.{}", u32::MAX - 2))]
        );
    }

    /// Duplicate entries in the input must not produce duplicate renames.
    #[test]
    fn rotation_deduplicates_its_input() {
        assert_eq!(
            pacsave_rotation(&[1, 1, 1], false),
            [(".pacsave.1".to_owned(), ".pacsave.2".to_owned())]
        );
    }
}
