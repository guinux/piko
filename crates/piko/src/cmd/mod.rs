//! One module per database a subcommand reads: the local database, a repository archive, the
//! two together, and the configuration file.
//!
//! Every function here returns [`std::process::ExitCode`] rather than a `Result`. A subcommand's
//! failure modes are already reported at the point they happen (through `output::report`). The
//! caller only needs to know whether to exit non-zero.

pub mod check;
pub mod conf;
pub mod files;
pub mod freshness;
pub mod group;
pub mod history;
pub mod info;
pub mod key;
pub mod list;
pub mod local;
pub mod merge;
pub mod owns;
pub mod plan;
pub mod provider;
pub mod refresh;
pub mod removal;
pub mod repo;
pub mod search;
pub mod sync;
pub mod txn;
pub mod why;

use piko_db::solve::{SolvableId, Universe};
use piko_db_write::DbLock;

/// Releases `db.lck`, and warns when the file cannot be removed.
///
/// libalpm warns too, and still returns success (`_alpm_handle_unlock`, `handle.c:171`): the
/// command's work is done, so its exit code stays what it was. A lock file left behind makes the
/// next command refuse with "database locked", and this warning is the one place that says why.
/// A lock file that is already gone is not reported, because [`DbLock::release`] counts it as
/// released.
pub(crate) fn release_lock(lock: DbLock) {
    if let Some(warning) = release_warning(lock) {
        crate::output::warn(warning);
    }
}

/// Releases `lock`, and returns the warning a failure to remove the file calls for.
fn release_warning(lock: DbLock) -> Option<String> {
    let path = lock.path().to_path_buf();
    let error = lock.release().err()?;
    let cause =
        std::error::Error::source(&error).map_or_else(String::new, |cause| format!(": {cause}"));
    Some(crate::i18n::tr!("cli-lock-not-removed", path = path.display().to_string(), cause = cause))
}

/// Writes a numbered candidate list, grouped by the repository each candidate came from.
///
/// Two questions render this list. [`provider`] asks which provider satisfies a dependency.
/// [`group`] asks which members of a group to install. The grouping is pacman's. The numbering
/// runs across the whole list rather than restarting per repository, because the answer
/// indexes the list, not the repository.
///
/// One candidate per line. piko reads no terminal width anywhere, and pacman's multi-column
/// layout is the only thing that would need it.
pub(crate) fn write_candidates(
    out: &mut impl std::io::Write,
    universe: &Universe<'_>,
    candidates: &[SolvableId],
) -> std::io::Result<()> {
    let mut current: Option<String> = None;
    for (index, id) in candidates.iter().enumerate() {
        let origin = origin_label(universe, *id);
        if current.as_deref() != Some(origin.as_str()) {
            writeln!(out, ":: {origin}")?;
            current = Some(origin);
        }
        let described = universe.get(*id).map_or_else(
            || crate::i18n::tr!("cli-unknown"),
            |solvable| format!("{} {}", solvable.name(), solvable.version()),
        );
        // `index` is bounded by `candidates.len()`.
        writeln!(out, "   {}) {described}", index.saturating_add(1))?;
    }
    Ok(())
}

/// The name of candidate `id`, or `<unknown>`.
pub(crate) fn candidate_name(universe: &Universe<'_>, id: SolvableId) -> String {
    universe
        .get(id)
        .map_or_else(|| crate::i18n::tr!("cli-unknown"), |solvable| solvable.name().to_string())
}

/// Names the first few `candidates` and counts the rest: `a, b, c, d, e, and 3 more`.
///
/// A note that reports a default answer names candidates rather than counting them, but not all
/// of them. `tesseract requires tessdata` has 128 providers on a real system, and `gnome` carries
/// 66 members. A note is not the prompt. The prompt lists every one, because there the list is
/// what the user answers.
pub(crate) fn candidate_sample(universe: &Universe<'_>, candidates: &[SolvableId]) -> String {
    const SHOWN: usize = 5;
    let listed: Vec<String> =
        candidates.iter().take(SHOWN).map(|id| candidate_name(universe, *id)).collect();
    let rest = candidates.len().saturating_sub(listed.len());
    let shown = listed.join(", ");
    if rest == 0 { shown } else { crate::i18n::tr!("cli-and-more", shown = shown, rest = rest) }
}

/// Where a candidate came from, as the heading [`write_candidates`] groups it under.
fn origin_label(universe: &Universe<'_>, id: SolvableId) -> String {
    match universe.get(id).map(|solvable| solvable.origin()) {
        Some(piko_db::solve::Origin::Repository(index)) => {
            universe.repository_name(index).map_or_else(
                || crate::i18n::tr!("cli-origin-repository", name = "?"),
                |name| crate::i18n::tr!("cli-origin-repository", name = name.to_string()),
            )
        }
        // This is reachable. A package file named on the command line is interned as a
        // candidate, and can provide a dependency like any other (`UniverseOptions::files`).
        Some(piko_db::solve::Origin::File(_)) => crate::i18n::tr!("cli-origin-file"),
        // An installed candidate is never listed: it suppresses a provider question, and a
        // group's members are the repository side only.
        Some(piko_db::solve::Origin::Installed) | None => crate::i18n::tr!("cli-origin-installed"),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// A lock file that cannot be removed is named, with the reason. One that can is not.
    #[test]
    fn a_lock_file_that_stays_is_named() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(release_warning(DbLock::acquire(dir.path()).unwrap()), None);

        // Root removes a file from a directory it cannot write, so the test has nothing to show.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let lock = DbLock::acquire(dir.path()).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let warning = release_warning(lock);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        let warning = warning.unwrap();
        let path = dir.path().join(piko_db_write::LOCK_FILE);
        assert!(
            warning.starts_with(&format!("could not remove lock file {}: ", path.display())),
            "{warning}"
        );
        assert!(path.exists(), "the lock file stays");
    }
}
