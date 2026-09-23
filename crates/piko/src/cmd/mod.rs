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

/// Where a candidate came from, as the heading a numbered list groups it under.
///
/// Two questions render a numbered list of candidates. [`provider`] asks which provider
/// satisfies a dependency. [`group`] asks which members of a group to install. Both head each
/// run of candidates with the repository it came from, as pacman does.
pub(crate) fn origin_label(universe: &Universe<'_>, id: SolvableId) -> String {
    match universe.get(id).map(|solvable| solvable.origin()) {
        Some(piko_db::solve::Origin::Repository(index)) => universe
            .repository_name(index)
            .map_or_else(|| "Repository ?".to_owned(), |name| format!("Repository {name}")),
        // This is reachable. A package file named on the command line is interned as a
        // candidate, and can provide a dependency like any other (`UniverseOptions::files`).
        Some(piko_db::solve::Origin::File(_)) => "Package file".to_owned(),
        // An installed candidate is never listed: it suppresses a provider question, and a
        // group's members are the repository side only.
        Some(piko_db::solve::Origin::Installed) | None => "Installed".to_owned(),
    }
}
