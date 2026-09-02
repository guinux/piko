//! Turns a solved [`piko_db::solve::Plan`] into a transaction: commit-engine steps, where
//! each incoming package can be downloaded from, and under what signature policy.
//!
//! `piko install foo` is `piko plan foo` turned into a transaction. This module is that
//! translation. It lives here rather than in a frontend, so any caller building a transaction
//! on top of `piko-db`'s solver gets it once, checked, instead of re-deriving
//! `_alpm_sync_prepare`'s install-reason rule or the repository/`SigLevel` lookup by hand.

use std::{collections::HashMap, path::Path};

use alpm_types::{PackageFileName, PackageInstallReason};
use piko_db::EntryName;
use piko_db::config::RepositoryConfig;
use piko_db::repo::RepoName;
use piko_db::solve::{Origin, Plan, SolvableId, Step as SolveStep, Universe};
use piko_sig::Policy;

use crate::source::{CacheDirSource, DownloadTarget, PackageSource};
use crate::transaction::Verification;
use crate::{Error, Result, Step};

/// Turns a solved plan into commit-engine steps, resolving each incoming candidate's cache
/// file name from its repository `desc`.
///
/// # Errors
///
/// [`Error::PlanInconsistent`], [`Error::NoRepositoryCandidate`],
/// [`Error::RepositoryPackageUnreadable`], or [`Error::InvalidEntryName`] if `built` and
/// `universe` disagree about what a step names. This should not happen, since `built` was
/// assembled from `universe`. It is checked rather than assumed.
pub fn install_steps(
    universe: &Universe<'_>,
    built: &Plan,
    targets: &[SolvableId],
    as_deps: bool,
) -> Result<Vec<Step>> {
    let mut steps = Vec::with_capacity(built.steps().len());
    for step in built.steps() {
        match step {
            SolveStep::Remove { package } => {
                steps.push(Step::Remove {
                    entry: entry_name_of(universe, *package)?,
                    no_save: false,
                });
            }
            SolveStep::Install { candidate, .. } => {
                let reason = reason_for(*candidate, targets, as_deps, None);
                steps.push(Step::Install { package: file_name_of(universe, *candidate)?, reason });
            }
            SolveStep::Change { from, to, .. } => {
                let previous = universe.get(*from).and_then(|solvable| solvable.install_reason());
                let reason = reason_for(*to, targets, as_deps, previous);
                steps.push(Step::Install { package: file_name_of(universe, *to)?, reason });
            }
        }
    }
    Ok(steps)
}

/// The reason recorded for one incoming package.
///
/// This is `Explicit` for a package named on the command line, unless `--asdeps` downgrades it.
/// That is `_alpm_sync_prepare`'s rule (`sync.c`), the same one `piko_db::solve::Plan::assemble`
/// applies for a fresh install. An upgrade of a package that was already installed is not
/// renamed by the plan itself — `solve::Step::Change` carries no reason of its own — so it
/// keeps whatever reason it already had, rather than falling to `Depend`. Only a package with
/// no previous install (a fresh dependency) defaults to `Depend`.
fn reason_for(
    candidate: SolvableId,
    targets: &[SolvableId],
    as_deps: bool,
    previous: Option<PackageInstallReason>,
) -> PackageInstallReason {
    if targets.contains(&candidate) && !as_deps {
        PackageInstallReason::Explicit
    } else {
        previous.unwrap_or(PackageInstallReason::Depend)
    }
}

/// The cache file name a repository candidate is installed from.
fn file_name_of(universe: &Universe<'_>, id: SolvableId) -> Result<PackageFileName> {
    let Some(candidate) = universe.get(id) else {
        return Err(Error::PlanInconsistent { id });
    };
    let Some(repo_package) = candidate.as_repository() else {
        // `Plan::assemble` only emits `Install`/`Change` for a candidate that is not already
        // the installed copy (`universe.rs`'s `incoming` filter). So this is unreachable unless
        // that invariant broke. Refusing is the only safe answer either way.
        return Err(Error::NoRepositoryCandidate { name: candidate.name().to_string() });
    };
    repo_package.desc().map(|desc| desc.file_name().clone()).map_err(|source| {
        Error::RepositoryPackageUnreadable { name: candidate.name().to_string(), source }
    })
}

/// The installed entry a removal step names.
fn entry_name_of(universe: &Universe<'_>, id: SolvableId) -> Result<EntryName> {
    let Some(candidate) = universe.get(id) else {
        return Err(Error::PlanInconsistent { id });
    };
    EntryName::new(candidate.name(), candidate.version()).map_err(|error| Error::InvalidEntryName {
        name: candidate.name().to_string(),
        reason: error.to_string(),
    })
}

/// Where each incoming candidate's package file can be downloaded from, and under what policy.
///
/// This is built from the same plan [`install_steps`] turns into commit-engine steps. Each
/// `Step::Install`'s originating repository is resolved through `Origin`/
/// [`Universe::repository_name`], then matched by name against `repos` — not by index, because
/// `Universe`'s repository index counts only the repositories that actually opened, while
/// `repos` may be longer. Matching prefers `CacheServer` over `Server`, as pacman.conf(5)
/// documents. A candidate whose repository or `desc` cannot be resolved is skipped here.
/// [`install_steps`]'s own `file_name_of` already reports that failure for the same candidate.
///
/// Each repository's own `SigLevel` is resolved through
/// [`RepositoryConfig::effective_sig_level`], not read off `RepositoryConfig::sig_level`
/// directly. That field can still carry the parser's `SigLevel::USE_DEFAULT` sentinel for a
/// repository that never set one at all.
#[must_use]
pub fn download_targets(
    universe: &Universe<'_>,
    built: &Plan,
    repos: &[RepositoryConfig],
    global_sig_level: piko_db::config::SigLevel,
) -> HashMap<String, DownloadTarget> {
    let by_name: HashMap<&RepoName, &RepositoryConfig> =
        repos.iter().map(|repo| (&repo.name, repo)).collect();

    let mut targets = HashMap::new();
    for step in built.steps() {
        let candidate = match step {
            SolveStep::Install { candidate, .. } => *candidate,
            SolveStep::Change { to, .. } => *to,
            SolveStep::Remove { .. } => continue,
        };
        let Some(solvable) = universe.get(candidate) else {
            continue;
        };
        let Origin::Repository(index) = solvable.origin() else {
            continue;
        };
        let Some(repo_name) = universe.repository_name(index) else {
            continue;
        };
        let Some(config) = by_name.get(repo_name).copied() else {
            continue;
        };
        let Some(repo_package) = solvable.as_repository() else {
            continue;
        };
        let Ok(desc) = repo_package.desc() else {
            continue;
        };

        let servers =
            if config.cache_servers.is_empty() { &config.servers } else { &config.cache_servers };
        targets.insert(
            desc.file_name().to_string(),
            DownloadTarget {
                repo_name: repo_name.to_string(),
                servers: servers.clone(),
                policy: Policy::for_package(config.effective_sig_level(global_sig_level)),
                size: repo_package.compressed_size(),
            },
        );
    }
    targets
}

/// Builds the verification policy from `pacman.conf`'s `GPGDir`, the fallback `SigLevel`, and
/// each candidate's own repository policy, plus the per-file overrides `Transaction` should
/// apply instead of the fallback wherever one is known.
///
/// A keyring is opened when *either* the fallback or some repository's policy asks for
/// checking, never only the fallback. A global `SigLevel = Never` with one repository
/// overriding to `PackageRequired` must still verify that repository's packages, so looking at
/// the fallback alone would silently skip it. A policy that asks for nothing anywhere needs no
/// keyring at all, so a system without one still works. But the moment anything *does* ask, an
/// unusable keyring is an error rather than a silent pass. Failing open here would make every
/// package install unverified the day the keyring broke.
///
/// # Errors
///
/// [`Error::KeyringUnusable`] if a keyring is needed and could not be opened.
pub fn verification_from(
    gpg_dir: &Path,
    fallback_sig_level: piko_db::config::SigLevel,
    package_targets: &HashMap<String, DownloadTarget>,
) -> Result<(Verification, HashMap<String, Policy>)> {
    let fallback = Policy::for_package(fallback_sig_level);
    let policy_overrides: HashMap<String, Policy> =
        package_targets.iter().map(|(name, target)| (name.clone(), target.policy)).collect();

    let needs_keyring = fallback.check || policy_overrides.values().any(|policy| policy.check);
    if !needs_keyring {
        return Ok((Verification::Disabled, policy_overrides));
    }
    let keyring = piko_sig::Keyring::open(gpg_dir)
        .map_err(|source| Error::KeyringUnusable { path: gpg_dir.to_path_buf(), source })?;
    Ok((Verification::Enabled { keyring, policy: fallback }, policy_overrides))
}

/// One package [`download_only`] located, with everything it learned about it.
#[derive(Clone, Debug)]
pub struct DownloadOnlyOutcome {
    /// The package's cache file name.
    pub package: PackageFileName,
    /// Whether it was already in a cache directory rather than freshly downloaded.
    pub was_cached: bool,
    /// The file's size in bytes.
    pub size: u64,
    /// Whether its signature was actually checked (`false` under `Verification::Disabled`, or
    /// when the effective policy asks for nothing).
    pub verified: bool,
}

/// Downloads every missing package named in `steps` into the cache, installing nothing. This
/// is pacman's `-Sw`.
///
/// Each [`PackageSource::locate`] call already downloads a miss and verifies nothing changed
/// about a hit. So this is the same lookup a transaction's `verify` step would make, without
/// the journal, the lock, or the `Transaction` that would follow it.
///
/// The signature is checked here too, through the same [`crate::transaction::check_signature`]
/// `Transaction::verify` uses, and under the same per-repository policy. libalpm does this:
/// `check_validity` (`sync.c:1275`) runs *before* `_alpm_sync_load` returns on
/// `ALPM_TRANS_FLAG_DOWNLOADONLY` (`sync.c:1279`), so `pacman -Sw` refuses a package it would
/// refuse to install. Leaving the check out fills a cache with bytes nothing has vouched for,
/// and defers the complaint to an install that might happen on another day.
///
/// The one thing not transcribed is libalpm's *phase* order. It downloads every package and
/// then validates them all. This function checks each one as it arrives, matching
/// `Transaction::verify`'s own loop, which locates and checks step by step. Piko failing fast
/// the same way in both of its paths is worth more than reproducing the order in which pacman
/// reports the same refusal.
///
/// `on_outcome` is called once per package, in `steps` order, immediately after it is located
/// and checked, before the next one is attempted. This lets a caller report progress as it
/// happens rather than only once every package has been handled. `cache` is asked *before*
/// each lookup so a caller can tell the two cases apart. Asking after `prefetch` has filled
/// the cache reports every hit as a download, which makes each run look like it re-fetched
/// everything it already had.
///
/// # Errors
///
/// Stops at the first package that cannot be located or whose signature check fails, and
/// returns that [`Error`]. Nothing after it in `steps` is attempted.
pub fn download_only(
    source: &dyn PackageSource,
    cache: &CacheDirSource,
    steps: &[Step],
    verification: &Verification,
    policy_overrides: &HashMap<String, Policy>,
    mut on_outcome: impl FnMut(DownloadOnlyOutcome),
) -> Result<()> {
    let installs: Vec<PackageFileName> = steps
        .iter()
        .filter_map(|step| match step {
            Step::Install { package, .. } => Some(package.clone()),
            Step::Remove { .. } => None,
        })
        .collect();
    // This is asked *before* anything is fetched. `prefetch` fills the cache, so a `contains`
    // call inside the loop below would answer "yes" for every package. That would report a run
    // that downloaded the whole transaction as one that downloaded nothing — the same bug as
    // the one above, in reverse.
    let cached: Vec<bool> = installs.iter().map(|package| cache.contains(package)).collect();
    source.prefetch(&installs)?;

    for (package, was_cached) in installs.iter().zip(cached) {
        let location = source.locate(package)?;
        let verified = crate::transaction::check_signature(
            verification,
            policy_overrides,
            package,
            location.path(),
        )?;
        on_outcome(DownloadOnlyOutcome {
            package: package.clone(),
            was_cached,
            size: location.size(),
            verified,
        });
    }
    Ok(())
}
