//! Turns a solved [`piko_db::solve::Plan`] into a transaction: commit-engine steps, where
//! each incoming package can be downloaded from, and under what signature policy.
//!
//! `piko install foo` is `piko plan foo` turned into a transaction. This module is that
//! translation. It lives here rather than in a frontend. So any caller building a transaction
//! on top of `piko-db`'s solver gets it once, checked. Nobody re-derives
//! `_alpm_sync_prepare`'s install-reason rule or the repository/`SigLevel` lookup by hand.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use alpm_types::{PackageFileName, PackageInstallReason};
use piko_db::EntryName;
use piko_db::config::RepositoryConfig;
use piko_db::repo::RepoName;
use piko_db::solve::{Origin, Plan, SolvableId, Step as SolveStep, Universe};
use piko_sig::Policy;

use crate::source::{CacheDirSource, DownloadTarget, DownloadingSource, PackageSource, PlanSource};
use crate::transaction::{Expected, Published, Validation, Verification};
use crate::{Error, Result, Step};

/// How each incoming package's install reason is decided.
///
/// libalpm settles this in three stages, and the last one wins. A pulled-in package is
/// `Depend` (`sync.c:492`). An upgrade copies the reason the installed copy had
/// (`add.c:476`). An `ALPM_TRANS_FLAG_ALLDEPS` or `ALLEXPLICIT` flag then overwrites whatever
/// the first two produced (`add.c:499`).
///
/// That third stage runs per package in `trans->add`, which holds the resolved dependencies
/// as well as the named targets. So a flag covers the whole transaction, not the command
/// line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReasonPolicy {
    /// No flag. A named target is `Explicit`, an upgrade keeps the reason it had, and a fresh
    /// dependency is `Depend`.
    #[default]
    AsResolved,
    /// `--asdeps`: record every incoming package as a dependency.
    AllDeps,
    /// `--asexplicit`: record every incoming package as explicitly installed.
    AllExplicit,
}

/// What `pacman.conf` and the command line say about where each incoming package comes from,
/// and what its signature is checked against.
///
/// [`TransactionPlan::new`] reads it to decide, for every package the plan installs, where it
/// is downloaded from and which signature policy it is held to, and opens the keyring when a
/// policy asks for one.
#[derive(Clone, Copy, Debug)]
pub struct PackageOrigins<'a> {
    /// Every configured repository, with its `Server`, `CacheServer` and `SigLevel`.
    pub repos: &'a [RepositoryConfig],
    /// `[options]`' `SigLevel`, which a repository with no `SigLevel` of its own inherits.
    pub sig_level: piko_db::config::SigLevel,
    /// The package files named on the command line, each with the `LocalFileSigLevel` or
    /// `RemoteFileSigLevel` policy its spelling selected.
    pub files: &'a [crate::FileTarget],
    /// `GPGDir`: the GnuPG keyring signatures are checked against, pacman's
    /// `/etc/pacman.d/gnupg`. Opened only when a policy asks for a check.
    pub gpg_dir: &'a Path,
}

/// A solved plan, turned into what a transaction needs: its steps, what the plan says each
/// incoming package is, and how each one is fetched and checked.
///
/// [`crate::Transaction::from_plan`] takes it. The parts are built together, from one plan and
/// one [`PackageOrigins`], so a transaction cannot get the steps without the rest. `verify`
/// compares:
///
/// - every archive's `.PKGINFO` with the fields the plan was solved from, as
///   `check_pkg_matches_db` does (`sync.c:1113`);
/// - every repository package with its database's `%SHA256SUM%` and `%PGPSIG%`, as
///   `_alpm_pkg_validate_internal` does (`be_package.c:279`);
/// - every package's signature under the policy of the repository it comes from, or of the
///   `LocalFileSigLevel`/`RemoteFileSigLevel` a named file was given.
///
/// The plan also holds the keyring those signatures are checked against, opened only when a
/// policy asks for one. So [`crate::Transaction::from_plan`] takes nothing else: no signature
/// check can be left off, or changed, apart from the configuration the plan was built from.
/// `SigLevel = Never` is how a transaction checks no signature, as with pacman.
///
/// A transaction built from bare steps with [`crate::Transaction::new`] gets none of these. It
/// gets the name and version check, and the `.sig` beside each file under one policy.
#[derive(Debug)]
pub struct TransactionPlan {
    steps: Vec<Step>,
    expectations: HashMap<String, Expected>,
    published: HashMap<String, Published>,
    downloads: HashMap<String, DownloadTarget>,
    policies: HashMap<String, Policy>,
    named: HashMap<String, PathBuf>,
    verification: Verification,
}

/// A [`TransactionPlan`] taken apart, for [`crate::Transaction::from_plan`].
pub(crate) struct Parts {
    pub(crate) steps: Vec<Step>,
    pub(crate) expectations: HashMap<String, Expected>,
    pub(crate) published: HashMap<String, Published>,
    pub(crate) policies: HashMap<String, Policy>,
    pub(crate) verification: Verification,
}

impl TransactionPlan {
    /// Turns `built` into commit-engine steps, and records what each incoming package must be,
    /// where it is downloaded from, and which signature policy it is held to.
    ///
    /// `targets` are the candidates the user named, which `reasons` records as explicit. See
    /// [`ReasonPolicy`]. `origins` supplies the repositories and the named files.
    ///
    /// # Errors
    ///
    /// [`Error::PlanInconsistent`], [`Error::NoRepositoryCandidate`],
    /// [`Error::RepositoryPackageUnreadable`], or [`Error::InvalidEntryName`] if `built` and
    /// `universe` disagree about what a step names. This should not happen, since `built` was
    /// assembled from `universe`. It is checked rather than assumed.
    /// [`Error::RepositoryPackageUnreadable`] also if a candidate's `desc` or `%DEPENDS%` cannot
    /// be read. [`Error::UnconfiguredSource`] if a package comes from a repository `origins` does
    /// not configure, or is a named file `origins` does not list. [`Error::KeyringUnusable`] if
    /// a policy asks for a signature check and the keyring at `origins.gpg_dir` cannot be
    /// opened.
    ///
    /// # The keyring
    ///
    /// It is opened when *any* package's policy, or the global one, asks for checking. It is
    /// never decided by the global policy alone. A global `SigLevel = Never` with one repository
    /// overriding to `PackageRequired` must still verify that repository's packages. A plan
    /// that asks for nothing anywhere opens no keyring at all, so a system without one still
    /// works. But the moment anything *does* ask, an unusable keyring is an error rather than a
    /// silent pass. Failing open here would make every package install unverified the day the
    /// keyring broke.
    pub fn new(
        universe: &Universe<'_>,
        built: &Plan,
        targets: &[SolvableId],
        reasons: ReasonPolicy,
        origins: PackageOrigins<'_>,
    ) -> Result<Self> {
        let Sources { downloads, policies, named } = sources(universe, built, origins)?;
        let steps = install_steps(universe, built, targets, reasons)?;
        let expectations = expectations(universe, built)?;
        let published = published(universe, built)?;
        let verification = verification(origins, &policies)?;
        Ok(Self { steps, expectations, published, downloads, policies, named, verification })
    }

    /// A transaction that removes `entries` and installs nothing.
    ///
    /// A removal reads no archive, so it needs nothing from a plan but the entries. `no_save`
    /// is pacman's `--nosave`, for every entry.
    #[must_use]
    pub fn removal(entries: impl IntoIterator<Item = EntryName>, no_save: bool) -> Self {
        Self {
            steps: entries.into_iter().map(|entry| Step::Remove { entry, no_save }).collect(),
            expectations: HashMap::new(),
            published: HashMap::new(),
            downloads: HashMap::new(),
            policies: HashMap::new(),
            named: HashMap::new(),
            verification: Verification::Disabled,
        }
    }

    /// The steps, in the order the transaction runs them.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Where each incoming repository package is downloaded from, keyed by cache file name.
    ///
    /// [`TransactionPlan::source`] downloads from these. A named file has no entry: nothing
    /// downloads it.
    #[must_use]
    pub const fn download_targets(&self) -> &HashMap<String, DownloadTarget> {
        &self.downloads
    }

    /// The package source this plan's transaction reads from.
    ///
    /// The named files go in front of the cache: the plan chose them, so the source must serve
    /// them. Each is served from a private `0700` copy, staged under the directory downloads go
    /// to, so the bytes the signature check reads are the bytes extraction writes. A repository
    /// package is found in `cache_dirs`, searched in order, or downloaded into the first usable
    /// one from the servers this plan recorded, `concurrency` at a time.
    ///
    /// `check_space` is `pacman.conf`'s `CheckSpace` on the download side: see
    /// [`DownloadingSource::check_space`]. Every download runs in a helper confined by
    /// `sandbox`. `progress` is called for every download event, and `cancel` stops the
    /// downloads.
    ///
    /// The source must outlive the commit. The staged copies are removed when it is dropped.
    ///
    /// # Errors
    ///
    /// As [`DownloadingSource::new`], and [`Error::Io`] if the staging directory cannot be
    /// created.
    pub fn source(
        &self,
        cache_dirs: impl IntoIterator<Item = PathBuf>,
        cancel: piko_net::Cancel,
        concurrency: piko_net::Concurrency,
        check_space: bool,
        sandbox: piko_net::Sandbox,
        progress: impl Fn(piko_net::Event) + Send + Sync + 'static,
    ) -> Result<PlanSource> {
        let downloading = DownloadingSource::new(
            cache_dirs,
            self.downloads.clone(),
            cancel,
            concurrency,
            sandbox,
            progress,
        )?
        .check_space(check_space);
        PlanSource::new(self.named.clone(), downloading)
    }

    /// The signature check this plan was built with.
    pub(crate) const fn verification(&self) -> &Verification {
        &self.verification
    }

    /// What each incoming repository package's database publishes, keyed by cache file name.
    pub(crate) const fn published(&self) -> &HashMap<String, Published> {
        &self.published
    }

    /// The signature policy each incoming package is held to, keyed by cache file name.
    pub(crate) const fn policies(&self) -> &HashMap<String, Policy> {
        &self.policies
    }

    /// The parts, for [`crate::Transaction::from_plan`].
    pub(crate) fn into_parts(self) -> Parts {
        Parts {
            steps: self.steps,
            expectations: self.expectations,
            published: self.published,
            policies: self.policies,
            verification: self.verification,
        }
    }
}

/// Turns a solved plan into commit-engine steps, resolving each incoming candidate's cache
/// file name from its repository `desc`.
///
/// # Errors
///
/// As [`TransactionPlan::new`].
fn install_steps(
    universe: &Universe<'_>,
    built: &Plan,
    targets: &[SolvableId],
    reasons: ReasonPolicy,
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
                let reason = reason_for(*candidate, targets, reasons, None);
                steps.push(Step::Install { package: file_name_of(universe, *candidate)?, reason });
            }
            SolveStep::Change { from, to, .. } => {
                let previous = universe.get(*from).and_then(|solvable| solvable.install_reason());
                let reason = reason_for(*to, targets, reasons, previous);
                steps.push(Step::Install { package: file_name_of(universe, *to)?, reason });
            }
        }
    }
    Ok(steps)
}

/// What the plan says each incoming package is, keyed by the cache file name its step installs.
///
/// [`TransactionPlan`] carries this, and `verify` compares every archive's
/// `.PKGINFO` with it: the installed size and `%DEPENDS%`, `%CONFLICTS%`, `%REPLACES%`,
/// `%PROVIDES%` and `%GROUPS%`, as `check_pkg_matches_db` does (`sync.c:1113`). A repository
/// candidate's entry comes from its `desc`. A package file named on the command line gets one
/// too, from the `.PKGINFO` the plan read; libalpm checks no such file.
///
/// # Errors
///
/// As [`install_steps`], and [`Error::RepositoryPackageUnreadable`] if a candidate's
/// `%DEPENDS%` cannot be read.
fn expectations(universe: &Universe<'_>, built: &Plan) -> Result<HashMap<String, Expected>> {
    let mut expectations = HashMap::new();
    for step in built.steps() {
        let candidate = match step {
            SolveStep::Remove { .. } => continue,
            SolveStep::Install { candidate, .. } => *candidate,
            SolveStep::Change { to, .. } => *to,
        };
        let file_name = file_name_of(universe, candidate)?;
        let Some(solvable) = universe.get(candidate) else {
            return Err(Error::PlanInconsistent { id: candidate });
        };
        let expected =
            Expected::of(&solvable).map_err(|source| Error::RepositoryPackageUnreadable {
                name: solvable.name().to_string(),
                source: std::sync::Arc::new(source),
            })?;
        expectations.insert(file_name.to_string(), expected);
    }
    Ok(expectations)
}

/// What each incoming repository package's database publishes about its file, keyed by the
/// cache file name its step installs.
///
/// [`TransactionPlan`] carries this, for `verify` and [`download_only`]. Each file is checked
/// against its `%SHA256SUM%`, and against its `%PGPSIG%` rather than the `.sig` beside it, as
/// `_alpm_pkg_validate_internal` does with the sync package (`be_package.c:279`). A package
/// file named on the command line has no entry: it has no repository.
///
/// # Errors
///
/// As [`install_steps`]: [`Error::RepositoryPackageUnreadable`] if a candidate's `desc` cannot
/// be read.
fn published(universe: &Universe<'_>, built: &Plan) -> Result<HashMap<String, Published>> {
    let mut published = HashMap::new();
    for step in built.steps() {
        let candidate = match step {
            SolveStep::Remove { .. } => continue,
            SolveStep::Install { candidate, .. } => *candidate,
            SolveStep::Change { to, .. } => *to,
        };
        let Some(solvable) = universe.get(candidate) else {
            return Err(Error::PlanInconsistent { id: candidate });
        };
        let Some(repo_package) = solvable.as_repository() else { continue };
        let desc = repo_package.desc().map_err(|source| Error::RepositoryPackageUnreadable {
            name: solvable.name().to_string(),
            source,
        })?;
        published.insert(desc.file_name().to_string(), Published::of(&desc));
    }
    Ok(published)
}

/// The reason recorded for one incoming package.
///
/// [`ReasonPolicy::AsResolved`] records `Explicit` for a package named on the command line.
/// That is `_alpm_sync_prepare`'s rule (`sync.c`), the same one
/// `piko_db::solve::Plan::assemble` applies for a fresh install. The plan itself does not
/// rename an upgrade of an already-installed package, because `solve::Step::Change` carries
/// no reason of its own. So it keeps whatever reason it already had, rather than falling to
/// `Depend`. Only a package with no previous install (a fresh dependency) defaults to
/// `Depend`.
///
/// Either override replaces that answer outright. It reaches every incoming package, and it
/// outranks the reason an upgraded package carried.
fn reason_for(
    candidate: SolvableId,
    targets: &[SolvableId],
    reasons: ReasonPolicy,
    previous: Option<PackageInstallReason>,
) -> PackageInstallReason {
    match reasons {
        ReasonPolicy::AllDeps => PackageInstallReason::Depend,
        ReasonPolicy::AllExplicit => PackageInstallReason::Explicit,
        ReasonPolicy::AsResolved if targets.contains(&candidate) => PackageInstallReason::Explicit,
        ReasonPolicy::AsResolved => previous.unwrap_or(PackageInstallReason::Depend),
    }
}

/// The name a candidate's package file is addressed by.
///
/// For a repository candidate that is `%FILENAME%`, the name it is cached and downloaded
/// under. For a package file named on the command line there is no `desc` to ask. The name is
/// rebuilt from the file's own `.PKGINFO` instead. That is the same rendering
/// [`crate::file_target::load`] produced, so [`crate::source::FileSource`] finds the path
/// again.
fn file_name_of(universe: &Universe<'_>, id: SolvableId) -> Result<PackageFileName> {
    let Some(candidate) = universe.get(id) else {
        return Err(Error::PlanInconsistent { id });
    };
    if let Some(file) = candidate.as_file() {
        return Ok(file.file_name().clone());
    }
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

/// Where each incoming package is downloaded from, and which signature policy it is held to,
/// both keyed by cache file name.
///
/// A repository package's repository is resolved through `Origin`/
/// [`Universe::repository_name`], then matched by name against `origins.repos`. It is not
/// matched by index. `Universe`'s repository index counts only the repositories that actually
/// opened, while `repos` may be longer. Matching prefers `CacheServer` over `Server`, as
/// pacman.conf(5) documents. Its policy is the repository's own `SigLevel`, resolved through
/// [`RepositoryConfig::effective_sig_level`], not read off `RepositoryConfig::sig_level`
/// directly. That field can still carry the parser's `SigLevel::USE_DEFAULT` sentinel for a
/// repository that never set one at all.
///
/// A named file is held to its `FileTarget`'s policy, `LocalFileSigLevel` or
/// `RemoteFileSigLevel`. That holds even when a repository carries a package of the same name,
/// because it is not that package.
///
/// A package with no configured source is an error, never the global policy. A repository
/// missing from `origins.repos`, or a named file missing from `origins.files`, would otherwise
/// be checked under `[options]`' `SigLevel`, which may check nothing.
///
/// # Errors
///
/// [`Error::UnconfiguredSource`], [`Error::PlanInconsistent`], or
/// [`Error::RepositoryPackageUnreadable`].
fn sources(universe: &Universe<'_>, built: &Plan, origins: PackageOrigins<'_>) -> Result<Sources> {
    let by_name: HashMap<&RepoName, &RepositoryConfig> =
        origins.repos.iter().map(|repo| (&repo.name, repo)).collect();

    let mut downloads = HashMap::new();
    let mut policies = HashMap::new();
    let mut named = HashMap::new();
    for step in built.steps() {
        let candidate = match step {
            SolveStep::Install { candidate, .. } => *candidate,
            SolveStep::Change { to, .. } => *to,
            SolveStep::Remove { .. } => continue,
        };
        let Some(solvable) = universe.get(candidate) else {
            return Err(Error::PlanInconsistent { id: candidate });
        };
        let unconfigured = |reason: String| Error::UnconfiguredSource {
            package: solvable.name().to_string(),
            reason,
        };

        if let Some(file) = solvable.as_file() {
            let file_name = file.file_name();
            let Some(target) = origins.files.iter().find(|target| target.file_name() == file_name)
            else {
                return Err(unconfigured(format!("{file_name} is not among the named files")));
            };
            policies.insert(file_name.to_string(), target.policy());
            named.insert(file_name.to_string(), target.path().to_path_buf());
            continue;
        }

        let (Origin::Repository(index), Some(repo_package)) =
            (solvable.origin(), solvable.as_repository())
        else {
            return Err(Error::NoRepositoryCandidate { name: solvable.name().to_string() });
        };
        let Some(repo_name) = universe.repository_name(index) else {
            return Err(Error::PlanInconsistent { id: candidate });
        };
        let Some(config) = by_name.get(repo_name).copied() else {
            return Err(unconfigured(format!("repository {repo_name} is not configured")));
        };
        let desc = repo_package.desc().map_err(|source| Error::RepositoryPackageUnreadable {
            name: solvable.name().to_string(),
            source,
        })?;

        let file_name = desc.file_name().to_string();
        let policy = Policy::for_package(config.effective_sig_level(origins.sig_level));
        let servers =
            if config.cache_servers.is_empty() { &config.servers } else { &config.cache_servers };
        downloads.insert(
            file_name.clone(),
            DownloadTarget {
                repo_name: repo_name.to_string(),
                servers: servers.clone(),
                policy,
                size: repo_package.compressed_size(),
            },
        );
        policies.insert(file_name, policy);
    }
    Ok(Sources { downloads, policies, named })
}

/// The signature check `policies` and `[options]`' `SigLevel` ask for, with the keyring at
/// `origins.gpg_dir` opened only if one of them asks. See [`TransactionPlan::new`].
///
/// # Errors
///
/// [`Error::KeyringUnusable`] if a keyring is needed and could not be opened.
fn verification(
    origins: PackageOrigins<'_>,
    policies: &HashMap<String, Policy>,
) -> Result<Verification> {
    let fallback = Policy::for_package(origins.sig_level);
    let needs_keyring = fallback.check || policies.values().any(|policy| policy.check);
    if !needs_keyring {
        return Ok(Verification::Disabled);
    }
    let keyring = piko_sig::Keyring::open(origins.gpg_dir)
        .map_err(|source| Error::KeyringUnusable { path: origins.gpg_dir.to_path_buf(), source })?;
    Ok(Verification::Enabled { keyring, policy: fallback })
}

/// Where each incoming package comes from, keyed by cache file name.
struct Sources {
    /// A repository package's servers and `%CSIZE%`.
    downloads: HashMap<String, DownloadTarget>,
    /// Every package's signature policy.
    policies: HashMap<String, Policy>,
    /// A named file's path.
    named: HashMap<String, PathBuf>,
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
    /// What its validation checked. The signature is unchecked under
    /// `Verification::Disabled`, or when the effective policy asks for nothing.
    pub validation: Validation,
}

/// Downloads every missing package `plan` installs into the cache, installing nothing.
///
/// This is pacman's `-Sw`.
///
/// Each [`PackageSource::locate`] call already downloads a miss and verifies nothing changed
/// about a hit. So this is the same lookup a transaction's `verify` step would make. It skips
/// the journal, the lock, and the `Transaction` that would follow it.
///
/// The package is validated here too, through the same [`crate::transaction::validate_package`]
/// `Transaction::verify` uses, under the same per-repository policy and against the same
/// `published` map. A file whose SHA-256 is not the published one, or whose signature is refused,
/// is removed from the cache, as `Transaction::verify` removes it. libalpm does this:
/// `check_validity` (`sync.c:1275`) runs *before* `_alpm_sync_load` returns on
/// `ALPM_TRANS_FLAG_DOWNLOADONLY` (`sync.c:1279`), so `pacman -Sw` refuses a package it would
/// refuse to install. Leaving the check out fills a cache with bytes nothing has vouched for.
/// It also defers the complaint to an install that might happen on another day.
///
/// The one thing not transcribed is libalpm's *phase* order. It downloads every package and
/// then validates them all. This function checks each one as it arrives, matching
/// `Transaction::verify`'s own loop, which locates and checks step by step. piko fails fast
/// the same way in both of its paths. That is worth more than reproducing the order in which
/// pacman reports the same refusal.
///
/// `on_outcome` is called once per package, in step order, immediately after it is located
/// and checked, before the next one is attempted. This lets a caller report progress as it
/// happens rather than only once every package has been handled. `cache` is asked *before*
/// each lookup so a caller can tell the two cases apart. Asking after `prefetch` has filled
/// the cache reports every hit as a download. Each run then looks like it re-fetched
/// everything it already had.
///
/// # Errors
///
/// Stops at the first package that cannot be located or fails validation, and returns that
/// [`Error`]. Nothing after it in `plan` is attempted.
pub fn download_only(
    source: &dyn PackageSource,
    cache: &CacheDirSource,
    plan: &TransactionPlan,
    mut on_outcome: impl FnMut(DownloadOnlyOutcome),
) -> Result<()> {
    let installs: Vec<PackageFileName> = plan
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::Install { package, .. } => Some(package.clone()),
            Step::Remove { .. } => None,
        })
        .collect();
    // This is asked *before* anything is fetched. `prefetch` fills the cache, so a `contains`
    // call inside the loop below would answer "yes" for every package. A run that downloaded
    // the whole transaction would then report downloading nothing. That is the failure above,
    // in reverse.
    let cached: Vec<bool> = installs.iter().map(|package| cache.contains(package)).collect();
    source.prefetch(&installs)?;

    for (package, was_cached) in installs.iter().zip(cached) {
        let location = source.locate(package)?;
        let validation = crate::transaction::validate_package(
            plan.verification(),
            plan.policies(),
            plan.published().get(&package.to_string()),
            package,
            location.path(),
        )
        .map_err(|refusal| match refusal {
            Error::ChecksumMismatch { .. } | Error::SignatureRejected { unsigned: false, .. } => {
                crate::transaction::discard(source, &location, refusal)
            }
            other => other,
        })?;
        on_outcome(DownloadOnlyOutcome {
            package: package.clone(),
            was_cached,
            size: location.size(),
            validation,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use piko_db::config::DbUsage;
    use piko_db::fixture::{PackageSpec, Scenario};
    use piko_db::solve::UniverseOptions;

    /// A keyring directory that does not exist.
    fn no_keyring() -> PathBuf {
        std::env::temp_dir().join("piko-test-no-keyring-here")
    }

    /// `core` configured with `sig_level`, and nothing else.
    fn core_config(sig_level: piko_db::config::SigLevel) -> RepositoryConfig {
        RepositoryConfig {
            name: RepoName::parse("core").unwrap(),
            servers: vec!["https://example.invalid/core".to_owned()],
            cache_servers: Vec::new(),
            usage: DbUsage::ALL,
            sig_level,
        }
    }

    /// Solves `app`, which needs `lib`, both in `core`, and builds the transaction plan with
    /// `repos` configured, `[options]`' `SigLevel = Never`, and the keyring at `gpg_dir`.
    fn app_plan(repos: &[RepositoryConfig], gpg_dir: &Path) -> Result<TransactionPlan> {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["lib"]),
                    PackageSpec::new("lib", "1.0.0-1"),
                ],
            )
            .build();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new().usage(DbUsage::ALL),
        )
        .unwrap();
        let app = *universe.candidates_named("app").first().unwrap();
        let request = piko_db::solve::Request::new().target(app);
        let limits = piko_db::Limits::default();
        let Ok(Ok(planned)) = piko_db::solve::solve_with_removals(&universe, &request, &limits)
        else {
            panic!("expected a solution");
        };
        let built = Plan::assemble(
            &universe,
            &planned,
            request.targets(),
            &limits,
            &piko_db::solve::NoCache,
        );
        let origins = PackageOrigins {
            repos,
            sig_level: piko_db::config::SigLevel::default(),
            files: &[],
            gpg_dir,
        };
        TransactionPlan::new(&universe, &built, &[app], ReasonPolicy::AsResolved, origins)
    }

    /// The cache file names a plan installs.
    fn installs(plan: &TransactionPlan) -> Vec<String> {
        plan.steps()
            .iter()
            .filter_map(|step| match step {
                Step::Install { package, .. } => Some(package.to_string()),
                Step::Remove { .. } => None,
            })
            .collect()
    }

    /// Every install step of a `TransactionPlan` carries what its package must be, keyed by the
    /// step's own file name, and `Transaction::from_plan` hands it to `verify`. Here the cached
    /// file is not the one the database publishes, so `verify` refuses it on its checksum,
    /// before it reads it as an archive.
    #[test]
    fn a_transaction_from_a_plan_compares_every_package_with_it() {
        let plan =
            app_plan(&[core_config(piko_db::config::SigLevel::default())], &no_keyring()).unwrap();
        let installs = installs(&plan);
        assert_eq!(installs.len(), 2, "{installs:?}");
        for file_name in &installs {
            assert!(plan.expectations.contains_key(file_name), "no expectation for {file_name}");
            assert!(plan.published.contains_key(file_name), "nothing published for {file_name}");
            assert!(plan.downloads.contains_key(file_name), "no download for {file_name}");
            assert!(plan.policies.contains_key(file_name), "no policy for {file_name}");
        }

        let cache = tempfile::tempdir().unwrap();
        for file_name in &installs {
            std::fs::write(cache.path().join(file_name), b"not the published bytes").unwrap();
        }
        let db = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(db.path().join("local")).unwrap();
        std::fs::write(db.path().join("local/ALPM_DB_VERSION"), "9\n").unwrap();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let error = crate::Transaction::from_plan(root.path(), db.path(), plan)
            .verify(&source)
            .unwrap_err();
        assert!(matches!(error, Error::ChecksumMismatch { .. }), "got {error:?}");
    }

    /// A repository's own `SigLevel` governs its packages, although `[options]` checks nothing.
    /// So the plan opens the keyring, and one that cannot be opened is an error, not a pass.
    #[test]
    fn a_repository_policy_is_kept_when_the_global_one_checks_nothing() {
        let required = [core_config(piko_db::config::SigLevel::PACKAGE)];
        let error = app_plan(&required, &no_keyring()).unwrap_err();
        assert!(matches!(error, Error::KeyringUnusable { .. }), "got {error:?}");

        let keys = tempfile::tempdir().unwrap();
        let plan = app_plan(&required, keys.path()).unwrap();
        for file_name in installs(&plan) {
            assert!(plan.policies.get(&file_name).unwrap().check, "{file_name} is not checked");
        }
        assert!(matches!(plan.verification(), Verification::Enabled { .. }));
    }

    /// A package from a repository the origins do not configure is refused, rather than
    /// checked under `[options]`' `SigLevel`.
    #[test]
    fn a_package_from_an_unconfigured_repository_is_refused() {
        let error = app_plan(&[], &no_keyring()).unwrap_err();
        assert!(matches!(error, Error::UnconfiguredSource { .. }), "got {error:?}");
    }

    /// Plans the named package file `tool`, held to `policy`, and builds the transaction plan
    /// with `named` as the files `PackageOrigins` lists: `true` for the file itself, `false` for
    /// none. `[options]`' `SigLevel` checks nothing.
    fn named_file_plan(
        policy: Policy,
        named: bool,
    ) -> Result<(TransactionPlan, String, tempfile::TempDir)> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool-1.0.0-1-x86_64.pkg.tar");
        let pkginfo = "pkgname = tool\npkgbase = tool\npkgver = 1.0.0-1\n\
                       pkgdesc = An example package\nurl = https://example.org/\n\
                       builddate = 1733737242\n\
                       packager = Foobar McFooface <foobar@mcfooface.org>\n\
                       size = 4096\narch = x86_64\nlicense = MIT\n";
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(pkginfo.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, ".PKGINFO", pkginfo.as_bytes()).unwrap();
        std::fs::write(&path, builder.into_inner().unwrap()).unwrap();
        let target =
            crate::file_target::load(&path, policy, &crate::extract::PackageLimits::default())
                .unwrap();

        let scenario = Scenario::new().build();
        let candidates = [target.candidate()];
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new().usage(DbUsage::ALL).files(&candidates),
        )
        .unwrap();
        let tool = *universe.file_candidates().first().unwrap();
        let request = piko_db::solve::Request::new().target(tool);
        let limits = piko_db::Limits::default();
        let Ok(Ok(planned)) = piko_db::solve::solve_with_removals(&universe, &request, &limits)
        else {
            panic!("expected a solution");
        };
        let built = Plan::assemble(
            &universe,
            &planned,
            request.targets(),
            &limits,
            &piko_db::solve::NoCache,
        );

        let files = if named { std::slice::from_ref(&target) } else { &[] };
        // An empty keyring: enough to open, which a required policy needs.
        let gpg_dir = dir.path().join("gnupg");
        std::fs::create_dir(&gpg_dir).unwrap();
        let origins = PackageOrigins {
            repos: &[],
            sig_level: piko_db::config::SigLevel::default(),
            files,
            gpg_dir: &gpg_dir,
        };
        let file_name = target.file_name().to_string();
        TransactionPlan::new(&universe, &built, &[tool], ReasonPolicy::AsResolved, origins)
            .map(|plan| (plan, file_name, dir))
    }

    /// A named file that `PackageOrigins` does not list is refused, rather than checked under
    /// `[options]`' `SigLevel`. Listed, it is held to its own policy, here a required signature
    /// that the global `SigLevel = Never` would not ask for.
    #[test]
    fn a_named_file_missing_from_the_origins_is_refused() {
        let required = Policy::for_package(piko_db::config::SigLevel::PACKAGE);

        let error = named_file_plan(required, false).unwrap_err();
        assert!(matches!(error, Error::UnconfiguredSource { .. }), "got {error:?}");

        let (plan, file_name, _dir) = named_file_plan(required, true).unwrap();
        assert_eq!(plan.policies.get(&file_name), Some(&required));
        assert!(plan.download_targets().is_empty(), "a named file is not downloaded");
    }

    /// The source of a plan with signature checking left to nothing: `cache` searched, no
    /// download expected.
    fn source_over(plan: &TransactionPlan, cache: &Path) -> PlanSource {
        plan.source(
            [cache.to_path_buf()],
            piko_net::Cancel::new(),
            piko_net::Concurrency::new(1),
            false,
            piko_net::Sandbox::disabled(),
            |_| {},
        )
        .unwrap()
    }

    /// The source a plan builds serves a named file from a private copy under the download
    /// directory, never from the path the user named. The copy holds the same bytes.
    #[test]
    fn a_plan_source_serves_a_named_file_from_a_private_copy() {
        let never = Policy::for_package(piko_db::config::SigLevel::default());
        let (plan, file_name, dir) = named_file_plan(never, true).unwrap();
        let cache = tempfile::tempdir().unwrap();
        let source = source_over(&plan, cache.path());
        assert_eq!(source.download_dir().path(), cache.path());

        let location = source.locate(&file_name.parse().unwrap()).unwrap();
        let named = dir.path().join(&file_name);
        assert_ne!(location.path(), named, "the user's own path was served");
        let staged = location.path().strip_prefix(cache.path()).unwrap();
        let staging = staged.components().next().unwrap().as_os_str().to_string_lossy();
        assert!(
            staging.starts_with(crate::source::STAGING_PREFIX),
            "{}",
            location.path().display()
        );
        assert_eq!(std::fs::read(location.path()).unwrap(), std::fs::read(named).unwrap());
    }

    /// The source a plan builds finds a repository package in the cache, and downloads nothing.
    #[test]
    fn a_plan_source_serves_a_repository_package_from_the_cache() {
        let plan =
            app_plan(&[core_config(piko_db::config::SigLevel::default())], &no_keyring()).unwrap();
        let cache = tempfile::tempdir().unwrap();
        for file_name in installs(&plan) {
            std::fs::write(cache.path().join(&file_name), b"cached").unwrap();
        }
        let source = source_over(&plan, cache.path());

        for file_name in installs(&plan) {
            let location = source.locate(&file_name.parse().unwrap()).unwrap();
            assert_eq!(location.path(), cache.path().join(&file_name));
        }
    }

    /// A plan that asks for no check anywhere opens no keyring, so a missing one is no error.
    #[test]
    fn a_plan_that_checks_nothing_needs_no_keyring() {
        let plan =
            app_plan(&[core_config(piko_db::config::SigLevel::default())], &no_keyring()).unwrap();
        assert!(matches!(plan.verification(), Verification::Disabled));
    }

    /// Two candidate ids: the one a command line named, and one the solver pulled in.
    fn named_and_pulled() -> (SolvableId, SolvableId) {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("app", "1.0.0-1"), PackageSpec::new("lib", "1.0.0-1")])
            .build();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new().usage(DbUsage::ALL),
        )
        .unwrap();
        let named = *universe.candidates_named("app").first().unwrap();
        let pulled = *universe.candidates_named("lib").first().unwrap();
        (named, pulled)
    }

    #[test]
    fn a_named_target_is_explicit_and_a_pulled_dependency_is_not() {
        let (named, pulled) = named_and_pulled();
        let targets = [named];
        let policy = ReasonPolicy::AsResolved;

        assert_eq!(
            reason_for(named, &targets, policy, None),
            PackageInstallReason::Explicit,
            "the package the user asked for"
        );
        assert_eq!(
            reason_for(pulled, &targets, policy, None),
            PackageInstallReason::Depend,
            "a fresh package nothing named"
        );
    }

    /// `add.c:476`: an upgrade copies the reason the installed copy carried. A dependency
    /// therefore stays a dependency through an upgrade.
    #[test]
    fn an_upgrade_keeps_the_reason_it_had() {
        let (named, pulled) = named_and_pulled();
        let targets = [named];

        assert_eq!(
            reason_for(
                pulled,
                &targets,
                ReasonPolicy::AsResolved,
                Some(PackageInstallReason::Depend)
            ),
            PackageInstallReason::Depend
        );
        assert_eq!(
            reason_for(
                pulled,
                &targets,
                ReasonPolicy::AsResolved,
                Some(PackageInstallReason::Explicit)
            ),
            PackageInstallReason::Explicit
        );
    }

    /// `add.c:499`: either override runs last and covers every incoming package. It reaches a
    /// dependency the command line never named, and an upgrade that carried its own reason.
    #[test]
    fn an_override_covers_the_whole_transaction_and_outranks_the_previous_reason() {
        let (named, pulled) = named_and_pulled();
        let targets = [named];

        for candidate in [named, pulled] {
            for previous in [None, Some(PackageInstallReason::Explicit)] {
                assert_eq!(
                    reason_for(candidate, &targets, ReasonPolicy::AllDeps, previous),
                    PackageInstallReason::Depend,
                    "--asdeps"
                );
            }
            for previous in [None, Some(PackageInstallReason::Depend)] {
                assert_eq!(
                    reason_for(candidate, &targets, ReasonPolicy::AllExplicit, previous),
                    PackageInstallReason::Explicit,
                    "--asexplicit"
                );
            }
        }
    }
}
