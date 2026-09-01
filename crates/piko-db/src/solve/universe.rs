//! The indexed candidate set a plan is solved against.
//!
//! A [`Universe`] interns every package that could take part in a transaction — each
//! installed package, and each package in each configured repository — behind a dense
//! [`SolvableId`]. It builds the indexes dependency solving actually queries:
//!
//! - **by name**, for `_alpm_depcmp_literal` and for the "at most one package per name"
//!   constraint;
//! - **by `%PROVIDES%`**, keyed by name for every **alpm-sonamev1** form and for a named
//!   relation, and by the whole rendered value for **alpm-sonamev2**. The key is only a hash
//!   bucket — [`crate::depcmp::provides_satisfies`] still decides. But the key must be no
//!   finer than what matching compares, which is why the named and soname grammars share one
//!   index instead of getting one each;
//! - **by `%CONFLICTS%` target**, because `_alpm_outerconflicts` (`conflict.c`) checks both
//!   directions. A package already installed may declare the conflict against an incoming one
//!   rather than the other way round;
//! - **by `%GROUPS%`**, so a target naming a group can expand to its members the way
//!   `pacman -S gnome` does.
//!
//! # Why the installed set is read eagerly
//!
//! [`crate::LocalPackage::desc`] is lazy, so building this index forces every installed
//! package's `desc` — 1157 file reads on the machine this was developed against, which
//! `piko list` never performs. That cost was measured before being accepted: about **85 ms**,
//! on top of the **671 ms** the same run already spends opening `core` and `extra`. Expanding
//! the installed side lazily, as a cone around the targets, would save at most that 12%. It
//! would also make every accessor here fallible and every solver step able to fail on I/O.
//! The measurement did not justify that complexity.
//!
//! An installed package whose `desc` cannot be read is therefore a hard
//! [`Error::PlanLocalDescUnreadable`], not a diagnostic. This is the one place where piko is
//! *stricter* than the rest of the crate. Elsewhere a broken entry costs you only that entry.
//! But a transaction planned against an installed set that is
//! only partly readable is a transaction planned against the wrong system. An unreadable
//! entry is indistinguishable from an absent one at exactly the moment that difference
//! decides whether a package is installed, upgraded, or left alone.

use std::collections::HashMap;

use alpm_types::{FullVersion, Name, PackageRelation, RelationOrSoname};

use crate::{
    EagerView, Error, Limits, LocalDatabase, LocalPackage, Result,
    config::DbUsage,
    depcmp,
    repo::{RepoDatabase, RepoName, RepoPackage},
    resolve::IgnoreList,
};

/// A dense identifier for one candidate package within a [`Universe`].
///
/// Only a [`Universe`] mints these, and one is meaningful only to the universe that minted
/// it. The representation is a `u32` so the solver can pack an id and a sign into a single
/// word without arithmetic that could overflow — see [`Universe::len`], which is bounded well
/// below [`u32::MAX`] by
/// [`Limits::solve_max_solvables`](crate::Limits::solve_max_solvables).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SolvableId(u32);

impl SolvableId {
    /// This id as an index into the universe's parallel arrays.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// The raw identifier, for a solver packing it into a literal.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Rebuilds an id from the raw value [`SolvableId::get`] produced.
    ///
    /// Crate-visible rather than public. Only [`crate::solve::Lit`] unpacks one. Letting a
    /// caller invent an id would make [`Universe::get`]'s `Option` meaningless.
    #[must_use]
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}

/// Where a candidate came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    /// Already installed, from the local database.
    Installed,
    /// Available from the configured repository at this index, in `pacman.conf` order —
    /// which **is** priority order.
    Repository(usize),
}

/// One candidate, resolved from a [`SolvableId`].
///
/// Holds its [`Source`] by value rather than by reference. [`Source`] is two words and
/// [`Copy`], so every accessor borrows the underlying package for `'a` rather than for as long
/// as the [`Universe`] is borrowed. Without that, indexing the universe by `&'a str` keys
/// taken from its own candidates would not typecheck.
#[derive(Clone, Copy, Debug)]
pub struct Solvable<'a> {
    id: SolvableId,
    source: Source<'a>,
}

impl<'a> Solvable<'a> {
    /// This candidate's identifier.
    #[must_use]
    pub const fn id(&self) -> SolvableId {
        self.id
    }

    /// Where the candidate came from.
    #[must_use]
    pub const fn origin(&self) -> Origin {
        match self.source {
            Source::Local { .. } => Origin::Installed,
            Source::Repo { index, .. } => Origin::Repository(index),
        }
    }

    /// Whether this candidate is the installed copy of its package.
    #[must_use]
    pub const fn is_installed(&self) -> bool {
        matches!(self.source, Source::Local { .. })
    }

    /// The package name, taken from the entry directory name rather than from `desc`.
    #[must_use]
    pub const fn name(&self) -> &'a Name {
        match self.source {
            Source::Local { package, .. } => package.name(),
            Source::Repo { package, .. } => package.name(),
        }
    }

    /// The package version, likewise from the entry directory name.
    #[must_use]
    pub const fn version(&self) -> &'a FullVersion {
        match self.source {
            Source::Local { package, .. } => package.version(),
            Source::Repo { package, .. } => package.version(),
        }
    }

    /// `%DEPENDS%`.
    ///
    /// The only accessor on this type that can fail, and deliberately so. A repository
    /// candidate's `%DEPENDS%` converts on first access rather than at open — see
    /// [`crate::eager::Depends`] — because only the solvables inside `encode`'s reachable
    /// cone ever need it: 16% of the universe on this machine. An installed package's
    /// `%DEPENDS%` is already in the eager tier, so this arm never fails.
    ///
    /// # Errors
    ///
    /// [`Error::RepoDescFields`] if the candidate's `%DEPENDS%` does not parse. The failure
    /// is cached on the package, so re-reading it costs nothing and reports the same thing.
    pub fn depends(&self) -> Result<&'a [RelationOrSoname]> {
        match self.source {
            Source::Local { eager, .. } => Ok(eager.depends()),
            Source::Repo { package, .. } => package.depends().map_err(|source| {
                Error::PlanRepoDependsUnreadable { name: package.name().clone(), source }
            }),
        }
    }

    /// `%DEPENDS%` for an **installed** candidate, infallibly.
    ///
    /// `None` for a repository candidate, whose `%DEPENDS%` is deferred and may fail to
    /// convert. Use [`Self::depends`] for those.
    ///
    /// This exists so a walk that only ever visits installed packages says so in its types,
    /// rather than handling an error it cannot produce. Three walks do this: `solve::why`'s
    /// dependent index, and both dependency walks in
    /// [`recurse_unneeded`](crate::solve::recurse_unneeded). Their inputs are a removal plan,
    /// so they are installed by construction.
    #[must_use]
    pub const fn installed_depends(&self) -> Option<&'a [RelationOrSoname]> {
        match self.source {
            Source::Local { eager, .. } => Some(eager.depends()),
            Source::Repo { .. } => None,
        }
    }

    /// `%PROVIDES%`.
    #[must_use]
    pub fn provides(&self) -> &'a [RelationOrSoname] {
        match self.source {
            Source::Local { eager, .. } => eager.provides(),
            Source::Repo { package, .. } => package.provides(),
        }
    }

    /// `%REASON%`: whether the user asked for this package or it arrived as a dependency.
    ///
    /// `None` for a repository candidate — the field exists only in a local `desc`, because
    /// the reason is a property of *this* installation rather than of the package.
    #[must_use]
    pub fn install_reason(&self) -> Option<alpm_types::PackageInstallReason> {
        match self.source {
            Source::Local { eager, .. } => Some(eager.install_reason()),
            Source::Repo { .. } => None,
        }
    }

    /// `%GROUPS%`.
    #[must_use]
    pub fn groups(&self) -> &'a [alpm_types::Group] {
        match self.source {
            Source::Local { eager, .. } => eager.groups(),
            Source::Repo { package, .. } => package.groups(),
        }
    }

    /// `%CONFLICTS%`.
    #[must_use]
    pub fn conflicts(&self) -> &'a [PackageRelation] {
        match self.source {
            Source::Local { eager, .. } => eager.conflicts(),
            Source::Repo { package, .. } => package.conflicts(),
        }
    }

    /// `%REPLACES%`.
    #[must_use]
    pub fn replaces(&self) -> &'a [PackageRelation] {
        match self.source {
            Source::Local { eager, .. } => eager.replaces(),
            Source::Repo { package, .. } => package.replaces(),
        }
    }

    /// `%SIZE%` (installed) or `%ISIZE%` (repository): the space the package occupies once it
    /// is installed.
    #[must_use]
    pub fn installed_size(&self) -> u64 {
        match self.source {
            Source::Local { eager, .. } => eager.installed_size(),
            Source::Repo { package, .. } => package.installed_size(),
        }
    }

    /// `%CSIZE%`: the download size, or `None` for an already-installed package, which has
    /// nothing to download and whose local `desc` does not record the field
    /// (`be_local.c`: "csize is irrelevant once installed").
    #[must_use]
    pub fn download_size(&self) -> Option<u64> {
        match self.source {
            Source::Local { .. } => None,
            Source::Repo { package, .. } => Some(package.compressed_size()),
        }
    }

    /// Whether this candidate satisfies `dep`, literally or through `%PROVIDES%` —
    /// `_alpm_depcmp` in full.
    ///
    /// This is what `%CONFLICTS%` matching needs. `check_conflict` (`conflict.c`) calls
    /// `_alpm_depcmp`, so a package conflicts with anything *providing* the named thing, not
    /// only with the package of that name.
    #[must_use]
    pub fn satisfies(&self, dep: &PackageRelation) -> bool {
        depcmp::satisfies(self.name(), self.version(), self.provides(), dep)
    }

    /// The installed package this candidate is, or `None` if it comes from a repository.
    #[must_use]
    pub const fn as_installed(&self) -> Option<&'a LocalPackage> {
        match self.source {
            Source::Local { package, .. } => Some(package),
            Source::Repo { .. } => None,
        }
    }

    /// The repository package this candidate is, or `None` if it is the installed copy.
    #[must_use]
    pub const fn as_repository(&self) -> Option<&'a RepoPackage> {
        match self.source {
            Source::Local { .. } => None,
            Source::Repo { package, .. } => Some(package),
        }
    }
}

/// The backing package a [`SolvableId`] refers to.
///
/// A local package carries its resolved [`EagerView`]. `LocalPackage::eager` is fallible, and
/// forcing it once at build removes every subsequent fallible lookup.
///
/// It is deliberately the **eager** view rather than [`crate::DescView`]. Every field this
/// module reads — the relation sections, `%GROUPS%`, `%REASON%`, `%SIZE%` — is in that tier.
/// A plan never pays for `alpm-db`'s typed conversion of `%LICENSE%`, `%URL%`, `%PACKAGER%`
/// and the checksum fields. Measured across this machine's 1206 installed packages:
/// **23.4 ms** for the full parse against **6.1 ms** for what is used.
///
/// A repository package carries no view for the same reason. Every field this module reads —
/// `%DEPENDS%`, `%PROVIDES%`, `%CONFLICTS%`, `%REPLACES%`, `%GROUPS%`, `%CSIZE%`, `%ISIZE%` —
/// is already parsed on [`RepoPackage`] itself, infallibly, by the time the database opens
/// (see [`crate::repo::RepoPackage`]'s two tiers). Holding a `RepoDescView` here would force
/// the *deferred* parse for all ~15 000 candidates, undoing the reason that split exists.
#[derive(Clone, Copy, Debug)]
enum Source<'a> {
    Local { package: &'a LocalPackage, eager: EagerView<'a> },
    Repo { index: usize, package: &'a RepoPackage },
}

/// How a [`Universe`] is built: which repositories count, and what is ignored.
///
/// `Usage` is a parameter rather than a constant because libalpm applies three different
/// masks at three call sites. `alpm_sync_get_new_version` (`-Qu`) applies none at all, `-Su`
/// target collection gates on `Upgrade` alone, and `resolvedep` gates on `Install|Upgrade`.
#[derive(Clone, Copy, Debug)]
pub struct UniverseOptions<'a> {
    usage: DbUsage,
    ignores: IgnoreList<'a>,
    limits: Limits,
}

impl Default for UniverseOptions<'_> {
    fn default() -> Self {
        Self { usage: DbUsage::INSTALL, ignores: IgnoreList::default(), limits: Limits::default() }
    }
}

impl<'a> UniverseOptions<'a> {
    /// `resolvedep`'s policy: a repository counts if its `Usage` includes `Install` or
    /// `Upgrade`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requires `usage` of a repository for its packages to be candidates at all.
    ///
    /// A repository is admitted when it carries **any** bit in `usage`, matching libalpm's
    /// `db->usage & (ALPM_DB_USAGE_INSTALL|ALPM_DB_USAGE_UPGRADE)` test.
    #[must_use]
    pub const fn usage(mut self, usage: DbUsage) -> Self {
        self.usage = usage;
        self
    }

    /// Applies `pacman.conf`'s `IgnorePkg`/`IgnoreGroup` to repository candidates.
    ///
    /// This never filters installed packages. `IgnorePkg` means "do not upgrade it", not
    /// "pretend it is not there". A planner that lost sight of an installed package would
    /// plan to install it again.
    #[must_use]
    pub const fn ignores(mut self, ignores: IgnoreList<'a>) -> Self {
        self.ignores = ignores;
        self
    }

    /// Overrides the resource bounds.
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

/// Every package a transaction could involve, indexed for solving.
#[derive(Debug)]
pub struct Universe<'a> {
    sources: Box<[Source<'a>]>,
    repo_names: Box<[&'a RepoName]>,
    /// Each admitted repository's `Usage`, so a caller can apply a *different* gate than the
    /// one the universe was built with — `-Su` gates on `Upgrade` alone (`sync.c:229`) while
    /// resolving its targets' dependencies still gates on `Install|Upgrade`.
    repo_usage: Box<[DbUsage]>,
    by_name: HashMap<&'a str, Vec<SolvableId>>,
    /// `%PROVIDES%` entries, keyed by [`Universe::provides_key`].
    ///
    /// One index rather than one per grammar. A dependency written `libsharpyuv.so` and a provide
    /// written `libsharpyuv.so=0-64` are both **alpm-sonamev1**, but different variants of it.
    /// libalpm has no soname concept at all: it compares plain name/version strings, and it
    /// matches them. Any key finer than the name misses exactly the pairs the index exists to
    /// find. The key is only a hash bucket; [`crate::depcmp::provides_satisfies`] still decides.
    provides: HashMap<Box<str>, Vec<SolvableId>>,
    conflicts_on: HashMap<&'a str, Vec<SolvableId>>,
    /// `%GROUPS%` membership, for a target that names a group rather than a package.
    groups: HashMap<&'a str, Vec<SolvableId>>,
    /// `%REPLACES%` entries, keyed by the name being replaced.
    ///
    /// `check_replacers` (`sync.c:124`) scans a whole repository per installed package. At
    /// 1157 installed against 15 200 available, that is 17 million comparisons. Sysupgrade
    /// needs the reverse index instead.
    replaces: HashMap<&'a str, Vec<SolvableId>>,
}

impl<'a> Universe<'a> {
    /// Indexes `local` together with `repos`, given in `pacman.conf` order.
    ///
    /// Candidates are interned installed-set first, then repository by repository in the
    /// order given, and within a repository in its own (name-sorted) order.
    /// [`Universe::candidates_named`] returns it unchanged.
    ///
    /// # Errors
    ///
    /// [`Error::PlanLocalDescUnreadable`] if an installed package's `desc` cannot be read,
    /// and [`Error::TooManySolvables`] if the combined candidate set exceeds
    /// [`Limits::solve_max_solvables`](crate::Limits::solve_max_solvables).
    pub fn build(
        local: &'a LocalDatabase,
        repos: impl IntoIterator<Item = (DbUsage, &'a RepoDatabase)>,
        options: UniverseOptions<'a>,
    ) -> Result<Self> {
        let admitted: Vec<(DbUsage, &'a RepoDatabase)> =
            repos.into_iter().filter(|(usage, _)| admits(*usage, options.usage)).collect();

        // The bound is checked before anything is interned. An oversized problem then costs
        // an addition rather than an index. A counting bound must fire where it prevents the work.
        let total = admitted
            .iter()
            .fold(local.len(), |count, (_, repository)| count.saturating_add(repository.len()));
        if total > options.limits.solve_max_solvables {
            return Err(Error::TooManySolvables { max: options.limits.solve_max_solvables });
        }

        let mut sources: Vec<Source<'a>> = Vec::with_capacity(total);
        for package in local {
            let eager = package.eager().map_err(|source| Error::PlanLocalDescUnreadable {
                name: package.name().clone(),
                source,
            })?;
            sources.push(Source::Local { package, eager });
        }
        for (index, (_, repository)) in admitted.iter().enumerate() {
            for package in *repository {
                if options.ignores.ignores(package) {
                    continue;
                }
                sources.push(Source::Repo { index, package });
            }
        }

        let repo_names: Box<[&'a RepoName]> =
            admitted.iter().map(|(_, repository)| repository.name()).collect();
        let repo_usage: Box<[DbUsage]> = admitted.iter().map(|(usage, _)| *usage).collect();

        let sources = sources.into_boxed_slice();
        let mut universe = Self {
            by_name: HashMap::new(),
            provides: HashMap::new(),
            conflicts_on: HashMap::new(),
            groups: HashMap::new(),
            replaces: HashMap::new(),
            sources,
            repo_names,
            repo_usage,
        };
        universe.index();
        Ok(universe)
    }

    /// Fills the three indexes in interning order, so every bucket comes out in the priority
    /// order [`Universe::build`] established.
    fn index(&mut self) {
        // Collected first so the borrow of `self.sources` ends before the maps are touched.
        // The keys borrow the *packages*, which outlive this universe, not the `Vec` holding
        // the sources.
        let entries: Vec<(SolvableId, Source<'a>)> = self
            .sources
            .iter()
            .enumerate()
            .filter_map(|(position, source)| {
                // Unreachable. `solve_max_solvables` is far below `u32::MAX`, and `build`
                // checks it before interning anything.
                u32::try_from(position).ok().map(|raw| (SolvableId(raw), *source))
            })
            .collect();

        for (id, source) in entries {
            let solvable = Solvable { id, source };

            self.by_name.entry(solvable.name().as_ref()).or_default().push(id);

            for provided in solvable.provides() {
                self.provides.entry(Self::provides_key(provided)).or_default().push(id);
            }

            for conflict in solvable.conflicts() {
                self.conflicts_on.entry(conflict.name.as_ref()).or_default().push(id);
            }

            // Only repository candidates. `pacman -S <group>` installs the group's members
            // from a repository. An installed member is already accounted for by the "must
            // remain" clause, not by being a target.
            if !solvable.is_installed() {
                for group in solvable.groups() {
                    self.groups.entry(group.as_ref()).or_default().push(id);
                }
                for replaces in solvable.replaces() {
                    self.replaces.entry(replaces.name.as_ref()).or_default().push(id);
                }
            }
        }
    }

    /// The number of candidates.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether there are no candidates at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Resolves an id minted by this universe.
    #[must_use]
    pub fn get(&self, id: SolvableId) -> Option<Solvable<'a>> {
        self.sources.get(id.index()).map(|source| Solvable { id, source: *source })
    }

    /// Every candidate, in interning order.
    pub fn iter(&self) -> impl Iterator<Item = Solvable<'a>> {
        self.sources.iter().enumerate().filter_map(|(position, source)| {
            u32::try_from(position)
                .ok()
                .map(|raw| Solvable { id: SolvableId(raw), source: *source })
        })
    }

    /// The `Usage` configured for the repository at `index`.
    #[must_use]
    pub fn repository_usage(&self, index: usize) -> Option<DbUsage> {
        self.repo_usage.get(index).copied()
    }

    /// The name of the repository at `index`, as [`Origin::Repository`] reports it.
    #[must_use]
    pub fn repository_name(&self, index: usize) -> Option<&'a RepoName> {
        self.repo_names.get(index).copied()
    }

    /// Every candidate literally named `name`, installed copy first, then repositories in
    /// priority order.
    ///
    /// This is also the "at most one package per name" group the solver constrains.
    #[must_use]
    pub fn candidates_named(&self, name: &str) -> &[SolvableId] {
        self.by_name.get(name).map_or(&[], Vec::as_slice)
    }

    /// Every candidate satisfying `dep`, in the order libalpm would have preferred them.
    ///
    /// Ordering is the whole point. It reproduces `resolvedep` (`deps.c`):
    ///
    /// 1. **Literal matches** — installed copy first, then repositories in priority order.
    ///    This is where "a package automatically provides its own name and version" comes
    ///    from. Never populated for a soname, which is not a package name.
    /// 2. **Installed providers**, mirroring the short-circuit at `deps.c:709` that returns an
    ///    already-installed provider without ever building the full `providers` list.
    /// 3. **Every other provider**, in repository-then-scan order.
    ///
    /// Real libalpm stops after step 1 when it finds anything: a literal hit `return`s before
    /// `%PROVIDES%` is consulted at all. This function returns the providers too, so a solver
    /// can *back out* of a literal choice that later turns out to conflict — a case where
    /// libalpm simply fails. The literal candidates come first, so a solver that always takes
    /// the head of this list reproduces libalpm exactly. The rest of the list is reachable
    /// only by backtracking.
    #[must_use]
    pub fn satisfiers(&self, dep: &RelationOrSoname) -> Vec<SolvableId> {
        let mut found = Vec::new();

        if let RelationOrSoname::Relation(relation) = dep {
            for id in self.candidates_named(relation.name.as_ref()) {
                if let Some(solvable) = self.get(*id)
                    && depcmp::version_satisfies(solvable.version(), relation)
                {
                    found.push(*id);
                }
            }
        }

        // Looked up by the same key the entries were filed under. A v1 relation keys by its
        // name, which is borrowed and costs nothing. Only **alpm-sonamev2**, which is matched
        // whole, needs the rendered string.
        let rendered;
        let key: &str = match crate::depcmp::v1_name(dep) {
            Some(name) => name,
            None => {
                rendered = dep.to_string();
                &rendered
            }
        };
        let providers = self.provides.get(key).map_or(&[][..], Vec::as_slice);

        // Installed providers first (`deps.c:709`), then the rest, each already in
        // repository-then-scan order because the index was filled in interning order.
        for installed_pass in [true, false] {
            for id in providers {
                let Some(solvable) = self.get(*id) else { continue };
                if solvable.is_installed() != installed_pass || found.contains(id) {
                    continue;
                }
                // `resolvedep`'s `pkg->name_hash != dep->name_hash` guard. A package named
                // after the dependency is step 1's business. It must not reappear here via a
                // self-referential `%PROVIDES%` entry when its own version did not match.
                if depcmp::dep_name(dep).is_some_and(|name| solvable.name() == name) {
                    continue;
                }
                if solvable
                    .provides()
                    .iter()
                    .any(|provided| depcmp::provides_satisfies(provided, dep))
                {
                    found.push(*id);
                }
            }
        }

        found
    }

    /// The bucket a `%PROVIDES%` entry (or a dependency) is filed under.
    ///
    /// The name, for every **alpm-sonamev1** form and for a named relation. The whole
    /// rendered value, for **alpm-sonamev2**, which is matched exactly and so can key on
    /// itself.
    fn provides_key(value: &RelationOrSoname) -> Box<str> {
        crate::depcmp::v1_name(value)
            .map_or_else(|| value.to_string().into_boxed_str(), |name| name.into())
    }

    /// Every repository candidate whose `%REPLACES%` names `name`, in priority then scan
    /// order.
    ///
    /// Whether the replacement actually applies still needs a version check. `check_replacers`
    /// (`sync.c:124`) matches with `_alpm_depcmp_literal` **only** — its own comment says "we
    /// only want to consider literal matches at this point". So a `%REPLACES%` entry never
    /// fires through `%PROVIDES%` the way a `%CONFLICTS%` entry does.
    #[must_use]
    pub fn replacers_of(&self, name: &str) -> &[SolvableId] {
        self.replaces.get(name).map_or(&[], Vec::as_slice)
    }

    /// Every repository candidate belonging to the `%GROUPS%` group `name`, in priority then
    /// scan order. Empty if `name` names no group.
    #[must_use]
    pub fn group_members(&self, name: &str) -> Vec<SolvableId> {
        self.groups.get(name).cloned().unwrap_or_default()
    }

    /// Every candidate declaring a `%CONFLICTS%` entry against `name`.
    ///
    /// The reverse direction of `_alpm_outerconflicts` (`conflict.c`). An installed package
    /// may name an incoming one, rather than the other way round, and libalpm checks both.
    /// Whether the conflict actually applies still needs [`crate::depcmp`], because a conflict
    /// matches through `%PROVIDES%` as well as literally.
    #[must_use]
    pub fn conflicting_with(&self, name: &str) -> &[SolvableId] {
        self.conflicts_on.get(name).map_or(&[], Vec::as_slice)
    }

    /// The installed candidate named `name`, if there is one.
    #[must_use]
    pub fn installed_named(&self, name: &str) -> Option<Solvable<'a>> {
        self.candidates_named(name)
            .iter()
            .find_map(|id| self.get(*id).filter(Solvable::is_installed))
    }
}

/// Whether a repository whose `Usage` is `usage` is admitted under `required`.
///
/// Any overlapping bit admits it, matching libalpm's
/// `db->usage & (ALPM_DB_USAGE_INSTALL|ALPM_DB_USAGE_UPGRADE)`. An empty `required` admits
/// everything — `alpm_sync_get_new_version`'s ungated policy.
fn admits(usage: DbUsage, required: DbUsage) -> bool {
    for flag in [DbUsage::SYNC, DbUsage::SEARCH, DbUsage::INSTALL, DbUsage::UPGRADE] {
        if required.contains(flag) && usage.contains(flag) {
            return true;
        }
    }
    !(required.contains(DbUsage::SYNC)
        || required.contains(DbUsage::SEARCH)
        || required.contains(DbUsage::INSTALL)
        || required.contains(DbUsage::UPGRADE))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::fixture::{BuiltScenario, PackageSpec, Scenario};

    /// Every repository in `scenario`, at `Usage = All`, under `resolvedep`'s policy.
    fn universe(scenario: &BuiltScenario) -> Universe<'_> {
        Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap()
    }

    fn relation(text: &str) -> RelationOrSoname {
        text.parse().unwrap()
    }

    fn names<'a>(universe: &Universe<'a>, ids: &[SolvableId]) -> Vec<&'a str> {
        ids.iter().map(|id| universe.get(*id).unwrap().name().as_ref()).collect()
    }

    #[test]
    fn interns_the_installed_set_and_every_repository() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("installed-only", "1.0.0-1"))
            .repo("core", [PackageSpec::new("a", "1.0.0-1")])
            .repo("extra", [PackageSpec::new("b", "1.0.0-1")])
            .build();
        let universe = universe(&scenario);

        assert_eq!(universe.len(), 3);
        assert_eq!(universe.repository_name(0).unwrap().as_str(), "core");
        assert_eq!(universe.repository_name(1).unwrap().as_str(), "extra");
        assert!(universe.repository_name(2).is_none());
    }

    /// The installed copy must come first, then repositories in priority order. Every later
    /// "first match wins" behavior is this ordering and nothing else.
    #[test]
    fn candidates_are_ordered_installed_first_then_by_repository_priority() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("foo", "1.0.0-1"))
            .repo("core", [PackageSpec::new("foo", "2.0.0-1")])
            .repo("extra", [PackageSpec::new("foo", "3.0.0-1")])
            .build();
        let universe = universe(&scenario);

        let candidates = universe.candidates_named("foo");
        assert_eq!(candidates.len(), 3);
        let origins: Vec<_> =
            candidates.iter().map(|id| universe.get(*id).unwrap().origin()).collect();
        assert_eq!(origins, [Origin::Installed, Origin::Repository(0), Origin::Repository(1)]);
    }

    #[test]
    fn a_literal_match_precedes_every_provider() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("provider", "1.0.0-1").provides(["foo"]),
                    PackageSpec::new("foo", "1.0.0-1"),
                ],
            )
            .build();
        let universe = universe(&scenario);

        let found = universe.satisfiers(&relation("foo"));
        assert_eq!(names(&universe, &found), ["foo", "provider"]);
    }

    /// `deps.c:709` returns an already-installed provider without building the full list. An
    /// installed provider must therefore outrank a repository one.
    #[test]
    fn an_installed_provider_outranks_a_repository_provider() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("installed-impl", "1.0.0-1").provides(["virtual"]))
            .repo("core", [PackageSpec::new("repo-impl", "1.0.0-1").provides(["virtual"])])
            .build();
        let universe = universe(&scenario);

        let found = universe.satisfiers(&relation("virtual"));
        assert_eq!(names(&universe, &found), ["installed-impl", "repo-impl"]);
    }

    #[test]
    fn a_version_constraint_filters_literal_candidates() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("foo", "1.0.0-1")])
            .repo("extra", [PackageSpec::new("foo", "3.0.0-1")])
            .build();
        let universe = universe(&scenario);

        let found = universe.satisfiers(&relation("foo>=2.0"));
        assert_eq!(found.len(), 1);
        assert_eq!(universe.get(found[0]).unwrap().version().to_string(), "3.0.0-1");
    }

    /// `resolvedep`'s `pkg->name_hash != dep->name_hash` guard. A package cannot reappear as
    /// its own provider once its version has failed the literal step.
    #[test]
    fn a_literally_named_package_is_excluded_from_the_provides_step() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("foo", "1.0.0-1").provides(["foo=1.0.0-1"])])
            .build();
        let universe = universe(&scenario);

        assert!(universe.satisfiers(&relation("foo>=2.0")).is_empty());
    }

    #[test]
    fn a_soname_resolves_only_through_provides_and_only_exactly() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [PackageSpec::new("example", "1.0.0-1").provides(["lib:libexample.so.1"])],
            )
            .build();
        let universe = universe(&scenario);

        assert_eq!(
            names(&universe, &universe.satisfiers(&relation("lib:libexample.so.1"))),
            ["example"]
        );
        assert!(universe.satisfiers(&relation("lib:libexample.so.2")).is_empty());
    }

    #[test]
    fn a_repository_without_the_required_usage_contributes_nothing() {
        let scenario = Scenario::new().repo("core", [PackageSpec::new("foo", "1.0.0-1")]).build();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::SEARCH, db)),
            UniverseOptions::new(),
        )
        .unwrap();

        assert_eq!(universe.len(), 0);
        assert!(universe.satisfiers(&relation("foo")).is_empty());
    }

    /// `IgnorePkg` hides a repository candidate but must never hide an installed one. Otherwise
    /// a planner would decide the package is missing and install it again.
    #[test]
    fn ignore_pkg_hides_a_repository_candidate_but_not_an_installed_one() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("foo", "1.0.0-1"))
            .repo("core", [PackageSpec::new("foo", "2.0.0-1")])
            .build();
        let ignored = vec!["foo".to_owned()];
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new().ignores(IgnoreList::new(&ignored, &[])),
        )
        .unwrap();

        let candidates = universe.candidates_named("foo");
        assert_eq!(candidates.len(), 1, "only the installed copy should survive");
        assert!(universe.get(candidates[0]).unwrap().is_installed());
        assert!(universe.installed_named("foo").is_some());
    }

    /// `_alpm_outerconflicts` checks both directions, so the index must find the declarer
    /// from the name it names.
    #[test]
    fn conflicts_are_indexed_by_the_name_they_target() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old", "1.0.0-1").conflicts(["new"]))
            .repo("core", [PackageSpec::new("new", "1.0.0-1")])
            .build();
        let universe = universe(&scenario);

        assert_eq!(names(&universe, universe.conflicting_with("new")), ["old"]);
        assert!(universe.conflicting_with("unrelated").is_empty());
    }

    /// `check_conflict` calls `_alpm_depcmp`, so a conflict matches a provider too.
    #[test]
    fn a_conflict_matches_through_provides() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("impl", "1.0.0-1").provides(["virtual"])])
            .build();
        let universe = universe(&scenario);
        let impl_pkg = universe.get(universe.candidates_named("impl")[0]).unwrap();

        assert!(impl_pkg.satisfies(&"virtual".parse().unwrap()));
        assert!(impl_pkg.satisfies(&"impl".parse().unwrap()));
        assert!(!impl_pkg.satisfies(&"unrelated".parse().unwrap()));
    }

    #[test]
    fn the_candidate_budget_is_enforced_before_anything_is_interned() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("a", "1.0.0-1"), PackageSpec::new("b", "1.0.0-1")])
            .build();

        let error = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new().limits(Limits { solve_max_solvables: 1, ..Limits::default() }),
        )
        .unwrap_err();

        assert!(matches!(error, Error::TooManySolvables { max: 1 }), "got {error:?}");
    }

    #[test]
    fn sizes_come_from_the_right_schema_on_each_side() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("foo", "1.0.0-1").installed_size(4096))
            .repo(
                "core",
                [PackageSpec::new("bar", "1.0.0-1").installed_size(8192).compressed_size(1024)],
            )
            .build();
        let universe = universe(&scenario);

        let foo = universe.installed_named("foo").unwrap();
        assert_eq!(foo.installed_size(), 4096);
        assert_eq!(foo.download_size(), None, "an installed package has nothing to download");

        let bar = universe.get(universe.candidates_named("bar")[0]).unwrap();
        assert_eq!(bar.installed_size(), 8192);
        assert_eq!(bar.download_size(), Some(1024));
    }
}
