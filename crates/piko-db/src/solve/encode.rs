//! Compiles a [`Universe`] and a request into the [`Problem`] the solver searches.
//!
//! # How "already installed" is expressed
//!
//! The obvious encoding is a unit clause per installed package, "it stays". This is wrong on
//! a real system: it forbids upgrading a dependency. Installing `foo`, which needs `bar>=2`,
//! while `bar-1` is installed would pin `bar-1` and make the problem unsatisfiable. pacman
//! instead pulls in `bar-2` as a dependency upgrade.
//!
//! The unit is therefore placed on the **package name**, not on the installed candidate:
//!
//! ```text
//! installed_bar ∨ repo_bar_v2 ∨ repo_bar_v3      "something called bar must remain"
//! ```
//!
//! An at-most-one clause covers the same group. Together these forbid the accidental removal
//! of an installed package, permit an upgrade when something forces one, and prefer the
//! status quo whenever nothing forces a change. The status-quo preference falls out of
//! [`Universe::satisfiers`] listing the installed copy first, combined with the solver taking
//! the first unassigned literal. This matches libalpm's behavior, with no separate "keep"
//! pass needed.
//!
//! An explicit target is a unit on the chosen candidate itself. This is what makes
//! `pacman -S foo` upgrade `foo` while leaving everything else alone: the target unit selects
//! the repository copy, and at-most-one then retires the installed one.
//!
//! # Which candidates are encoded
//!
//! Not all of them. A universe holds every package in every configured repository — 16 357 on
//! the machine this was developed against. Emitting dependency clauses for all of them would
//! compile a problem thousands of times larger than the question asked. The encoder walks the
//! **reachable cone** instead: the installed set and the targets, plus everything that could
//! satisfy one of their dependencies, transitively. Anything outside the cone cannot be
//! selected, so its clauses could never matter.

use std::collections::{BTreeSet, HashMap, HashSet};

use alpm_types::{FullVersion, Name, RelationOrSoname};

use crate::diagnostics::Sink;
use crate::resolve::IgnoreReason;
use crate::solve::clause::{ClauseId, ClauseKind, Lit, Problem};
use crate::solve::glob::{Expansion, ExpansionFailure, expand_installable_targets};
use crate::solve::{Origin, Solvable, SolvableId, Universe};
use crate::{Error, Limits, Result};

/// What the user asked for.
#[derive(Clone, Debug)]
pub struct Request {
    targets: Vec<SolvableId>,
    removals: Vec<SolvableId>,
    needed: bool,
    allow_removals: bool,
    recursive: bool,
    ignored_upgrades: Vec<IgnoredUpgrade>,
}

impl Default for Request {
    fn default() -> Self {
        Self::new()
    }
}

impl Request {
    /// An empty request: no targets, so the answer is "the system as it stands".
    ///
    /// Removing an installed package to resolve a conflict is **allowed** by default. This
    /// matches `pacman`'s effective behavior rather than libalpm's library default of
    /// refusing (`ALPM_QUESTION_CONFLICT_PKG` answers no unless a frontend overrides it).
    /// Callers that want the stricter behavior pass `allow_removals(false)` and get
    /// "conflicting dependencies" instead.
    #[must_use]
    pub fn new() -> Self {
        Self {
            targets: Vec::new(),
            removals: Vec::new(),
            needed: false,
            allow_removals: true,
            recursive: false,
            ignored_upgrades: Vec::new(),
        }
    }

    /// Adds an explicit target, which the plan must select.
    #[must_use]
    pub fn target(mut self, target: SolvableId) -> Self {
        self.targets.push(target);
        self
    }

    /// Requests that an installed package be removed.
    ///
    /// Nothing named the same may be selected afterwards. The "must remain" clause that would
    /// otherwise pin it is not emitted. If another installed package still depends on it, the
    /// problem becomes unsatisfiable: this is `-R` refusing to break the system.
    /// `allow_removals(true)` turns that refusal into a cascade, which is `-Rc`.
    #[must_use]
    pub fn remove(mut self, package: SolvableId) -> Self {
        self.removals.push(package);
        self
    }

    /// The packages requested for removal.
    #[must_use]
    pub fn removals(&self) -> &[SolvableId] {
        &self.removals
    }

    /// `-s`: also remove dependencies that nothing needs once the targets are gone.
    #[must_use]
    pub const fn recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// Whether `-s` was requested.
    #[must_use]
    pub const fn is_recursive(&self) -> bool {
        self.recursive
    }

    /// `--needed`: skip a target whose installed copy is already at the same version.
    #[must_use]
    pub const fn needed(mut self, needed: bool) -> Self {
        self.needed = needed;
        self
    }

    /// Whether an installed package may be removed to make room for the request.
    #[must_use]
    pub const fn allow_removals(mut self, allow: bool) -> Self {
        self.allow_removals = allow;
        self
    }

    /// Adds `-Su`'s target set to this request.
    ///
    /// Every package [`sysupgrade`] selects becomes a target. Every `%REPLACES%` pair becomes
    /// a target plus the removal it displaces. This mirrors `alpm_sync_sysupgrade`'s own
    /// effect on a transaction.
    ///
    /// `piko plan -u` and `piko update` both need exactly this. The second only commits what
    /// the first prints. The logic lives here once, instead of as a hand-written loop at each
    /// call site that could drift apart from the other.
    #[must_use]
    pub fn with_sysupgrade(mut self, universe: &Universe<'_>, downgrade: bool) -> Self {
        let upgrade = sysupgrade(universe, downgrade);
        for id in &upgrade.upgrades {
            self = self.target(*id);
        }
        for (replacement, replaced) in &upgrade.replacements {
            self = self.target(*replacement).remove(*replaced);
        }
        self.ignored_upgrades = upgrade.ignored;
        self
    }

    /// The upgrades `IgnorePkg`/`IgnoreGroup` kept out of this request.
    ///
    /// Empty unless [`Self::with_sysupgrade`] was applied. Carried on the request rather than
    /// returned separately so the one call that decides `-Su`'s targets also carries what it
    /// decided against: a caller that reports these cannot forget to ask, and a second
    /// [`sysupgrade`] call to recover them could not disagree with the first but would walk
    /// the installed set twice.
    #[must_use]
    pub fn ignored_upgrades(&self) -> &[IgnoredUpgrade] {
        &self.ignored_upgrades
    }

    /// The requested targets.
    #[must_use]
    pub fn targets(&self) -> &[SolvableId] {
        &self.targets
    }

    /// Whether this request only takes packages away.
    ///
    /// A pure removal must never *install* anything. Left unconstrained, the solver happily
    /// satisfies an orphaned dependency by pulling in some other package that provides the
    /// same name. Asked to remove `bubblewrap`, it proposed installing `bubblewrap-suid`,
    /// which provides `bubblewrap`, so that `glycin` and `loupe` stayed satisfied. That is a
    /// correct solution to the constraints, and the wrong answer to the question: `pacman -R`
    /// removes or refuses, and never substitutes. So a removal-only request restricts the
    /// candidate set to what is already installed.
    #[must_use]
    pub fn is_removal_only(&self) -> bool {
        !self.removals.is_empty() && self.targets.is_empty()
    }
}

/// A requirement clause, kept so the plan can tell whether the solver took the candidate
/// libalpm would have taken.
#[derive(Clone, Copy, Debug)]
pub struct Requirement {
    /// The clause encoding this requirement.
    pub clause: ClauseId,
    /// The package that declared the dependency.
    pub dependent: SolvableId,
    /// Which of `dependent`'s `%DEPENDS%` entries this was, so a report can quote the exact
    /// relation instead of guessing at it. [`ClauseKind::Requires`] carries the same index.
    /// It is kept here too, so naming a requirement costs no clause lookup.
    pub dependency: usize,
    /// The candidate libalpm's greedy descent would have chosen: the first satisfier in
    /// preference order, or `None` if the dependency has no satisfier at all.
    pub preferred: Option<SolvableId>,
}

/// A compiled problem, plus what is needed to interpret its solution.
#[derive(Clone, Debug)]
pub struct Encoded {
    problem: Problem,
    requirements: Vec<Requirement>,
}

impl Encoded {
    /// The compiled problem.
    #[must_use]
    pub const fn problem(&self) -> &Problem {
        &self.problem
    }

    /// Every requirement clause emitted, in emission order.
    #[must_use]
    pub fn requirements(&self) -> &[Requirement] {
        &self.requirements
    }

    /// Explains why this compiled problem has no solution, as a chain of human-readable facts.
    ///
    /// Re-solves rather than requiring the caller to have kept the
    /// [`Unsatisfiable`](crate::solve::Unsatisfiable) certificate around. This is fast, since
    /// the problem is already compiled, so any caller holding an `Encoded` that came back from
    /// [`solve_with_removals`]'s `Err` arm can explain it without repeating the encode step.
    /// Returns an empty vector if the problem turns out solvable after all. That should not
    /// happen for an `Encoded` obtained that way, but this function does not assume it.
    #[must_use]
    pub fn explain(&self, universe: &Universe<'_>, limits: &Limits) -> Vec<String> {
        let Ok(crate::solve::Outcome::Unsatisfiable(unsat)) =
            crate::solve::Solver::new(&self.problem, *limits).solve()
        else {
            return Vec::new();
        };
        crate::solve::Derivation::build(universe, &self.problem, &unsat)
            .facts()
            .iter()
            .map(ToString::to_string)
            .collect()
    }
}

/// Resolves a dependency string to the candidate `pacman -S` would install for it.
///
/// Unlike [`Universe::satisfiers`], the installed copy is skipped. Asking to install
/// something means asking for a repository package, even when a satisfying one is already
/// present. `--needed` is applied later, against the target that comes back.
#[must_use]
pub fn resolve_target(universe: &Universe<'_>, dep: &RelationOrSoname) -> Option<SolvableId> {
    universe
        .satisfiers(dep)
        .into_iter()
        .find(|id| universe.get(*id).is_some_and(|solvable| !solvable.is_installed()))
}

/// Expands a target that names a `%GROUPS%` group rather than a package.
///
/// `pacman -S gnome` installs every member of the `gnome` group. The group is not a package,
/// so it resolves to nothing on its own. Returns the members in the order
/// [`Universe::group_members`] found them — one per package name, whatever the number of
/// repositories carrying it — or an empty vector if `name` is not a group.
///
/// Checked only *after* [`resolve_target`] fails. This matches pacman, which prefers a
/// package to a group of the same name rather than installing both.
#[must_use]
pub fn resolve_group(universe: &Universe<'_>, name: &str) -> Vec<SolvableId> {
    universe.group_members(name)
}

/// Why [`resolve_targets`] could not resolve one of its targets.
#[derive(Debug)]
pub enum TargetResolutionFailure {
    /// A target did not parse as a dependency string (`name`, `name>=1.0`, or a soname).
    InvalidDependencyString(String),
    /// A target parsed but named neither a package nor a `%GROUPS%` group in any configured
    /// repository.
    NotFound(String),
    /// A glob target could not be expanded into names.
    ///
    /// Wraps the expansion's own refusal, so the two commands that expand — install and
    /// removal — quote one set of messages rather than two.
    Pattern(ExpansionFailure),
    /// A target resolved to nothing only because `IgnorePkg`/`IgnoreGroup` covered every
    /// candidate for it.
    ///
    /// Distinct from [`Self::NotFound`] because the two call for opposite actions: one means
    /// the name is wrong, the other means `pacman.conf` says not to touch it. libalpm draws
    /// the same line, between `ALPM_ERR_PKG_IGNORED` and `ALPM_ERR_PKG_NOT_FOUND`
    /// (`deps.c:743`).
    Ignored {
        /// The target as the user spelled it.
        target: String,
        /// What was passed over for it. Never empty.
        candidates: Vec<IgnoredTarget>,
    },
}

/// A named target, or a member of a named group, that `IgnorePkg`/`IgnoreGroup` covered.
#[derive(Clone, Debug)]
pub struct IgnoredTarget {
    /// The package's name.
    pub name: Name,
    /// Its version in the repository that carried it.
    pub version: FullVersion,
    /// Which list covered it, and the pattern that matched.
    pub reason: IgnoreReason,
}

impl IgnoredTarget {
    pub(super) fn from_candidate(candidate: &crate::solve::IgnoredCandidate<'_>) -> Self {
        Self {
            name: candidate.package().name().clone(),
            version: candidate.package().version().clone(),
            reason: candidate.reason().clone(),
        }
    }
}

/// What [`resolve_targets`] produced.
#[derive(Debug)]
pub struct Resolution {
    /// The request, with one target added per resolved name.
    pub request: Request,
    /// Ignored candidates that were passed over, whether by a named group or by a pattern.
    pub ignored: Vec<IgnoredTarget>,
    /// One entry per glob target, in the order the targets were given. Empty when the caller
    /// named no pattern.
    pub expansions: Vec<Expansion>,
}

/// Resolves `targets` against `universe`, adding each one to `request`.
///
/// A target is tried as a literal dependency string first ([`resolve_target`], matching a
/// package name or a soname). A target that resolves to nothing may still name a `%GROUPS%`
/// group, which pacman expands to its members. This group check runs second, so a package
/// always wins over a group of the same name.
///
/// Shared by `piko plan` and `piko install`. A name-based install resolves its arguments
/// through exactly this rule, so both commands treat `foo`, `foo>=1.0`, and a group name
/// alike.
///
/// # A glob target is rewritten before any of that
///
/// A target carrying `*`, `?` or `[` is a pattern, expanded into the names it selects by
/// [`expand_installable_targets`] ahead of the loop below. So the loop sees only names the user
/// could have typed, and a pattern plans exactly what naming its expansion would have planned.
/// Doing it here rather than in a frontend is what keeps `piko install`, `piko plan` and
/// `piko update` from reading one differently: all three arrive through this function.
///
/// # `IgnorePkg` is reported, never overridden
///
/// A target every candidate of which is ignored fails with
/// [`TargetResolutionFailure::Ignored`] rather than being installed anyway. pacman asks
/// `ALPM_QUESTION_INSTALL_IGNOREPKG` here and installs on a yes; piko does not ask, and the
/// answer is always no. A group target is the partial case: its non-ignored members are still
/// resolved, and the ignored ones come back in the returned list so the caller can say what it
/// left out. A pattern behaves as a group does, for the same reason: it names a set, and
/// dropping one member leaves the target meaningful. A pattern whose every candidate is ignored
/// is the literal case again, and fails.
///
/// # Errors
///
/// [`TargetResolutionFailure`], naming the first target that could not be resolved.
pub fn resolve_targets(
    universe: &Universe<'_>,
    mut request: Request,
    targets: &[String],
    limits: &Limits,
) -> Result<Resolution, TargetResolutionFailure> {
    let expanded = expand_installable_targets(universe, targets, limits).map_err(|failure| {
        match failure {
            // The pattern is right and `pacman.conf` says not to touch what it names. That is
            // the same answer a fully-ignored literal gets, so it is reported the same way.
            ExpansionFailure::AllIgnored { pattern, candidates } => {
                TargetResolutionFailure::Ignored { target: pattern, candidates }
            }
            other => TargetResolutionFailure::Pattern(other),
        }
    })?;

    let mut ignored: Vec<IgnoredTarget> = expanded.ignored;
    for target in &expanded.names {
        let Ok(dep) = target.parse::<alpm_types::RelationOrSoname>() else {
            return Err(TargetResolutionFailure::InvalidDependencyString(target.clone()));
        };
        if let Some(id) = resolve_target(universe, &dep) {
            request = request.target(id);
            continue;
        }

        let members = resolve_group(universe, target);
        let ignored_members: Vec<IgnoredTarget> =
            universe.ignored_in_group(target).map(IgnoredTarget::from_candidate).collect();
        if !members.is_empty() {
            for member in members {
                request = request.target(member);
            }
            ignored.extend(ignored_members);
            continue;
        }

        // Nothing was resolvable. Say which of the two reasons it was.
        let mut candidates: Vec<IgnoredTarget> =
            universe.ignored_satisfiers(&dep).map(IgnoredTarget::from_candidate).collect();
        candidates.extend(ignored_members);
        if candidates.is_empty() {
            return Err(TargetResolutionFailure::NotFound(target.clone()));
        }
        return Err(TargetResolutionFailure::Ignored { target: target.clone(), candidates });
    }
    Ok(Resolution { request, ignored, expansions: expanded.expansions })
}

/// Compiles `request` against `universe`.
///
/// # Errors
///
/// [`Error::SolveBudgetExhausted`] is not raised here — that is the solver's bound.
/// [`Error::TooManyClauses`] is raised if the encoding exceeds
/// [`Limits::solve_max_clauses`](crate::Limits::solve_max_clauses). The bound is checked
/// while clauses are emitted, not afterwards, so a pathological repository costs a comparison
/// rather than the whole encoding.
pub fn encode(
    universe: &Universe<'_>,
    request: &Request,
    limits: &Limits,
    relaxed: &HashSet<SolvableId>,
) -> Result<Encoded> {
    let mut problem = Problem::new(universe.len());
    let mut requirements = Vec::new();

    let cone = reachable_cone(universe, request, limits)?;

    // 1. Targets. A unit on the specific candidate. This distinguishes "install this" from
    //    "keep whatever is there".
    for target in &request.targets {
        if request.needed && already_current(universe, *target) {
            continue;
        }
        problem.add([Lit::positive(*target)], ClauseKind::Target { target: *target });
        check_clause_budget(&problem, limits)?;
    }

    // 1b. Removals. Nothing sharing the name may be selected. This is stronger than simply
    //     dropping the "must remain" clause below: without these units, the solver could
    //     satisfy a dependency by *upgrading* the package the user asked to remove.
    let mut removed_names: BTreeSet<&str> = BTreeSet::new();
    for removal in &request.removals {
        let Some(solvable) = universe.get(*removal) else { continue };
        removed_names.insert(solvable.name().as_ref());
        for candidate in in_cone(&cone, universe.candidates_named(solvable.name().as_ref())) {
            problem.add([Lit::negative(candidate)], ClauseKind::Excluded { excluded: candidate });
            check_clause_budget(&problem, limits)?;
        }
    }

    // 2. Every installed package must remain, in some version. See the module documentation
    //    for why the unit is on the name rather than on the installed candidate.
    for solvable in universe.iter().filter(Solvable::is_installed) {
        if removed_names.contains(solvable.name().as_ref()) {
            continue;
        }
        // A relaxed package is one an earlier attempt found to be standing in the way of the
        // request: the `ALPM_QUESTION_CONFLICT_PKG` case. Dropping its clause lets the solver
        // plan its removal. See `solve_with_removals`.
        if relaxed.contains(&solvable.id()) {
            continue;
        }
        let group = in_cone(&cone, universe.candidates_named(solvable.name().as_ref()));
        if group.is_empty() {
            continue;
        }
        problem.add(
            group.iter().copied().map(Lit::positive),
            ClauseKind::Installed { installed: solvable.id() },
        );
        check_clause_budget(&problem, limits)?;
    }

    // 3. At most one candidate per package name.
    let mut grouped: BTreeSet<&str> = BTreeSet::new();
    for id in &cone {
        if let Some(solvable) = universe.get(*id) {
            grouped.insert(solvable.name().as_ref());
        }
    }
    for name in grouped {
        let group = in_cone(&cone, universe.candidates_named(name));
        problem.add_at_most_one(&group);
        check_clause_budget(&problem, limits)?;
    }

    // 4. Dependencies, conflicts and replacements, for everything that could be selected.
    for id in &cone {
        let Some(solvable) = universe.get(*id) else { continue };

        for (index, dep) in solvable.depends()?.iter().enumerate() {
            let satisfiers = in_cone(&cone, &universe.satisfiers(dep));
            let mut literals = vec![Lit::negative(*id)];
            literals.extend(satisfiers.iter().copied().map(Lit::positive));
            let clause =
                problem.add(literals, ClauseKind::Requires { dependent: *id, dependency: index });
            requirements.push(Requirement {
                clause,
                dependent: *id,
                dependency: index,
                preferred: satisfiers.first().copied(),
            });
            check_clause_budget(&problem, limits)?;
        }

        for conflict in solvable.conflicts() {
            for other in &cone {
                if other == id {
                    continue;
                }
                let Some(candidate) = universe.get(*other) else { continue };
                // `check_conflict` (`conflict.c`) uses `_alpm_depcmp`, so this matches
                // through `%PROVIDES%` as well as by name. Both directions are covered
                // without a second pass: every installed package is in the cone, so its own
                // conflicts are iterated here too.
                if candidate.satisfies(conflict) {
                    problem.add(
                        [Lit::negative(*id), Lit::negative(*other)],
                        ClauseKind::Conflicts { declarer: *id, other: *other },
                    );
                    check_clause_budget(&problem, limits)?;
                }
            }
        }

        // `%REPLACES%` matches by literal name only — `check_replacers` (`sync.c:124`) is
        // explicit that "we only want to consider literal matches at this point", so a
        // replacement never fires through `%PROVIDES%` the way a conflict does.
        if !solvable.is_installed() {
            for replaces in solvable.replaces() {
                for other in in_cone(&cone, universe.candidates_named(replaces.name.as_ref())) {
                    let Some(candidate) = universe.get(other) else { continue };
                    if candidate.is_installed()
                        && crate::depcmp::version_satisfies(candidate.version(), replaces)
                    {
                        problem.add(
                            [Lit::negative(*id), Lit::negative(other)],
                            ClauseKind::Replaces { replacement: *id, replaced: other },
                        );
                        check_clause_budget(&problem, limits)?;
                    }
                }
            }
        }
    }

    Ok(Encoded { problem, requirements })
}

/// Whether the installed copy of `target`'s package is already at `target`'s version.
fn already_current(universe: &Universe<'_>, target: SolvableId) -> bool {
    let Some(candidate) = universe.get(target) else { return false };
    universe
        .installed_named(candidate.name().as_ref())
        .is_some_and(|installed| installed.version() == candidate.version())
}

/// The candidates that could take part, starting from the installed set and the targets and
/// closing over every dependency's satisfiers.
///
/// Returned sorted. This keeps the encoding, and therefore the clause order the solver scans,
/// and therefore which candidate a tie picks, independent of hash iteration order.
fn reachable_cone(
    universe: &Universe<'_>,
    request: &Request,
    limits: &Limits,
) -> Result<Vec<SolvableId>> {
    let mut seen: HashSet<SolvableId> = HashSet::new();
    let mut queue: Vec<SolvableId> = Vec::new();

    for solvable in universe.iter().filter(Solvable::is_installed) {
        if seen.insert(solvable.id()) {
            queue.push(solvable.id());
        }
    }
    for target in request.targets.iter().chain(request.removals.iter()) {
        if seen.insert(*target) {
            queue.push(*target);
        }
    }

    // Every other candidate sharing a name with something already reachable. An upgrade or a
    // downgrade of it is a legitimate move, and at-most-one needs the whole group.
    // A pure removal may not install anything, so nothing that is not already installed is
    // even a candidate. See `Request::is_removal_only`.
    let installed_only = request.is_removal_only();
    let admit = |universe: &Universe<'_>, id: SolvableId| {
        !installed_only || universe.get(id).is_some_and(|solvable| solvable.is_installed())
    };

    let mut index = 0;
    while let Some(id) = queue.get(index).copied() {
        index = index.saturating_add(1);
        let Some(solvable) = universe.get(id) else { continue };

        for sibling in universe.candidates_named(solvable.name().as_ref()) {
            if admit(universe, *sibling) && seen.insert(*sibling) {
                queue.push(*sibling);
            }
        }
        for dep in solvable.depends()? {
            for satisfier in universe.satisfiers(dep) {
                if admit(universe, satisfier) && seen.insert(satisfier) {
                    queue.push(satisfier);
                }
            }
        }
        if seen.len() > limits.solve_max_solvables {
            return Err(Error::TooManySolvables { max: limits.solve_max_solvables });
        }
    }

    let mut cone: Vec<SolvableId> = seen.into_iter().collect();
    cone.sort_unstable();
    Ok(cone)
}

/// Those of `ids` that are in `cone`, preserving `ids`' order — which is preference order.
fn in_cone(cone: &[SolvableId], ids: &[SolvableId]) -> Vec<SolvableId> {
    ids.iter().copied().filter(|id| cone.binary_search(id).is_ok()).collect()
}

/// Fails once the clause count exceeds its bound.
///
/// Checked as clauses are emitted, not after the fact. The point of the bound is to stop the
/// allocation. A repository crafted to explode the encoding would already have been fully
/// compiled by the time an after-the-fact check fired.
fn check_clause_budget(problem: &Problem, limits: &Limits) -> Result<()> {
    if problem.len() > limits.solve_max_clauses {
        return Err(Error::TooManyClauses { max: limits.solve_max_clauses });
    }
    Ok(())
}

/// How closely a solution tracked libalpm's greedy descent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fidelity {
    /// Every requirement was satisfied by the candidate `resolvedep` would have returned.
    ///
    /// The plan is what `pacman` would have produced.
    Greedy,
    /// Some requirement was satisfied by a lower-preference candidate.
    ///
    /// The plan is valid; it may simply not be the one `pacman -Sp` prints. **This does not
    /// mean pacman would have failed.** Two different situations produce it, and the count
    /// does not distinguish them:
    ///
    /// - libalpm's first choice was impossible, and it would have failed where this backtracked.
    /// - A provider selected for some other requirement already satisfied this one, so the
    ///   preferred candidate was never needed. pacman succeeds here too, with a plan of the
    ///   same size or larger. Its own answer depends on the order targets are named on the
    ///   command line; this one does not. `piko plan cl-hu-dwim-stefil` is the case measured
    ///   on real data.
    ///
    /// The count is of requirements, not of packages. [`FidelityReport::diverged`] names them.
    Diverged {
        /// How many requirements took a candidate other than their preferred one.
        requirements: usize,
    },
}

/// One requirement that took a candidate other than the one libalpm would have taken.
///
/// Candidates are identified rather than rendered. Naming them needs a [`Universe`], which
/// the caller already has, and formatting here would allocate for a report that may never be
/// shown. To quote the relation, index `dependent`'s `%DEPENDS%` with `dependency`: the same
/// resolution `solve::explain` performs for [`ClauseKind::Requires`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Divergence {
    /// The package whose `%DEPENDS%` declared the requirement.
    pub dependent: SolvableId,
    /// Which of `dependent`'s `%DEPENDS%` entries this was.
    pub dependency: usize,
    /// The candidate libalpm's greedy descent would have taken.
    pub preferred: SolvableId,
    /// The candidate that actually satisfied the requirement.
    pub selected: SolvableId,
}

/// The fidelity measure, together with the requirements it counted.
#[derive(Clone, Debug)]
pub struct FidelityReport {
    fidelity: Fidelity,
    diverged: Box<[Divergence]>,
    dropped: usize,
}

impl FidelityReport {
    /// How closely the solution tracked libalpm's greedy descent.
    #[must_use]
    pub const fn fidelity(&self) -> Fidelity {
        self.fidelity
    }

    /// The requirements that diverged, up to [`Limits::max_diagnostics`].
    ///
    /// Bounded because a pathological universe could otherwise make this list as long as the
    /// requirement set itself. [`Fidelity::Diverged`] carries the untruncated count.
    #[must_use]
    pub fn diverged(&self) -> &[Divergence] {
        &self.diverged
    }

    /// How many diverged requirements [`Limits::max_diagnostics`] withheld.
    #[must_use]
    pub const fn dropped(&self) -> usize {
        self.dropped
    }
}

/// Compares a solution against the greedy choice each requirement would have made.
///
/// This is the honest fidelity measure. The solver's backjump counter is not: unit
/// propagation can reject libalpm's first choice without any decision ever being retracted,
/// so a run with zero conflicts may still have diverged. Only the requirements themselves
/// know which candidate was preferred.
///
/// Two filters keep the measure meaningful. Both close a bug in which it fired on every plan
/// it was ever shown:
///
/// 1. **Compared by package name, not by candidate.** A requirement whose preferred satisfier
///    was the installed copy of `foo`, and whose selected satisfier is `foo` from a
///    repository, has not diverged. That is what an upgrade *is*, and during `-Su` it
///    describes most of the transaction. Counting those made a clean 59-package sysupgrade
///    report 28 divergences.
/// 2. **Only requirements libalpm would have raised at all.** [`encode`] emits a requirement
///    for every `%DEPENDS%` entry of every candidate in the cone. The cone is seeded with the
///    whole installed set, and "every installed package must remain" keeps all of them
///    selected. So `encoded.requirements` covers the entire installed system, not the
///    transaction. libalpm reaches the preference order only through `alpm_checkdeps`, which
///    raises a dependency **only when the package list it has already accumulated does not
///    satisfy it**. Three things are in that list before the order is ever consulted. A
///    requirement any of them answers is not a departure from the descent: libalpm never
///    walked it.
///
///    - an installed package the transaction keeps,
///    - a package the user named, which is in the list before resolution starts,
///    - a provider pulled in for an *earlier* `%DEPENDS%` entry of the same dependent, since
///      libalpm resolves one package's dependencies in declaration order.
///
/// A genuine divergence is a different package answering a dependency the transaction
/// reached: `fcron` where libalpm would have taken `cronie`.
///
/// The third filter is modeled per dependent, not across the whole descent. libalpm's outer
/// queue order also decides which provider arrives first, and reproducing that would mean
/// running a second resolver alongside the one whose answer is being audited. The measured
/// false positives came from the inner loop: `cl-alexandria` declares `cl-asdf` before
/// `common-lisp`, so `ecl` answers both and `clisp` is never tried.
#[must_use]
pub fn fidelity(
    universe: &Universe<'_>,
    encoded: &Encoded,
    selected: &[SolvableId],
    limits: &Limits,
) -> FidelityReport {
    let chosen: HashSet<SolvableId> = selected.iter().copied().collect();
    // What the transaction actually changes. An installed candidate that was merely
    // re-selected is the status quo. Its requirements were resolved by whatever installed it,
    // not by this plan.
    let changing: HashSet<SolvableId> = selected
        .iter()
        .copied()
        .filter(|id| universe.get(*id).is_some_and(|solvable| !solvable.is_installed()))
        .collect();
    let name_of = |id: SolvableId| universe.get(id).map(|solvable| solvable.name());
    // libalpm puts every named target in its package list before resolving anything, so a
    // dependency one of them satisfies is never raised.
    let targets: HashSet<SolvableId> = encoded
        .problem
        .iter()
        .filter_map(|(_, clause)| match clause.kind() {
            ClauseKind::Target { target } => Some(target),
            _ => None,
        })
        .collect();
    // Per dependent, what the descent would have pulled in for its earlier `%DEPENDS%`
    // entries. Keyed by dependent, because that inner loop is the part of libalpm's order
    // this models. See the note on the outer queue above.
    let mut pulled: HashMap<SolvableId, HashSet<SolvableId>> = HashMap::new();

    let mut diverged = 0_usize;
    let mut sink = Sink::new(limits);
    for requirement in &encoded.requirements {
        // A requirement only applies if its dependent was actually selected.
        if !chosen.contains(&requirement.dependent) {
            continue;
        }
        let Some(preferred) = requirement.preferred else {
            continue;
        };

        // The clause is `¬dependent ∨ sat₁ ∨ …` and `dependent` is selected, so at least one
        // of these is true. Iterated twice rather than collected, because this loop runs over
        // every requirement in the encoding, and most of them stop at the checks above.
        let all_satisfiers = || {
            encoded
                .problem
                .literals_of(requirement.clause)
                .iter()
                .filter(|literal| !literal.is_negative())
                .map(|literal| literal.solvable())
        };
        let satisfiers = || all_satisfiers().filter(|id| chosen.contains(id));

        let Some(satisfier) = satisfiers().next() else { continue };

        // Already answered by an installed package the transaction keeps, or by a package the
        // user named. `alpm_checkdeps` reports no missing dependency here, so the descent
        // stops before the preference order.
        if satisfiers().any(|id| !changing.contains(&id) || targets.contains(&id)) {
            continue;
        }
        // Already answered by what an earlier `%DEPENDS%` entry of this same dependent pulled
        // in. Tested against every satisfier, not just the selected ones, because libalpm's
        // pick for that earlier entry need not be in this plan at all.
        if pulled
            .get(&requirement.dependent)
            .is_some_and(|acc| all_satisfiers().any(|id| acc.contains(&id)))
        {
            continue;
        }
        // Raised, so the descent takes its preferred candidate and carries it into the rest of
        // this dependent's dependencies. Recorded before the checks below, which decide only
        // whether the pick *differed*, not whether it happened.
        pulled.entry(requirement.dependent).or_default().insert(preferred);

        if chosen.contains(&preferred) {
            continue;
        }
        let Some(wanted) = name_of(preferred) else { continue };
        // Satisfied by a different version of the same package? Then this is an upgrade of
        // the preferred candidate, not a departure from it.
        if satisfiers().any(|id| name_of(id) == Some(wanted)) {
            continue;
        }

        diverged = diverged.saturating_add(1);
        sink.push(|| Divergence {
            dependent: requirement.dependent,
            dependency: requirement.dependency,
            preferred,
            selected: satisfier,
        });
    }

    let (collected, dropped) = sink.finish();
    let fidelity = if diverged == 0 {
        Fidelity::Greedy
    } else {
        Fidelity::Diverged { requirements: diverged }
    };
    FidelityReport { fidelity, diverged: collected, dropped }
}

/// A solved request, together with the installed packages that had to go.
#[derive(Debug)]
pub struct Planned {
    /// The compiled problem the solution belongs to.
    pub encoded: Encoded,
    /// The candidates selected.
    pub selected: Vec<SolvableId>,
    /// Installed packages the transaction removes, because something it must install
    /// conflicts with them.
    pub removed: Vec<SolvableId>,
    /// How closely the solution tracked libalpm's greedy descent, and which requirements
    /// departed from it.
    pub fidelity: FidelityReport,
}

/// Solves `request`, removing installed packages that stand in the way when policy allows.
///
/// This is `_alpm_sync_prepare`'s conflict step (`sync.c:367`) expressed as a loop rather
/// than as a callback. libalpm asks `ALPM_QUESTION_CONFLICT_PKG` in the middle of resolution.
/// If the answer is yes, it appends the offending local package to `sync->removes` and
/// carries on. Its own default answer is **no**, which is why a library caller sees
/// `ALPM_ERR_CONFLICTING_DEPS` where `pacman`, whose frontend asks the user, proceeds.
///
/// piko cannot prompt from a library: diagnostics are returned to the caller, never printed
/// or logged. So the question becomes a policy on the [`Request`], and the retry becomes explicit:
/// solve with every installed package pinned, and if that is unsatisfiable, relax exactly the pins the
///  unsatisfiable core blames, then solve again. A package is only ever a candidate
/// for removal once the solver has already proved the request impossible while it stays.
///
/// # Errors
///
/// As [`encode`], plus [`crate::Error::SolveBudgetExhausted`] from the solver.
pub fn solve_with_removals(
    universe: &Universe<'_>,
    request: &Request,
    limits: &Limits,
) -> Result<std::result::Result<Planned, Encoded>> {
    let mut relaxed: HashSet<SolvableId> = HashSet::new();

    // Each pass relaxes at least one pin. There are finitely many installed packages, so this
    // terminates without needing a bound of its own.
    loop {
        let encoded = encode(universe, request, limits, &relaxed)?;
        let outcome = crate::solve::Solver::new(encoded.problem(), *limits).solve()?;

        let unsat = match outcome {
            crate::solve::Outcome::Satisfied(solution) => {
                let mut selected: Vec<SolvableId> = solution.selected().to_vec();
                let chosen: HashSet<SolvableId> = selected.iter().copied().collect();

                // Anything pinned-then-relaxed that the solution did not keep is gone. So is
                // anything the user named for removal.
                let mut removed: Vec<SolvableId> = relaxed
                    .iter()
                    .copied()
                    .chain(request.removals.iter().copied())
                    .filter(|id| !chosen.contains(id))
                    .collect();
                removed.sort_unstable();
                removed.dedup();

                if request.recursive {
                    // `-s` sweeps orphans out of what survives; those then become removals
                    // too. Run against the installed survivors only. A package this
                    // transaction is *installing* was asked for, directly or transitively,
                    // and is by definition not an orphan.
                    let survivors: Vec<SolvableId> = selected
                        .iter()
                        .copied()
                        .filter(|id| {
                            universe.get(*id).is_some_and(|solvable| solvable.is_installed())
                        })
                        .collect();
                    // Seeded from *everything* being removed, not just what the user named.
                    // `_alpm_remove_prepare` (`remove.c:249`) runs `_alpm_recursedeps` over
                    // `trans->remove` *after* the cascade has appended the dependents to it,
                    // per its own comment: "`-Rcs` == `-Rc` then `-Rs`". Seeding from the
                    // named targets alone leaves every cascaded dependent's own dependencies
                    // behind. `piko remove -cs phonon-qt6` took 4 packages where
                    // `pacman -Rcs` takes 35, because the 31 belonged to the cascaded
                    // `phonon-qt6-vlc`, not to the target.
                    let orphans = recurse_unneeded(universe, &removed, &survivors, false);
                    let gone: HashSet<SolvableId> = orphans.iter().copied().collect();
                    selected.retain(|id| !gone.contains(id));
                    removed.extend(orphans);
                }

                removed.sort_unstable();
                removed.dedup();
                let fidelity = fidelity(universe, &encoded, &selected, limits);
                return Ok(Ok(Planned { encoded, selected, removed, fidelity }));
            }
            crate::solve::Outcome::Unsatisfiable(unsat) => unsat,
        };

        if !request.allow_removals {
            return Ok(Err(encoded));
        }

        let newly: Vec<SolvableId> = unsat
            .core()
            .iter()
            .filter_map(|id| encoded.problem().get(*id))
            .filter_map(|clause| match clause.kind() {
                ClauseKind::Installed { installed } => Some(installed),
                _ => None,
            })
            .filter(|id| !relaxed.contains(id))
            .collect();

        if newly.is_empty() {
            // Nothing left to give. The request is impossible however much is removed.
            return Ok(Err(encoded));
        }
        relaxed.extend(newly);
    }
}

/// `-s`: drops installed packages that only existed to satisfy the packages being removed.
///
/// A faithful transcription of `_alpm_recursedeps` (`deps.c:579`), whose three phases matter
/// individually:
///
/// 1. `keep` starts as everything still installed once the targets are gone.
/// 2. Everything the **targets** depend on, then, transitively, everything the newly-doomed
///    depend on, moves from `keep` into `rem`. This is filtered to `ALPM_PKG_REASON_DEPEND`
///    unless `include_explicit` (`-Rss`).
/// 3. **Re-widen**: anything a surviving `keep` package still needs moves back out of `rem`.
///    Run to a fixpoint, because rescuing one package can rescue its dependencies too.
///
/// The seeding in phase 2 is the part that is easy to get wrong and impossible to spot
/// without real data. Sweeping *every* orphan on the system — any installed dependency
/// nothing needs any more — looks like it converges to the same fixpoint. It does not. A
/// system accumulates orphans that have nothing to do with the package being removed:
/// `pacman -Rs amberol` removes one package where a whole-system sweep removes eighty-one.
/// `-Rs` is scoped to the targets' own dependencies, not to tidiness.
#[must_use]
pub fn recurse_unneeded(
    universe: &Universe<'_>,
    removing: &[SolvableId],
    surviving: &[SolvableId],
    include_explicit: bool,
) -> Vec<SolvableId> {
    let mut keep: HashSet<SolvableId> = surviving.iter().copied().collect();
    let mut rem: HashSet<SolvableId> = HashSet::new();

    // Phase 2: pull the targets' dependencies out of `keep`, transitively.
    let mut frontier: Vec<SolvableId> = removing.to_vec();
    while let Some(id) = frontier.pop() {
        let Some(solvable) = universe.get(id) else { continue };
        // Installed by construction. `removing` and `surviving` both come from a removal
        // plan, which can only name packages that are on the system.
        let Some(depends) = solvable.installed_depends() else { continue };
        for dep in depends {
            for satisfier in universe.satisfiers(dep) {
                if !keep.contains(&satisfier) {
                    continue;
                }
                let Some(candidate) = universe.get(satisfier) else { continue };
                let sweepable = include_explicit
                    || candidate.install_reason() == Some(alpm_types::PackageInstallReason::Depend);
                if !sweepable {
                    continue;
                }
                keep.remove(&satisfier);
                rem.insert(satisfier);
                frontier.push(satisfier);
            }
        }
    }

    // Phase 3: rescue anything a survivor still needs, to a fixpoint.
    loop {
        let mut rescued: Vec<SolvableId> = Vec::new();
        for id in &keep {
            let Some(solvable) = universe.get(*id) else { continue };
            let Some(depends) = solvable.installed_depends() else { continue };
            for dep in depends {
                for satisfier in universe.satisfiers(dep) {
                    if rem.contains(&satisfier) {
                        rescued.push(satisfier);
                    }
                }
            }
        }
        if rescued.is_empty() {
            break;
        }
        for id in rescued {
            rem.remove(&id);
            keep.insert(id);
        }
    }

    let mut dropped: Vec<SolvableId> = rem.into_iter().collect();
    dropped.sort_unstable();
    dropped
}

/// What a full system upgrade would target.
#[derive(Clone, Debug, Default)]
pub struct Sysupgrade {
    /// Repository candidates to install, in installed-set order.
    pub upgrades: Vec<SolvableId>,
    /// `(replacement, replaced)` pairs from `%REPLACES%`.
    pub replacements: Vec<(SolvableId, SolvableId)>,
    /// What `IgnorePkg`/`IgnoreGroup` kept out, in the same order.
    pub ignored: Vec<IgnoredUpgrade>,
}

/// Which change `IgnorePkg`/`IgnoreGroup` prevented.
///
/// One variant per warning libalpm prints: `check_literal`'s two (`sync.c:96`, `sync.c:106`)
/// and `check_replacers`' one (`sync.c:156`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IgnoredChange {
    /// A newer repository version was available.
    Upgrade,
    /// An older repository version would have been taken, `-Suu` having been asked for.
    Downgrade,
    /// Another package's `%REPLACES%` named the installed one.
    Replacement,
}

/// A change a full system upgrade would have made, had `IgnorePkg`/`IgnoreGroup` not covered
/// one of the two packages involved.
///
/// The available side is carried by value rather than as a [`SolvableId`]: an ignored
/// repository candidate is never interned, so no id names it. `installed` still is one — the
/// installed set is interned unconditionally.
#[derive(Clone, Debug)]
pub struct IgnoredUpgrade {
    /// The installed package that stays as it is.
    pub installed: SolvableId,
    /// The name of the repository package that was passed over. Equal to the installed name
    /// except for [`IgnoredChange::Replacement`].
    pub name: Name,
    /// That package's version.
    pub version: FullVersion,
    /// Which list covered it, and the pattern that matched. Either side of the pair can be
    /// the covered one: `check_literal` tests
    /// `alpm_pkg_should_ignore(spkg) || alpm_pkg_should_ignore(lpkg)`.
    pub reason: IgnoreReason,
    /// What was prevented.
    pub kind: IgnoredChange,
}

/// Chooses what `-Su` would do, mirroring `alpm_sync_sysupgrade` (`sync.c:200`).
///
/// For each installed package, repositories are walked in `pacman.conf` order. The **first
/// one that carries the name at all** decides the outcome, even if it carries the same
/// version and so yields no upgrade. That is libalpm's `found = 1; break`, and it is what
/// makes repository priority mean something here rather than "whichever repo happens to have
/// the newest build".
///
/// Within a repository, `%REPLACES%` is checked **before** the literal name. A replacement
/// matches by `_alpm_depcmp_literal` only. `check_replacers` is explicit that "we only want to
/// consider literal matches at this point", so unlike a conflict it never fires through
/// `%PROVIDES%`.
///
/// The `Usage` gate here is `Upgrade` **alone** (`sync.c:229`), a different mask from the
/// `Install|Upgrade` that `resolvedep` applies when the resulting targets' dependencies are
/// resolved. The universe is built with the wider mask, and this applies the narrower one,
/// because a repository marked `Usage = Install` may satisfy a dependency but must not
/// volunteer upgrades.
///
/// `enable_downgrade` is `-Suu`. Without it, a repository version older than the installed
/// one is left alone (libalpm warns "local (%s) is newer than %s (%s)"); this function simply
/// does not select it.
///
/// # `IgnorePkg`/`IgnoreGroup` is tested on both sides, and an ignored copy still settles the
/// repository
///
/// `check_literal` and `check_replacers` both test
/// `alpm_pkg_should_ignore(spkg) || alpm_pkg_should_ignore(lpkg)`. Only the repository side
/// can be filtered while the universe is interned, because an installed package is always
/// interned — `IgnorePkg` means "do not upgrade it", not "pretend it is not there". The
/// installed side is therefore tested here, through [`Universe::ignores`]. Without it an
/// `IgnoreGroup` that the installed `desc` carries but the repository `desc` does not is
/// silently bypassed, and piko upgrades a package pacman leaves alone.
///
/// The repository walk also has to *see* an ignored candidate. `_alpm_db_get_pkgfromcache`
/// finds a package whatever its ignore status, and the caller then `break`s
/// (`sync.c:239-246`), so the first repository carrying the name settles the outcome even
/// when that outcome is "nothing, it is ignored". Skipping ignored candidates here instead
/// would let a lower-priority repository volunteer an upgrade that pacman never offers.
/// [`Universe::ignored_named`] is what makes them visible again.
///
/// What was passed over is returned in [`Sysupgrade::ignored`], decided by this one walk
/// rather than by a second pass that would have to reproduce the same priority rules.
#[must_use]
pub fn sysupgrade(universe: &Universe<'_>, enable_downgrade: bool) -> Sysupgrade {
    let mut result = Sysupgrade::default();

    for installed in universe.iter().filter(Solvable::is_installed) {
        let name = installed.name().as_ref();
        // The `lpkg` half of the test, which no filter upstream of here can apply.
        let local = universe.ignores().reason(name, installed.groups());

        for index in 0.. {
            let Some(usage) = universe.repository_usage(index) else { break };
            if !usage.contains(crate::config::DbUsage::UPGRADE) {
                continue;
            }

            // `%REPLACES%` first. An ignored replacer is reported and skipped rather than
            // ending the search, matching `check_replacers`' `continue`: a second replacer in
            // the same repository is still considered, and so is the literal name below.
            let replaces_installed = |entry: &alpm_types::PackageRelation| {
                entry.name.as_ref() == name
                    && crate::depcmp::version_satisfies(installed.version(), entry)
            };
            let ignored_replacers = universe
                .ignored_in(index)
                .filter(|candidate| candidate.package().replaces().iter().any(replaces_installed));
            for candidate in ignored_replacers {
                result.ignored.push(IgnoredUpgrade {
                    installed: installed.id(),
                    name: candidate.package().name().clone(),
                    version: candidate.package().version().clone(),
                    reason: candidate.reason().clone(),
                    kind: IgnoredChange::Replacement,
                });
            }
            let replacer = universe.replacers_of(name).iter().copied().find(|id| {
                let Some(candidate) = universe.get(*id) else { return false };
                if candidate.origin() != Origin::Repository(index) {
                    return false;
                }
                candidate.replaces().iter().any(replaces_installed)
            });
            if let Some(replacer) = replacer {
                match (&local, universe.get(replacer)) {
                    (Some(reason), Some(candidate)) => result.ignored.push(IgnoredUpgrade {
                        installed: installed.id(),
                        name: candidate.name().clone(),
                        version: candidate.version().clone(),
                        reason: reason.clone(),
                        kind: IgnoredChange::Replacement,
                    }),
                    _ => result.replacements.push((replacer, installed.id())),
                }
                break;
            }

            // Then the literal name. Finding it settles the matter for this package, whether
            // or not it turns out to be newer, and whether or not it is ignored.
            let literal = universe.candidates_named(name).iter().copied().find(|id| {
                universe.get(*id).is_some_and(|c| c.origin() == Origin::Repository(index))
            });
            if let Some((id, candidate)) = literal.and_then(|id| Some((id, universe.get(id)?))) {
                let change =
                    ignored_change(installed.version(), candidate.version(), enable_downgrade);
                match (change, local.clone()) {
                    (Some(kind), Some(reason)) => result.ignored.push(IgnoredUpgrade {
                        installed: installed.id(),
                        name: candidate.name().clone(),
                        version: candidate.version().clone(),
                        reason,
                        kind,
                    }),
                    (Some(_), None) => result.upgrades.push(id),
                    (None, _) => {}
                }
                break;
            }

            // No usable candidate: the repository may still carry an ignored copy, which
            // settles the search the same way an ordinary one would.
            let mut ignored_here = universe.ignored_named(name).filter(|c| c.repository() == index);
            if let Some(candidate) = ignored_here.next() {
                if let Some(kind) = ignored_change(
                    installed.version(),
                    candidate.package().version(),
                    enable_downgrade,
                ) {
                    result.ignored.push(IgnoredUpgrade {
                        installed: installed.id(),
                        name: candidate.package().name().clone(),
                        version: candidate.package().version().clone(),
                        reason: candidate.reason().clone(),
                        kind,
                    });
                }
                break;
            }
        }
    }

    result
}

/// Which change a version pair would have produced, or `None` when it would have produced
/// none.
///
/// The ignore test is nested inside the version comparison, never the other way round: an
/// ignored package already at the repository version has had nothing prevented, and neither
/// has one whose repository copy is older while `-Suu` was not asked for. `check_literal`
/// nests them the same way, which is why it stays silent in both cases.
fn ignored_change(
    installed: &FullVersion,
    available: &FullVersion,
    enable_downgrade: bool,
) -> Option<IgnoredChange> {
    if available > installed {
        Some(IgnoredChange::Upgrade)
    } else if available < installed && enable_downgrade {
        Some(IgnoredChange::Downgrade)
    } else {
        None
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::config::DbUsage;
    use crate::fixture::{BuiltScenario, PackageSpec, Scenario};
    use crate::solve::UniverseOptions;

    fn universe_of(scenario: &BuiltScenario, usage: DbUsage) -> Universe<'_> {
        Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (usage, db)),
            UniverseOptions::new().usage(DbUsage::ALL),
        )
        .unwrap()
    }

    fn named<'a>(universe: &Universe<'a>, ids: &[SolvableId]) -> Vec<&'a str> {
        ids.iter().filter_map(|id| universe.get(*id)).map(|s| s.name().as_ref()).collect()
    }

    #[test]
    fn a_newer_repository_version_is_an_upgrade() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "1.0.0-1"))
            .repo("core", [PackageSpec::new("app", "2.0.0-1")])
            .build();
        let universe = universe_of(&scenario, DbUsage::ALL);

        let result = sysupgrade(&universe, false);
        assert_eq!(named(&universe, &result.upgrades), ["app"]);
    }

    #[test]
    fn an_identical_version_is_not_an_upgrade() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "1.0.0-1"))
            .repo("core", [PackageSpec::new("app", "1.0.0-1")])
            .build();
        let universe = universe_of(&scenario, DbUsage::ALL);

        assert!(sysupgrade(&universe, false).upgrades.is_empty());
    }

    /// libalpm warns "local (%s) is newer than %s (%s)" and leaves it alone unless
    /// `enable_downgrade`. Real repositories are never behind a synced system, so this path
    /// gets only fixture coverage.
    #[test]
    fn an_older_repository_version_is_taken_only_with_downgrade() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "2.0.0-1"))
            .repo("core", [PackageSpec::new("app", "1.0.0-1")])
            .build();
        let universe = universe_of(&scenario, DbUsage::ALL);

        assert!(sysupgrade(&universe, false).upgrades.is_empty());
        assert_eq!(named(&universe, &sysupgrade(&universe, true).upgrades), ["app"]);
    }

    /// `-Su` gates on `Upgrade` alone (`sync.c:229`), a narrower mask than the
    /// `Install|Upgrade` used when resolving the resulting targets' dependencies.
    #[test]
    fn a_repository_without_upgrade_usage_volunteers_nothing() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "1.0.0-1"))
            .repo("core", [PackageSpec::new("app", "2.0.0-1")])
            .build();
        let universe = universe_of(&scenario, DbUsage::INSTALL);

        assert!(
            sysupgrade(&universe, false).upgrades.is_empty(),
            "Usage = Install may satisfy a dependency but must not offer upgrades"
        );
    }

    #[test]
    fn a_replaces_entry_produces_a_replacement_pair() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old-name", "1.0.0-1"))
            .repo("core", [PackageSpec::new("new-name", "2.0.0-1").replaces(["old-name"])])
            .build();
        let universe = universe_of(&scenario, DbUsage::ALL);

        let result = sysupgrade(&universe, false);
        assert_eq!(result.replacements.len(), 1);
        let (replacement, replaced) = result.replacements[0];
        assert_eq!(universe.get(replacement).unwrap().name().as_ref(), "new-name");
        assert_eq!(universe.get(replaced).unwrap().name().as_ref(), "old-name");
    }

    /// `check_replacers` matches with `_alpm_depcmp_literal` only, so a version constraint on
    /// the `%REPLACES%` entry is honoured.
    #[test]
    fn a_replaces_entry_honours_its_version_constraint() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old-name", "3.0.0-1"))
            .repo("core", [PackageSpec::new("new-name", "2.0.0-1").replaces(["old-name<2.0"])])
            .build();
        let universe = universe_of(&scenario, DbUsage::ALL);

        assert!(
            sysupgrade(&universe, false).replacements.is_empty(),
            "installed 3.0.0-1 does not satisfy `old-name<2.0`"
        );
    }

    /// Replacers are checked before literals, so a repository offering both settles on the
    /// replacement.
    #[test]
    fn a_replacement_wins_over_a_literal_upgrade_in_the_same_repository() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "1.0.0-1"))
            .repo(
                "core",
                [
                    PackageSpec::new("app", "2.0.0-1"),
                    PackageSpec::new("app-ng", "2.0.0-1").replaces(["app"]),
                ],
            )
            .build();
        let universe = universe_of(&scenario, DbUsage::ALL);

        let result = sysupgrade(&universe, false);
        assert!(result.upgrades.is_empty(), "the replacement settles it");
        assert_eq!(result.replacements.len(), 1);
        assert_eq!(universe.get(result.replacements[0].0).unwrap().name().as_ref(), "app-ng");
    }

    /// The first repository carrying the name decides, even when it offers no upgrade and a
    /// later repository would have. This is libalpm's `found = 1; break`. It is what makes
    /// repository priority mean something.
    #[test]
    fn the_first_repository_carrying_the_name_settles_it() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "1.0.0-1"))
            .repo("core", [PackageSpec::new("app", "1.0.0-1")])
            .repo("extra", [PackageSpec::new("app", "9.0.0-1")])
            .build();
        let universe = universe_of(&scenario, DbUsage::ALL);

        assert!(
            sysupgrade(&universe, false).upgrades.is_empty(),
            "core carries app at the installed version, so extra is never consulted"
        );
    }
    /// A universe built with `IgnorePkg = <packages>` / `IgnoreGroup = <groups>`.
    fn ignoring<'a>(
        scenario: &'a BuiltScenario,
        packages: &'a [String],
        groups: &'a [String],
    ) -> Universe<'a> {
        Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new()
                .usage(DbUsage::ALL)
                .ignores(crate::resolve::IgnoreList::new(packages, groups)),
        )
        .unwrap()
    }

    #[test]
    fn an_ignored_upgrade_is_reported_instead_of_taken() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("gedit", "46.2-1"))
            .repo("core", [PackageSpec::new("gedit", "47.0-1")])
            .build();
        let ignored = vec!["gedit".to_owned()];
        let universe = ignoring(&scenario, &ignored, &[]);

        let result = sysupgrade(&universe, false);
        assert!(result.upgrades.is_empty());
        assert_eq!(result.ignored.len(), 1);
        assert_eq!(result.ignored[0].kind, IgnoredChange::Upgrade);
        assert_eq!(result.ignored[0].version.to_string(), "47.0-1");
    }

    /// The ignore test is nested inside the version comparison. A held-back package that has
    /// nothing to be held back from has had nothing prevented, and libalpm stays silent.
    #[test]
    fn an_ignored_package_already_at_the_repository_version_reports_nothing() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("gedit", "47.0-1"))
            .repo("core", [PackageSpec::new("gedit", "47.0-1")])
            .build();
        let ignored = vec!["gedit".to_owned()];

        assert!(sysupgrade(&ignoring(&scenario, &ignored, &[]), false).ignored.is_empty());
    }

    /// Without `-Suu` an older repository version was never going to be taken, so nothing was
    /// prevented. With it, the downgrade is what `IgnorePkg` held back.
    #[test]
    fn an_older_ignored_version_is_reported_only_under_downgrade() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("gedit", "47.0-1"))
            .repo("core", [PackageSpec::new("gedit", "46.2-1")])
            .build();
        let ignored = vec!["gedit".to_owned()];
        let universe = ignoring(&scenario, &ignored, &[]);

        assert!(sysupgrade(&universe, false).ignored.is_empty());
        let downgraded = sysupgrade(&universe, true);
        assert_eq!(downgraded.ignored.len(), 1);
        assert_eq!(downgraded.ignored[0].kind, IgnoredChange::Downgrade);
    }

    /// `check_replacers` warns and `continue`s rather than replacing.
    #[test]
    fn an_ignored_replacer_is_reported_and_not_applied() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old", "1.0.0-1"))
            .repo("core", [PackageSpec::new("new", "2.0.0-1").replaces(["old"])])
            .build();
        let ignored = vec!["new".to_owned()];
        let universe = ignoring(&scenario, &ignored, &[]);

        let result = sysupgrade(&universe, false);
        assert!(result.replacements.is_empty());
        assert_eq!(result.ignored.len(), 1);
        assert_eq!(result.ignored[0].kind, IgnoredChange::Replacement);
        assert_eq!(result.ignored[0].name.as_ref(), "new");
    }

    /// `check_literal` tests `should_ignore(spkg) || should_ignore(lpkg)`. Only the repository
    /// side can be filtered while interning, so an `IgnoreGroup` that only the installed
    /// `desc` carries is the case that a candidate-side filter alone lets through.
    #[test]
    fn an_ignore_group_carried_only_by_the_installed_package_still_holds_the_upgrade_back() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "1.0.0-1").groups(["held"]))
            .repo("core", [PackageSpec::new("app", "2.0.0-1")])
            .build();
        let groups = vec!["held".to_owned()];
        let universe = ignoring(&scenario, &[], &groups);

        let result = sysupgrade(&universe, false);
        assert!(
            result.upgrades.is_empty(),
            "the installed side of the test must hold the upgrade back, as `lpkg` does"
        );
        assert_eq!(result.ignored.len(), 1);
        assert_eq!(result.ignored[0].kind, IgnoredChange::Upgrade);
    }

    /// `_alpm_db_get_pkgfromcache` finds a package whatever its ignore status, and the caller
    /// then `break`s: the first repository carrying the name settles the outcome. A candidate
    /// filtered out of the universe must not let a lower-priority repository volunteer an
    /// upgrade pacman never offers.
    #[test]
    fn an_ignored_copy_in_the_first_repository_settles_the_search() {
        // Only `core`'s copy carries the ignored group, so `extra`'s newer copy is a perfectly
        // ordinary candidate — and must still never be reached.
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "1.0.0-1"))
            .repo("core", [PackageSpec::new("app", "2.0.0-1").groups(["held"])])
            .repo("extra", [PackageSpec::new("app", "3.0.0-1")])
            .build();
        let groups = vec!["held".to_owned()];
        let universe = ignoring(&scenario, &[], &groups);

        let result = sysupgrade(&universe, false);
        assert!(
            result.upgrades.is_empty(),
            "core carries the name, ignored or not, so extra is never consulted"
        );
        assert_eq!(result.ignored.len(), 1);
        assert_eq!(result.ignored[0].version.to_string(), "2.0.0-1", "core's copy, not extra's");
    }

    /// The names `resolve_targets` put on `request`, in the order it added them.
    fn resolved<'a>(universe: &Universe<'a>, targets: &[&str]) -> Vec<&'a str> {
        let owned: Vec<String> = targets.iter().map(|target| (*target).to_owned()).collect();
        let resolution =
            resolve_targets(universe, Request::new(), &owned, &Limits::default()).unwrap();
        named(universe, resolution.request.targets())
    }

    #[test]
    fn a_group_target_expands_to_every_member() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("editor", "1.0.0-1").groups(["tools"]),
                    PackageSpec::new("linker", "1.0.0-1").groups(["tools"]),
                    PackageSpec::new("unrelated", "1.0.0-1"),
                ],
            )
            .build();
        let universe = universe_of(&scenario, DbUsage::ALL);

        let mut members = resolved(&universe, &["tools"]);
        members.sort_unstable();
        assert_eq!(members, ["editor", "linker"]);
    }

    /// pacman tries the name as a package first, so a package and a group sharing a name
    /// install the package alone rather than both.
    #[test]
    fn a_package_wins_over_a_group_of_the_same_name() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("tools", "1.0.0-1"),
                    PackageSpec::new("member", "1.0.0-1").groups(["tools"]),
                ],
            )
            .build();
        let universe = universe_of(&scenario, DbUsage::ALL);

        assert_eq!(resolved(&universe, &["tools"]), ["tools"]);
    }

    #[test]
    fn a_target_naming_neither_a_package_nor_a_group_is_reported() {
        let scenario = Scenario::new().repo("core", [PackageSpec::new("app", "1.0.0-1")]).build();
        let universe = universe_of(&scenario, DbUsage::ALL);

        let failure =
            resolve_targets(&universe, Request::new(), &["absent".to_owned()], &Limits::default())
                .unwrap_err();
        assert!(matches!(failure, TargetResolutionFailure::NotFound(name) if name == "absent"));
    }

    /// A member both enabled repositories carry expands to one target, so the at-most-one
    /// clause on its name has one unit to agree with rather than two to contradict. Offering
    /// both candidates makes this request unsatisfiable.
    #[test]
    fn a_member_carried_by_two_repositories_still_solves() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("shared", "1.0.0-1").groups(["tools"])])
            .repo("extra", [PackageSpec::new("shared", "2.0.0-1").groups(["tools"])])
            .build();
        let universe = universe_of(&scenario, DbUsage::ALL);

        let resolution =
            resolve_targets(&universe, Request::new(), &["tools".to_owned()], &Limits::default())
                .unwrap();
        let planned = solve_with_removals(&universe, &resolution.request, &Limits::default())
            .unwrap()
            .expect("a group target must not encode an unsatisfiable request");

        let selected: Vec<String> = planned
            .selected
            .iter()
            .filter_map(|id| universe.get(*id))
            .filter(|candidate| candidate.name().as_ref() == "shared")
            .map(|candidate| candidate.version().to_string())
            .collect();
        assert_eq!(selected, ["1.0.0-1"], "core's build, and only it");
    }
}
