//! Turning an unsatisfiable core into something a person can act on.
//!
//! libalpm reports a failed transaction through a `void **data` out-param whose real type
//! depends on the error code: `alpm_depmissing_t*` for `ALPM_ERR_UNSATISFIED_DEPS`,
//! `alpm_conflict_t*` for `ALPM_ERR_CONFLICTING_DEPS`, a bare `char*` elsewhere. It is a flat
//! list of *symptoms* — which dependency was missing, which two packages clashed. It cannot say
//! why the situation arose, because by the time it is built, the search that produced it is
//! gone.
//!
//! A [`Derivation`] keeps the search's own reasoning. Each [`Fact`] is one clause the solver
//! actually used, resolved from candidate ids back to package names and the exact relation
//! involved, so the chain reads as an argument:
//!
//! ```text
//! cannot remove bubblewrap:
//!   bubblewrap 0.11.2-1 (installed) cannot be selected
//!   glycin 2.1.5-2 (installed) is installed and must remain
//!   glycin 2.1.5-2 (installed) requires bubblewrap
//! ```
//!
//! Rendering lives here rather than in the CLI because it needs the [`Universe`] the ids came
//! from. Every future frontend — a commit engine's error path, a TUI — needs the same thing.
//! The CLI adds only the indentation.

use std::fmt;

use alpm_types::RelationOrSoname;

use crate::Limits;
use crate::solve::clause::{ClauseKind, Lit};
use crate::solve::{Outcome, Problem, SolvableId, Solver, Universe, Unsatisfiable};

/// One clause from the core, in terms of packages rather than candidate ids.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Fact {
    /// A package was requested.
    Requested {
        /// How the package prints, including its origin.
        package: String,
    },
    /// A package cannot be selected — the user asked for it to go.
    Excluded {
        /// How the package prints.
        package: String,
    },
    /// A package is installed and this transaction does not remove it.
    MustRemain {
        /// How the package prints.
        package: String,
    },
    /// A package needs something.
    Requires {
        /// The package with the dependency.
        package: String,
        /// The `%DEPENDS%` entry, verbatim, so the version constraint is visible.
        relation: String,
    },
    /// Two packages cannot both be present.
    Conflicts {
        /// The package whose `%CONFLICTS%` names the other.
        package: String,
        /// The package named — possibly matched through `%PROVIDES%`.
        other: String,
    },
    /// One package replaces another.
    Replaces {
        /// The incoming package.
        package: String,
        /// The installed package it displaces.
        replaced: String,
    },
    /// A `%DEPENDS%` entry had a satisfier in a repository, and `IgnorePkg`/`IgnoreGroup`
    /// removed it from the candidate set.
    ///
    /// Accompanies a [`Fact::Requires`] rather than replacing it: the requirement is the
    /// clause in the core, and this says why nothing answers it. Without it the explanation
    /// reads as "no such package exists", which sends the user looking for a typo instead of
    /// at `pacman.conf`. libalpm separates the same two outcomes as `ALPM_ERR_PKG_IGNORED`
    /// versus `ALPM_ERR_PKG_NOT_FOUND` (`deps.c:743`).
    Ignored {
        /// The `%DEPENDS%` entry nothing satisfies.
        relation: String,
        /// The package that would have satisfied it.
        candidate: String,
        /// Which list covered it, and the pattern that matched.
        reason: String,
    },
    /// A `%DEPENDS%` entry nothing satisfies, although a package of that name exists.
    ///
    /// Accompanies a [`Fact::Requires`], for the reason [`Fact::Ignored`] does: the
    /// requirement is the clause in the core, and this says why nothing answers it. Without
    /// it a version dead-end reads as "no such package", which sends the reader looking for
    /// a typo rather than at the version they asked for.
    ///
    /// Mutually exclusive with [`Fact::Ignored`] on one relation. When a candidate was set
    /// aside, that is the answer, and a second line about versions only competes with it.
    NoVersion {
        /// The `%DEPENDS%` entry nothing satisfies.
        relation: String,
        /// The highest-versioned candidate carrying that name.
        nearest: String,
    },
    /// A caller answered `ALPM_QUESTION_SELECT_PROVIDER`, so one provider satisfies a
    /// `%DEPENDS%` entry and the others no longer do.
    ///
    /// Replaces the [`Fact::Requires`] for that entry rather than accompanying it, because
    /// the clause itself carries the answer. Without it the explanation reads as "nothing
    /// satisfies this dependency" while several packages plainly do. That is the same
    /// misreading [`Fact::Ignored`] exists to prevent.
    Chose {
        /// The package with the dependency.
        package: String,
        /// The `%DEPENDS%` entry, verbatim.
        relation: String,
        /// The provider the answer named.
        chosen: String,
    },
    /// Two candidates are versions of the same package, so at most one can be chosen.
    SameName {
        /// The first candidate.
        first: String,
        /// The second candidate.
        second: String,
    },
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested { package } => write!(f, "{package} was requested"),
            Self::Excluded { package } => write!(f, "{package} cannot be selected"),
            Self::MustRemain { package } => {
                write!(f, "{package} is installed and must remain")
            }
            Self::Requires { package, relation } => write!(f, "{package} requires {relation}"),
            Self::Conflicts { package, other } => {
                write!(f, "{package} conflicts with {other}")
            }
            Self::Replaces { package, replaced } => write!(f, "{package} replaces {replaced}"),
            Self::Ignored { relation, candidate, reason } => {
                write!(f, "{candidate} would satisfy {relation}, but it is ignored ({reason})")
            }
            Self::NoVersion { relation, nearest } => {
                write!(f, "nothing satisfies {relation}; the closest candidate is {nearest}")
            }
            Self::Chose { package, relation, chosen } => {
                write!(f, "{chosen} was chosen to satisfy {relation}, which {package} requires")
            }
            Self::SameName { first, second } => {
                write!(f, "{first} and {second} are versions of the same package")
            }
        }
    }
}

/// What kind of failure an unsatisfiable core describes.
///
/// libalpm discriminates the same thing by error code — `ALPM_ERR_UNSATISFIED_DEPS`,
/// `ALPM_ERR_CONFLICTING_DEPS`, `ALPM_ERR_PKG_IGNORED` — and the code decides how to read the
/// `void **data` beside it. Here it is read off the facts instead, so a frontend leads with
/// the diagnosis and the facts stay the supporting argument.
///
/// [`Shape::Unclassified`] is the closed fallback. A core it does not name still carries its
/// facts, so an unrecognised shape prints what it always printed rather than nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Shape {
    /// Nothing in any configured repository satisfies a `%DEPENDS%` entry.
    Unsatisfied {
        /// One of the entries nothing satisfies. Others may appear in the facts.
        relation: String,
    },
    /// The only candidates for a `%DEPENDS%` entry are covered by `IgnorePkg`/`IgnoreGroup`.
    IgnoredOnly {
        /// The entry whose satisfiers were all set aside.
        relation: String,
    },
    /// A caller's answer to `ALPM_QUESTION_SELECT_PROVIDER` left no solution.
    ChosenProvider {
        /// The entry the answer was about.
        relation: String,
        /// The provider the answer named.
        chosen: String,
    },
    /// Two candidates that cannot both be present are both needed.
    Conflict {
        /// The candidate whose `%CONFLICTS%` names the other.
        first: String,
        /// The candidate named.
        second: String,
    },
    /// A package the caller asked to remove is one the installed set still needs.
    Removal {
        /// The package that cannot go.
        package: String,
    },
    /// The rules above do not name this core.
    Unclassified,
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsatisfied { relation } => write!(f, "nothing satisfies {relation}"),
            Self::IgnoredOnly { relation } => {
                write!(f, "every candidate satisfying {relation} is ignored")
            }
            Self::ChosenProvider { relation, chosen } => {
                write!(f, "{chosen} was chosen to satisfy {relation}, and leaves no solution")
            }
            Self::Conflict { first, second } => {
                write!(f, "{first} and {second} cannot both be installed")
            }
            Self::Removal { package } => {
                write!(f, "removing {package} would leave the system unsatisfied")
            }
            Self::Unclassified => write!(f, "the requested transaction has no solution"),
        }
    }
}

impl Shape {
    /// Reads the shape off an ordered fact listing.
    ///
    /// The tests run most specific first, because several hold at once on a real core. An
    /// ignored candidate names a `pacman.conf` line to change and beats everything. An
    /// answered provider question names a choice the caller made. A conflict names two
    /// packages. A version dead-end names one. A removal is left last, because the facts that
    /// make it up — something excluded, something held in place — also appear under every
    /// shape above.
    fn of(facts: &[Fact]) -> Self {
        for fact in facts {
            if let Fact::Ignored { relation, .. } = fact {
                return Self::IgnoredOnly { relation: relation.clone() };
            }
        }
        for fact in facts {
            if let Fact::Chose { relation, chosen, .. } = fact {
                return Self::ChosenProvider { relation: relation.clone(), chosen: chosen.clone() };
            }
        }
        for fact in facts {
            if let Fact::Conflicts { package, other } = fact {
                return Self::Conflict { first: package.clone(), second: other.clone() };
            }
        }
        for fact in facts {
            if let Fact::NoVersion { relation, .. } = fact {
                return Self::Unsatisfied { relation: relation.clone() };
            }
        }
        for fact in facts {
            if let Fact::Excluded { package } = fact {
                return Self::Removal { package: package.clone() };
            }
        }
        // A requirement with nothing beside it. The note explaining why nothing answers it is
        // emitted only when the relation names a package that exists, so a relation naming
        // nothing at all reaches here.
        for fact in facts {
            if let Fact::Requires { relation, .. } = fact {
                return Self::Unsatisfied { relation: relation.clone() };
            }
        }
        Self::Unclassified
    }
}

/// A single change that leaves the request solvable.
///
/// Every variant but [`Remedy::Unignore`] is **verified**: the constraint it names was taken
/// out of the compiled problem and the rest solved again. libalpm proposes nothing at all, so
/// the choice here is between a verified suggestion and none.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Remedy {
    /// Dropping this target leaves a solution.
    DropTarget {
        /// The target to drop.
        package: String,
    },
    /// Letting this installed package go leaves a solution.
    AllowRemoval {
        /// The package that would have to be removed.
        package: String,
    },
    /// Answering a provider question with this candidate instead leaves a solution.
    ChooseOther {
        /// The `%DEPENDS%` entry the answer is about.
        relation: String,
        /// A provider the re-solve actually selected, not merely one that was available.
        provider: String,
    },
    /// An `IgnorePkg`/`IgnoreGroup` entry covers the only candidate.
    ///
    /// The one variant that is **not** verified. An ignored candidate is never interned, so
    /// testing it needs a second encode against a different universe rather than a solve over
    /// the problem already in hand. A frontend words it as a suggestion.
    Unignore {
        /// The candidate that was set aside.
        package: String,
        /// Which list covered it, and the pattern that matched.
        reason: String,
    },
}

impl fmt::Display for Remedy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DropTarget { package } => write!(f, "drop {package} from the transaction"),
            Self::AllowRemoval { package } => write!(f, "let {package} be removed"),
            Self::ChooseOther { relation, provider } => {
                write!(f, "take {provider} for {relation} instead")
            }
            Self::Unignore { package, reason } => {
                write!(f, "allow {package}, which {reason} covers")
            }
        }
    }
}

/// Why a request has no solution: the diagnosis, the facts that support it, and what would
/// leave it solvable.
#[derive(Clone, Debug)]
pub struct Diagnosis {
    shape: Shape,
    derivation: Derivation,
    remedies: Vec<Remedy>,
    probes_dropped: usize,
    gave_up: bool,
}

impl Diagnosis {
    /// What kind of failure this is.
    #[must_use]
    pub const fn shape(&self) -> &Shape {
        &self.shape
    }

    /// The facts supporting it.
    #[must_use]
    pub const fn derivation(&self) -> &Derivation {
        &self.derivation
    }

    /// Whether the explanation could not be obtained at all.
    ///
    /// The re-solve an explanation needs runs under the same
    /// [`crate::Limits::solve_max_conflicts`] as the search that failed, and can exhaust it.
    /// A caller must be able to tell that from a failure there was simply nothing to say
    /// about, which is otherwise the same empty listing.
    #[must_use]
    pub const fn gave_up(&self) -> bool {
        self.gave_up
    }

    /// The single changes that were tried and found to leave a solution.
    ///
    /// Empty when no single change among those tried does, which is an answer rather than a
    /// gap: the request is impossible however one of its constraints is relaxed.
    #[must_use]
    pub fn remedies(&self) -> &[Remedy] {
        &self.remedies
    }

    /// How many candidate changes [`crate::Limits::explain_max_probes`] left untried.
    #[must_use]
    pub const fn probes_dropped(&self) -> usize {
        self.probes_dropped
    }

    /// Classifies a derivation and proposes what would leave the request solvable.
    #[must_use]
    pub(crate) fn of(
        universe: &Universe<'_>,
        problem: &Problem,
        unsat: &Unsatisfiable,
        derivation: Derivation,
        limits: &Limits,
    ) -> Self {
        let shape = Shape::of(derivation.facts());
        let (mut remedies, probes_dropped) = probe(universe, problem, unsat, limits);
        // An ignored candidate is the one remedy no probe can reach, so it is read off the
        // facts that already found it.
        for fact in derivation.facts() {
            if let Fact::Ignored { candidate, reason, .. } = fact {
                remedies
                    .push(Remedy::Unignore { package: candidate.clone(), reason: reason.clone() });
            }
        }
        Self { shape, derivation, remedies, probes_dropped, gave_up: false }
    }

    /// A diagnosis for a failure no explanation could be obtained for.
    #[must_use]
    pub(crate) fn gave_up_on() -> Self {
        Self {
            shape: Shape::Unclassified,
            derivation: Derivation::empty(),
            remedies: Vec::new(),
            probes_dropped: 0,
            gave_up: true,
        }
    }
}

/// The parts of the argument a listing is ordered into.
///
/// The order is the order the facts read in: what was asked for, what the installed set holds
/// in place, the requirements at issue, then what rules the rest out.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Bucket {
    /// What the caller asked for.
    Asked,
    /// What the installed set holds in place.
    Held,
    /// The requirements at issue, and the notes saying why nothing answers them.
    Required,
    /// What rules the rest out.
    Contradiction,
}

impl Bucket {
    /// Whether [`crate::Limits::explain_max_facts`] may drop a fact from this part.
    ///
    /// [`Self::Asked`] holds one fact per target and [`Self::Contradiction`] one per
    /// contradiction, so neither runs away. They are also the two an explanation cannot do
    /// without: trimmed to neither, it names nothing.
    const fn is_supporting(self) -> bool {
        matches!(self, Self::Held | Self::Required)
    }
}

/// A fact together with what places it in the listing.
#[derive(Debug)]
struct Ranked {
    bucket: Bucket,
    /// The package name of the relation this fact is about, so lines frustrated by one
    /// package stay adjacent whatever version each of them asked for. `None` for a fact about
    /// no particular relation, which sorts before every named group.
    group: Option<String>,
    /// Places a note after the requirement it annotates, inside one group.
    within: u8,
    fact: Fact,
}

/// Why a request could not be satisfied.
#[derive(Clone, Debug)]
pub struct Derivation {
    facts: Vec<Fact>,
    facts_dropped: usize,
}

impl Derivation {
    /// The facts that together cannot all hold.
    ///
    /// Ordered as an argument rather than in the order the search derived them: what was
    /// asked for, what is held in place, the requirements at issue grouped by the package
    /// frustrating them, then the contradiction. Within a group, a requirement is followed by
    /// the note saying why nothing answers it.
    #[must_use]
    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }

    /// How many supporting facts [`crate::Limits::explain_max_facts`] left out.
    ///
    /// Counted rather than dropped in silence, so a caller can say the listing is partial.
    #[must_use]
    pub const fn facts_dropped(&self) -> usize {
        self.facts_dropped
    }

    /// Whether nothing could be explained.
    ///
    /// Possible in principle: a core made entirely of learned clauses has no package-level
    /// facts to report. Worth checking rather than printing an empty explanation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    /// A derivation with nothing to say, for a caller that could not obtain a core.
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self { facts: Vec::new(), facts_dropped: 0 }
    }

    /// Renders `unsat` against the universe its ids came from.
    #[must_use]
    pub fn build(
        universe: &Universe<'_>,
        problem: &Problem,
        unsat: &Unsatisfiable,
        limits: &Limits,
    ) -> Self {
        let mut ranked: Vec<Ranked> = unsat
            .core()
            .iter()
            .filter_map(|id| problem.get(*id))
            .flat_map(|clause| facts_for(universe, clause.kind()))
            .collect();

        // Stable, so the search's own order survives as the last tiebreak and two runs over
        // one core print one listing.
        ranked.sort_by(|left, right| {
            (left.bucket, &left.group, left.within).cmp(&(right.bucket, &right.group, right.within))
        });
        // One note is emitted per requirement clause, so two packages frustrated by the same
        // relation produce the same note twice. Equal facts sort adjacent, so an adjacent
        // pass catches every duplicate.
        ranked.dedup_by(|left, right| left.fact == right.fact);

        let mut budget = limits.explain_max_facts;
        let mut facts = Vec::new();
        let mut facts_dropped = 0usize;
        for item in ranked {
            if !item.bucket.is_supporting() {
                facts.push(item.fact);
                continue;
            }
            if budget == 0 {
                facts_dropped = facts_dropped.saturating_add(1);
                continue;
            }
            budget = budget.saturating_sub(1);
            facts.push(item.fact);
        }
        Self { facts, facts_dropped }
    }
}

impl fmt::Display for Derivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, item) in self.facts.iter().enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            write!(f, "{item}")?;
        }
        Ok(())
    }
}

/// Takes each constraint in the core out of the problem in turn and solves the rest.
///
/// Returns what left a solution, and how many candidates
/// [`crate::Limits::explain_max_probes`] left untried. Only core constraints are candidates:
/// a clause outside the core plays no part in the contradiction, so dropping it cannot
/// change the answer.
///
/// A probe that exceeds [`crate::Limits::solve_max_conflicts`] is passed over in silence. A
/// diagnosis reports on a failure that has already happened, and replacing it with a second
/// one tells the caller less than saying nothing would.
fn probe(
    universe: &Universe<'_>,
    problem: &Problem,
    unsat: &Unsatisfiable,
    limits: &Limits,
) -> (Vec<Remedy>, usize) {
    let mut remedies = Vec::new();
    let mut budget = limits.explain_max_probes;
    let mut dropped = 0usize;

    for id in unsat.core() {
        let Some(kind) = problem.get(*id).map(|clause| clause.kind()) else { continue };
        if !matches!(
            kind,
            ClauseKind::Target { .. } | ClauseKind::Installed { .. } | ClauseKind::Chosen { .. }
        ) {
            continue;
        }
        if budget == 0 {
            dropped = dropped.saturating_add(1);
            continue;
        }
        budget = budget.saturating_sub(1);
        if let Some(remedy) = probe_one(universe, problem, *id, kind, limits) {
            remedies.push(remedy);
        }
    }
    (remedies, dropped)
}

/// Solves the problem without one constraint, and names the change if that leaves a solution.
fn probe_one(
    universe: &Universe<'_>,
    problem: &Problem,
    id: crate::solve::ClauseId,
    kind: ClauseKind,
    limits: &Limits,
) -> Option<Remedy> {
    let mut subset = problem.without(&[id]);

    // An answered provider question is not a constraint to drop. Its clause *replaces* the
    // requirement, so dropping it alone would leave the dependency unenforced, and a solution
    // found that way would say the dependency is the problem rather than the answer. Putting
    // the unanswered requirement back asks the question this remedy is about.
    let restored = match kind {
        ClauseKind::Chosen { dependent, dependency, chosen } => {
            let relation = relation_of(universe, dependent, dependency)?;
            let satisfiers = universe.satisfiers(&relation);
            let mut literals = vec![Lit::negative(dependent)];
            literals.extend(satisfiers.iter().copied().map(Lit::positive));
            subset.add(literals, ClauseKind::Requires { dependent, dependency });
            Some((relation, satisfiers, chosen))
        }
        _ => None,
    };

    let Ok(Outcome::Satisfied(solution)) = Solver::new(&subset, *limits).solve() else {
        return None;
    };

    match kind {
        ClauseKind::Target { target } => {
            Some(Remedy::DropTarget { package: describe_candidate(universe, target) })
        }
        ClauseKind::Installed { installed } => {
            Some(Remedy::AllowRemoval { package: describe_candidate(universe, installed) })
        }
        ClauseKind::Chosen { .. } => {
            let (relation, satisfiers, chosen) = restored?;
            // The restored requirement is satisfiable by `chosen` too, and a solution that
            // picked it would mean the dependent is simply not selected here rather than that
            // another provider works. So the remedy names the provider the re-solve actually
            // took, and is withheld when that is the answer already given.
            let provider =
                satisfiers.iter().find(|id| **id != chosen && solution.selected().contains(id))?;
            Some(Remedy::ChooseOther {
                relation: relation.to_string(),
                provider: describe_candidate(universe, *provider),
            })
        }
        _ => None,
    }
}

/// Resolves one clause into the facts it contributes, each placed in the listing.
///
/// At most one clause-level [`Fact`], plus a note saying why an unsatisfiable requirement has
/// no satisfier: a [`Fact::Ignored`] per candidate set aside, or else a [`Fact::NoVersion`]
/// naming the closest candidate there is. The note is attached here, where the relation is
/// already in hand. Otherwise a caller re-derives it by comparing the explanation against the
/// universe.
fn facts_for(universe: &Universe<'_>, kind: ClauseKind) -> Vec<Ranked> {
    let relation = match kind {
        ClauseKind::Requires { dependent, dependency }
        | ClauseKind::Chosen { dependent, dependency, .. } => {
            relation_of(universe, dependent, dependency)
        }
        _ => None,
    };
    // The group key is the relation's package name, not its text, so `leaf>=100` and
    // `leaf>=101` list together. A requirement is what a group is about, so a clause without
    // one joins no group.
    let group = relation.as_ref().and_then(|dep| crate::depcmp::v1_name(dep)).map(str::to_owned);

    let mut ranked: Vec<Ranked> = fact(universe, kind)
        .into_iter()
        .map(|fact| Ranked { bucket: bucket_of(&fact), group: group.clone(), within: 0, fact })
        .collect();

    let ClauseKind::Requires { .. } = kind else { return ranked };
    let Some(relation) = relation else { return ranked };
    // Only when nothing interned answers it. A requirement that *is* satisfiable is in the
    // core for some other reason, and naming an alternative there would be noise.
    if !universe.satisfiers(&relation).is_empty() {
        return ranked;
    }

    // `within: 1` places a note after the requirement it annotates, inside the group.
    let note =
        |fact: Fact| Ranked { bucket: Bucket::Required, group: group.clone(), within: 1, fact };

    let ignored: Vec<Ranked> = universe
        .ignored_satisfiers(&relation)
        .map(|candidate| {
            note(Fact::Ignored {
                relation: relation.to_string(),
                candidate: format!(
                    "{}-{}",
                    candidate.package().name(),
                    candidate.package().version()
                ),
                reason: candidate.reason().to_string(),
            })
        })
        .collect();
    if !ignored.is_empty() {
        ranked.extend(ignored);
        return ranked;
    }

    if let Some(nearest) = nearest_candidate(universe, &relation) {
        ranked.push(note(Fact::NoVersion {
            relation: relation.to_string(),
            nearest: describe_candidate(universe, nearest),
        }));
    }
    ranked
}

/// Which part of the argument a fact belongs to.
///
/// Total by construction: a variant added later lands in [`Bucket::Required`], which is
/// bounded and prints in the middle, rather than escaping the listing's order.
const fn bucket_of(fact: &Fact) -> Bucket {
    match fact {
        Fact::Requested { .. } | Fact::Excluded { .. } => Bucket::Asked,
        Fact::MustRemain { .. } => Bucket::Held,
        Fact::Conflicts { .. } | Fact::Replaces { .. } | Fact::SameName { .. } => {
            Bucket::Contradiction
        }
        _ => Bucket::Required,
    }
}

/// One of `dependent`'s `%DEPENDS%` entries, or `None` if it cannot be read.
fn relation_of(
    universe: &Universe<'_>,
    dependent: SolvableId,
    dependency: usize,
) -> Option<RelationOrSoname> {
    universe
        .get(dependent)
        .and_then(|solvable| solvable.depends().ok())
        .and_then(|depends| depends.get(dependency).cloned())
}

/// The highest-versioned candidate carrying `dep`'s package name.
///
/// Answers "the package is there, no version of it fits" for a relation nothing satisfies.
/// `None` when no candidate carries the name at all, which is the ordinary missing-package
/// case and needs no extra line.
///
/// Keyed by the name alone. A relation satisfied only through some other package's
/// `%PROVIDES%` is deliberately not searched: that is a scan of every candidate's
/// `%PROVIDES%` per frustrated relation, and it answers by naming a package the reader never
/// mentioned. **alpm-sonamev2** is matched whole rather than by name, so it has no nearest
/// candidate either.
///
/// Ties go to the first candidate, which is the installed copy when there is one, then
/// repositories in priority order.
pub(crate) fn nearest_candidate(
    universe: &Universe<'_>,
    dep: &RelationOrSoname,
) -> Option<SolvableId> {
    let name = crate::depcmp::v1_name(dep)?;
    let mut best: Option<SolvableId> = None;
    for id in universe.candidates_named(name) {
        let Some(candidate) = universe.get(*id) else { continue };
        let better = best
            .and_then(|current| universe.get(current))
            .is_none_or(|current| candidate.version() > current.version());
        if better {
            best = Some(*id);
        }
    }
    best
}

/// Resolves one clause into a [`Fact`], or `None` for a clause with nothing to say.
fn fact(universe: &Universe<'_>, kind: ClauseKind) -> Option<Fact> {
    match kind {
        ClauseKind::Requires { dependent, dependency } => Some(Fact::Requires {
            package: describe_candidate(universe, dependent),
            relation: relation_text(universe, dependent, dependency),
        }),
        ClauseKind::Chosen { dependent, dependency, chosen } => Some(Fact::Chose {
            package: describe_candidate(universe, dependent),
            relation: relation_text(universe, dependent, dependency),
            chosen: describe_candidate(universe, chosen),
        }),
        ClauseKind::Conflicts { declarer, other } => Some(Fact::Conflicts {
            package: describe_candidate(universe, declarer),
            other: describe_candidate(universe, other),
        }),
        ClauseKind::SameName { first, second } => Some(Fact::SameName {
            first: describe_candidate(universe, first),
            second: describe_candidate(universe, second),
        }),
        ClauseKind::Replaces { replacement, replaced } => Some(Fact::Replaces {
            package: describe_candidate(universe, replacement),
            replaced: describe_candidate(universe, replaced),
        }),
        ClauseKind::Target { target } => {
            Some(Fact::Requested { package: describe_candidate(universe, target) })
        }
        ClauseKind::Installed { installed } => {
            Some(Fact::MustRemain { package: describe_candidate(universe, installed) })
        }
        ClauseKind::Excluded { excluded } => {
            Some(Fact::Excluded { package: describe_candidate(universe, excluded) })
        }
        // A learned clause is a fact the solver derived, not one a user could act on. The core
        // already replaces each one with the problem clauses that produced it.
        ClauseKind::Learned => None,
    }
}

/// One of `dependent`'s `%DEPENDS%` entries, verbatim, or `?` if it cannot be read.
fn relation_text(universe: &Universe<'_>, dependent: SolvableId, dependency: usize) -> String {
    universe
        .get(dependent)
        .and_then(|solvable| solvable.depends().ok())
        .and_then(|depends| depends.get(dependency).map(ToString::to_string))
        .unwrap_or_else(|| "?".to_owned())
}

/// `name version (origin)`, the form every fact refers to a package by.
///
/// The origin matters. "glibc (installed)" and "glibc (core)" are different candidates. An
/// explanation that could not tell them apart would be unreadable exactly when it matters.
///
/// This is public because a frontend sometimes names a candidate outside an explanation, in a
/// prompt listing the providers of a dependency. It must spell it the same way, or the two
/// drift.
#[must_use]
pub fn describe_candidate(universe: &Universe<'_>, id: SolvableId) -> String {
    universe.get(id).map_or_else(
        || "<unknown>".to_owned(),
        |solvable| {
            let origin = match solvable.origin() {
                crate::solve::Origin::Installed => "installed".to_owned(),
                crate::solve::Origin::Repository(index) => universe
                    .repository_name(index)
                    .map_or_else(|| "?".to_owned(), ToString::to_string),
                crate::solve::Origin::File(_) => "file".to_owned(),
            };
            format!("{} {} ({origin})", solvable.name(), solvable.version())
        },
    )
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
    use crate::Limits;
    use crate::config::DbUsage;
    use crate::fixture::{PackageSpec, Scenario};
    use crate::resolve::IgnoreList;
    use crate::solve::{
        Outcome, ProviderChoice, Request, Solver, UniverseOptions, encode, resolve_target,
    };

    /// A dependency nothing provides must name the package and the exact relation.
    #[test]
    fn a_missing_dependency_names_the_relation_that_is_missing() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("app", "1.0.0-1").depends(["absent>=2.0"])])
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let request = Request::new().target(id);
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();

        let Ok(Outcome::Unsatisfiable(unsat)) = Solver::new(encoded.problem(), limits).solve()
        else {
            panic!("expected unsatisfiable");
        };

        let derivation = Derivation::build(&universe, encoded.problem(), &unsat, &limits);
        let rendered = derivation.to_string();
        assert!(
            derivation.facts().iter().any(|fact| matches!(
                fact,
                Fact::Requires { relation, .. } if relation == "absent>=2.0"
            )),
            "the exact relation must appear: {rendered}"
        );
        assert!(rendered.contains("app 1.0.0-1 (core)"), "{rendered}");
    }

    /// A conflict explanation must name both sides and say which is installed.
    #[test]
    fn a_conflict_names_both_packages_and_their_origins() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old-thing", "1.0.0-1"))
            .installed(PackageSpec::new("needs-old", "1.0.0-1").depends(["old-thing"]))
            .repo("core", [PackageSpec::new("new-thing", "1.0.0-1").conflicts(["old-thing"])])
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"new-thing".parse().unwrap()).unwrap();
        // `allow_removals(false)` keeps the conflict fatal, so there is a core to explain.
        let request = Request::new().target(id).allow_removals(false);
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();

        let Ok(Outcome::Unsatisfiable(unsat)) = Solver::new(encoded.problem(), limits).solve()
        else {
            panic!("expected unsatisfiable");
        };

        let rendered = Derivation::build(&universe, encoded.problem(), &unsat, &limits).to_string();
        assert!(rendered.contains("old-thing 1.0.0-1 (installed)"), "{rendered}");
        assert!(rendered.contains("new-thing 1.0.0-1 (core)"), "{rendered}");
        assert!(rendered.contains("conflicts with"), "{rendered}");
    }

    /// Builds `scenario`'s universe, solves `target`, and renders the derivation.
    fn derivation_for(scenario: &crate::fixture::BuiltScenario, target: &str) -> Derivation {
        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &target.parse().unwrap()).unwrap();
        let request = Request::new().target(id);
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();
        let Ok(Outcome::Unsatisfiable(unsat)) = Solver::new(encoded.problem(), limits).solve()
        else {
            panic!("expected unsatisfiable");
        };
        Derivation::build(&universe, encoded.problem(), &unsat, &limits)
    }

    /// A version dead-end must name the version that *is* there. Without it the explanation
    /// reads as a missing package, and the reader checks their spelling instead of their
    /// constraint.
    #[test]
    fn a_version_dead_end_names_the_closest_candidate() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["leaf>=2.0"]),
                    PackageSpec::new("leaf", "1.0.0-1"),
                ],
            )
            .build();

        let derivation = derivation_for(&scenario, "app");
        let rendered = derivation.to_string();
        assert!(
            derivation.facts().iter().any(|fact| matches!(
                fact,
                Fact::NoVersion { relation, nearest }
                    if relation == "leaf>=2.0" && nearest == "leaf 1.0.0-1 (core)"
            )),
            "{rendered}"
        );
    }

    /// A name no candidate carries has no closest candidate to name, so the requirement
    /// stands on its own.
    #[test]
    fn a_missing_name_gets_no_closest_candidate() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("app", "1.0.0-1").depends(["absent>=2.0"])])
            .build();

        let derivation = derivation_for(&scenario, "app");
        assert!(
            !derivation.facts().iter().any(|fact| matches!(fact, Fact::NoVersion { .. })),
            "{derivation}"
        );
    }

    /// `IgnorePkg` is the answer whenever it applies, and a version line beside it would only
    /// compete with it.
    #[test]
    fn an_ignored_satisfier_suppresses_the_closest_candidate() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["leaf>=2.0"]),
                    PackageSpec::new("leaf", "1.0.0-1"),
                    PackageSpec::new("newleaf", "3.0.0-1").provides(["leaf=3.0.0"]),
                ],
            )
            .build();

        let limits = Limits::default();
        let ignored = ["newleaf".to_owned()];
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new().ignores(IgnoreList::new(&ignored, &[])),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let encoded =
            encode(&universe, &Request::new().target(id), &limits, &Default::default()).unwrap();
        let Ok(Outcome::Unsatisfiable(unsat)) = Solver::new(encoded.problem(), limits).solve()
        else {
            panic!("expected unsatisfiable");
        };

        let derivation = Derivation::build(&universe, encoded.problem(), &unsat, &limits);
        assert!(
            derivation.facts().iter().any(|fact| matches!(fact, Fact::Ignored { .. })),
            "{derivation}"
        );
        assert!(
            !derivation.facts().iter().any(|fact| matches!(fact, Fact::NoVersion { .. })),
            "{derivation}"
        );
    }

    /// Builds an app whose one dependency has `providers` providers, each needing a version
    /// of `leaf` that does not exist. This is the fan-out the listing has to survive.
    fn fan_out(providers: usize) -> crate::fixture::BuiltScenario {
        let mut specs = vec![PackageSpec::new("app", "1.0.0-1").depends(["mid"])];
        for index in 0..providers {
            let wanted = format!("leaf>={}", index.saturating_add(100));
            specs.push(
                PackageSpec::new(&format!("p{index}"), "1.0.0-1")
                    .provides(["mid"])
                    .depends([wanted.as_str()]),
            );
        }
        specs.push(PackageSpec::new("leaf", "1.0.0-1"));
        Scenario::new().repo("core", specs).build()
    }

    /// The listing reads as an argument, not in the order the search derived it: what was
    /// asked for, then the requirements, then the contradiction.
    #[test]
    fn facts_are_ordered_as_an_argument() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old-thing", "1.0.0-1"))
            .installed(PackageSpec::new("needs-old", "1.0.0-1").depends(["old-thing"]))
            .repo("core", [PackageSpec::new("new-thing", "1.0.0-1").conflicts(["old-thing"])])
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"new-thing".parse().unwrap()).unwrap();
        let request = Request::new().target(id).allow_removals(false);
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();
        let Ok(Outcome::Unsatisfiable(unsat)) = Solver::new(encoded.problem(), limits).solve()
        else {
            panic!("expected unsatisfiable");
        };

        let derivation = Derivation::build(&universe, encoded.problem(), &unsat, &limits);
        let buckets: Vec<Bucket> = derivation.facts().iter().map(bucket_of).collect();
        let mut sorted = buckets.clone();
        sorted.sort_unstable();
        assert_eq!(buckets, sorted, "{derivation}");
        assert_eq!(buckets.first(), Some(&Bucket::Asked), "{derivation}");
        assert_eq!(buckets.last(), Some(&Bucket::Contradiction), "{derivation}");
    }

    /// Requirements frustrated by one package list together, whatever version each asked for,
    /// and the note naming the closest candidate comes last inside that run.
    #[test]
    fn requirements_on_one_package_list_together_with_their_note() {
        let scenario = fan_out(3);
        let derivation = derivation_for(&scenario, "app");
        let facts = derivation.facts();

        let first_leaf = facts
            .iter()
            .position(|fact| matches!(fact, Fact::Requires { relation, .. } if relation.starts_with("leaf")))
            .unwrap();
        let note = facts.iter().position(|fact| matches!(fact, Fact::NoVersion { .. })).unwrap();
        assert!(note > first_leaf, "{derivation}");
        for fact in facts.get(first_leaf..note).unwrap() {
            assert!(
                matches!(fact, Fact::Requires { relation, .. } if relation.starts_with("leaf")),
                "an unrelated fact split the group: {derivation}"
            );
        }
    }

    /// One note is emitted per requirement clause, so two dependents frustrated by the same
    /// relation would otherwise print it twice.
    #[test]
    fn a_note_shared_by_two_dependents_prints_once() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["mid"]),
                    PackageSpec::new("one", "1.0.0-1").provides(["mid"]).depends(["leaf>=2.0"]),
                    PackageSpec::new("two", "1.0.0-1").provides(["mid"]).depends(["leaf>=2.0"]),
                    PackageSpec::new("leaf", "1.0.0-1"),
                ],
            )
            .build();

        let derivation = derivation_for(&scenario, "app");
        let notes =
            derivation.facts().iter().filter(|fact| matches!(fact, Fact::NoVersion { .. })).count();
        assert_eq!(notes, 1, "{derivation}");
    }

    /// A fan-out is trimmed to the bound, and the trimming is counted rather than silent.
    #[test]
    fn a_fan_out_is_bounded_and_the_overflow_is_counted() {
        let scenario = fan_out(40);
        let limits = Limits { explain_max_facts: 8, ..Limits::default() };
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let encoded =
            encode(&universe, &Request::new().target(id), &limits, &Default::default()).unwrap();
        let Ok(Outcome::Unsatisfiable(unsat)) = Solver::new(encoded.problem(), limits).solve()
        else {
            panic!("expected unsatisfiable");
        };

        let derivation = Derivation::build(&universe, encoded.problem(), &unsat, &limits);
        let supporting =
            derivation.facts().iter().filter(|fact| bucket_of(fact).is_supporting()).count();
        assert_eq!(supporting, 8, "{derivation}");
        assert!(derivation.facts_dropped() > 0, "the overflow must be counted: {derivation}");
    }

    /// The bound covers the supporting detail only. Trimmed to neither what was asked for nor
    /// what contradicts it, an explanation names nothing.
    #[test]
    fn a_bound_of_zero_still_names_what_was_asked_for_and_what_contradicts_it() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old-thing", "1.0.0-1"))
            .repo("core", [PackageSpec::new("new-thing", "1.0.0-1").conflicts(["old-thing"])])
            .build();

        let limits = Limits { explain_max_facts: 0, ..Limits::default() };
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"new-thing".parse().unwrap()).unwrap();
        let request = Request::new().target(id).allow_removals(false);
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();
        let Ok(Outcome::Unsatisfiable(unsat)) = Solver::new(encoded.problem(), limits).solve()
        else {
            panic!("expected unsatisfiable");
        };

        let derivation = Derivation::build(&universe, encoded.problem(), &unsat, &limits);
        assert!(
            derivation.facts().iter().any(|fact| matches!(fact, Fact::Requested { .. })),
            "{derivation}"
        );
        assert!(
            derivation.facts().iter().any(|fact| matches!(fact, Fact::Conflicts { .. })),
            "{derivation}"
        );
    }

    /// A conflict names both sides in the headline, so a reader has the diagnosis before the
    /// supporting facts.
    #[test]
    fn a_conflict_is_classified_as_one() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old-thing", "1.0.0-1"))
            .repo("core", [PackageSpec::new("new-thing", "1.0.0-1").conflicts(["old-thing"])])
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"new-thing".parse().unwrap()).unwrap();
        let request = Request::new().target(id).allow_removals(false);
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();

        let diagnosis = encoded.diagnose(&universe, &limits);
        assert!(!diagnosis.gave_up());
        let Shape::Conflict { first, second } = diagnosis.shape() else {
            panic!("expected a conflict: {:?}", diagnosis.shape());
        };
        let named = [first.as_str(), second.as_str()];
        assert!(named.contains(&"new-thing 1.0.0-1 (core)"), "{named:?}");
        assert!(named.contains(&"old-thing 1.0.0-1 (installed)"), "{named:?}");
    }

    /// A version dead-end is a different failure from a conflict, and must not borrow its
    /// headline.
    #[test]
    fn a_version_dead_end_is_classified_by_its_relation() {
        let scenario = fan_out(3);
        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let encoded =
            encode(&universe, &Request::new().target(id), &limits, &Default::default()).unwrap();

        let diagnosis = encoded.diagnose(&universe, &limits);
        assert!(
            matches!(diagnosis.shape(), Shape::Unsatisfied { relation } if relation.starts_with("leaf")),
            "{:?}",
            diagnosis.shape()
        );
    }

    /// `IgnorePkg` names a `pacman.conf` line to change, so it wins over every other shape a
    /// core holds at the same time.
    #[test]
    fn an_ignored_satisfier_wins_the_classification() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["leaf>=2.0"]),
                    PackageSpec::new("leaf", "1.0.0-1"),
                    PackageSpec::new("newleaf", "3.0.0-1").provides(["leaf=3.0.0"]),
                ],
            )
            .build();

        let limits = Limits::default();
        let ignored = ["newleaf".to_owned()];
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new().ignores(IgnoreList::new(&ignored, &[])),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let encoded =
            encode(&universe, &Request::new().target(id), &limits, &Default::default()).unwrap();

        assert!(
            matches!(
                encoded.diagnose(&universe, &limits).shape(),
                Shape::IgnoredOnly { relation } if relation == "leaf>=2.0"
            ),
            "{:?}",
            encoded.diagnose(&universe, &limits).shape()
        );
    }

    /// A core the rules do not name falls back rather than mis-naming itself, and the
    /// fallback still reads as a refusal. The facts beside it are kept by the caller, which
    /// never consults the shape to decide what to print.
    #[test]
    fn a_core_the_rules_do_not_name_falls_back() {
        let facts = [Fact::MustRemain { package: "held 1.0.0-1 (installed)".to_owned() }];

        assert_eq!(Shape::of(&facts), Shape::Unclassified);
        assert!(Shape::of(&facts).to_string().contains("no solution"));
        assert_eq!(Shape::of(&[]), Shape::Unclassified);
    }

    /// Two targets that conflict have two ways out, and each must be verified rather than
    /// inferred from the shape.
    #[test]
    fn two_conflicting_targets_yield_one_remedy_each() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("one", "1.0.0-1").conflicts(["two"]),
                    PackageSpec::new("two", "1.0.0-1"),
                ],
            )
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let first = resolve_target(&universe, &"one".parse().unwrap()).unwrap();
        let second = resolve_target(&universe, &"two".parse().unwrap()).unwrap();
        let request = Request::new().target(first).target(second);
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();

        let diagnosis = encoded.diagnose(&universe, &limits);
        let dropped: Vec<&str> = diagnosis
            .remedies()
            .iter()
            .filter_map(|remedy| match remedy {
                Remedy::DropTarget { package } => Some(package.as_str()),
                _ => None,
            })
            .collect();
        assert!(dropped.contains(&"one 1.0.0-1 (core)"), "{dropped:?}");
        assert!(dropped.contains(&"two 1.0.0-1 (core)"), "{dropped:?}");
        assert_eq!(diagnosis.probes_dropped(), 0);
    }

    /// A proposed remedy must be one that really works. Applying each `DropTarget` to the
    /// problem it came from has to leave a solvable one.
    #[test]
    fn every_proposed_remedy_really_leaves_a_solution() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("one", "1.0.0-1").conflicts(["two"]),
                    PackageSpec::new("two", "1.0.0-1"),
                ],
            )
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let first = resolve_target(&universe, &"one".parse().unwrap()).unwrap();
        let second = resolve_target(&universe, &"two".parse().unwrap()).unwrap();
        let encoded = encode(
            &universe,
            &Request::new().target(first).target(second),
            &limits,
            &Default::default(),
        )
        .unwrap();

        for remedy in encoded.diagnose(&universe, &limits).remedies() {
            let Remedy::DropTarget { package } = remedy else { continue };
            let target = [first, second]
                .into_iter()
                .find(|id| describe_candidate(&universe, *id) == *package)
                .unwrap();
            let kept = if target == first { second } else { first };
            let reduced =
                encode(&universe, &Request::new().target(kept), &limits, &Default::default())
                    .unwrap();
            assert!(
                matches!(Solver::new(reduced.problem(), limits).solve(), Ok(Outcome::Satisfied(_))),
                "{remedy} does not leave a solution"
            );
        }
    }

    /// A request nothing can rescue must say so by proposing nothing. A measure that fires on
    /// every failure reports nothing at all, so the silent case needs pinning as much as the
    /// loud one.
    #[test]
    fn an_impossible_request_proposes_nothing() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("app", "1.0.0-1").depends(["absent"])])
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let encoded =
            encode(&universe, &Request::new().target(id), &limits, &Default::default()).unwrap();

        let diagnosis = encoded.diagnose(&universe, &limits);
        assert!(diagnosis.remedies().is_empty(), "{:?}", diagnosis.remedies());
        assert!(!diagnosis.derivation().is_empty(), "there is still something to say");
    }

    /// An answer that boxes the search in is undone by naming a provider that works, not by
    /// dropping the dependency the answer was about.
    #[test]
    fn an_answered_provider_question_names_a_provider_that_works() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["mid"]),
                    PackageSpec::new("bad", "1.0.0-1").provides(["mid"]).depends(["absent"]),
                    PackageSpec::new("good", "1.0.0-1").provides(["mid"]),
                ],
            )
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let app = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let bad = resolve_target(&universe, &"bad".parse().unwrap()).unwrap();
        let request = Request::new().target(app).choose_provider(ProviderChoice {
            dependent: app,
            dependency: 0,
            chosen: bad,
        });
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();

        let diagnosis = encoded.diagnose(&universe, &limits);
        assert!(
            diagnosis.remedies().iter().any(|remedy| matches!(
                remedy,
                Remedy::ChooseOther { provider, .. } if provider == "good 1.0.0-1 (core)"
            )),
            "{:?}",
            diagnosis.remedies()
        );
    }

    /// An ignored candidate is the one remedy no probe can reach, so it comes off the facts.
    #[test]
    fn an_ignored_candidate_is_proposed_unverified() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["leaf>=2.0"]),
                    PackageSpec::new("leaf", "1.0.0-1"),
                    PackageSpec::new("newleaf", "3.0.0-1").provides(["leaf=3.0.0"]),
                ],
            )
            .build();

        let limits = Limits::default();
        let ignored = ["newleaf".to_owned()];
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new().ignores(IgnoreList::new(&ignored, &[])),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let encoded =
            encode(&universe, &Request::new().target(id), &limits, &Default::default()).unwrap();

        let diagnosis = encoded.diagnose(&universe, &limits);
        assert!(
            diagnosis.remedies().iter().any(|remedy| matches!(
                remedy,
                Remedy::Unignore { package, .. } if package == "newleaf-3.0.0-1"
            )),
            "{:?}",
            diagnosis.remedies()
        );
    }

    /// Learned clauses are the solver's own bookkeeping and must never surface.
    #[test]
    fn a_derivation_reports_no_derived_clauses() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("app", "1.0.0-1").depends(["absent"])])
            .build();

        let limits = Limits::default();
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let request = Request::new().target(id);
        let encoded = encode(&universe, &request, &limits, &Default::default()).unwrap();

        let Ok(Outcome::Unsatisfiable(unsat)) = Solver::new(encoded.problem(), limits).solve()
        else {
            panic!("expected unsatisfiable");
        };

        let derivation = Derivation::build(&universe, encoded.problem(), &unsat, &limits);
        assert!(!derivation.is_empty(), "there should be something to say");
        assert!(!derivation.to_string().contains("(derived)"), "{derivation}");
    }
}
