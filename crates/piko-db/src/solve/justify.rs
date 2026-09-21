//! Why each step of a solved plan is in it.
//!
//! [`crate::solve::Derivation`] explains a plan that has **no** solution. This explains one
//! that has. The two read the same structure — the clause set, with each clause's
//! [`ClauseKind`](crate::solve::ClauseKind) recording why it exists. So neither reconstructs an
//! argument the solver did not make.
//!
//! pacman has no counterpart. `pacman -Qi` reports a "Required By" list over installed
//! packages only, so it says nothing about a package a transaction is about to add.
//!
//! # One line per step, not a tree
//!
//! Every step's cause names a package that is itself a step of the same plan, or an installed
//! package the plan keeps. So a reader follows a chain by reading upward through the listing,
//! and the explanation costs one line per step rather than one subtree.
//!
//! # What is not said
//!
//! A package can be required by several others. [`Cause::Required`] names one dependent and
//! counts the rest. The one named is a dependent the caller asked for when there is one, and
//! the lowest [`SolvableId`] otherwise. That order is fixed so two runs over one plan print
//! the same line.
//!
//! An [`Alternative`] is listed only when it tells the reader something: a candidate
//! `IgnorePkg` or `IgnoreGroup` held back, a candidate libalpm would have preferred, or a
//! provider question nobody answered. A complete list of every candidate that could have
//! satisfied each link would need one `%PROVIDES%` scan per link. All three sources here are
//! already-computed values plus the ignored index, so no scan is needed.
//!
//! # Bounds
//!
//! No new limit. There is one cause per step, and the step count is bounded by
//! [`Limits::solve_max_solvables`](crate::Limits). The alternatives come from
//! [`FidelityReport::diverged`] and [`AmbiguityReport::found`], both already held to
//! [`Limits::max_diagnostics`](crate::Limits), and from
//! [`Universe::ignored`](crate::solve::Universe::ignored), a subset of what
//! `solve_max_solvables` counted.

use std::collections::{HashMap, HashSet};

use crate::solve::{
    AmbiguityReport, Planned, RemovalCause, Request, SolvableId, Universe, describe_candidate,
};

/// Why one step is in a plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Cause {
    /// The caller named this candidate.
    Requested,
    /// A full system upgrade found the repositories had moved past the installed version.
    Sysupgrade,
    /// A `%REPLACES%` entry of this candidate names an installed package.
    Replaces {
        /// The installed package it displaces.
        replaced: SolvableId,
    },
    /// A `%DEPENDS%` entry of a package the plan selects.
    Required {
        /// The package that declared the dependency.
        dependent: SolvableId,
        /// Which of `dependent`'s `%DEPENDS%` entries this was. Index that list to quote the
        /// relation, the same resolution [`crate::solve::Divergence`] asks for.
        dependency: usize,
        /// How many further selected packages also require this one.
        others: usize,
    },
    /// The plan takes this installed package away.
    Removed {
        /// Which of the four removal sources claimed it.
        cause: RemovalCause,
    },
}

/// A candidate that could have answered a link, and did not.
///
/// The candidate is spelled rather than identified, unlike [`Cause`]. An ignored candidate is
/// never interned, so no [`SolvableId`] names it. [`crate::solve::Fact`] carries its packages
/// the same way, for the same reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Alternative {
    /// How the candidate prints, including its origin.
    pub package: String,
    /// Why it is worth naming.
    pub verdict: Verdict,
}

impl std::fmt::Display for Alternative {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let package = &self.package;
        match &self.verdict {
            Verdict::Ignored { reason } => write!(f, "{package} is ignored ({reason})"),
            Verdict::Preferred => write!(f, "{package} is what pacman would have taken"),
            Verdict::UnaskedProvider => {
                write!(f, "{package} provides the same, and was not asked about")
            }
        }
    }
}

/// What makes an [`Alternative`] worth printing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Verdict {
    /// `IgnorePkg` or `IgnoreGroup` held it out of the candidate set.
    Ignored {
        /// Which list covered it, and the pattern that matched.
        reason: String,
    },
    /// `resolvedep` ranks it above the candidate the solver took.
    Preferred,
    /// Several packages provide what the link asks for, and nobody answered the question.
    UnaskedProvider,
}

/// Every step's cause, plus the alternatives worth naming.
#[derive(Clone, Debug, Default)]
pub struct PlanExplanation {
    causes: HashMap<SolvableId, Cause>,
    alternatives: HashMap<SolvableId, Vec<Alternative>>,
}

impl PlanExplanation {
    /// Why `id` is in the plan, or `None` for a candidate the plan does not touch.
    #[must_use]
    pub fn cause(&self, id: SolvableId) -> Option<Cause> {
        self.causes.get(&id).copied()
    }

    /// The candidates passed over for `id`'s link, in the order they are worth reading.
    ///
    /// Empty unless [`Self::cause`] is [`Cause::Required`].
    #[must_use]
    pub fn alternatives(&self, id: SolvableId) -> &[Alternative] {
        self.alternatives.get(&id).map_or(&[][..], Vec::as_slice)
    }

    /// Whether nothing could be explained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.causes.is_empty()
    }
}

/// Explains every step of a solved request.
///
/// `ambiguities` is a parameter rather than a second [`crate::solve::ambiguities`] call. A
/// caller that reports the provider questions already holds the report, and two calls could
/// return two lists.
#[must_use]
pub fn explain_plan(
    universe: &Universe<'_>,
    planned: &Planned,
    request: &Request,
    ambiguities: &AmbiguityReport,
) -> PlanExplanation {
    let selected: HashSet<SolvableId> = planned.selected.iter().copied().collect();
    let dependents = dependent_index(planned, &selected);
    let targets: HashSet<SolvableId> = request.targets().iter().copied().collect();
    let upgrades: HashSet<SolvableId> = request.sysupgrade_upgrades().iter().copied().collect();
    let replacements: HashMap<SolvableId, SolvableId> =
        request.sysupgrade_replacements().iter().copied().collect();

    let mut causes: HashMap<SolvableId, Cause> = HashMap::new();
    let mut alternatives: HashMap<SolvableId, Vec<Alternative>> = HashMap::new();

    for id in &planned.selected {
        // An installed candidate the solution keeps is the status quo, not a step.
        if universe.get(*id).is_some_and(|solvable| solvable.is_installed()) {
            continue;
        }
        let cause = install_cause(*id, &targets, &upgrades, &replacements, &dependents);
        if let Cause::Required { dependent, dependency, .. } = cause {
            let named = notable(universe, planned, ambiguities, dependent, dependency, *id);
            if !named.is_empty() {
                alternatives.insert(*id, named);
            }
        }
        causes.insert(*id, cause);
    }

    for id in &planned.removed {
        let cause = planned.removal_causes.get(id).copied().unwrap_or(RemovalCause::Blocking);
        causes.insert(*id, Cause::Removed { cause });
    }

    PlanExplanation { causes, alternatives }
}

/// For each selected candidate, the selected packages whose `%DEPENDS%` it answers.
///
/// A requirement clause is `¬dependent ∨ q₁ ∨ … ∨ qₙ`, so the positive literals are its
/// satisfiers. More than one of them can be selected at once: a provider taken for one
/// requirement silently answers a later requirement it also provides. All of them are kept,
/// which is what [`Cause::Required::others`] counts.
///
/// Each list is sorted, so the dependent named for a step does not change between runs.
fn dependent_index(
    planned: &Planned,
    selected: &HashSet<SolvableId>,
) -> HashMap<SolvableId, Vec<(SolvableId, usize)>> {
    let problem = planned.encoded.problem();
    let mut index: HashMap<SolvableId, Vec<(SolvableId, usize)>> = HashMap::new();

    for requirement in planned.encoded.requirements() {
        if !selected.contains(&requirement.dependent) {
            continue;
        }
        for literal in problem.literals_of(requirement.clause) {
            if literal.is_negative() {
                continue;
            }
            let satisfier = literal.solvable();
            if !selected.contains(&satisfier) {
                continue;
            }
            index
                .entry(satisfier)
                .or_default()
                .push((requirement.dependent, requirement.dependency));
        }
    }

    for entry in index.values_mut() {
        entry.sort_unstable();
    }
    index
}

/// Why an incoming candidate is in the plan.
///
/// The tests run in this order, and the order is the answer's precedence. A replacement is
/// also a target of the upgrade that produced it, and an upgrade target is also a target. So
/// the more specific source must be tested first, or every one of them reads as
/// [`Cause::Requested`].
fn install_cause(
    id: SolvableId,
    targets: &HashSet<SolvableId>,
    upgrades: &HashSet<SolvableId>,
    replacements: &HashMap<SolvableId, SolvableId>,
    dependents: &HashMap<SolvableId, Vec<(SolvableId, usize)>>,
) -> Cause {
    if let Some(replaced) = replacements.get(&id) {
        return Cause::Replaces { replaced: *replaced };
    }
    if upgrades.contains(&id) {
        return Cause::Sysupgrade;
    }
    if targets.contains(&id) {
        return Cause::Requested;
    }

    let Some(links) = dependents.get(&id) else { return Cause::Requested };
    // A dependent the caller named ends the chain in one line, so it is the one to print.
    // Otherwise the list is already sorted, and its first entry is the stable choice.
    let chosen =
        links.iter().find(|(dependent, _)| targets.contains(dependent)).or_else(|| links.first());
    let Some((dependent, dependency)) = chosen.copied() else { return Cause::Requested };

    Cause::Required { dependent, dependency, others: links.len().saturating_sub(1) }
}

/// The candidates worth naming for one link, in reading order.
///
/// Three sources, none of which needs a `%PROVIDES%` scan. A candidate is named once, however
/// many sources cover it: a diverged requirement is also an unanswered provider question, and
/// printing the same package twice under two labels says nothing more.
fn notable(
    universe: &Universe<'_>,
    planned: &Planned,
    ambiguities: &AmbiguityReport,
    dependent: SolvableId,
    dependency: usize,
    satisfier: SolvableId,
) -> Vec<Alternative> {
    let mut found: Vec<Alternative> = Vec::new();
    let mut seen: HashSet<SolvableId> = HashSet::from([satisfier]);

    for divergence in planned.fidelity.diverged() {
        if divergence.dependent == dependent
            && divergence.dependency == dependency
            && seen.insert(divergence.preferred)
        {
            found.push(Alternative {
                package: describe_candidate(universe, divergence.preferred),
                verdict: Verdict::Preferred,
            });
        }
    }

    for ambiguity in ambiguities.found() {
        if ambiguity.dependent != dependent || ambiguity.dependency != dependency {
            continue;
        }
        for provider in &ambiguity.providers {
            if seen.insert(*provider) {
                found.push(Alternative {
                    package: describe_candidate(universe, *provider),
                    verdict: Verdict::UnaskedProvider,
                });
            }
        }
    }

    let relation = universe
        .get(dependent)
        .and_then(|solvable| solvable.depends().ok())
        .and_then(|depends| depends.get(dependency));
    if let Some(relation) = relation {
        for candidate in universe.ignored_satisfiers(relation) {
            // Spelled the way `describe_candidate` spells an interned one, so the two kinds
            // of alternative read as one list.
            let name = candidate.package().name();
            let version = candidate.package().version();
            let origin = universe
                .repository_name(candidate.repository())
                .map_or_else(|| "?".to_owned(), ToString::to_string);
            found.push(Alternative {
                package: format!("{name} {version} ({origin})"),
                verdict: Verdict::Ignored { reason: candidate.reason().to_string() },
            });
        }
    }

    found
}

/// One line saying why a step is in the plan, in terms of packages rather than candidate ids.
///
/// Rendering lives here rather than in a frontend because it needs the [`Universe`] the ids
/// came from, the same reason [`crate::solve::Derivation`] renders itself. A frontend adds the
/// indentation and the color.
#[must_use]
pub fn describe_cause(universe: &Universe<'_>, cause: Cause) -> String {
    match cause {
        Cause::Requested => "requested".to_owned(),
        Cause::Sysupgrade => "sysupgrade: the repository has a newer version".to_owned(),
        Cause::Replaces { replaced } => {
            format!("replaces {}", describe_candidate(universe, replaced))
        }
        Cause::Required { dependent, dependency, others } => {
            let relation = relation_text(universe, dependent, dependency);
            let package = describe_candidate(universe, dependent);
            let more = match others {
                0 => String::new(),
                1 => " (and 1 other package)".to_owned(),
                count => format!(" (and {count} other packages)"),
            };
            format!("{package} requires {relation}{more}")
        }
        Cause::Removed { cause } => describe_removal(universe, cause),
    }
}

/// One line saying why a package is removed.
fn describe_removal(universe: &Universe<'_>, cause: RemovalCause) -> String {
    match cause {
        RemovalCause::Replaced { replacement } => {
            format!("{} replaces it", describe_candidate(universe, replacement))
        }
        RemovalCause::Requested => "requested".to_owned(),
        RemovalCause::Conflicts { with } => {
            format!("{} conflicts with it", describe_candidate(universe, with))
        }
        RemovalCause::Cascaded { needed } => {
            format!("it requires {}, which is removed", describe_candidate(universe, needed))
        }
        RemovalCause::Blocking => "the transaction has no solution while it stays".to_owned(),
        RemovalCause::Unneeded => "nothing that remains needs it".to_owned(),
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
    use crate::fixture::{BuiltScenario, PackageSpec, Scenario};
    use crate::resolve::IgnoreList;
    use crate::solve::{
        RemovalOptions, Request, UniverseOptions, ambiguities, plan_removal, resolve_target,
        solve_with_removals,
    };

    /// The universe a scenario builds, with `ignore_pkg` applied as `pacman.conf` would.
    fn universe<'a>(scenario: &'a BuiltScenario, ignore_pkg: &'a [String]) -> Universe<'a> {
        Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new().ignores(IgnoreList::new(ignore_pkg, &[])),
        )
        .unwrap()
    }

    /// Solves `request` and explains the result.
    fn explained(universe: &Universe<'_>, request: &Request) -> (Planned, PlanExplanation) {
        let limits = Limits::default();
        let planned = match solve_with_removals(universe, request, &limits) {
            Ok(Ok(planned)) => planned,
            Ok(Err(_)) => panic!("expected a solution"),
            Err(error) => panic!("planner failed: {error}"),
        };
        let asked = ambiguities(universe, &planned.encoded, &planned.selected, &limits);
        let explanation = explain_plan(universe, &planned, request, &asked);
        (planned, explanation)
    }

    /// The candidate named `name` that is not installed.
    fn candidate(universe: &Universe<'_>, name: &str) -> SolvableId {
        resolve_target(universe, &name.parse().unwrap()).unwrap()
    }

    #[test]
    fn a_named_target_is_requested_and_its_dependency_names_it() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["lib>=2.0"]),
                    PackageSpec::new("lib", "2.1.0-1"),
                ],
            )
            .build();
        let universe = universe(&scenario, &[]);
        let app = candidate(&universe, "app");
        let lib = candidate(&universe, "lib");

        let (_, explanation) = explained(&universe, &Request::new().target(app));

        assert_eq!(explanation.cause(app), Some(Cause::Requested));
        assert_eq!(
            explanation.cause(lib),
            Some(Cause::Required { dependent: app, dependency: 0, others: 0 })
        );
        assert_eq!(
            describe_cause(&universe, explanation.cause(lib).unwrap()),
            "app 1.0.0-1 (core) requires lib>=2.0"
        );
    }

    /// A chain must stay walkable: each cause names a package the plan also touches.
    #[test]
    fn a_three_hop_chain_names_a_step_at_every_hop() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("top", "1.0.0-1").depends(["middle"]),
                    PackageSpec::new("middle", "1.0.0-1").depends(["bottom"]),
                    PackageSpec::new("bottom", "1.0.0-1"),
                ],
            )
            .build();
        let universe = universe(&scenario, &[]);
        let top = candidate(&universe, "top");
        let middle = candidate(&universe, "middle");
        let bottom = candidate(&universe, "bottom");

        let (_, explanation) = explained(&universe, &Request::new().target(top));

        assert_eq!(explanation.cause(top), Some(Cause::Requested));
        assert_eq!(
            explanation.cause(middle),
            Some(Cause::Required { dependent: top, dependency: 0, others: 0 })
        );
        assert_eq!(
            explanation.cause(bottom),
            Some(Cause::Required { dependent: middle, dependency: 0, others: 0 })
        );
    }

    /// Two dependents means one is named and the other is counted, never dropped in silence.
    #[test]
    fn a_shared_dependency_counts_the_dependents_it_does_not_name() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("one", "1.0.0-1").depends(["shared"]),
                    PackageSpec::new("two", "1.0.0-1").depends(["shared"]),
                    PackageSpec::new("shared", "1.0.0-1"),
                ],
            )
            .build();
        let universe = universe(&scenario, &[]);
        let one = candidate(&universe, "one");
        let two = candidate(&universe, "two");
        let shared = candidate(&universe, "shared");

        let (_, explanation) = explained(&universe, &Request::new().target(one).target(two));

        let Some(Cause::Required { dependent, others, .. }) = explanation.cause(shared) else {
            panic!("expected a dependency cause");
        };
        assert_eq!(others, 1, "the dependent that is not named is still counted");
        assert!(dependent == one || dependent == two);
    }

    /// The named dependent must not change between runs, or two identical plans print
    /// differently.
    #[test]
    fn the_named_dependent_is_the_same_on_a_second_run() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("a", "1.0.0-1").depends(["shared"]),
                    PackageSpec::new("b", "1.0.0-1").depends(["shared"]),
                    PackageSpec::new("c", "1.0.0-1").depends(["shared"]),
                    PackageSpec::new("root", "1.0.0-1").depends(["a", "b", "c"]),
                    PackageSpec::new("shared", "1.0.0-1"),
                ],
            )
            .build();
        let universe = universe(&scenario, &[]);
        let root = candidate(&universe, "root");
        let shared = candidate(&universe, "shared");

        let first = explained(&universe, &Request::new().target(root)).1.cause(shared);
        let second = explained(&universe, &Request::new().target(root)).1.cause(shared);
        assert_eq!(first, second);
    }

    /// A dependent the caller named ends the chain in one line, so it wins the tie.
    #[test]
    fn a_dependent_the_caller_named_is_preferred_over_one_it_did_not() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("pulled", "1.0.0-1").depends(["shared"]),
                    PackageSpec::new("named", "1.0.0-1").depends(["pulled", "shared"]),
                    PackageSpec::new("shared", "1.0.0-1"),
                ],
            )
            .build();
        let universe = universe(&scenario, &[]);
        let named = candidate(&universe, "named");
        let shared = candidate(&universe, "shared");

        let (_, explanation) = explained(&universe, &Request::new().target(named));

        let Some(Cause::Required { dependent, .. }) = explanation.cause(shared) else {
            panic!("expected a dependency cause");
        };
        assert_eq!(dependent, named);
    }

    #[test]
    fn a_sysupgrade_target_is_told_apart_from_a_named_one() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old", "1.0.0-1"))
            .repo("core", [PackageSpec::new("old", "2.0.0-1")])
            .build();
        let universe = universe(&scenario, &[]);
        let request = Request::new().with_sysupgrade(&universe, false);
        let newer = candidate(&universe, "old");

        let (_, explanation) = explained(&universe, &request);

        assert_eq!(explanation.cause(newer), Some(Cause::Sysupgrade));
    }

    #[test]
    fn a_replacement_names_what_it_displaces_on_both_sides() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("gone", "1.0.0-1"))
            .repo("core", [PackageSpec::new("heir", "1.0.0-1").replaces(["gone"])])
            .build();
        let universe = universe(&scenario, &[]);
        let request = Request::new().with_sysupgrade(&universe, false);
        let heir = candidate(&universe, "heir");
        let gone = universe.installed_named("gone").unwrap().id();

        let (_, explanation) = explained(&universe, &request);

        assert_eq!(explanation.cause(heir), Some(Cause::Replaces { replaced: gone }));
        assert_eq!(
            explanation.cause(gone),
            Some(Cause::Removed { cause: RemovalCause::Replaced { replacement: heir } })
        );
    }

    #[test]
    fn a_conflict_names_the_incoming_package_that_forced_the_removal() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old-thing", "1.0.0-1"))
            .repo("core", [PackageSpec::new("new-thing", "1.0.0-1").conflicts(["old-thing"])])
            .build();
        let universe = universe(&scenario, &[]);
        let incoming = candidate(&universe, "new-thing");
        let old = universe.installed_named("old-thing").unwrap().id();

        let (_, explanation) = explained(&universe, &Request::new().target(incoming));

        assert_eq!(
            explanation.cause(old),
            Some(Cause::Removed { cause: RemovalCause::Conflicts { with: incoming } })
        );
        assert_eq!(
            describe_cause(&universe, explanation.cause(old).unwrap()),
            "new-thing 1.0.0-1 (core) conflicts with it"
        );
    }

    /// `-Rc` takes a dependent the caller never named. The line must say which dependency
    /// pulled it in, not repeat "requested".
    #[test]
    fn a_cascaded_removal_names_the_dependency_it_followed() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("base", "1.0.0-1"))
            .installed(PackageSpec::new("dependent", "1.0.0-1").depends(["base"]))
            .build();
        let universe = universe(&scenario, &[]);
        let base = universe.installed_named("base").unwrap().id();
        let dependent = universe.installed_named("dependent").unwrap().id();

        let removal = plan_removal(
            scenario.local(),
            &universe,
            &["base".to_owned()],
            RemovalOptions { cascade: true, explain: true, ..RemovalOptions::default() },
            &Limits::default(),
        )
        .unwrap();
        let explanation = removal.explanation.expect("asked for an explanation");

        assert_eq!(
            explanation.cause(base),
            Some(Cause::Removed { cause: RemovalCause::Requested })
        );
        assert_eq!(
            explanation.cause(dependent),
            Some(Cause::Removed { cause: RemovalCause::Cascaded { needed: base } })
        );
    }

    /// `-Rs` sweeps an orphan the caller never named. That is its own cause.
    #[test]
    fn a_recursive_sweep_reports_an_orphan_as_unneeded() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "1.0.0-1").depends(["helper"]))
            .installed(
                PackageSpec::new("helper", "1.0.0-1")
                    .reason(alpm_types::PackageInstallReason::Depend),
            )
            .build();
        let universe = universe(&scenario, &[]);
        let helper = universe.installed_named("helper").unwrap().id();

        let removal = plan_removal(
            scenario.local(),
            &universe,
            &["app".to_owned()],
            RemovalOptions { recursive: true, explain: true, ..RemovalOptions::default() },
            &Limits::default(),
        )
        .unwrap();
        let explanation = removal.explanation.expect("asked for an explanation");

        assert_eq!(
            explanation.cause(helper),
            Some(Cause::Removed { cause: RemovalCause::Unneeded })
        );
    }

    /// An explanation is computed only when it is asked for.
    #[test]
    fn a_removal_plan_carries_no_explanation_unless_asked() {
        let scenario = Scenario::new().installed(PackageSpec::new("app", "1.0.0-1")).build();
        let universe = universe(&scenario, &[]);

        let removal = plan_removal(
            scenario.local(),
            &universe,
            &["app".to_owned()],
            RemovalOptions::default(),
            &Limits::default(),
        )
        .unwrap();

        assert!(removal.explanation.is_none());
    }

    /// `IgnorePkg` hides a candidate from the universe entirely. Naming it is the only way a
    /// reader learns the plan had a choice.
    #[test]
    fn an_ignored_candidate_is_named_as_an_alternative() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["provider"]),
                    PackageSpec::new("plain", "1.0.0-1").provides(["provider"]),
                    PackageSpec::new("fancy", "1.0.0-1").provides(["provider"]),
                ],
            )
            .build();
        let ignore = ["fancy".to_owned()];
        let universe = universe(&scenario, &ignore);
        let app = candidate(&universe, "app");
        let plain = candidate(&universe, "plain");

        let (_, explanation) = explained(&universe, &Request::new().target(app));

        let named: Vec<String> =
            explanation.alternatives(plain).iter().map(ToString::to_string).collect();
        assert!(
            named
                .iter()
                .any(|line| line.contains("fancy 1.0.0-1 (core)") && line.contains("ignored")),
            "{named:?}"
        );
    }

    /// Several providers and no answer is a choice the reader never saw made.
    #[test]
    fn an_unanswered_provider_question_is_named_as_an_alternative() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["provider"]),
                    PackageSpec::new("first", "1.0.0-1").provides(["provider"]),
                    PackageSpec::new("second", "1.0.0-1").provides(["provider"]),
                ],
            )
            .build();
        let universe = universe(&scenario, &[]);
        let app = candidate(&universe, "app");

        let (planned, explanation) = explained(&universe, &Request::new().target(app));

        let taken = planned
            .selected
            .iter()
            .copied()
            .find(|id| {
                universe
                    .get(*id)
                    .is_some_and(|solvable| matches!(solvable.name().as_ref(), "first" | "second"))
            })
            .expect("a provider was selected");
        let named: Vec<String> =
            explanation.alternatives(taken).iter().map(ToString::to_string).collect();
        assert_eq!(named.len(), 1, "the other provider, once: {named:?}");
        assert!(named[0].contains("was not asked about"), "{named:?}");
    }

    /// An installed package the plan keeps is the status quo, not a step.
    #[test]
    fn a_package_the_plan_leaves_alone_has_no_cause() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("untouched", "1.0.0-1"))
            .repo("core", [PackageSpec::new("app", "1.0.0-1")])
            .build();
        let universe = universe(&scenario, &[]);
        let app = candidate(&universe, "app");
        let untouched = universe.installed_named("untouched").unwrap().id();

        let (_, explanation) = explained(&universe, &Request::new().target(app));

        assert_eq!(explanation.cause(app), Some(Cause::Requested));
        assert_eq!(explanation.cause(untouched), None);
    }
}
