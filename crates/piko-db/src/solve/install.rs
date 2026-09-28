//! Planning an install: from the targets a user named to an assembled [`Plan`].
//!
//! `piko plan`, `piko install` and `piko update` plan through [`plan_install`]. A second
//! frontend gets the same resolution order, the same group and provider questions, and the
//! same answers to them, without re-deriving the sequence. What a frontend supplies is the
//! asking: [`InstallQuestions`]. A library cannot prompt, so every question comes back to the
//! caller as data, and the caller's answer comes back in.

use std::collections::HashMap;

use crate::solve::justify::relation_text;
use crate::solve::{
    Ambiguity, AmbiguityReport, Diagnosis, Expansion, GroupChoice, GroupTarget, IgnoredTarget,
    IgnoredUpgrade, PackageCache, Plan, PlanExplanation, ProviderChoice, Request, SolvableId,
    TargetResolutionFailure, Universe, ambiguities, explain_plan, resolve_targets,
    solve_with_removals,
};
use crate::{Error, Limits};

/// The questions an install plan can raise, and the notices it gives on the way.
///
/// [`plan_install`] calls these in a fixed order: [`InstallQuestions::groups`] once, when a
/// target names a group; [`InstallQuestions::resolved`] once; then
/// [`InstallQuestions::provider`] per provider question, round by round, while the solution
/// still raises one.
pub trait InstallQuestions {
    /// Says what the targets resolved to, before anything is solved.
    ///
    /// Called once, after the group answers are applied and the sysupgrade targets are added.
    fn resolved(&mut self, _universe: &Universe<'_>, _notes: &ResolutionNotes<'_>) {}

    /// Answers which members of each group target to install.
    ///
    /// Called only when a target names a group. `None` takes every group whole, and resolves
    /// nothing a second time.
    fn groups(
        &mut self,
        universe: &Universe<'_>,
        groups: &[GroupTarget],
    ) -> Option<Vec<GroupChoice>>;

    /// Whether this frontend answers provider questions at all.
    ///
    /// When `false`, every question takes libalpm's own default, `use_index = 0`: the first
    /// provider in repository priority order. [`InstallPlan::defaulted`] then lists them, so
    /// the frontend can say a choice was made on its behalf.
    fn asks_providers(&self) -> bool;

    /// Answers one provider question.
    ///
    /// `relation` is the `%DEPENDS%` entry the question is about, verbatim. The providers are
    /// in preference order, and the first is libalpm's default. An answer that is not one of
    /// them takes that default.
    ///
    /// A question whose `relation` an earlier answer covers is not asked again. The earlier
    /// answer is applied, if it is still among the providers.
    fn provider(
        &mut self,
        universe: &Universe<'_>,
        question: &Ambiguity,
        relation: &str,
    ) -> SolvableId;

    /// Says that the bound withheld `count` further provider questions this round. Each one
    /// takes its default.
    fn withheld(&mut self, _count: usize) {}
}

/// The frontend that asks nothing: every group whole, every provider question at its default.
///
/// This is `piko plan`, and what an unattended `--noconfirm` run answers.
#[derive(Clone, Copy, Debug, Default)]
pub struct Defaults;

impl InstallQuestions for Defaults {
    fn groups(&mut self, _: &Universe<'_>, _: &[GroupTarget]) -> Option<Vec<GroupChoice>> {
        None
    }

    fn asks_providers(&self) -> bool {
        false
    }

    fn provider(&mut self, _: &Universe<'_>, question: &Ambiguity, _: &str) -> SolvableId {
        // Unreachable: `asks_providers` is false. The default answer stands anyway.
        question.providers.first().copied().unwrap_or(question.dependent)
    }
}

/// What the targets resolved to, for [`InstallQuestions::resolved`].
#[derive(Clone, Copy, Debug)]
pub struct ResolutionNotes<'a> {
    /// What each glob target selected, in the order the targets were given.
    pub expansions: &'a [Expansion],
    /// The members of a group or pattern target that `IgnorePkg`/`IgnoreGroup` left out.
    pub ignored: &'a [IgnoredTarget],
    /// Every group target. Each one is whole unless [`InstallQuestions::groups`] answered.
    pub groups: &'a [GroupTarget],
    /// The upgrades a sysupgrade did not make because a package is ignored.
    pub ignored_upgrades: &'a [IgnoredUpgrade],
}

/// How to plan an install.
#[derive(Clone, Copy, Debug, Default)]
pub struct InstallOptions {
    /// `--needed`: drop a named target already at the version that would be installed.
    pub needed: bool,
    /// `-u`: also upgrade every installed package the repositories have moved on from.
    /// `Some(true)` is `-uu`, which accepts an older repository version.
    pub sysupgrade: Option<bool>,
    /// Also say why each step is in the plan.
    pub explain: bool,
}

/// A planned install.
#[derive(Debug)]
pub struct InstallPlan {
    /// The steps, their order, their sizes, and what the planner noticed.
    pub plan: Plan,
    /// The targets named before a sysupgrade added its own.
    ///
    /// These decide `Explicit` against `Depend`. A package `-u` pulled in on its own was not
    /// named by anyone.
    pub explicit: Vec<SolvableId>,
    /// The provider questions the plan answered with their defaults, because the frontend
    /// asks none. Empty when it asks.
    pub defaulted: AmbiguityReport,
    /// Why each step is in the plan, when [`InstallOptions::explain`] asked for it.
    pub explanation: Option<PlanExplanation>,
}

/// Why an install could not be planned.
#[derive(Debug)]
pub enum InstallFailure {
    /// A target resolved to nothing installable.
    Target(TargetResolutionFailure),
    /// The request has no solution.
    ///
    /// Boxed, as [`crate::solve::RemovalFailure::WouldBreakSystem`] is, because a diagnosis
    /// carries a fact listing and a remedy list.
    Unsatisfiable(Box<Diagnosis>),
    /// The universe holds fewer package-file candidates than it was given.
    ///
    /// Nothing filters a file candidate out, so this is a broken invariant, checked rather
    /// than assumed. Targeting the files by name instead would install a repository package
    /// in their place.
    LostFileCandidate,
    /// The planner itself failed.
    Planner(Box<Error>),
}

/// Plans installing `names` and every package file `universe` holds, as `piko install` does.
///
/// The order is fixed, and it is the order the result depends on:
///
/// 1. `names` resolve through [`resolve_targets`]: a literal first, a `%GROUPS%` group
///    second, a glob pattern rewritten ahead of both.
/// 2. A group target is asked about. The answers settle the target list, not a clause inside
///    the solve, so the names resolve a second time with them. That second call cannot find a
///    group the first did not: expansion reads the universe and the names, never the answers.
/// 3. Each package file is targeted by its id, never by its name. A name resolves to
///    whichever candidate the universe prefers, which is the file only by construction.
/// 4. The targets named so far are kept as [`InstallPlan::explicit`]. A sysupgrade then adds
///    its upgrades and its `%REPLACES%` pairs.
/// 5. The request is solved, and each provider question the solution raises is asked. An
///    answer narrows its requirement to one satisfier, so it is never raised again, and the
///    set of requirements the cone can raise does not depend on the answers. So each round
///    adds at least one answer, and the rounds run out. A round that adds none ends the loop,
///    so a frontend that repeats its answers cannot keep it going.
///
/// An answer is remembered by the text of the `%DEPENDS%` entry it answered. A later question
/// about the same text takes it without asking, if the answer can still satisfy it. That is
/// libalpm's accumulated package list answering the later occurrences (`deps.c:816`). It also
/// makes two dependents raising the same dependency in one round one question.
///
/// `cache` decides only the download size the plan reports.
///
/// # Errors
///
/// [`InstallFailure`], naming the first thing that stopped the plan.
pub fn plan_install(
    universe: &Universe<'_>,
    names: &[String],
    options: InstallOptions,
    questions: &mut dyn InstallQuestions,
    cache: &dyn PackageCache,
    limits: &Limits,
) -> Result<InstallPlan, InstallFailure> {
    let base = Request::new().needed(options.needed);
    let mut resolution =
        resolve_targets(universe, base.clone(), names, limits).map_err(InstallFailure::Target)?;
    if !resolution.groups.is_empty()
        && let Some(choices) = questions.groups(universe, &resolution.groups)
    {
        let mut answered = base;
        for choice in choices {
            answered = answered.choose_group(choice);
        }
        resolution =
            resolve_targets(universe, answered, names, limits).map_err(InstallFailure::Target)?;
    }

    let mut request = resolution.request;
    let file_ids = universe.file_candidates();
    if file_ids.len() != universe.files_named() {
        return Err(InstallFailure::LostFileCandidate);
    }
    for id in file_ids {
        request = request.target(id);
    }

    let explicit = request.targets().to_vec();
    if let Some(downgrade) = options.sysupgrade {
        request = request.with_sysupgrade(universe, downgrade);
    }
    questions.resolved(
        universe,
        &ResolutionNotes {
            expansions: &resolution.expansions,
            ignored: &resolution.ignored,
            groups: &resolution.groups,
            ignored_upgrades: request.ignored_upgrades(),
        },
    );

    let mut remembered: HashMap<String, SolvableId> = HashMap::new();
    let mut given: Vec<ProviderChoice> = Vec::new();
    let (planned, defaulted) = loop {
        let planned = match solve_with_removals(universe, &request, limits) {
            Ok(Ok(planned)) => planned,
            Ok(Err(encoded)) => {
                return Err(InstallFailure::Unsatisfiable(Box::new(
                    encoded.diagnose(universe, limits),
                )));
            }
            Err(error) => return Err(InstallFailure::Planner(Box::new(error))),
        };

        let report = ambiguities(universe, &planned.encoded, &planned.selected, limits);
        if report.is_empty() || !questions.asks_providers() {
            break (planned, report);
        }

        let mut added = false;
        for question in report.found() {
            let Some(first) = question.providers.first().copied() else { continue };
            let relation = relation_text(universe, question.dependent, question.dependency);
            let chosen = match remembered.get(&relation) {
                // Only if it can still satisfy this requirement. The same text asked of a
                // different dependent can carry a different version constraint.
                Some(previous) if question.providers.contains(previous) => *previous,
                _ => {
                    let answer = questions.provider(universe, question, &relation);
                    if question.providers.contains(&answer) { answer } else { first }
                }
            };
            remembered.insert(relation, chosen);
            let choice = ProviderChoice {
                dependent: question.dependent,
                dependency: question.dependency,
                chosen,
            };
            if !given.contains(&choice) {
                given.push(choice);
                request = request.choose_provider(choice);
                added = true;
            }
        }
        if report.dropped() > 0 {
            questions.withheld(report.dropped());
        }
        if !added {
            break (planned, AmbiguityReport::default());
        }
    };

    let explanation =
        options.explain.then(|| explain_plan(universe, &planned, &request, &defaulted));
    let plan = Plan::assemble(universe, &planned, request.targets(), limits, cache);
    Ok(InstallPlan { plan, explicit, defaulted, explanation })
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
    use crate::config::DbUsage;
    use crate::fixture::{BuiltScenario, PackageSpec, Scenario};
    use crate::solve::{NoCache, Step, UniverseOptions};

    fn universe(scenario: &BuiltScenario) -> Universe<'_> {
        Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new().limits(Limits::default()),
        )
        .unwrap()
    }

    /// The names every install or change step of `plan` puts on the system, sorted.
    fn installed(universe: &Universe<'_>, plan: &Plan) -> Vec<String> {
        let mut names: Vec<String> = plan
            .steps()
            .iter()
            .filter_map(|step| match step {
                Step::Install { candidate, .. } => Some(*candidate),
                Step::Change { to, .. } => Some(*to),
                Step::Remove { .. } => None,
            })
            .map(|id| universe.get(id).unwrap().name().to_string())
            .collect();
        names.sort();
        names
    }

    fn plan(
        universe: &Universe<'_>,
        names: &[&str],
        options: InstallOptions,
        questions: &mut dyn InstallQuestions,
    ) -> Result<InstallPlan, InstallFailure> {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        plan_install(universe, &names, options, questions, &NoCache, &Limits::default())
    }

    /// A frontend that answers from a script, and records what it was asked.
    #[derive(Default)]
    struct Scripted {
        groups: Option<Vec<(&'static str, Vec<&'static str>)>>,
        providers: Vec<&'static str>,
        asked: Vec<String>,
        notes: usize,
    }

    impl InstallQuestions for Scripted {
        fn resolved(&mut self, _: &Universe<'_>, _: &ResolutionNotes<'_>) {
            self.notes = self.notes.saturating_add(1);
        }

        fn groups(
            &mut self,
            universe: &Universe<'_>,
            groups: &[GroupTarget],
        ) -> Option<Vec<GroupChoice>> {
            let script = self.groups.as_ref()?;
            Some(
                groups
                    .iter()
                    .map(|group| {
                        let keep = script
                            .iter()
                            .find(|(name, _)| *name == group.name)
                            .map(|(_, keep)| keep.clone())
                            .unwrap_or_default();
                        let chosen = group
                            .members
                            .iter()
                            .copied()
                            .filter(|id| keep.contains(&universe.get(*id).unwrap().name().as_ref()))
                            .collect();
                        GroupChoice { group: group.name.clone(), chosen }
                    })
                    .collect(),
            )
        }

        fn asks_providers(&self) -> bool {
            true
        }

        fn provider(
            &mut self,
            universe: &Universe<'_>,
            question: &Ambiguity,
            relation: &str,
        ) -> SolvableId {
            self.asked.push(relation.to_owned());
            let wanted = self.providers.get(self.asked.len().saturating_sub(1)).copied();
            question
                .providers
                .iter()
                .copied()
                .find(|id| Some(universe.get(*id).unwrap().name().as_ref()) == wanted)
                .unwrap_or(question.providers[0])
        }
    }

    /// Two providers for `sh`: `bash` first in priority order, `dash` second.
    fn two_shells() -> BuiltScenario {
        Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["sh"]),
                    PackageSpec::new("tool", "1.0.0-1").depends(["sh"]),
                    PackageSpec::new("bash", "5.0.0-1").provides(["sh"]),
                    PackageSpec::new("dash", "0.5.0-1").provides(["sh"]),
                ],
            )
            .build()
    }

    #[test]
    fn an_answered_provider_is_the_one_installed() {
        let scenario = two_shells();
        let universe = universe(&scenario);
        let mut questions = Scripted { providers: vec!["dash"], ..Scripted::default() };

        let planned = plan(&universe, &["app"], InstallOptions::default(), &mut questions).unwrap();

        assert_eq!(installed(&universe, &planned.plan), ["app", "dash"]);
        assert_eq!(questions.asked, ["sh"]);
        assert!(planned.defaulted.is_empty());
        assert_eq!(questions.notes, 1, "`resolved` is called exactly once");
    }

    /// libalpm's accumulated package list answers the second occurrence of `sh`. So one
    /// answer serves both dependents, and nothing is asked twice.
    #[test]
    fn one_answer_serves_every_dependent_of_the_same_relation() {
        let scenario = two_shells();
        let universe = universe(&scenario);
        let mut questions = Scripted { providers: vec!["dash"], ..Scripted::default() };

        let planned =
            plan(&universe, &["app", "tool"], InstallOptions::default(), &mut questions).unwrap();

        assert_eq!(installed(&universe, &planned.plan), ["app", "dash", "tool"]);
        assert_eq!(questions.asked, ["sh"], "the same relation is asked once");
    }

    /// `Defaults` asks nothing and reports what it took, so a preview can say so.
    #[test]
    fn defaults_take_the_first_provider_and_report_it() {
        let scenario = two_shells();
        let universe = universe(&scenario);

        let planned = plan(&universe, &["app"], InstallOptions::default(), &mut Defaults).unwrap();

        assert_eq!(installed(&universe, &planned.plan), ["app", "bash"]);
        assert_eq!(planned.defaulted.found().len(), 1);
    }

    /// A frontend whose answers change nothing cannot keep the loop going.
    #[test]
    fn a_round_that_adds_no_answer_ends_the_loop() {
        struct Stubborn;
        impl InstallQuestions for Stubborn {
            fn groups(&mut self, _: &Universe<'_>, _: &[GroupTarget]) -> Option<Vec<GroupChoice>> {
                None
            }
            fn asks_providers(&self) -> bool {
                true
            }
            fn provider(&mut self, _: &Universe<'_>, question: &Ambiguity, _: &str) -> SolvableId {
                question.providers[0]
            }
        }
        let scenario = two_shells();
        let universe = universe(&scenario);

        let planned = plan(&universe, &["app"], InstallOptions::default(), &mut Stubborn).unwrap();
        assert_eq!(installed(&universe, &planned.plan), ["app", "bash"]);
    }

    fn a_group() -> BuiltScenario {
        Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("editor", "1.0.0-1").groups(["tools"]),
                    PackageSpec::new("linker", "1.0.0-1").groups(["tools"]),
                ],
            )
            .build()
    }

    #[test]
    fn a_group_answer_narrows_the_targets() {
        let scenario = a_group();
        let universe = universe(&scenario);
        let mut questions =
            Scripted { groups: Some(vec![("tools", vec!["linker"])]), ..Scripted::default() };

        let planned =
            plan(&universe, &["tools"], InstallOptions::default(), &mut questions).unwrap();
        assert_eq!(installed(&universe, &planned.plan), ["linker"]);
    }

    /// No answer takes the group whole, as `pacman -S <group> --noconfirm` does.
    #[test]
    fn no_group_answer_takes_the_group_whole() {
        let scenario = a_group();
        let universe = universe(&scenario);

        let planned =
            plan(&universe, &["tools"], InstallOptions::default(), &mut Defaults).unwrap();
        assert_eq!(installed(&universe, &planned.plan), ["editor", "linker"]);
    }

    /// Choosing no member is an answer, not a target that does not exist.
    #[test]
    fn choosing_no_member_is_not_a_missing_target() {
        let scenario = a_group();
        let universe = universe(&scenario);
        let mut questions =
            Scripted { groups: Some(vec![("tools", Vec::new())]), ..Scripted::default() };

        let planned =
            plan(&universe, &["tools"], InstallOptions::default(), &mut questions).unwrap();
        assert!(planned.plan.steps().is_empty());
    }

    /// A package `-u` pulled in on its own was not named, so it is not explicit.
    #[test]
    fn explicit_targets_exclude_what_the_sysupgrade_added() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old", "1.0.0-1"))
            .repo("core", [PackageSpec::new("old", "2.0.0-1"), PackageSpec::new("new", "1.0.0-1")])
            .build();
        let universe = universe(&scenario);
        let options = InstallOptions { sysupgrade: Some(false), ..InstallOptions::default() };

        let planned = plan(&universe, &["new"], options, &mut Defaults).unwrap();

        let explicit: Vec<String> = planned
            .explicit
            .iter()
            .map(|id| universe.get(*id).unwrap().name().to_string())
            .collect();
        assert_eq!(explicit, ["new"]);
        assert_eq!(installed(&universe, &planned.plan), ["new", "old"]);
    }

    #[test]
    fn an_unknown_target_is_a_target_failure() {
        let scenario = a_group();
        let universe = universe(&scenario);

        let failure =
            plan(&universe, &["absent"], InstallOptions::default(), &mut Defaults).unwrap_err();
        assert!(matches!(failure, InstallFailure::Target(_)), "got {failure:?}");
    }

    #[test]
    fn an_unsatisfiable_request_carries_its_diagnosis() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("app", "1.0.0-1").depends(["missing"])])
            .build();
        let universe = universe(&scenario);

        let failure =
            plan(&universe, &["app"], InstallOptions::default(), &mut Defaults).unwrap_err();
        assert!(matches!(failure, InstallFailure::Unsatisfiable(_)), "got {failure:?}");
    }
}
