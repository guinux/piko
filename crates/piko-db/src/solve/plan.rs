//! The ordered, inspectable result of planning a transaction.
//!
//! libalpm has no equivalent value. Its plan is scattered across `trans->add`,
//! `trans->remove`, `pkg->removes`, `pkg->oldpkg` and `trans->skip_remove`. It is observable
//! only through callbacks that fire in the middle of resolution. A [`Plan`] is a plain
//! struct instead: it can be printed, asserted on in a test, diffed against `pacman -Sp`, and
//! handed to a commit engine that did not compute it.
//!
//! # Ordering
//!
//! [`Plan::steps`] follows the order `_alpm_sortbydeps` (`deps.c:213`) uses for a
//! transaction: an iterative depth-first search over a graph. Each edge points from a
//! package to a package it depends on. The search emits each vertex on the way *out*.
//! Post-order over dependent → dependency yields dependencies first, which is install order.
//! Removals use the same order reversed, and come first. This mirrors `_alpm_sync_commit`'s
//! "`_alpm_remove_packages` then `_alpm_upgrade_packages`".
//!
//! **A dependency cycle is a diagnostic, not an error.** libalpm logs
//! `"%s will be installed before its %s dependency"` and proceeds with an arbitrary but
//! deterministic order. piko reports the same fact as a [`PlanDiagnostic::DependencyCycle`]
//! and also proceeds. Refusing here would make piko unable to install package sets pacman
//! installs every day. Cycles are common and benign in practice, because the scriptlets that
//! would care about ordering rarely exist.

use alpm_types::PackageInstallReason;

use crate::Limits;
use crate::diagnostics::Sink;
use crate::solve::encode::{Divergence, Fidelity, Planned};
use crate::solve::{PackageCache, Solvable, SolvableId, Universe};

/// What a plan does to one package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// Remove an installed package without replacing it.
    Remove {
        /// The installed package that goes away.
        package: SolvableId,
    },
    /// Install a package that is not currently installed.
    Install {
        /// The candidate to install.
        candidate: SolvableId,
        /// Whether the user asked for this package or it was pulled in.
        reason: PackageInstallReason,
    },
    /// Replace an installed package with a different version of itself.
    Change {
        /// The installed package being replaced.
        from: SolvableId,
        /// The candidate replacing it.
        to: SolvableId,
        /// Which direction the version moved.
        kind: Change,
    },
}

/// Which way a [`Step::Change`] moves the version.
///
/// Mirrors `commit_single_pkg`'s classification (`add.c:438`). It picks the progress bar and
/// the `alpm_package_operation_t` from this comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Change {
    /// The new version is newer.
    Upgrade,
    /// The new version is older. Reachable only when the user asked for a downgrade.
    Downgrade,
    /// The versions are equal.
    Reinstall,
}

/// Something worth telling the user, that did not stop piko from producing the plan.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PlanDiagnostic {
    /// Two or more packages in the transaction depend on each other. No ordering then puts
    /// every dependency before its dependent.
    ///
    /// libalpm logs this at debug level and carries on; so does piko.
    DependencyCycle {
        /// A package on the cycle. The order chosen remains deterministic.
        package: SolvableId,
    },

    /// A step's `%DEPENDS%` failed to convert, so it contributes no ordering edges.
    ///
    /// Not reachable through a normal plan. The solver selects every step, and it converts
    /// each candidate's `%DEPENDS%` while building its reachable cone. It fails the whole
    /// solve if one does not parse. This is reported rather than ignored because
    /// [`topological_order`] cannot return an error. A step ordered as if it had no
    /// dependencies would be exactly the silent downgrade `Lazy` exists to prevent.
    DependsUnreadable {
        /// The package whose dependencies piko could not read.
        package: SolvableId,
    },
}

/// An ordered transaction plan.
#[derive(Clone, Debug)]
pub struct Plan {
    steps: Box<[Step]>,
    fidelity: Fidelity,
    divergences: Box<[Divergence]>,
    divergences_dropped: usize,
    diagnostics: Box<[PlanDiagnostic]>,
    diagnostics_dropped: usize,
    download_size: u64,
    installed_size_delta: i64,
}

impl Plan {
    /// The steps, in execution order: removals first, then installs and changes with each
    /// package after everything it depends on.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Whether the solution tracked libalpm's greedy descent.
    #[must_use]
    pub const fn fidelity(&self) -> Fidelity {
        self.fidelity
    }

    /// The requirements [`Fidelity::Diverged`] counted, up to [`Limits::max_diagnostics`].
    ///
    /// Empty when [`Plan::fidelity`] is [`Fidelity::Greedy`]. A caller reporting a divergence
    /// should quote these, not the bare count. Measurement showed the count alone is
    /// indistinguishable from noise.
    #[must_use]
    pub fn divergences(&self) -> &[Divergence] {
        &self.divergences
    }

    /// How many diverged requirements [`Limits::max_diagnostics`] withheld.
    #[must_use]
    pub const fn divergences_dropped(&self) -> usize {
        self.divergences_dropped
    }

    /// Problems that did not stop piko from producing a plan.
    #[must_use]
    pub fn diagnostics(&self) -> &[PlanDiagnostic] {
        &self.diagnostics
    }

    /// How many diagnostics [`Limits::max_diagnostics`] withheld.
    #[must_use]
    pub const fn diagnostics_dropped(&self) -> usize {
        self.diagnostics_dropped
    }

    /// Total `%CSIZE%` of everything that would actually be downloaded.
    ///
    /// A candidate that the [`PackageCache`] passed to [`Plan::assemble`] reports as already
    /// downloaded contributes nothing, however large it is. `compute_download_size`
    /// (`sync.c:310`) makes the same distinction; `sync.c:746` is why it exists.
    #[must_use]
    pub const fn download_size(&self) -> u64 {
        self.download_size
    }

    /// Net change in occupied space: what is installed minus what is removed.
    #[must_use]
    pub const fn installed_size_delta(&self) -> i64 {
        self.installed_size_delta
    }

    /// Whether the plan would change nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Assembles a plan from a solved request.
    ///
    /// `targets` are the candidates the user named. This is what distinguishes an `Explicit`
    /// install reason from a `Depend` one. `_alpm_sync_prepare` applies the same rule: it
    /// marks everything in `resolved` but not in the original `trans->add` as a dependency
    /// (`sync.c`).
    ///
    /// `cache` answers what is already downloaded. Only [`Plan::download_size`] consults it;
    /// the steps themselves do not change. Pass [`NoCache`](crate::solve::NoCache) when there
    /// is no cache to consult. The result is then an upper bound, not a wrong answer.
    #[must_use]
    pub fn assemble(
        universe: &Universe<'_>,
        planned: &Planned,
        targets: &[SolvableId],
        limits: &Limits,
        cache: &dyn PackageCache,
    ) -> Self {
        let mut sink = Sink::new(limits);
        let mut download_size = 0_u64;
        let mut installed_delta = 0_i64;

        // Everything the solution selected that is not already installed is a change.
        // The installed copies it also selected are the status quo, not steps.
        let mut incoming: Vec<SolvableId> = Vec::new();
        for id in &planned.selected {
            let Some(candidate) = universe.get(*id) else { continue };
            if candidate.is_installed() {
                continue;
            }
            incoming.push(*id);
            download_size = download_size.saturating_add(pending_download(&candidate, cache));
            installed_delta = installed_delta
                .saturating_add(i64::try_from(candidate.installed_size()).unwrap_or(i64::MAX));
        }

        let ordered = topological_order(universe, &incoming, &mut sink);

        let mut steps: Vec<Step> =
            Vec::with_capacity(ordered.len().saturating_add(planned.removed.len()));

        // Removals first, matching `_alpm_sync_commit`. Replaced and conflicting packages are
        // taken out in bulk before anything installs.
        for id in &planned.removed {
            if let Some(gone) = universe.get(*id) {
                installed_delta = installed_delta
                    .saturating_sub(i64::try_from(gone.installed_size()).unwrap_or(i64::MAX));
            }
            steps.push(Step::Remove { package: *id });
        }

        for id in ordered {
            let Some(candidate) = universe.get(id) else { continue };
            let reason = if targets.contains(&id) {
                PackageInstallReason::Explicit
            } else {
                PackageInstallReason::Depend
            };
            match universe.installed_named(candidate.name().as_ref()) {
                Some(previous) => {
                    // This replaces the installed copy with a different version of itself.
                    // It is one step, not a removal plus an install: libalpm performs the
                    // removal *inside* `commit_single_pkg`, so the two halves cannot be
                    // separated or reordered.
                    installed_delta = installed_delta.saturating_sub(
                        i64::try_from(previous.installed_size()).unwrap_or(i64::MAX),
                    );
                    let kind = match candidate.version().cmp(previous.version()) {
                        std::cmp::Ordering::Greater => Change::Upgrade,
                        std::cmp::Ordering::Less => Change::Downgrade,
                        std::cmp::Ordering::Equal => Change::Reinstall,
                    };
                    steps.push(Step::Change { from: previous.id(), to: id, kind });
                }
                None => steps.push(Step::Install { candidate: id, reason }),
            }
        }

        let (diagnostics, diagnostics_dropped) = sink.finish();
        Self {
            steps: steps.into_boxed_slice(),
            fidelity: planned.fidelity.fidelity(),
            divergences: planned.fidelity.diverged().into(),
            divergences_dropped: planned.fidelity.dropped(),
            diagnostics,
            diagnostics_dropped,
            download_size,
            installed_size_delta: installed_delta,
        }
    }
}

/// How many bytes `candidate` would actually pull over the network.
///
/// `compute_download_size` (`sync.c:310`): a package already in the cache costs nothing,
/// whatever its `%CSIZE%` says.
///
/// Three details are easy to miss on a first reading:
///
/// - **The cache is probed under `%FILENAME%`, never under a name rebuilt from
///   `<name>-<version>-<arch>`.** The compression suffix varies between packages (`.zst`,
///   `.xz`), so a rebuilt name can miss a file that is sitting right there. libalpm reads
///   `pkg->filename` for exactly this reason.
/// - **Reaching `%FILENAME%` forces the deferred `desc` parse.** The eager tier
///   (`repo::eager`) deliberately skips this field. The cost is bounded by the size of the
///   *plan*, not of the repository. Every caller that goes on to install forces the same
///   parse for the same candidates moments later, and `Lazy` then serves it from cache.
/// - **A candidate whose `desc` cannot be read counts in full.** Refusing to guess is the
///   conservative choice, and it matches what an absent `%CSIZE%` already does.
fn pending_download(candidate: &Solvable<'_>, cache: &dyn PackageCache) -> u64 {
    // `None` means an installed solvable, which has nothing to fetch. `assemble` already
    // filters those out, so answering zero here costs nothing.
    let Some(size) = candidate.download_size() else {
        return 0;
    };
    let cached = candidate
        .as_repository()
        .and_then(|package| package.desc().ok())
        .is_some_and(|desc| cache.is_cached(desc.file_name()));
    if cached { 0 } else { size }
}

/// Orders `incoming` so that every package follows the packages it depends on.
///
/// This is `_alpm_sortbydeps` (`deps.c:213`) as an explicit-stack DFS. It uses no recursion,
/// so a pathological dependency depth cannot overflow the stack. This matters because the
/// depth is attacker-influenced.
///
/// libalpm also pulls *installed* packages into the graph lazily, so a cycle running through
/// an already-installed package stays visible. piko does not: those vertices are traversal
/// scaffolding libalpm never emits, and they only affect which cycles get warned about. The
/// order of the packages actually being installed is identical.
fn topological_order(
    universe: &Universe<'_>,
    incoming: &[SolvableId],
    sink: &mut Sink<PlanDiagnostic>,
) -> Vec<SolvableId> {
    /// Where the traversal has got to with a vertex.
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum State {
        Unvisited,
        InProgress,
        Done,
    }

    // Positions within `incoming`, so the graph is dense and the traversal deterministic.
    let position = |id: SolvableId| incoming.iter().position(|candidate| *candidate == id);

    // Edge list: vertex -> the vertices it depends on, in the order its `%DEPENDS%` names
    // them. A tie breaks the same way every run.
    let edges: Vec<Vec<usize>> = incoming
        .iter()
        .map(|id| {
            let mut targets = Vec::new();
            let Some(solvable) = universe.get(*id) else { return targets };
            let Ok(depends) = solvable.depends() else {
                sink.push(|| PlanDiagnostic::DependsUnreadable { package: *id });
                return targets;
            };
            for dep in depends {
                for satisfier in universe.satisfiers(dep) {
                    if let Some(index) = position(satisfier)
                        && !targets.contains(&index)
                    {
                        targets.push(index);
                    }
                }
            }
            targets
        })
        .collect();

    let mut state = vec![State::Unvisited; incoming.len()];
    let mut ordered = Vec::with_capacity(incoming.len());

    for root in 0..incoming.len() {
        if state.get(root).copied().unwrap_or(State::Done) != State::Unvisited {
            continue;
        }
        // Each frame is (vertex, how many of its edges the search has followed).
        let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
        if let Some(slot) = state.get_mut(root) {
            *slot = State::InProgress;
        }

        while let Some((vertex, cursor)) = stack.pop() {
            match edges.get(vertex).and_then(|list| list.get(cursor).copied()) {
                Some(next) => {
                    stack.push((vertex, cursor.saturating_add(1)));
                    match state.get(next).copied().unwrap_or(State::Done) {
                        State::Unvisited => {
                            if let Some(slot) = state.get_mut(next) {
                                *slot = State::InProgress;
                            }
                            stack.push((next, 0));
                        }
                        State::InProgress => {
                            // A back edge: this dependency is an ancestor, so the two are on
                            // a cycle and no order satisfies both.
                            if let Some(id) = incoming.get(next).copied() {
                                sink.push(|| PlanDiagnostic::DependencyCycle { package: id });
                            }
                        }
                        State::Done => {}
                    }
                }
                None => {
                    // Every edge followed: emit on the way out, which is what puts
                    // dependencies before dependents.
                    if let Some(slot) = state.get_mut(vertex) {
                        *slot = State::Done;
                    }
                    if let Some(id) = incoming.get(vertex).copied() {
                        ordered.push(id);
                    }
                }
            }
        }
    }

    ordered
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
    use crate::fixture::{PackageSpec, Scenario};
    use crate::solve::{
        Fidelity, NoCache, Request, UniverseOptions, resolve_target, solve_with_removals,
    };

    /// Plans removing `target` from `scenario`.
    fn plan_removal(
        scenario: &crate::fixture::BuiltScenario,
        target: &str,
        recursive: bool,
        cascade: bool,
    ) -> Option<Vec<String>> {
        let limits = Limits::default();
        let universe = crate::solve::Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();

        let installed = universe.installed_named(target).expect("target must be installed");
        let request =
            Request::new().remove(installed.id()).recursive(recursive).allow_removals(cascade);
        let planned = solve_with_removals(&universe, &request, &limits).unwrap().ok()?;
        let plan = Plan::assemble(&universe, &planned, request.targets(), &limits, &NoCache);

        let mut names: Vec<String> = plan
            .steps()
            .iter()
            .map(|step| {
                let id = match step {
                    Step::Remove { package } => *package,
                    Step::Install { candidate, .. } => *candidate,
                    Step::Change { to, .. } => *to,
                };
                universe.get(id).unwrap().name().to_string()
            })
            .collect();
        names.sort();
        Some(names)
    }

    /// A cache holding exactly the package file names it was built with.
    ///
    /// The point of [`PackageCache`] being a trait: the download-size rule is exercised without
    /// a directory, a file, or a `tempfile` anywhere in sight.
    #[derive(Debug)]
    struct FakeCache(Vec<String>);

    impl PackageCache for FakeCache {
        fn is_cached(&self, file_name: &alpm_types::PackageFileName) -> bool {
            self.0.contains(&file_name.to_string())
        }
    }

    /// Plans `target` against `scenario`, returning the ordered step list as names.
    fn plan_names(scenario: &crate::fixture::BuiltScenario, target: &str) -> (Vec<String>, Plan) {
        plan_names_with(scenario, target, &NoCache)
    }

    /// As [`plan_names`], with a say in what counts as already downloaded.
    fn plan_names_with(
        scenario: &crate::fixture::BuiltScenario,
        target: &str,
        cache: &dyn PackageCache,
    ) -> (Vec<String>, Plan) {
        let limits = Limits::default();
        let universe = crate::solve::Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();

        let dep = target.parse().unwrap();
        let id = resolve_target(&universe, &dep).expect("target should resolve");
        let request = Request::new().target(id);
        let planned = solve_with_removals(&universe, &request, &limits).unwrap().unwrap();
        let plan = Plan::assemble(&universe, &planned, request.targets(), &limits, cache);

        let names = plan
            .steps()
            .iter()
            .map(|step| {
                let id = match step {
                    Step::Remove { package } => *package,
                    Step::Install { candidate, .. } => *candidate,
                    Step::Change { to, .. } => *to,
                };
                universe.get(id).unwrap().name().to_string()
            })
            .collect();
        (names, plan)
    }

    /// The property the whole ordering exists for: nothing is installed before something it
    /// depends on.
    #[test]
    fn dependencies_are_ordered_before_their_dependents() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["mid"]),
                    PackageSpec::new("mid", "1.0.0-1").depends(["base"]),
                    PackageSpec::new("base", "1.0.0-1"),
                ],
            )
            .build();

        let (names, plan) = plan_names(&scenario, "app");
        assert_eq!(names, ["base", "mid", "app"]);
        assert!(plan.diagnostics().is_empty());
    }

    #[test]
    fn a_diamond_still_places_the_shared_dependency_first() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["left", "right"]),
                    PackageSpec::new("left", "1.0.0-1").depends(["base"]),
                    PackageSpec::new("right", "1.0.0-1").depends(["base"]),
                    PackageSpec::new("base", "1.0.0-1"),
                ],
            )
            .build();

        let (names, _) = plan_names(&scenario, "app");
        let position = |name: &str| names.iter().position(|item| item == name).unwrap();
        assert!(position("base") < position("left"));
        assert!(position("base") < position("right"));
        assert!(position("left") < position("app"));
        assert!(position("right") < position("app"));
    }

    /// libalpm warns and proceeds on a cycle rather than failing; so must piko, or piko could
    /// not install package sets pacman installs every day.
    #[test]
    fn a_dependency_cycle_is_reported_but_still_produces_a_plan() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["ring-a"]),
                    PackageSpec::new("ring-a", "1.0.0-1").depends(["ring-b"]),
                    PackageSpec::new("ring-b", "1.0.0-1").depends(["ring-a"]),
                ],
            )
            .build();

        let (names, plan) = plan_names(&scenario, "app");
        assert_eq!(names.len(), 3, "every package is still planned: {names:?}");
        assert!(
            plan.diagnostics()
                .iter()
                .any(|item| matches!(item, PlanDiagnostic::DependencyCycle { .. })),
            "the cycle must be reported: {:?}",
            plan.diagnostics()
        );
    }

    #[test]
    fn an_upgrade_is_one_step_not_a_removal_and_an_install() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "1.0.0-1"))
            .repo("core", [PackageSpec::new("app", "2.0.0-1")])
            .build();

        let (_, plan) = plan_names(&scenario, "app");
        assert_eq!(plan.steps().len(), 1);
        assert!(
            matches!(plan.steps()[0], Step::Change { kind: Change::Upgrade, .. }),
            "got {:?}",
            plan.steps()[0]
        );
    }

    #[test]
    fn a_target_is_explicit_and_a_pulled_dependency_is_not() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["lib"]),
                    PackageSpec::new("lib", "1.0.0-1"),
                ],
            )
            .build();

        let (_, plan) = plan_names(&scenario, "app");
        let reasons: Vec<_> = plan
            .steps()
            .iter()
            .filter_map(|step| match step {
                Step::Install { reason, .. } => Some(*reason),
                _ => None,
            })
            .collect();
        assert_eq!(
            reasons,
            [PackageInstallReason::Depend, PackageInstallReason::Explicit],
            "lib is pulled in, app was asked for"
        );
    }

    /// A conflict with an installed package becomes a removal step, and removals precede
    /// installs the way `_alpm_sync_commit` performs them.
    #[test]
    fn a_conflicting_installed_package_is_removed_before_anything_is_installed() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old-thing", "1.0.0-1"))
            .repo("core", [PackageSpec::new("new-thing", "1.0.0-1").conflicts(["old-thing"])])
            .build();

        let (names, plan) = plan_names(&scenario, "new-thing");
        assert_eq!(names, ["old-thing", "new-thing"]);
        assert!(matches!(plan.steps()[0], Step::Remove { .. }), "got {:?}", plan.steps()[0]);
        assert!(matches!(plan.steps()[1], Step::Install { .. }), "got {:?}", plan.steps()[1]);
    }

    #[test]
    fn sizes_are_accumulated_across_the_plan() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1")
                        .depends(["lib"])
                        .installed_size(1000)
                        .compressed_size(300),
                    PackageSpec::new("lib", "1.0.0-1").installed_size(500).compressed_size(200),
                ],
            )
            .build();

        let (_, plan) = plan_names(&scenario, "app");
        assert_eq!(plan.download_size(), 500);
        assert_eq!(plan.installed_size_delta(), 1500);
    }

    /// `%CSIZE%` is what a package weighs, not what it costs to fetch: a candidate already in
    /// the cache crosses no network at all.
    ///
    /// `compute_download_size` (`sync.c:310`) drops such a candidate to zero the same way.
    /// Before this, `piko install` announced the full figure for a plan it already had entirely
    /// on disk, and drew a progress bar that could never move — which read as re-downloading.
    #[test]
    fn a_cached_candidate_costs_nothing_to_download() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1")
                        .depends(["lib"])
                        .installed_size(1000)
                        .compressed_size(300),
                    PackageSpec::new("lib", "1.0.0-1").installed_size(500).compressed_size(200),
                ],
            )
            .build();

        let cache = FakeCache(vec!["lib-1.0.0-1-x86_64.pkg.tar.zst".to_owned()]);
        let (_, plan) = plan_names_with(&scenario, "app", &cache);
        assert_eq!(plan.download_size(), 300, "only the candidate that is missing counts");
        assert_eq!(
            plan.installed_size_delta(),
            1500,
            "where a package came from does not change what it occupies once installed"
        );

        let cache = FakeCache(vec![
            "lib-1.0.0-1-x86_64.pkg.tar.zst".to_owned(),
            "app-1.0.0-1-x86_64.pkg.tar.zst".to_owned(),
        ]);
        let (names, plan) = plan_names_with(&scenario, "app", &cache);
        assert_eq!(plan.download_size(), 0, "nothing to fetch when everything is on disk");
        assert_eq!(names, ["lib", "app"], "the steps are the same either way");
    }

    #[test]
    fn removing_a_leaf_takes_only_that_package() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("leaf", "1.0.0-1"))
            .installed(PackageSpec::new("other", "1.0.0-1"))
            .repo("core", [PackageSpec::new("leaf", "1.0.0-1")])
            .build();

        assert_eq!(plan_removal(&scenario, "leaf", false, false).unwrap(), ["leaf"]);
    }

    /// `-R` refuses rather than breaking a package that is staying.
    #[test]
    fn removing_something_still_depended_on_is_refused() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("lib", "1.0.0-1"))
            .installed(PackageSpec::new("app", "1.0.0-1").depends(["lib"]))
            .repo("core", [PackageSpec::new("lib", "1.0.0-1")])
            .build();

        assert!(plan_removal(&scenario, "lib", false, false).is_none());
    }

    /// `-Rc` takes the dependents with it instead of refusing.
    #[test]
    fn cascade_removes_the_dependents_too() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("lib", "1.0.0-1"))
            .installed(PackageSpec::new("app", "1.0.0-1").depends(["lib"]))
            .repo("core", [PackageSpec::new("lib", "1.0.0-1")])
            .build();

        assert_eq!(plan_removal(&scenario, "lib", false, true).unwrap(), ["app", "lib"]);
    }

    /// `-Rs` takes the target's own dependencies when nothing else wants them.
    #[test]
    fn recursive_removal_sweeps_the_targets_dependencies() {
        let scenario = Scenario::new()
            .installed(
                PackageSpec::new("app", "1.0.0-1")
                    .depends(["helper"])
                    .reason(alpm_types::PackageInstallReason::Explicit),
            )
            .installed(
                PackageSpec::new("helper", "1.0.0-1")
                    .reason(alpm_types::PackageInstallReason::Depend),
            )
            .repo("core", [PackageSpec::new("app", "1.0.0-1")])
            .build();

        assert_eq!(plan_removal(&scenario, "app", true, false).unwrap(), ["app", "helper"]);
    }

    /// The bug real data exposed: `-Rs` is scoped to the target's dependencies, not to every
    /// orphan on the system. An unrelated package installed as a dependency and needed by
    /// nothing must survive.
    #[test]
    fn recursive_removal_leaves_unrelated_orphans_alone() {
        let scenario = Scenario::new()
            .installed(
                PackageSpec::new("app", "1.0.0-1")
                    .depends(["helper"])
                    .reason(alpm_types::PackageInstallReason::Explicit),
            )
            .installed(
                PackageSpec::new("helper", "1.0.0-1")
                    .reason(alpm_types::PackageInstallReason::Depend),
            )
            .installed(
                PackageSpec::new("unrelated-orphan", "1.0.0-1")
                    .reason(alpm_types::PackageInstallReason::Depend),
            )
            .repo("core", [PackageSpec::new("app", "1.0.0-1")])
            .build();

        let removed = plan_removal(&scenario, "app", true, false).unwrap();
        assert_eq!(removed, ["app", "helper"]);
        assert!(!removed.contains(&"unrelated-orphan".to_owned()));
    }

    /// `-Rcs` recurses over what the *cascade* pulled in too, not only over the named target.
    ///
    /// `remove.c:249` runs `_alpm_recursedeps` a second time after `remove_prepare_cascade`
    /// has appended the dependents to `trans->remove` — "`-Rcs` == `-Rc` then `-Rs`". Seeding
    /// from the named targets alone left `dependent`'s own dependency behind: real data had
    /// `piko remove -cs phonon-qt6` take 4 packages where `pacman -Rcs` takes 35.
    #[test]
    fn cascading_removal_recurses_into_the_cascaded_dependents_dependencies() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("target", "1.0.0-1"))
            .installed(
                PackageSpec::new("dependent", "1.0.0-1")
                    .depends(["target", "cascaded-helper"])
                    .reason(alpm_types::PackageInstallReason::Explicit),
            )
            .installed(
                PackageSpec::new("cascaded-helper", "1.0.0-1")
                    .reason(alpm_types::PackageInstallReason::Depend),
            )
            .repo("core", [PackageSpec::new("target", "1.0.0-1")])
            .build();

        // `-Rc` alone stops at the dependent.
        assert_eq!(
            plan_removal(&scenario, "target", false, true).unwrap(),
            ["dependent", "target"]
        );
        // `-Rcs` also takes what only the cascaded dependent needed.
        assert_eq!(
            plan_removal(&scenario, "target", true, true).unwrap(),
            ["cascaded-helper", "dependent", "target"]
        );
    }

    /// `-Rs` must not sweep a dependency something surviving still needs — libalpm's
    /// re-widening phase.
    #[test]
    fn recursive_removal_keeps_a_dependency_another_package_still_needs() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "1.0.0-1").depends(["shared"]))
            .installed(PackageSpec::new("keeper", "1.0.0-1").depends(["shared"]))
            .installed(
                PackageSpec::new("shared", "1.0.0-1")
                    .reason(alpm_types::PackageInstallReason::Depend),
            )
            .repo("core", [PackageSpec::new("app", "1.0.0-1")])
            .build();

        assert_eq!(plan_removal(&scenario, "app", true, false).unwrap(), ["app"]);
    }

    /// A removal must never install a substitute, however neatly one would fit.
    #[test]
    fn a_removal_never_installs_a_replacement_provider() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("thing", "1.0.0-1"))
            .installed(PackageSpec::new("user", "1.0.0-1").depends(["thing"]))
            .repo(
                "core",
                [
                    PackageSpec::new("thing", "1.0.0-1"),
                    PackageSpec::new("thing-alt", "1.0.0-1").provides(["thing"]),
                ],
            )
            .build();

        // `thing-alt` would satisfy `user`, but substituting it is not what `-R` means.
        assert!(plan_removal(&scenario, "thing", false, false).is_none());
    }

    /// Fidelity must still fire when a *different package* answers a dependency — the
    /// name-based comparison that stopped `-Su` reporting 28 false divergences must not have
    /// made the measure dead.
    #[test]
    fn choosing_a_different_provider_is_reported_as_divergence() {
        let scenario = Scenario::new()
            // `blocker` is installed and must remain; `impl-a` conflicts with it.
            .installed(PackageSpec::new("blocker", "1.0.0-1"))
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["virtual"]),
                    PackageSpec::new("impl-a", "1.0.0-1")
                        .provides(["virtual"])
                        .conflicts(["blocker"]),
                    PackageSpec::new("impl-b", "1.0.0-1").provides(["virtual"]),
                ],
            )
            .build();

        let limits = Limits::default();
        let universe = crate::solve::Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        // `allow_removals(false)`: removing `blocker` would be the other way out, and this
        // test is about the provider choice.
        let request = Request::new().target(id).allow_removals(false);
        let planned = solve_with_removals(&universe, &request, &limits).unwrap().unwrap();
        let plan = Plan::assemble(&universe, &planned, request.targets(), &limits, &NoCache);

        let names: Vec<String> = planned
            .selected
            .iter()
            .filter_map(|id| universe.get(*id))
            .filter(|s| !s.is_installed())
            .map(|s| s.name().to_string())
            .collect();
        assert!(names.contains(&"impl-b".to_owned()), "must fall back to impl-b: {names:?}");
        assert!(!names.contains(&"impl-a".to_owned()), "{names:?}");
        assert!(
            matches!(plan.fidelity(), Fidelity::Diverged { requirements: 1 }),
            "a different package answered the dependency: {:?}",
            plan.fidelity()
        );

        // The count on its own is what §52 measured to be uninformative; the report has to
        // name what it counted, or the same always-on failure cannot be told from a real hit.
        let [divergence] = plan.divergences() else {
            panic!("the counted requirement must be named: {:?}", plan.divergences())
        };
        assert_eq!(plan.divergences_dropped(), 0);
        let named = |id| universe.get(id).map(|s| s.name().to_string());
        assert_eq!(named(divergence.dependent).as_deref(), Some("app"));
        assert_eq!(named(divergence.preferred).as_deref(), Some("impl-a"));
        assert_eq!(named(divergence.selected).as_deref(), Some("impl-b"));
        let relation = universe
            .get(divergence.dependent)
            .and_then(|s| s.depends().ok())
            .and_then(|depends| depends.get(divergence.dependency).map(ToString::to_string));
        assert_eq!(relation.as_deref(), Some("virtual"), "the index must reach the relation");
    }

    /// The bug §52 measured: `encode` emits a requirement for every `%DEPENDS%` entry of every
    /// candidate in the cone, the cone holds the whole installed set, and "every installed
    /// package must remain" keeps all of it selected — so an unrelated quirk anywhere on the
    /// system used to be counted as a divergence of *every* plan, whatever the plan was.
    ///
    /// Here `host` already has `impl-b` answering its `virtual` dependency, while `impl-a`
    /// outranks it in preference order. libalpm never re-resolves `host`, so installing an
    /// unrelated package must report `Greedy`. Before the scope filter this reported
    /// `Diverged { requirements: 1 }`.
    #[test]
    fn a_pre_existing_provider_choice_is_not_a_divergence_of_an_unrelated_plan() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("impl-b", "1.0.0-1").provides(["virtual"]))
            .installed(PackageSpec::new("host", "1.0.0-1").depends(["virtual"]))
            .repo(
                "core",
                [
                    // Literally named `virtual`, so it heads the preference order ahead of any
                    // provider — including the installed one that actually satisfies `host`.
                    PackageSpec::new("virtual", "1.0.0-1"),
                    PackageSpec::new("unrelated", "1.0.0-1"),
                ],
            )
            .build();

        let limits = Limits::default();
        let universe = crate::solve::Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"unrelated".parse().unwrap()).unwrap();
        let request = Request::new().target(id);
        let planned = solve_with_removals(&universe, &request, &limits).unwrap().unwrap();
        let plan = Plan::assemble(&universe, &planned, request.targets(), &limits, &NoCache);

        assert_eq!(
            plan.fidelity(),
            Fidelity::Greedy,
            "installing `unrelated` decided nothing about `host`: {:?}",
            plan.divergences()
        );
        assert!(plan.divergences().is_empty());
    }

    /// A provider pulled in for an *earlier* `%DEPENDS%` entry of the same package answers the
    /// later one, so libalpm never reaches the preference order for it.
    ///
    /// Measured on real data as `piko plan cl-alexandria`, which declares `cl-asdf` before
    /// `common-lisp`: `ecl` provides both, so `clisp` — the head of the `common-lisp`
    /// preference list — is never tried, and pacman's plan is `ecl` too. Reporting a
    /// divergence there was a false positive.
    #[test]
    fn a_provider_taken_for_an_earlier_dependency_is_not_a_divergence() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    // `asdf` first, `virtual` second — the declaration order is the point.
                    PackageSpec::new("app", "1.0.0-1").depends(["asdf", "virtual"]),
                    // Preferred for `virtual`, but provides nothing for `asdf`.
                    PackageSpec::new("impl-a", "1.0.0-1").provides(["virtual"]),
                    // The only way to satisfy `asdf`, and it answers `virtual` as well.
                    PackageSpec::new("impl-b", "1.0.0-1").provides(["virtual", "asdf"]),
                ],
            )
            .build();

        let limits = Limits::default();
        let universe = crate::solve::Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let request = Request::new().target(id);
        let planned = solve_with_removals(&universe, &request, &limits).unwrap().unwrap();
        let plan = Plan::assemble(&universe, &planned, request.targets(), &limits, &NoCache);

        assert_eq!(
            plan.fidelity(),
            Fidelity::Greedy,
            "`impl-b` was already pulled in for `asdf`: {:?}",
            plan.divergences()
        );
    }

    /// A package the user named is in libalpm's package list before dependency resolution
    /// starts, so a dependency it satisfies is never raised.
    ///
    /// Measured as `piko plan tesseract-data-sun`: the target pulls in `tesseract`, which
    /// requires `tessdata`; the target itself provides it, so the head of the `tessdata` list
    /// (`tesseract-data-afr`) is never consulted. Reporting that was a false positive.
    #[test]
    fn a_dependency_answered_by_the_named_target_is_not_a_divergence() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    // Preferred for `virtual`, and nothing else brings it in.
                    PackageSpec::new("data-a", "1.0.0-1").provides(["virtual"]),
                    // The target: it provides `virtual` and pulls in the package needing it.
                    PackageSpec::new("data-b", "1.0.0-1").provides(["virtual"]).depends(["host"]),
                    PackageSpec::new("host", "1.0.0-1").depends(["virtual"]),
                ],
            )
            .build();

        let limits = Limits::default();
        let universe = crate::solve::Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"data-b".parse().unwrap()).unwrap();
        let request = Request::new().target(id);
        let planned = solve_with_removals(&universe, &request, &limits).unwrap().unwrap();
        let plan = Plan::assemble(&universe, &planned, request.targets(), &limits, &NoCache);

        assert_eq!(
            plan.fidelity(),
            Fidelity::Greedy,
            "`data-b` is what the user asked for: {:?}",
            plan.divergences()
        );
    }

    /// An installed package the transaction keeps already satisfies the dependency, so
    /// `alpm_checkdeps` reports nothing missing and the repository's literal match — which
    /// outranks an installed *provider* — is never tried.
    ///
    /// Measured as `piko plan corrosion`: it requires `rust`, `rustup` is installed and
    /// provides it, and the literal `rust` package heads the preference list. pacman keeps
    /// `rustup` too. Reporting that was a false positive.
    #[test]
    fn a_dependency_answered_by_an_untouched_installed_package_is_not_a_divergence() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("rustup", "1.0.0-1").provides(["rust"]))
            .repo(
                "core",
                [
                    PackageSpec::new("app", "1.0.0-1").depends(["rust"]),
                    // A literal name match, which `Universe::satisfiers` ranks first.
                    PackageSpec::new("rust", "1.0.0-1"),
                    PackageSpec::new("rustup", "1.0.0-1").provides(["rust"]),
                ],
            )
            .build();

        let limits = Limits::default();
        let universe = crate::solve::Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"app".parse().unwrap()).unwrap();
        let request = Request::new().target(id);
        let planned = solve_with_removals(&universe, &request, &limits).unwrap().unwrap();
        let plan = Plan::assemble(&universe, &planned, request.targets(), &limits, &NoCache);

        let names: Vec<String> = planned
            .selected
            .iter()
            .filter_map(|id| universe.get(*id))
            .filter(|s| !s.is_installed())
            .map(|s| s.name().to_string())
            .collect();
        assert!(!names.contains(&"rust".to_owned()), "installed `rustup` answers it: {names:?}");
        assert_eq!(
            plan.fidelity(),
            Fidelity::Greedy,
            "the dependency was already satisfied on disk: {:?}",
            plan.divergences()
        );
    }

    /// An upgrade is not a divergence: the same package answers the dependency, at a newer
    /// version. This is what `-Su` does to almost every requirement it touches.
    #[test]
    fn upgrading_the_preferred_candidate_is_not_a_divergence() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("lib", "1.0.0-1"))
            .installed(PackageSpec::new("app", "1.0.0-1").depends(["lib"]))
            .repo("core", [PackageSpec::new("lib", "2.0.0-1")])
            .build();

        let limits = Limits::default();
        let universe = crate::solve::Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let id = resolve_target(&universe, &"lib".parse().unwrap()).unwrap();
        let request = Request::new().target(id);
        let planned = solve_with_removals(&universe, &request, &limits).unwrap().unwrap();
        let plan = Plan::assemble(&universe, &planned, request.targets(), &limits, &NoCache);

        assert_eq!(plan.fidelity(), Fidelity::Greedy, "an upgrade is not a divergence");
    }

    /// Removing something bigger than what arrives must be a net loss, not an underflow.
    #[test]
    fn a_net_shrink_is_reported_as_negative() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("old-thing", "1.0.0-1").installed_size(10_000))
            .repo(
                "core",
                [PackageSpec::new("new-thing", "1.0.0-1")
                    .conflicts(["old-thing"])
                    .installed_size(1000)],
            )
            .build();

        let (_, plan) = plan_names(&scenario, "new-thing");
        assert_eq!(plan.installed_size_delta(), -9000);
    }
}
