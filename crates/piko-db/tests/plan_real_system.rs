//! Tests the planning layer against the live databases of the machine running them.
//!
//! Every test here is `#[ignore]`d, because the machine may have no sync databases at all
//! and the results depend on what repositories are configured. Run them explicitly:
//!
//! ```text
//! cargo test -p piko-db --test plan_real_system -- --ignored --nocapture
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::collections::BTreeSet;
use std::path::Path;

use alpm_types::RelationOrSoname;
use piko_db::{
    LocalDatabase,
    config::DbUsage,
    fixture::DbFixture,
    repo::{RepoDatabase, RepoName},
    resolve::{SyncRepo, SyncRepos},
    solve::{Universe, UniverseOptions},
};

const SYNC_DIR: &str = "/var/lib/pacman/sync";

/// Opens the repositories this machine actually has, in `core`-then-`extra` priority order.
fn open_repos() -> Vec<RepoDatabase> {
    if !Path::new(SYNC_DIR).is_dir() {
        eprintln!("skipping: {SYNC_DIR} does not exist");
        return Vec::new();
    }
    ["core", "extra"]
        .iter()
        .filter_map(|repo| {
            let name = RepoName::parse(repo).unwrap();
            RepoDatabase::open_repo(SYNC_DIR, &name).ok()
        })
        .collect()
}

/// Every distinct `%DEPENDS%` entry across `repos`, capped so the comparison stays quick.
fn sample_dependencies(repos: &[RepoDatabase], cap: usize) -> Vec<RelationOrSoname> {
    let mut seen = BTreeSet::new();
    let mut sample = Vec::new();
    for repo in repos {
        for package in repo {
            let Ok(depends) = package.depends() else { continue };
            for dep in depends {
                if seen.insert(dep.to_string()) {
                    sample.push(dep.clone());
                    if sample.len() >= cap {
                        return sample;
                    }
                }
            }
        }
    }
    sample
}

/// The indexed [`Universe`] and the scanning [`SyncRepos`] must agree on every real
/// dependency this machine's repositories actually declare.
///
/// They are two implementations of `resolvedep` over the same data: one built for a single
/// query, one for thousands. `SyncRepos` is the one already verified against real pacman. If
/// they disagree, the index is wrong, and every plan built on it is too.
///
/// The universe is built against an **empty** installed set so the two stay comparable.
/// `SyncRepos` knows nothing about installed packages. A real universe ranks an installed
/// provider first instead (`deps.c:709`).
#[test]
#[ignore = "requires a real ALPM sync database"]
fn the_index_answers_exactly_what_the_verified_scanner_answers() {
    let repos = open_repos();
    if repos.is_empty() {
        eprintln!("skipping: no repository could be opened");
        return;
    }

    let empty = DbFixture::new();
    let local = LocalDatabase::open(empty.path()).unwrap();
    let universe =
        Universe::build(&local, repos.iter().map(|db| (DbUsage::ALL, db)), UniverseOptions::new())
            .unwrap();
    let scanner = SyncRepos::new(repos.iter().map(|db| SyncRepo::new(DbUsage::ALL, db)));

    let sample = sample_dependencies(&repos, 4000);
    assert!(sample.len() > 100, "expected a substantial sample, got {}", sample.len());

    let mut literal = 0_usize;
    let mut provided = 0_usize;
    let mut unsatisfied = 0_usize;

    for dep in &sample {
        let scanned = scanner.find_satisfiers(dep);
        let indexed = universe.satisfiers(dep);

        if scanned.is_empty() {
            assert!(
                indexed.is_empty(),
                "{dep}: the scanner found nothing but the index found {:?}",
                indexed
                    .iter()
                    .map(|id| universe.get(*id).unwrap().name().as_ref())
                    .collect::<Vec<_>>()
            );
            unsatisfied += 1;
            continue;
        }

        assert!(!indexed.is_empty(), "{dep}: the index found nothing but the scanner did");

        // Whatever each picks first must be the same package. This is the property that
        // matters: it lets a greedy descent through the index reproduce libalpm's answer.
        let first = universe.get(indexed[0]).unwrap();
        assert_eq!(
            (first.name().as_ref(), first.version().to_string()),
            (scanned[0].package().name().as_ref(), scanned[0].package().version().to_string()),
            "{dep}: the index and the scanner disagree on the preferred candidate"
        );

        let is_literal = matches!(dep, RelationOrSoname::Relation(relation)
            if scanned[0].package().name() == &relation.name);
        if is_literal {
            // `find_satisfiers` returns the single literal and stops. The index also offers
            // the lower-priority literals and the providers, reachable only by backtracking.
            literal += 1;
        } else {
            // No literal exists, so both are enumerating providers and must agree entirely.
            let scanned_names: Vec<_> =
                scanned.iter().map(|hit| hit.package().name().as_ref()).collect();
            let indexed_names: Vec<_> =
                indexed.iter().map(|id| universe.get(*id).unwrap().name().as_ref()).collect();
            assert_eq!(
                scanned_names, indexed_names,
                "{dep}: provider lists differ in content or order"
            );
            provided += 1;
        }
    }

    eprintln!(
        "compared {} real dependencies: {literal} literal, {provided} provided, \
         {unsatisfied} unsatisfied",
        sample.len()
    );
}

/// The universe must see every installed package, including one that no repository carries.
#[test]
#[ignore = "requires a real ALPM local database and sync databases"]
fn every_installed_package_is_a_candidate() {
    let repos = open_repos();
    if repos.is_empty() {
        eprintln!("skipping: no repository could be opened");
        return;
    }
    let Ok(local) = LocalDatabase::open("/var/lib/pacman/local") else {
        eprintln!("skipping: no real local database");
        return;
    };

    let universe =
        Universe::build(&local, repos.iter().map(|db| (DbUsage::ALL, db)), UniverseOptions::new())
            .unwrap();

    for package in &local {
        let found = universe.installed_named(package.name().as_ref());
        assert!(found.is_some(), "{} is installed but is not a candidate", package.name());
        assert_eq!(found.unwrap().version(), package.version());
    }

    eprintln!("{} installed packages, {} candidates in total", local.len(), universe.len());
}

/// The ordering property on a real transaction: every package is planned after everything it
/// depends on that the same plan installs.
///
/// This is what `_alpm_sortbydeps` exists to guarantee. The only way to check it meaningfully
/// is against a dependency graph large enough to have depth — here, the closure of a real
/// meta-package, several hundred packages wide.
#[test]
#[ignore = "requires a real ALPM local database and sync databases"]
fn a_real_plan_orders_every_dependency_before_its_dependent() {
    let repos = open_repos();
    if repos.is_empty() {
        eprintln!("skipping: no repository could be opened");
        return;
    }
    let Ok(local) = LocalDatabase::open("/var/lib/pacman/local") else {
        eprintln!("skipping: no real local database");
        return;
    };

    let limits = piko_db::Limits::default();
    let universe =
        Universe::build(&local, repos.iter().map(|db| (DbUsage::ALL, db)), UniverseOptions::new())
            .unwrap();

    // A target with a deep, wide closure. Skipped rather than failed if this machine's
    // repositories do not carry it.
    let target = "plasma-meta";
    let Ok(dep) = target.parse::<RelationOrSoname>() else { return };
    let Some(id) = piko_db::solve::resolve_target(&universe, &dep) else {
        eprintln!("skipping: {target} is not available here");
        return;
    };

    let request = piko_db::solve::Request::new().target(id);
    let planned = piko_db::solve::solve_with_removals(&universe, &request, &limits)
        .unwrap()
        .unwrap_or_else(|_| panic!("{target} should be plannable"));
    let plan = piko_db::solve::Plan::assemble(
        &universe,
        &planned,
        request.targets(),
        &limits,
        &piko_db::solve::NoCache,
    );

    // Position of each incoming package in execution order.
    let mut position = std::collections::HashMap::new();
    for (index, step) in plan.steps().iter().enumerate() {
        let id = match step {
            piko_db::solve::Step::Install { candidate, .. } => *candidate,
            piko_db::solve::Step::Change { to, .. } => *to,
            piko_db::solve::Step::Remove { .. } => continue,
        };
        position.insert(id, index);
    }
    assert!(position.len() > 100, "expected a deep plan, got {}", position.len());

    let mut violations = 0_usize;
    let mut cycles = 0_usize;
    for (id, index) in &position {
        let solvable = universe.get(*id).unwrap();
        let Ok(depends) = solvable.depends() else { continue };
        for want in depends {
            for satisfier in universe.satisfiers(want) {
                let Some(other) = position.get(&satisfier) else { continue };
                if other > index {
                    // A cycle makes some inversion unavoidable; libalpm accepts that too.
                    // Count it as a violation only when the plan reported no cycle at all.
                    if plan.diagnostics().is_empty() {
                        eprintln!(
                            "  {} (at {index}) depends on {} (at {other})",
                            solvable.name(),
                            universe.get(satisfier).unwrap().name()
                        );
                        violations += 1;
                    } else {
                        cycles += 1;
                    }
                    break;
                }
            }
        }
    }

    eprintln!(
        "{target}: {} packages ordered, {violations} violations, {cycles} inversions excused by \
         {} reported cycle(s)",
        position.len(),
        plan.diagnostics().len()
    );
    assert_eq!(violations, 0, "a dependency was planned after its dependent");
}

/// A removal plan must not depend on which repositories are configured.
///
/// This is not a curiosity. `piko remove` is a removal-only operation. If the answer is
/// independent of the repository set, it need not open a sync database at all — which lets
/// it work in a chroot with none, and saves the ~700 ms of opening `core` and `extra` before
/// deleting some files.
///
/// The claim rests on `Request::is_removal_only`: a request that only takes packages away
/// restricts the candidate set to what is already installed, so repository candidates are
/// inert. That is an argument, not evidence, which is why this test exists. It covers `-R`,
/// `-Rs`, `-Rc` and `-Rcs`, since each reaches the solver differently.
#[test]
#[ignore = "requires a real ALPM local database and sync databases"]
fn a_removal_plan_is_the_same_with_and_without_repositories() {
    /// Each target is solved eight times: four flag combinations, two universes. This knob
    /// keeps the test runtime sensible — 25 targets costs two minutes in a debug build. A
    /// 25-package run (75 plans) was clean when this landed; the committed sample is smaller
    /// only to keep `--ignored` usable.
    const SAMPLE: usize = 12;

    let repos = open_repos();
    if repos.is_empty() {
        eprintln!("skipping: no repository could be opened");
        return;
    }
    let Ok(local) = LocalDatabase::open("/var/lib/pacman/local") else {
        eprintln!("skipping: no real local database");
        return;
    };

    let limits = piko_db::Limits::default();
    let with_repos =
        Universe::build(&local, repos.iter().map(|db| (DbUsage::ALL, db)), UniverseOptions::new())
            .unwrap();
    let without_repos =
        Universe::build(&local, std::iter::empty(), UniverseOptions::new()).unwrap();

    /// The names a removal plan would take away, sorted so the comparison is order-free.
    ///
    /// Names rather than ids: a `SolvableId` is an index into one universe and means nothing
    /// in the other. That is the whole reason ids cannot be compared directly.
    fn removed_names(
        universe: &Universe<'_>,
        target: &str,
        recursive: bool,
        cascade: bool,
        limits: &piko_db::Limits,
    ) -> Option<Vec<String>> {
        let installed = universe.installed_named(target)?;
        let request = piko_db::solve::Request::new()
            .recursive(recursive)
            .allow_removals(cascade)
            .remove(installed.id());
        let planned = piko_db::solve::solve_with_removals(universe, &request, limits).ok()?.ok()?;
        let plan = piko_db::solve::Plan::assemble(
            universe,
            &planned,
            request.targets(),
            limits,
            &piko_db::solve::NoCache,
        );

        let mut names: Vec<String> = plan
            .steps()
            .iter()
            .map(|step| {
                let id = match step {
                    piko_db::solve::Step::Remove { package } => *package,
                    piko_db::solve::Step::Install { candidate, .. } => *candidate,
                    piko_db::solve::Step::Change { to, .. } => *to,
                };
                universe.get(id).map_or_else(|| "<unknown>".to_owned(), |s| s.name().to_string())
            })
            .collect();
        names.sort();
        Some(names)
    }

    let targets: Vec<String> =
        local.iter().map(|package| package.name().to_string()).take(SAMPLE).collect();

    let mut compared = 0_usize;
    let mut disagreements = Vec::new();
    for target in &targets {
        for (recursive, cascade, flag) in
            [(false, false, "-R"), (true, false, "-Rs"), (false, true, "-Rc"), (true, true, "-Rcs")]
        {
            let a = removed_names(&with_repos, target, recursive, cascade, &limits);
            let b = removed_names(&without_repos, target, recursive, cascade, &limits);
            if a != b {
                disagreements.push(format!("{target} {flag}: with={a:?} without={b:?}"));
            }
            compared += 1;
        }
    }

    eprintln!("{compared} removal plans compared across {} packages", targets.len());
    assert!(
        disagreements.is_empty(),
        "{} removal plan(s) changed with the repository set:\n  {}",
        disagreements.len(),
        disagreements.join("\n  ")
    );
}
