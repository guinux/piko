//! Planning a removal — the algorithm shared by `piko plan -R` and `piko remove`.
//!
//! One function, every caller, on purpose. `piko plan -R` is the *oracle* for `piko remove`. It
//! is what has been diffed against `pacman -R/-Rs/-Rc --print` across 85 real packages with
//! zero disagreements. If the two computed their plans separately, that verification would
//! stop applying to the operation that actually deletes files. The first divergence between
//! them would then appear as data loss rather than as a failing test. Living here rather than
//! in a frontend crate keeps that property true for any future frontend, not just the CLI's two
//! commands.
//!
//! # No repository is needed to remove something
//!
//! The universe a removal is solved against can be built from the local database alone. This
//! is not an optimisation taken on faith. `Request::is_removal_only` restricts the candidate
//! set to what is already installed, so repository candidates are inert. The test
//! `a_removal_plan_is_the_same_with_and_without_repositories` in
//! `crates/piko-db/tests/plan_real_system.rs` checks this against the real database over `-R`,
//! `-Rs`, and `-Rc` alike. It matters in practice: a chroot being torn down may have no sync
//! database at all, and requiring one would make a removal fail there for no reason.
//!
//! # `HoldPkg` does not live here
//!
//! `HoldPkg` is a **pacman frontend** guard, not a libalpm rule: `src/pacman/remove.c:133`,
//! with nothing corresponding in `lib/libalpm/`. [`removal_names`] exists so a frontend can
//! apply that guard against the *prepared* removal list (`alpm_trans_get_remove`, not the names
//! the user typed). The guard itself, its prompt, and its `pacman.conf` parsing are a
//! frontend's concern.

use crate::solve::{Plan, Request, Step, Universe, solve_with_removals};
use crate::{Error, Limits, LocalDatabase};

/// Which flavour of removal to plan.
#[derive(Clone, Copy, Debug, Default)]
pub struct RemovalOptions {
    /// `-s`: also remove dependencies that nothing needs once the targets are gone.
    pub recursive: bool,
    /// `-c`: remove dependents too, instead of refusing.
    pub cascade: bool,
}

/// Why a removal could not be planned.
#[derive(Debug)]
pub enum RemovalFailure {
    /// A target names neither an installed package nor a group any installed package
    /// belongs to.
    NotInstalled(String),
    /// Removing the targets would break the system, and `-c` was not given.
    ///
    /// Carries the derivation, already rendered: the chain of facts that makes the refusal
    /// actionable rather than a bare "cannot remove".
    WouldBreakSystem(Vec<String>),
    /// The planner itself failed.
    Planner(Box<Error>),
}

/// Plans removing `targets`, exactly as `piko plan -R` does.
///
/// A target names an installed package, or a `%GROUPS%` group, which expands to every
/// installed member — `pacman -R <group>` "will remove every package in that group". A member
/// also named on its own costs nothing: the plan is read back from the solution, not from the
/// request's list.
///
/// # Errors
///
/// [`RemovalFailure`], describing why no plan could be built.
pub fn plan_removal(
    local: &LocalDatabase,
    universe: &Universe<'_>,
    targets: &[String],
    options: RemovalOptions,
    limits: &Limits,
) -> Result<Plan, RemovalFailure> {
    // `-R` refuses when something still depends on the target. `-Rc` cascades instead, using
    // exactly the relax-and-retry loop conflict resolution already uses.
    let mut request = Request::new().recursive(options.recursive).allow_removals(options.cascade);

    for target in targets {
        // A package first, a `%GROUPS%` group second. That is `remove_target`'s order in
        // `src/pacman/remove.c`, and the same preference `resolve_targets` applies on the
        // install side, so a name that is both means the package in either direction.
        match local.get_str(target).and_then(|_| universe.installed_named(target)) {
            Some(installed) => request = request.remove(installed.id()),
            None => {
                let members = universe.installed_group_members(target);
                if members.is_empty() {
                    return Err(RemovalFailure::NotInstalled(target.clone()));
                }
                for member in members {
                    request = request.remove(member);
                }
            }
        }
    }

    match solve_with_removals(universe, &request, limits) {
        Ok(Ok(planned)) => {
            // `NoCache`, not any caller-supplied cache directories: a removal plan selects no
            // repository candidate at all (verified by
            // `a_removal_plan_is_the_same_with_and_without_repositories`). So the oracle is
            // never consulted, and its download size is zero either way.
            Ok(Plan::assemble(
                universe,
                &planned,
                request.targets(),
                limits,
                &crate::solve::NoCache,
            ))
        }
        Ok(Err(encoded)) => {
            Err(RemovalFailure::WouldBreakSystem(encoded.explain(universe, limits)))
        }
        Err(error) => Err(RemovalFailure::Planner(Box::new(error))),
    }
}

/// The package names `plan_removal`'s removal steps refer to, in plan order.
///
/// This is `alpm_trans_get_remove`: the *prepared* removal list, not the names the user typed.
/// pacman defines a `HoldPkg`-style guard over that same list, which is what makes such a guard
/// fire on a `-Rc` cascade that reaches a held package without naming it.
///
/// A step the universe cannot resolve is skipped rather than reported. This list is meant to
/// feed a guard, and a caller walking the same steps again immediately afterwards gets a real
/// error for that case. Failing twice for one cause would only bury the message that explains
/// it.
#[must_use]
pub fn removal_names(universe: &Universe<'_>, plan: &Plan) -> Vec<String> {
    plan.steps()
        .iter()
        .filter_map(|step| match step {
            Step::Remove { package } => Some(universe.get(*package)?.name().to_string()),
            _ => None,
        })
        .collect()
}
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::config::DbUsage;
    use crate::fixture::{BuiltScenario, PackageSpec, Scenario};
    use crate::solve::UniverseOptions;

    /// The names a plain `-R` of `targets` takes away from `scenario`, sorted.
    fn removed(scenario: &BuiltScenario, targets: &[&str]) -> Result<Vec<String>, RemovalFailure> {
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new(),
        )
        .unwrap();
        let owned: Vec<String> = targets.iter().map(|target| (*target).to_owned()).collect();
        let plan = plan_removal(
            scenario.local(),
            &universe,
            &owned,
            RemovalOptions::default(),
            &Limits::default(),
        )?;

        let mut names = removal_names(&universe, &plan);
        names.sort();
        Ok(names)
    }

    /// "Groups can also be specified to be removed, in which case every package in that group
    /// will be removed" — `pacman(8)`, on `-R`.
    #[test]
    fn a_group_target_removes_every_installed_member() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("editor", "1.0.0-1").groups(["tools"]))
            .installed(PackageSpec::new("linker", "1.0.0-1").groups(["tools"]))
            .installed(PackageSpec::new("unrelated", "1.0.0-1"))
            .build();

        assert_eq!(removed(&scenario, &["tools"]).unwrap(), ["editor", "linker"]);
    }

    /// `remove_target` looks the name up as a package before it looks it up as a group, so a
    /// system carrying both takes away the package alone.
    #[test]
    fn a_package_wins_over_a_group_of_the_same_name() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("tools", "1.0.0-1"))
            .installed(PackageSpec::new("member", "1.0.0-1").groups(["tools"]))
            .build();

        assert_eq!(removed(&scenario, &["tools"]).unwrap(), ["tools"]);
    }

    /// A removal reads the *local* database's groups. A group only a repository defines is
    /// something to install and nothing to remove.
    #[test]
    fn a_group_no_installed_package_belongs_to_is_not_a_target() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("unrelated", "1.0.0-1"))
            .repo("core", [PackageSpec::new("member", "1.0.0-1").groups(["tools"])])
            .build();

        let failure = removed(&scenario, &["tools"]).unwrap_err();
        assert!(matches!(failure, RemovalFailure::NotInstalled(name) if name == "tools"));
    }

    /// `_alpm_remove_pkg` skips a duplicate target rather than refusing it. piko needs no
    /// check of its own: the plan is read back from the solution, so naming a package twice —
    /// as itself and through its group — describes the same removal.
    #[test]
    fn naming_a_group_and_one_of_its_members_removes_each_package_once() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("editor", "1.0.0-1").groups(["tools"]))
            .installed(PackageSpec::new("linker", "1.0.0-1").groups(["tools"]))
            .build();

        assert_eq!(removed(&scenario, &["tools", "editor"]).unwrap(), ["editor", "linker"]);
    }
}
