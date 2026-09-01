//! Why an installed package is present: the shortest chain back to an explicit ancestor.
//!
//! `pacman -Qi` reports a "Required By" list, which answers "what would break" but not "why is
//! this here". Following it by hand across five levels is the actual question a user has when
//! they find a package they do not recognise. [`explain_why_installed`] walks the
//! reverse-dependency graph breadth-first from the target, so the chain it returns is the
//! shortest explanation there is.
//!
//! Only `%DEPENDS%` is followed, never `%OPTDEPENDS%`, matching how the rest of the planner
//! treats them: libalpm reports optional dependencies and never resolves them. The verdict
//! therefore agrees with `pacman -Qdtt` rather than `pacman -Qdt`, which counts an optional
//! dependency as requiring. This was measured identical to `-Qdttq` across a real system's
//! such packages. `piko plan -R -s` sweeps by the same rule (`crate::solve::recurse_unneeded`),
//! so the two agree with each other — which matters more than agreeing with whichever `-Qdt`
//! spelling a user reaches for.

use std::collections::{HashMap, HashSet, VecDeque};

use alpm_types::{Name, RelationOrSoname};

use crate::LocalDatabase;
use crate::solve::{Solvable, SolvableId, Universe, UniverseOptions};

/// Why an installed package is present, in increasing order of "nobody meant to keep this".
#[derive(Clone, Debug)]
pub enum WhyResult {
    /// The target itself was installed explicitly — nothing pulled it in.
    Explicit(SolvableId),
    /// The shortest chain from an explicitly-installed package down to the target, root first,
    /// target last.
    Chain(Vec<SolvableId>),
    /// No explicitly-installed package requires the target, directly or indirectly. Carries
    /// whatever installed packages directly depend on it, empty for a leaf with no dependents
    /// at all. The two are different situations: `arrow` required only by `python-pyarrow`,
    /// itself required by nothing, is not the same claim as "nothing requires `arrow`".
    Orphan {
        /// The target itself.
        target: SolvableId,
        /// Installed packages that directly require the target.
        direct: Vec<SolvableId>,
    },
}

/// The reverse-dependency index: for each installed package, every installed package that
/// directly depends on it via `%DEPENDS%`, never `%OPTDEPENDS%` — matching this module's
/// hard-deps-only convention (see the module docs).
///
/// `satisfiers` is indexed, but calling it per query would still be the dominant cost. So
/// both [`explain_why_installed`] and [`orphans`] build this once rather than sharing a cache.
fn required_by_index(universe: &Universe<'_>) -> HashMap<SolvableId, Vec<SolvableId>> {
    let mut required_by: HashMap<SolvableId, Vec<SolvableId>> = HashMap::new();
    for solvable in universe.iter().filter(Solvable::is_installed) {
        // `installed_depends`, not `depends`: the filter above already restricts this to
        // installed packages, whose `%DEPENDS%` is in the eager tier and cannot fail.
        let Some(depends) = solvable.installed_depends() else { continue };
        for dep in depends {
            for satisfier in universe.satisfiers(dep) {
                required_by.entry(satisfier).or_default().push(solvable.id());
            }
        }
    }
    required_by
}

/// Explains why `target` is installed, or `None` if it isn't.
#[must_use]
pub fn explain_why_installed(universe: &Universe<'_>, target: &str) -> Option<WhyResult> {
    let wanted = universe.installed_named(target)?;

    if wanted.install_reason() == Some(alpm_types::PackageInstallReason::Explicit) {
        return Some(WhyResult::Explicit(wanted.id()));
    }

    let required_by = required_by_index(universe);

    // Breadth-first from the target *up* the graph, so the first explicitly-installed
    // package reached gives the shortest chain.
    let mut came_from: HashMap<SolvableId, SolvableId> = HashMap::new();
    let mut seen: HashSet<SolvableId> = HashSet::from([wanted.id()]);
    let mut queue: VecDeque<SolvableId> = VecDeque::from([wanted.id()]);
    let mut root = None;

    while let Some(id) = queue.pop_front() {
        let Some(solvable) = universe.get(id) else { continue };
        let explicit =
            solvable.install_reason() == Some(alpm_types::PackageInstallReason::Explicit);
        if explicit && id != wanted.id() {
            root = Some(id);
            break;
        }
        for dependent in required_by.get(&id).map_or(&[][..], Vec::as_slice) {
            if seen.insert(*dependent) {
                came_from.insert(*dependent, id);
                queue.push_back(*dependent);
            }
        }
    }

    let Some(root) = root else {
        let direct = required_by.get(&wanted.id()).cloned().unwrap_or_default();
        return Some(WhyResult::Orphan { target: wanted.id(), direct });
    };

    // Walk back down the parent links to get root -> ... -> target.
    let mut chain = vec![root];
    let mut cursor = root;
    while let Some(parent) = came_from.get(&cursor) {
        chain.push(*parent);
        cursor = *parent;
    }

    Some(WhyResult::Chain(chain))
}

/// Every installed package with `PackageInstallReason::Depend` that no installed package
/// requires via `%DEPENDS%` — the batch form of [`WhyResult::Orphan`] with an empty `direct`,
/// matching `pacman -Qdttq`. See the module docs for why only hard dependencies count. A
/// package that is only ever someone's `%OPTDEPENDS%` still counts as an orphan here, the
/// same as [`explain_why_installed`] would report.
///
/// Sorted by name, the same order [`crate::LocalDatabase`] iterates in.
#[must_use]
pub fn orphans(universe: &Universe<'_>) -> Vec<SolvableId> {
    let required_by = required_by_index(universe);

    let mut found: Vec<Solvable<'_>> = universe
        .iter()
        .filter(Solvable::is_installed)
        .filter(|solvable| {
            solvable.install_reason() == Some(alpm_types::PackageInstallReason::Depend)
        })
        .filter(|solvable| required_by.get(&solvable.id()).is_none_or(Vec::is_empty))
        .collect();

    found.sort_by_key(Solvable::name);
    found.into_iter().map(|solvable| solvable.id()).collect()
}

/// Every installed package that directly requires a target package, split by how:
/// `required_by` via `%DEPENDS%` (`pacman -Qi`'s "Required By"), `optional_for` via
/// `%OPTDEPENDS%` ("Optional For"). Both are empty, not an error, for a target that is not
/// installed.
#[derive(Clone, Debug, Default)]
pub struct Dependents {
    /// Installed packages whose `%DEPENDS%` requires the target.
    pub required_by: Vec<Name>,
    /// Installed packages whose `%OPTDEPENDS%` names the target.
    pub optional_for: Vec<Name>,
}

/// [`Dependents`] of `target`, among installed packages.
///
/// Builds its own installed-only universe internally — the same scope
/// [`explain_why_installed`]/[`orphans`] already use. So the caller needs nothing but the
/// local database, never `Universe`/`UniverseOptions` directly.
///
/// `optional_for` reuses [`Universe::satisfiers`], the same depcmp machinery `required_by`
/// matches through, rather than a literal name comparison. An `%OPTDEPENDS%` entry carries a
/// full [`alpm_types::PackageRelation`] just like `%DEPENDS%` does, with a description suffix
/// stripped by the parser, and libalpm's own `find_requiredby` (`package.c`) matches both
/// lists identically. `Universe` never resolves `%OPTDEPENDS%` on its own — the planner has
/// no use for it — so this walks [`LocalDatabase::iter`] directly instead of going through a
/// `Solvable` accessor.
///
/// # Errors
///
/// If the local database cannot be scanned.
pub fn dependents(local: &LocalDatabase, target: &str) -> crate::Result<Dependents> {
    let universe = Universe::build(local, [], UniverseOptions::new())?;
    let Some(wanted) = universe.installed_named(target) else {
        return Ok(Dependents::default());
    };

    let required_by = required_by_index(&universe)
        .remove(&wanted.id())
        .unwrap_or_default()
        .iter()
        .filter_map(|id| universe.get(*id).map(|solvable| solvable.name().clone()))
        .collect();

    let mut optional_for = Vec::new();
    for package in local.iter() {
        let Ok(desc) = package.desc() else { continue };
        let requires_target = desc.optional_depends().iter().any(|optdep| {
            let relation = RelationOrSoname::Relation(optdep.package_relation().clone());
            universe.satisfiers(&relation).contains(&wanted.id())
        });
        if requires_target {
            optional_for.push(package.name().clone());
        }
    }

    Ok(Dependents { required_by, optional_for })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use alpm_types::PackageInstallReason;

    use super::*;
    use crate::fixture::{BuiltScenario, PackageSpec, Scenario};
    use crate::solve::UniverseOptions;

    /// The installed set alone, no repositories — the same shape `piko why`/`piko list -o`
    /// build, since orphan status is a question about what's already installed.
    fn universe(scenario: &BuiltScenario) -> Universe<'_> {
        Universe::build(scenario.local(), [], UniverseOptions::new()).unwrap()
    }

    fn names<'a>(universe: &Universe<'a>, ids: &[SolvableId]) -> Vec<&'a str> {
        ids.iter().map(|id| universe.get(*id).unwrap().name().as_ref()).collect()
    }

    #[test]
    fn an_explicitly_installed_package_is_never_an_orphan() {
        let scenario = Scenario::new().installed(PackageSpec::new("foo", "1.0.0-1")).build();
        let universe = universe(&scenario);

        assert!(orphans(&universe).is_empty());
    }

    #[test]
    fn a_dependency_required_by_nothing_is_an_orphan() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("foo", "1.0.0-1").reason(PackageInstallReason::Depend))
            .build();
        let universe = universe(&scenario);

        assert_eq!(names(&universe, &orphans(&universe)), ["foo"]);
    }

    #[test]
    fn a_dependency_required_by_something_installed_is_not_an_orphan() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("foo", "1.0.0-1").reason(PackageInstallReason::Depend))
            .installed(PackageSpec::new("bar", "1.0.0-1").depends(["foo"]))
            .build();
        let universe = universe(&scenario);

        assert!(orphans(&universe).is_empty());
    }

    /// %OPTDEPENDS%` never counts as "required".
    /// A dependency-reason package that is only ever someone's optional
    /// dependency is still reported as an orphan, matching `pacman -Qdtt`, not `-Qdt`.
    #[test]
    fn an_optional_dependency_does_not_save_a_package_from_being_an_orphan() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("foo", "1.0.0-1").reason(PackageInstallReason::Depend))
            .installed(PackageSpec::new("bar", "1.0.0-1").optdepends(["foo: some reason"]))
            .build();
        let universe = universe(&scenario);

        assert_eq!(names(&universe, &orphans(&universe)), ["foo"]);
    }

    #[test]
    fn results_are_sorted_by_name() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("zeta", "1.0.0-1").reason(PackageInstallReason::Depend))
            .installed(PackageSpec::new("alpha", "1.0.0-1").reason(PackageInstallReason::Depend))
            .build();
        let universe = universe(&scenario);

        assert_eq!(names(&universe, &orphans(&universe)), ["alpha", "zeta"]);
    }

    fn as_strs(names: &[Name]) -> Vec<&str> {
        names.iter().map(AsRef::as_ref).collect()
    }

    #[test]
    fn required_by_lists_a_hard_dependent() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("foo", "1.0.0-1"))
            .installed(PackageSpec::new("bar", "1.0.0-1").depends(["foo"]))
            .build();

        let found = dependents(scenario.local(), "foo").unwrap();
        assert_eq!(as_strs(&found.required_by), ["bar"]);
        assert!(found.optional_for.is_empty());
    }

    #[test]
    fn optional_for_lists_an_optional_dependent_but_not_a_required_by() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("foo", "1.0.0-1"))
            .installed(PackageSpec::new("bar", "1.0.0-1").optdepends(["foo: some reason"]))
            .build();

        let found = dependents(scenario.local(), "foo").unwrap();
        assert!(found.required_by.is_empty());
        assert_eq!(as_strs(&found.optional_for), ["bar"]);
    }

    #[test]
    fn dependents_of_an_uninstalled_package_are_both_empty() {
        let scenario = Scenario::new().installed(PackageSpec::new("foo", "1.0.0-1")).build();

        let found = dependents(scenario.local(), "not-installed").unwrap();
        assert!(found.required_by.is_empty());
        assert!(found.optional_for.is_empty());
    }
}
