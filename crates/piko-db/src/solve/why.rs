//! Why an installed package is present: the shortest chain back to an explicit ancestor.
//!
//! `pacman -Qi` reports a "Required By" list, which answers "what would break" but not "why is
//! this here". A user who finds a package they do not recognise is asking the second question.
//! Following "Required By" by hand across five levels is what that costs them.
//! [`explain_why_installed`] walks the
//! reverse-dependency graph breadth-first from the target, so the chain it returns is the
//! shortest explanation there is.
//!
//! Only `%DEPENDS%` is followed, never `%OPTDEPENDS%`. That matches how the rest of the
//! planner treats them, since libalpm reports optional dependencies and never resolves them.
//! The verdict therefore agrees with `pacman -Qdtt` rather than `pacman -Qdt`, which counts an
//! optional dependency as requiring. This measures identical to `-Qdttq` across a real system's
//! such packages. `piko plan -R -s` sweeps by the same rule (`crate::solve::recurse_unneeded`),
//! so the two agree with each other. That matters more than agreeing with whichever `-Qdt`
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
    /// at all. The two are different situations. `arrow` required only by `python-pyarrow`,
    /// itself required by nothing, is not the same claim as "nothing requires `arrow`".
    Orphan {
        /// The target itself.
        target: SolvableId,
        /// Installed packages that directly require the target.
        direct: Vec<SolvableId>,
    },
}

/// The reverse-dependency index. For each installed package, it holds every installed package
/// that directly depends on it via `%DEPENDS%`, never `%OPTDEPENDS%`. That matches this
/// module's hard-deps-only convention (see the module docs).
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
                // A dependent is listed once, however many of its `%DEPENDS%` entries the
                // target satisfies. A package naming both `gtk3` and `libgtk-3.so` is one
                // dependent, not two. libalpm's `find_requiredby` (`package.c`) guards the
                // same push with `alpm_list_find_str`.
                let dependents = required_by.entry(satisfier).or_default();
                if !dependents.contains(&solvable.id()) {
                    dependents.push(solvable.id());
                }
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
/// requires via `%DEPENDS%`. This is the batch form of [`WhyResult::Orphan`] with an empty
/// `direct`, matching `pacman -Qdttq`.
///
/// See the module docs for why only hard dependencies count. A package that is only ever
/// someone's `%OPTDEPENDS%` still counts as an orphan here, the same as
/// [`explain_why_installed`] would report.
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

/// Every installed package that directly requires a target package, split by how. `required_by`
/// holds those requiring it via `%DEPENDS%` (`pacman -Qi`'s "Required By"). `optional_for`
/// holds those naming it in `%OPTDEPENDS%` ("Optional For").
///
/// Both are empty, not an error, for a target that is not installed.
#[derive(Clone, Debug, Default)]
pub struct Dependents {
    /// Installed packages whose `%DEPENDS%` requires the target.
    pub required_by: Vec<Name>,
    /// Installed packages whose `%OPTDEPENDS%` names the target.
    pub optional_for: Vec<Name>,
    /// What could not be read while `optional_for` was built: a package whose `desc` is
    /// unreadable, or one invalid `%OPTDEPENDS%` line. Each may name the target, so
    /// `optional_for` is complete only when this is empty.
    pub unread: Vec<Unread>,
}

/// An installed package, or one line of it, that [`dependents`] could not read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unread {
    /// The package.
    pub package: Name,
    /// Why it could not be read.
    pub reason: String,
}

/// [`Dependents`] of `target`, among installed packages.
///
/// This builds a [`DependentsIndex`] and asks it once. A caller with more than one target builds
/// the index itself, and asks it for each: the build reads the whole installed set.
///
/// # Errors
///
/// If the local database cannot be scanned.
pub fn dependents(local: &LocalDatabase, target: &str) -> crate::Result<Dependents> {
    Ok(DependentsIndex::build(local)?.get(target))
}

/// The [`Dependents`] of every installed package, computed in one pass over the installed set.
///
/// `pacman -Qi` asks "Required By" and "Optional For" of every package it shows, and each
/// answer reads every installed package. Built once, the index answers each package with a
/// lookup: `piko info` over a whole system then reads the installed set once rather than once
/// per package.
///
/// It builds an installed-only universe, the same scope [`explain_why_installed`] and
/// [`orphans`] use. So the caller needs nothing but the local database, never
/// `Universe`/`UniverseOptions` directly.
///
/// `optional_for` reuses [`Universe::satisfiers`], the same depcmp machinery `required_by`
/// matches through, rather than a literal name comparison. An `%OPTDEPENDS%` entry carries a
/// full [`alpm_types::PackageRelation`] just like `%DEPENDS%` does, with a description suffix
/// stripped by the parser. libalpm's own `find_requiredby` (`package.c`) matches both lists
/// identically. `Universe` never resolves `%OPTDEPENDS%` on its own, because the planner has no
/// use for it. So this walks [`LocalDatabase::iter`] directly instead of going through a
/// `Solvable` accessor.
#[derive(Clone, Debug, Default)]
pub struct DependentsIndex {
    /// Every installed package, by name, with what requires it and what names it optionally.
    ///
    /// Keyed by the name's text, so [`Self::get`] looks a `&str` up without parsing it.
    by_target: HashMap<String, (Vec<Name>, Vec<Name>)>,
    /// What could not be read while the optional dependents were collected.
    unread: Vec<Unread>,
}

impl DependentsIndex {
    /// Reads the dependents of every installed package in `local`.
    ///
    /// # Errors
    ///
    /// If the local database cannot be scanned.
    pub fn build(local: &LocalDatabase) -> crate::Result<Self> {
        let universe = Universe::build(local, [], UniverseOptions::new())?;

        let mut by_target: HashMap<String, (Vec<Name>, Vec<Name>)> = universe
            .iter()
            .filter(Solvable::is_installed)
            .map(|solvable| (solvable.name().to_string(), (Vec::new(), Vec::new())))
            .collect();

        // `required_by_index` lists each target's dependents in installed-set order, and each
        // once.
        let name_of = |id: &SolvableId| universe.get(*id).map(|solvable| solvable.name().clone());
        for (target, dependents) in required_by_index(&universe) {
            let Some(target) = name_of(&target) else { continue };
            if let Some((required_by, _)) = by_target.get_mut(target.as_ref()) {
                required_by.extend(dependents.iter().filter_map(name_of));
            }
        }

        let mut unread = Vec::new();
        for package in local.iter() {
            let desc = match package.desc() {
                Ok(desc) => desc,
                Err(error) => {
                    unread.push(Unread {
                        package: package.name().clone(),
                        reason: error.to_string(),
                    });
                    continue;
                }
            };
            // A package is listed once for a target, however many of its `%OPTDEPENDS%`
            // entries that target satisfies.
            let mut targets: Vec<SolvableId> = Vec::new();
            for optdep in desc.optional_depends_each() {
                match optdep {
                    Ok(optdep) => {
                        let relation =
                            RelationOrSoname::Relation(optdep.package_relation().clone());
                        for satisfier in universe.satisfiers(&relation) {
                            if !targets.contains(&satisfier) {
                                targets.push(satisfier);
                            }
                        }
                    }
                    Err(error) => {
                        unread.push(Unread {
                            package: package.name().clone(),
                            reason: error.to_string(),
                        });
                    }
                }
            }
            for target in targets.iter().filter_map(name_of) {
                if let Some((_, optional_for)) = by_target.get_mut(target.as_ref()) {
                    optional_for.push(package.name().clone());
                }
            }
        }

        Ok(Self { by_target, unread })
    }

    /// The [`Dependents`] of `target`: both lists empty, and nothing unread, for a target that
    /// is not installed.
    #[must_use]
    pub fn get(&self, target: &str) -> Dependents {
        let Some((required_by, optional_for)) = self.by_target.get(target) else {
            return Dependents::default();
        };
        Dependents {
            required_by: required_by.clone(),
            optional_for: optional_for.clone(),
            unread: self.unread.clone(),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
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

    /// A dependent that names the target twice — once by name, once by a soname it provides —
    /// is one entry, not two.
    #[test]
    fn a_dependent_matching_several_depends_entries_is_listed_once() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("foo", "1.0.0-1").provides(["libfoo.so=1-64"]))
            .installed(PackageSpec::new("bar", "1.0.0-1").depends(["foo", "libfoo.so=1-64"]))
            .build();

        let found = dependents(scenario.local(), "foo").unwrap();
        assert_eq!(as_strs(&found.required_by), ["bar"]);
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
        assert!(found.unread.is_empty());
    }

    /// An invalid `%OPTDEPENDS%` line costs that line alone, and is named.
    #[test]
    fn optional_for_reads_past_an_invalid_line_and_names_it() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("foo", "1.0.0-1"))
            .installed(PackageSpec::new("bar", "1.0.0-1").optdepends(["bad>", "foo: some reason"]))
            .build();

        let found = dependents(scenario.local(), "foo").unwrap();
        assert_eq!(as_strs(&found.optional_for), ["bar"]);
        assert_eq!(found.unread.len(), 1, "{:?}", found.unread);
        assert!(
            found.unread.first().is_some_and(
                |entry| entry.package.as_ref() == "bar" && entry.reason.contains("bad>")
            )
        );
    }

    /// A package whose `desc` cannot be read is named, since it may name the target.
    #[test]
    fn optional_for_names_a_package_whose_desc_is_unreadable() {
        let db = crate::fixture::DbFixture::new();
        db.package("foo-1.0.0-1").with_defaults().build();
        let broken = crate::fixture::MINIMAL_DESC_V1
            .replacen("%NAME%\nfoo", "%NAME%\nbaz", 1)
            .replacen("%ARCH%\nx86_64", "%ARCH%\nnot an arch", 1);
        db.package("baz-1.0.0-1").desc(&broken).files(crate::fixture::MINIMAL_FILES).build();
        let local = LocalDatabase::open(db.path()).unwrap();

        let found = dependents(&local, "foo").unwrap();
        let unread: Vec<&str> = found.unread.iter().map(|entry| entry.package.as_ref()).collect();
        assert_eq!(unread, ["baz"], "{:?}", found.unread);
    }

    /// The dependents of `target` computed alone, by a scan of the whole installed set: the
    /// reference [`DependentsIndex`] must agree with for every package.
    fn one_by_one(local: &LocalDatabase, target: &str) -> Dependents {
        let universe = Universe::build(local, [], UniverseOptions::new()).unwrap();
        let Some(wanted) = universe.installed_named(target) else {
            return Dependents::default();
        };
        let required_by = required_by_index(&universe)
            .remove(&wanted.id())
            .unwrap_or_default()
            .iter()
            .filter_map(|id| universe.get(*id).map(|solvable| solvable.name().clone()))
            .collect();
        let mut optional_for = Vec::new();
        let mut unread = Vec::new();
        for package in local.iter() {
            let Ok(desc) = package.desc() else {
                unread.push(package.name().clone());
                continue;
            };
            let mut requires_target = false;
            for optdep in desc.optional_depends_each() {
                match optdep {
                    Ok(optdep) => {
                        let relation =
                            RelationOrSoname::Relation(optdep.package_relation().clone());
                        requires_target |= universe.satisfiers(&relation).contains(&wanted.id());
                    }
                    Err(_) => unread.push(package.name().clone()),
                }
            }
            if requires_target {
                optional_for.push(package.name().clone());
            }
        }
        let unread =
            unread.into_iter().map(|package| Unread { package, reason: String::new() }).collect();
        Dependents { required_by, optional_for, unread }
    }

    /// One index answers every package as a scan for that package alone does: the same
    /// dependents in the same order, through names, `%PROVIDES%`, sonames and version
    /// constraints, each dependent once.
    #[test]
    fn the_index_agrees_with_a_scan_per_package() {
        let scenario =
            Scenario::new()
                .installed(PackageSpec::new("lib", "2.0.0-1").provides(["libfoo.so=1-64", "virt"]))
                .installed(PackageSpec::new("old", "1.0.0-1"))
                .installed(
                    PackageSpec::new("app", "1.0.0-1")
                        .depends(["lib", "libfoo.so=1-64"])
                        .optdepends(["virt: extras", "old>=2: too new", "lib: again"]),
                )
                .installed(PackageSpec::new("tool", "1.0.0-1").depends(["virt", "old"]))
                .installed(PackageSpec::new("extra", "1.0.0-1").optdepends(["bad>", "tool: x"]))
                .build();
        let local = scenario.local();
        let index = DependentsIndex::build(local).unwrap();

        for name in ["lib", "old", "app", "tool", "extra", "absent"] {
            let (indexed, scanned) = (index.get(name), one_by_one(local, name));
            assert_eq!(as_strs(&indexed.required_by), as_strs(&scanned.required_by), "{name}");
            assert_eq!(as_strs(&indexed.optional_for), as_strs(&scanned.optional_for), "{name}");
            let unread = |found: &Dependents| {
                found.unread.iter().map(|entry| entry.package.to_string()).collect::<Vec<_>>()
            };
            assert_eq!(unread(&indexed), unread(&scanned), "{name}");
        }
        assert_eq!(as_strs(&index.get("lib").required_by), ["app", "tool"]);
        assert_eq!(as_strs(&index.get("lib").optional_for), ["app"]);
        assert!(index.get("old").optional_for.is_empty(), "old>=2 is not met by old 1.0.0-1");
    }

    #[test]
    fn dependents_of_an_uninstalled_package_are_both_empty() {
        let scenario = Scenario::new().installed(PackageSpec::new("foo", "1.0.0-1")).build();

        let found = dependents(scenario.local(), "not-installed").unwrap();
        assert!(found.required_by.is_empty());
        assert!(found.optional_for.is_empty());
    }
}
