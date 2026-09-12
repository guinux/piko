//! Expanding a glob target into the package names it selects.
//!
//! A target carrying `*`, `?` or `[` names a pattern rather than a package. Expanding it is a
//! **rewrite of the target list**, and nothing more: what comes back is a list of ordinary
//! names, which the caller then resolves exactly as if the user had typed them. That is what
//! makes `piko install`, `piko plan` and `piko update` agree on a pattern by construction —
//! all three reach the planner through the same rewrite, so none of them can read one
//! differently.
//!
//! The domain is package names and `%GROUPS%` group names, the two things a literal target can
//! already mean. `%PROVIDES%` is deliberately out: a provides name is not something a user
//! installs by name, so selecting one would plan a package whose name the pattern never
//! matched.

use std::collections::BTreeSet;

use crate::glob::{Glob, is_pattern};
use crate::solve::Universe;
use crate::solve::encode::IgnoredTarget;
use crate::{Limits, LocalDatabase};

/// Characters that turn a pattern into a version comparison, and so into a refusal.
///
/// None of them can appear in a package name, so testing for them cannot misread a name.
const VERSION_CHARACTERS: [char; 3] = ['<', '>', '='];

/// What one glob target selected.
#[derive(Clone, Debug)]
pub struct Expansion {
    /// The pattern as the user spelled it.
    pub pattern: String,
    /// The `%GROUPS%` group names the pattern matched, sorted. Each contributed its members to
    /// [`Expansion::names`].
    pub groups: Vec<String>,
    /// Every package name the pattern selected, directly or through a group. Sorted and
    /// de-duplicated, so one database always expands one pattern to one list.
    pub names: Vec<String>,
}

impl Expansion {
    /// Whether the pattern selected no package name, and so nothing that can be targeted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Everything an install-side rewrite produced.
#[derive(Clone, Debug)]
pub struct InstallableTargets {
    /// The rewritten target list: literals in place, each pattern replaced by its names.
    pub names: Vec<String>,
    /// One entry per glob target, in the order the targets were given.
    pub expansions: Vec<Expansion>,
    /// The ignored candidates the patterns passed over. Empty unless `IgnorePkg` or
    /// `IgnoreGroup` covered something a pattern matched.
    pub ignored: Vec<IgnoredTarget>,
}

/// Which set a pattern is expanded against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    /// `install`, `plan` and `update`: names with a candidate that is not already installed,
    /// and the `%GROUPS%` groups those candidates carry.
    Installable,
    /// `remove` and `plan -R`: installed package names, and the `%GROUPS%` groups installed
    /// packages carry.
    Installed,
}

/// Why a glob target could not be expanded.
#[derive(Clone, Debug)]
pub enum ExpansionFailure {
    /// The pattern selected no package name and no group name.
    NoMatch {
        /// The pattern as the user spelled it.
        pattern: String,
        /// Which set it was expanded against, so the message can say where it found nothing.
        side: Side,
    },
    /// The pattern selected more names than [`Limits::glob_max_expansion`] allows.
    ///
    /// Carries no count. The bound stops the scan where it prevents the work, so the total is
    /// never computed — reporting it would mean doing the thing the bound refuses.
    TooBroad {
        /// The pattern as the user spelled it.
        pattern: String,
        /// The bound it passed.
        limit: usize,
    },
    /// Every candidate the pattern selected is covered by `IgnorePkg` or `IgnoreGroup`.
    ///
    /// A different fact from [`ExpansionFailure::NoMatch`], and it calls for a different
    /// action: the pattern is right, and `pacman.conf` says not to touch what it names.
    AllIgnored {
        /// The pattern as the user spelled it.
        pattern: String,
        /// What was passed over for it. Never empty.
        candidates: Vec<IgnoredTarget>,
    },
    /// The pattern also carries a version requirement, such as `python-*>=3.0`.
    ///
    /// Refused rather than guessed at. The string has two honest readings — the names matching
    /// `python-*`, constrained to `>= 3.0`, or the literal pattern `python-*>=3.0` — and
    /// nothing in the target decides between them.
    Versioned(String),
}

/// How a target is read. The one place the pattern rule is applied.
enum Reading {
    /// A name, a dependency string or a soname: resolved as it was typed.
    Literal,
    /// A glob pattern, compiled.
    Pattern(Box<Glob>),
    /// A glob pattern carrying a version requirement, which is refused.
    Versioned,
}

/// Classifies `target`.
///
/// The version test runs *before* the pattern is compiled, so `python-*>=3.0` is refused by its
/// shape rather than expanded into a pattern that matches nothing and reported as "no match" —
/// a message that would be true and useless.
fn read(target: &str) -> Reading {
    if !is_pattern(target) {
        return Reading::Literal;
    }
    if target.contains(VERSION_CHARACTERS) {
        return Reading::Versioned;
    }
    Reading::Pattern(Box::new(Glob::new(target)))
}

/// The names and groups one pattern has selected so far, with the bound applied as they arrive.
struct Selection {
    limit: usize,
    names: BTreeSet<String>,
    groups: BTreeSet<String>,
    overflowed: bool,
}

impl Selection {
    const fn new(limit: usize) -> Self {
        Self { limit, names: BTreeSet::new(), groups: BTreeSet::new(), overflowed: false }
    }

    /// Records `name`. Answers `false` once the bound is passed, so the caller stops scanning.
    ///
    /// A name already recorded costs nothing and never trips the bound: a package carried by
    /// two repositories is one name, not two.
    fn push_name(&mut self, name: &str) -> bool {
        if self.names.contains(name) {
            return true;
        }
        if self.names.len() >= self.limit {
            self.overflowed = true;
            return false;
        }
        self.names.insert(name.to_owned());
        true
    }

    fn push_group(&mut self, group: &str) {
        self.groups.insert(group.to_owned());
    }

    /// The expansion, or the refusal the bound raised while it was built.
    fn finish(self, pattern: &str) -> Result<Expansion, ExpansionFailure> {
        if self.overflowed {
            return Err(ExpansionFailure::TooBroad {
                pattern: pattern.to_owned(),
                limit: self.limit,
            });
        }
        Ok(Expansion {
            pattern: pattern.to_owned(),
            groups: self.groups.into_iter().collect(),
            names: self.names.into_iter().collect(),
        })
    }
}

/// Rewrites `targets`, replacing each pattern with what `select` finds for it.
///
/// A literal target is copied through unchanged and **in place**, so the caller's order is the
/// order it typed. An expansion that found nothing is returned as an empty [`Expansion`] rather
/// than refused here: only the caller knows whether an ignored candidate explains it.
fn expand_all(
    targets: &[String],
    limits: &Limits,
    mut select: impl FnMut(&Glob, &mut Selection),
) -> Result<(Vec<String>, Vec<Expansion>), ExpansionFailure> {
    let mut names: Vec<String> = Vec::new();
    let mut expansions: Vec<Expansion> = Vec::new();
    for target in targets {
        match read(target) {
            Reading::Literal => names.push(target.clone()),
            Reading::Versioned => return Err(ExpansionFailure::Versioned(target.clone())),
            Reading::Pattern(glob) => {
                let mut selection = Selection::new(limits.glob_max_expansion);
                select(&glob, &mut selection);
                let expansion = selection.finish(target)?;
                names.extend(expansion.names.iter().cloned());
                expansions.push(expansion);
            }
        }
    }
    Ok((names, expansions))
}

/// The first pattern that selected nothing, as a refusal.
fn first_empty(expansions: &[Expansion], side: Side) -> Option<ExpansionFailure> {
    expansions
        .iter()
        .find(|expansion| expansion.is_empty())
        .map(|expansion| ExpansionFailure::NoMatch { pattern: expansion.pattern.clone(), side })
}

/// Rewrites `targets` against what an install could select: names with a candidate that is not
/// already installed, and the `%GROUPS%` groups those candidates carry.
///
/// The third return value names the ignored candidates the patterns passed over.
/// [`Universe::ignored`] holds them, and no index does: `IgnorePkg` is applied while candidates
/// are interned, so a scan of the name index alone would drop an ignored package in silence
/// rather than reporting it.
///
/// A pattern that selected only ignored candidates comes back as an empty [`Expansion`] with
/// those candidates listed, rather than as a refusal. Its caller reports "every package
/// matching this is ignored", which is a different fact from "nothing matches it".
///
/// # Errors
///
/// [`ExpansionFailure`], naming the first pattern that could not be expanded.
pub fn expand_installable_targets(
    universe: &Universe<'_>,
    targets: &[String],
    limits: &Limits,
) -> Result<InstallableTargets, ExpansionFailure> {
    let (names, expansions) = expand_all(targets, limits, |glob, selection| {
        for name in universe.installable_names() {
            if glob.matches(name) && !selection.push_name(name) {
                return;
            }
        }
        for group in universe.installable_group_names() {
            if !glob.matches(group) {
                continue;
            }
            selection.push_group(group);
            for id in universe.group_members(group) {
                let Some(member) = universe.get(id) else { continue };
                if !selection.push_name(member.name().as_ref()) {
                    return;
                }
            }
        }
    })?;

    let mut ignored: Vec<IgnoredTarget> = Vec::new();
    for expansion in &expansions {
        let covered = ignored_for(universe, expansion);
        if expansion.is_empty() {
            let pattern = expansion.pattern.clone();
            if covered.is_empty() {
                return Err(ExpansionFailure::NoMatch { pattern, side: Side::Installable });
            }
            return Err(ExpansionFailure::AllIgnored { pattern, candidates: covered });
        }
        ignored.extend(covered);
    }
    Ok(InstallableTargets { names, expansions, ignored })
}

/// The ignored candidates `expansion`'s pattern covers but did not select.
///
/// A candidate matches through its own name or through one of its `%GROUPS%`, the same two
/// ways the expansion itself selects. One already in the expansion is left out: another
/// repository carries a copy that is not ignored, so nothing was passed over.
fn ignored_for(universe: &Universe<'_>, expansion: &Expansion) -> Vec<IgnoredTarget> {
    let glob = Glob::new(&expansion.pattern);
    universe
        .ignored()
        .iter()
        .filter(|candidate| {
            let package = candidate.package();
            let matched = glob.matches(package.name().as_ref())
                || package.groups().iter().any(|group| glob.matches(group.as_ref()));
            matched && !expansion.names.iter().any(|name| name == package.name().as_ref())
        })
        .map(IgnoredTarget::from_candidate)
        .collect()
}

/// [`expand_installable_targets`]' removal counterpart: installed names, and the `%GROUPS%`
/// groups installed packages carry.
///
/// `IgnorePkg` does not apply to a removal — it means "do not upgrade it", not "pretend it is
/// not there" — so nothing is passed over and nothing is reported.
///
/// # Errors
///
/// [`ExpansionFailure`], naming the first pattern that could not be expanded.
pub fn expand_installed_targets(
    universe: &Universe<'_>,
    targets: &[String],
    limits: &Limits,
) -> Result<(Vec<String>, Vec<Expansion>), ExpansionFailure> {
    let (names, expansions) = expand_all(targets, limits, |glob, selection| {
        for name in universe.installed_names() {
            if glob.matches(name) && !selection.push_name(name) {
                return;
            }
        }
        for group in universe.installed_group_names() {
            if !glob.matches(group) {
                continue;
            }
            selection.push_group(group);
            for id in universe.installed_group_members(group) {
                let Some(member) = universe.get(id) else { continue };
                if !selection.push_name(member.name().as_ref()) {
                    return;
                }
            }
        }
    })?;
    if let Some(failure) = first_empty(&expansions, Side::Installed) {
        return Err(failure);
    }
    Ok((names, expansions))
}

/// [`expand_installed_targets`] over the local database alone, with **no** group expansion.
///
/// `piko remove --nodeps` resolves a target with [`LocalDatabase::get_str`] and nothing else, so
/// it has never accepted a group name. A pattern must not become the one spelling that does:
/// the escape hatch stays exactly as narrow with one as without.
///
/// # Errors
///
/// [`ExpansionFailure`], naming the first pattern that could not be expanded.
pub fn expand_installed_names(
    local: &LocalDatabase,
    targets: &[String],
    limits: &Limits,
) -> Result<(Vec<String>, Vec<Expansion>), ExpansionFailure> {
    let (names, expansions) = expand_all(targets, limits, |glob, selection| {
        for package in local.iter() {
            let name = package.name().as_ref();
            if glob.matches(name) && !selection.push_name(name) {
                return;
            }
        }
    })?;
    if let Some(failure) = first_empty(&expansions, Side::Installed) {
        return Err(failure);
    }
    Ok((names, expansions))
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
    use crate::resolve::IgnoreList;
    use crate::solve::UniverseOptions;

    fn universe_of<'a>(scenario: &'a BuiltScenario, ignores: IgnoreList<'a>) -> Universe<'a> {
        Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (DbUsage::ALL, db)),
            UniverseOptions::new().ignores(ignores),
        )
        .unwrap()
    }

    fn owned(targets: &[&str]) -> Vec<String> {
        targets.iter().map(|target| (*target).to_owned()).collect()
    }

    /// Two repository packages sharing a group, one that does not, and one installed package.
    fn scenario() -> BuiltScenario {
        Scenario::new()
            .installed(PackageSpec::new("app-old", "1.0.0-1").groups(["installed-tools"]))
            .repo(
                "core",
                [
                    PackageSpec::new("app-a", "1.0.0-1").groups(["tools"]),
                    PackageSpec::new("app-b", "1.0.0-1").groups(["tools"]),
                    PackageSpec::new("other", "1.0.0-1"),
                ],
            )
            .build()
    }

    #[test]
    fn a_pattern_expands_to_the_names_it_matches_sorted() {
        let scenario = scenario();
        let universe = universe_of(&scenario, IgnoreList::default());
        let expanded =
            expand_installable_targets(&universe, &owned(&["app-*"]), &Limits::default()).unwrap();

        assert_eq!(expanded.names, ["app-a", "app-b"]);
        assert_eq!(expanded.expansions.len(), 1);
        assert_eq!(expanded.expansions[0].pattern, "app-*");
        assert!(expanded.expansions[0].groups.is_empty());
        assert!(expanded.ignored.is_empty());
    }

    /// A literal keeps its position, so the caller's argument order survives the rewrite.
    #[test]
    fn a_literal_target_passes_through_in_place() {
        let scenario = scenario();
        let universe = universe_of(&scenario, IgnoreList::default());
        let expanded =
            expand_installable_targets(&universe, &owned(&["other", "app-*"]), &Limits::default())
                .unwrap();

        assert_eq!(expanded.names, ["other", "app-a", "app-b"]);
        assert_eq!(expanded.expansions.len(), 1, "only the pattern is an expansion");
    }

    #[test]
    fn a_pattern_matching_a_group_name_expands_to_its_members() {
        let scenario = scenario();
        let universe = universe_of(&scenario, IgnoreList::default());
        let expanded =
            expand_installable_targets(&universe, &owned(&["tool*"]), &Limits::default()).unwrap();

        assert_eq!(expanded.expansions[0].groups, ["tools"]);
        assert_eq!(expanded.names, ["app-a", "app-b"]);
    }

    /// A name only the local database carries resolves to nothing, so a pattern must not
    /// select it either.
    #[test]
    fn an_installed_only_name_is_not_installable() {
        let scenario = scenario();
        let universe = universe_of(&scenario, IgnoreList::default());
        let failure =
            expand_installable_targets(&universe, &owned(&["app-o*"]), &Limits::default())
                .unwrap_err();

        assert!(matches!(
            failure,
            ExpansionFailure::NoMatch { ref pattern, side: Side::Installable } if pattern == "app-o*"
        ));
    }

    #[test]
    fn a_removal_pattern_expands_against_installed_names() {
        let scenario = scenario();
        let universe = universe_of(&scenario, IgnoreList::default());
        let (names, expansions) =
            expand_installed_targets(&universe, &owned(&["app-*"]), &Limits::default()).unwrap();

        assert_eq!(names, ["app-old"], "the repository copies are not installed");
        assert_eq!(expansions[0].pattern, "app-*");
    }

    #[test]
    fn a_removal_pattern_expands_an_installed_group_name() {
        let scenario = scenario();
        let universe = universe_of(&scenario, IgnoreList::default());
        let (names, expansions) =
            expand_installed_targets(&universe, &owned(&["installed-*"]), &Limits::default())
                .unwrap();

        assert_eq!(expansions[0].groups, ["installed-tools"]);
        assert_eq!(names, ["app-old"]);
    }

    /// `--nodeps` resolves a target with `LocalDatabase::get_str` alone, so it never accepted a
    /// group name. A pattern does not widen it.
    #[test]
    fn the_nodeps_expansion_never_matches_a_group() {
        let scenario = scenario();
        let (names, _) =
            expand_installed_names(scenario.local(), &owned(&["app-*"]), &Limits::default())
                .unwrap();
        assert_eq!(names, ["app-old"]);

        let failure =
            expand_installed_names(scenario.local(), &owned(&["installed-*"]), &Limits::default())
                .unwrap_err();
        assert!(matches!(failure, ExpansionFailure::NoMatch { .. }));
    }

    /// `IgnorePkg` is applied while candidates are interned, so an ignored one appears in no
    /// index. A pattern must scan the report list too, or it drops the package in silence.
    #[test]
    fn a_pattern_reports_the_ignored_candidates_it_passed_over() {
        let scenario = scenario();
        let ignore_pkg = [String::from("app-b")];
        let universe = universe_of(&scenario, IgnoreList::new(&ignore_pkg, &[]));
        let expanded =
            expand_installable_targets(&universe, &owned(&["app-*"]), &Limits::default()).unwrap();

        assert_eq!(expanded.names, ["app-a"]);
        assert_eq!(expanded.ignored.len(), 1);
        assert_eq!(expanded.ignored[0].name.as_ref(), "app-b");
    }

    /// A pattern every candidate of which is ignored is not "no match". The two call for
    /// opposite actions: one means the pattern is wrong, the other that `pacman.conf` says not
    /// to touch what it names.
    #[test]
    fn a_wholly_ignored_pattern_is_not_reported_as_a_miss() {
        let scenario = scenario();
        let ignore_pkg = [String::from("app-*")];
        let universe = universe_of(&scenario, IgnoreList::new(&ignore_pkg, &[]));
        let failure = expand_installable_targets(&universe, &owned(&["app-*"]), &Limits::default())
            .unwrap_err();

        match failure {
            ExpansionFailure::AllIgnored { pattern, candidates } => {
                assert_eq!(pattern, "app-*");
                assert_eq!(candidates.len(), 2);
            }
            other => panic!("expected AllIgnored, got {other:?}"),
        }
    }

    #[test]
    fn a_pattern_wider_than_the_bound_is_refused() {
        let scenario = scenario();
        let universe = universe_of(&scenario, IgnoreList::default());
        let limits = Limits { glob_max_expansion: 1, ..Limits::default() };
        let failure =
            expand_installable_targets(&universe, &owned(&["app-*"]), &limits).unwrap_err();

        assert!(matches!(
            failure,
            ExpansionFailure::TooBroad { ref pattern, limit: 1 } if pattern == "app-*"
        ));
    }

    #[test]
    fn a_pattern_exactly_at_the_bound_is_accepted() {
        let scenario = scenario();
        let universe = universe_of(&scenario, IgnoreList::default());
        let limits = Limits { glob_max_expansion: 2, ..Limits::default() };
        let expanded = expand_installable_targets(&universe, &owned(&["app-*"]), &limits).unwrap();

        assert_eq!(expanded.names, ["app-a", "app-b"]);
    }

    #[test]
    fn a_versioned_pattern_is_refused_rather_than_expanded() {
        let scenario = scenario();
        let universe = universe_of(&scenario, IgnoreList::default());
        let failure =
            expand_installable_targets(&universe, &owned(&["app-*>=1.0"]), &Limits::default())
                .unwrap_err();

        assert!(
            matches!(failure, ExpansionFailure::Versioned(ref target) if target == "app-*>=1.0")
        );
    }

    /// A version requirement with no metacharacter is an ordinary target, not a refusal.
    #[test]
    fn a_versioned_literal_still_passes_through() {
        let scenario = scenario();
        let universe = universe_of(&scenario, IgnoreList::default());
        let expanded =
            expand_installable_targets(&universe, &owned(&["app-a>=1.0"]), &Limits::default())
                .unwrap();

        assert_eq!(expanded.names, ["app-a>=1.0"]);
        assert!(expanded.expansions.is_empty());
    }
}
