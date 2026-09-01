//! Resolving a package name to a single sync-repository package, honoring `pacman.conf`'s
//! repository order (priority) and each repository's `Usage` directive.
//!
//! [`SyncRepos::find_literal_satisfier`] mirrors the *literal name* step of libalpm's
//! `resolvedep` (`deps.c`): walk configured repositories in file order — which **is**
//! priority — skipping any whose `Usage` lacks `Install` and `Upgrade`
//! (`db->usage & (ALPM_DB_USAGE_INSTALL|ALPM_DB_USAGE_UPGRADE)`), and return the first exact
//! name match. This is the "a name can legitimately exist in both `core` and `extra`" case —
//! the order-and-gate piece of dependency resolution that stands on its own, ahead of the rest.
//!
//! [`IgnoreList`] additionally applies `pacman.conf`'s `IgnorePkg`/`IgnoreGroup`, matching
//! `alpm_pkg_should_ignore` (`package.c`): a literal match whose name or whose group is
//! ignored is treated as if that repository did not carry it at all, and resolution falls
//! through to the next repository in priority order — the same as libalpm's non-interactive
//! path through `resolvedep` (`prompt == 0`: warn and `continue`, rather than asking
//! `ALPM_QUESTION_INSTALL_IGNOREPKG`), since piko has no prompt machinery. Unlike libalpm,
//! nothing is logged, since `piko-db` never calls a logging macro: a caller cannot currently tell an ignored
//! match from a genuinely absent one, which is fine for `piko resolve`'s "did I get a
//! package back" question but would need a real return value if a future caller needs to
//! explain *why* nothing came back.
//!
//! [`SyncRepos::find_literal_satisfier`] also honors a version constraint, if `dep` carries one
//! (`foo>=1.0`, `foo=1.2.3-1`, ...) — this is `_alpm_depcmp_literal`'s other half in `deps.c`:
//! name equality *and* `dep_vercmp(pkg->version, dep->mod, dep->version)`. Nothing here
//! reimplements comparison or parsing: `PackageRelation`'s `FromStr` impl already splits
//! a dependency string into `name`/`version_requirement` (a bare name yields `None`, matching
//! `ALPM_DEP_MOD_ANY`'s "any version satisfies"), and
//! [`alpm_types::VersionRequirement::is_satisfied_by`] already evaluates the operator — including
//! `dep_vercmp`'s own `parseEVR`-derived rule that a constraint with no `pkgrel` is satisfied by
//! any `pkgrel` of a matching `pkgver`. The only piece piko supplies is converting
//! [`crate::repo::RepoPackage::version`]'s [`alpm_types::FullVersion`] (mandatory `pkgrel`) to the
//! [`alpm_types::Version`] (optional `pkgrel`) `VersionRequirement` compares against — a lossless
//! `From` conversion the crate already provides. A version mismatch is treated exactly like an
//! [`IgnoreList`] mismatch: that repository's match is skipped and resolution falls through to
//! the next repository in priority order, the same as `resolvedep`'s per-db loop does when
//! `_alpm_depcmp_literal` returns false.
//!
//! [`SyncRepos::find_satisfiers`] implements the rest of `resolvedep`'s two-step control flow —
//! including its `%PROVIDES%` step, covering both a soname (`lib:libfoo.so.1`, `libfoo.so=1-64`,
//! ...) and a plain named relation (`provides = python` satisfying a dependency on `python3`) —
//! and returns every match rather than picking one. Real libalpm collects a `providers` list and
//! asks `ALPM_QUESTION_SELECT_PROVIDER` when there is more than one; piko has no prompt
//! machinery (same reasoning as `IgnorePkg`, above), so it returns the whole list and leaves the
//! choice to the caller instead. Two steps, in this exact order, mirroring `resolvedep`
//! (`deps.c`) field-for-field:
//!
//! 1. **Literal match first, and only.** If [`SyncRepos::find_literal_satisfier`] finds a match, that
//!    single package *is* the result — step 2 is not even attempted. This is where "a package
//!    automatically provides its own name and version" comes from: self-satisfaction is
//!    `_alpm_depcmp_literal`, not something a package needs to list in its own `%PROVIDES%`, and
//!    real libalpm's step 1 `return`s immediately on a literal hit before ever looking at
//!    `%PROVIDES%`. Only the earliest-priority repository's literal match is ever considered
//!    here, same as [`SyncRepos::find_literal_satisfier`] alone.
//! 2. **`%PROVIDES%` scan, only if step 1 found nothing usable** (absent everywhere, or every
//!    occurrence was `IgnorePkg`'d or version-mismatched). Unlike step 1, this does not stop at
//!    the first repository: every `Usage`-gated, non-ignored package across *every* configured
//!    repository whose `%PROVIDES%` satisfies `dep` is collected, in repository-then-scan order
//!    — real libalpm's `providers` list, gathered across all `dbs` rather than truncated at the
//!    first hit. A package literally named `dep`'s name is skipped here even when its version
//!    did not satisfy step 1, matching `resolvedep`'s own `pkg->name_hash != dep->name_hash`
//!    guard — a same-named-but-wrong-version package cannot reappear as its own "provider". For
//!    a soname target this step is the *only* one that ever runs (a soname is never a package's
//!    own name), and a `%PROVIDES%` entry counts only if it is
//!    [`alpm_types::RelationOrSoname`]'s derived structural equality with `dep` — the
//!    **alpm-soname** "exact match" rule, no compatible-range notion to evaluate. For a plain
//!    name/version target, a `%PROVIDES%` entry only counts if it is itself an exact-version
//!    provide (`foo=1.2.3`, i.e. `VersionComparison::Equal`) whenever `dep` carries a version
//!    constraint — `_alpm_depcmp_provides` (`deps.c`) never lets an unversioned (or non-`=`)
//!    provide satisfy a versioned dependency, matched here field-for-field.
//!
//! This intentionally does **not** use the `alpm-soname` crate: that crate *extracts* soname
//! data from ELF files (`SONAME`/`NEEDED` fields) to *produce* `%DEPENDS%`/`%PROVIDES%` entries
//! at package-build time (`makepkg`'s `autodeps`); piko is a database reader that only ever
//! *consumes* those entries once a repository has already recorded them as text, so there is no
//! ELF file to scan and nothing for `alpm-soname` to do here.
//!
//! What this module itself does **not** do — conflict/replacement handling, and the
//! already-installed-provider short-circuit real libalpm's `resolvedep` applies before
//! prompting — now lives in [`crate::solve`] instead (`solve::solve_with_removals`/
//! `solve::sysupgrade`, and `solve::universe`'s installed-providers pass), reached through
//! `piko plan`/`piko install`/`piko update`.
//! This module remains the single-query API neither concept belongs in.
//! Other libalpm call sites gate on a
//! different `Usage` mask entirely
//! — `alpm_sync_get_new_version` (`-Qu`, [`crate::LocalDatabase::check_updates`] here) applies no
//! gate at all, and sync.c's `-Su` target collection gates on `Upgrade` alone — so this module
//! intentionally does not become a shared primitive for those; each caller's gate is a distinct
//! policy, not a variation to parameterize away.

use alpm_types::{PackageRelation, RelationOrSoname};

use crate::{
    config::DbUsage,
    depcmp,
    repo::{RepoDatabase, RepoName, RepoPackage},
};

/// The first installed package that satisfies `dep`, if any — `alpm_find_satisfier` (`deps.c`)
/// over the local database.
///
/// The repository-side functions below answer "what could I install"; this answers "what is
/// already here", which is a different question with a different caller. libalpm's hook engine
/// asks it for every `Depends` line of every triggered hook (`hook.c:507`), and it is the only
/// place in piko that needs it.
///
/// # A package with an unreadable `desc` is an error, not a package that provides nothing
///
/// Name and version come from the directory name and are always available, so the *literal*
/// half of `_alpm_depcmp` can always be evaluated. `%PROVIDES%` cannot: it needs `desc`. Rather
/// than treat an unreadable entry as one with no `%PROVIDES%` — which would silently answer
/// "not satisfied" for a dependency that is in fact met — the failure is returned. This is the
/// crate's lazy-loading rule (see [`crate::lazy`]) applied to a question where getting it wrong
/// means skipping a hook the system needed.
///
/// # Errors
///
/// [`crate::SharedError`] if an entry's `desc` cannot be read, and no earlier package satisfied
/// `dep` literally.
pub fn installed_satisfier<'a>(
    local: &'a crate::LocalDatabase,
    dep: &PackageRelation,
) -> std::result::Result<Option<&'a crate::LocalPackage>, crate::SharedError> {
    for package in local.iter() {
        if depcmp::literal_satisfies(package.name(), package.version(), dep) {
            return Ok(Some(package));
        }
        if depcmp::satisfies(package.name(), package.version(), package.desc()?.provides(), dep) {
            return Ok(Some(package));
        }
    }
    Ok(None)
}

/// One configured repository, paired with its opened database.
#[derive(Clone, Copy, Debug)]
pub struct SyncRepo<'a> {
    usage: DbUsage,
    database: &'a RepoDatabase,
}

impl<'a> SyncRepo<'a> {
    /// Pairs an opened database with the `Usage` its `pacman.conf` section configured.
    #[must_use]
    pub const fn new(usage: DbUsage, database: &'a RepoDatabase) -> Self {
        Self { usage, database }
    }
}

/// A package resolved by [`SyncRepos::find_literal_satisfier`]/[`SyncRepos::find_satisfiers`],
/// and which repository it came from.
#[derive(Clone, Copy, Debug)]
pub struct Resolved<'a> {
    repo: &'a RepoName,
    package: &'a RepoPackage,
}

impl<'a> Resolved<'a> {
    /// The repository that provided the match.
    #[must_use]
    pub const fn repo(&self) -> &'a RepoName {
        self.repo
    }

    /// The matched package.
    #[must_use]
    pub const fn package(&self) -> &'a RepoPackage {
        self.package
    }
}

/// `pacman.conf`'s `IgnorePkg`/`IgnoreGroup` lists, each entry a shell-glob pattern matched the
/// same way `alpm_pkg_should_ignore` does (`_alpm_fnmatch`, `package.c`): a package is ignored
/// if its own name matches any `IgnorePkg` pattern, or if any of its `%GROUPS%` matches any
/// `IgnoreGroup` pattern.
///
/// The default (`IgnoreList::default()`, two empty lists) ignores nothing — the same as an
/// absent `IgnorePkg`/`IgnoreGroup` directive.
#[derive(Clone, Copy, Debug, Default)]
pub struct IgnoreList<'a> {
    packages: &'a [String],
    groups: &'a [String],
}

impl<'a> IgnoreList<'a> {
    /// Pairs `pacman.conf`'s `IgnorePkg` and `IgnoreGroup` values (see
    /// [`crate::config::Options::ignore_pkg`]/[`crate::config::Options::ignore_group`]).
    #[must_use]
    pub const fn new(packages: &'a [String], groups: &'a [String]) -> Self {
        Self { packages, groups }
    }

    /// Whether `package` is covered by either list.
    ///
    /// Crate-visible because [`crate::solve::Universe`] applies the same filter when it
    /// interns repository candidates, and two copies of `alpm_pkg_should_ignore` would be
    /// two chances to disagree.
    pub(crate) fn ignores(&self, package: &RepoPackage) -> bool {
        matches_any(self.packages, package.name().as_ref())
            || package.groups().iter().any(|group| matches_any(self.groups, group))
    }
}

/// Whether `patterns` selects `text`, as libalpm's `_alpm_fnmatch_patterns` does (`util.c:1528`).
///
/// # The list is scanned backwards, and a `!` inverts
///
/// Neither is decoration, and the obvious `patterns.iter().any(..)` gets both wrong:
///
/// - A pattern beginning with `!` **de-selects** what it matches. A leading literal `!` or `\`
///   is escaped by a `\`, which is stripped.
/// - The scan runs from the **last** pattern to the first and stops at the first one that
///   matches, so a later entry overrides an earlier one. `pacman.conf(5)` states it directly:
///   "Subsequent matches will override previous ones."
///
/// The two only matter together. With no `!` anywhere, forward-`any` and this agree, which is
/// why the difference went unnoticed while the only callers were `IgnorePkg`/`IgnoreGroup`.
/// It stops being invisible with hook triggers: the "this directory but nothing inside it"
/// idiom is two patterns, the second inverted, and it is what
/// `/usr/share/libalpm/hooks/gtk-update-icon-cache.hook` and `60-depmod.hook` are both built
/// out of on a real Arch system.
///
/// A malformed glob pattern (e.g. an unbalanced `[`) falls back to an exact-string match rather
/// than matching everything or being treated as a parse error — real `fnmatch` has no notion of
/// "invalid pattern" to propagate in the first place, and `IgnorePkg`/`IgnoreGroup` entries are
/// almost always plain names.
///
/// Public because `--overwrite`, `NoExtract`, `NoUpgrade` and a hook's `Target` are the same
/// `fnmatch` against a path rather than a package name, and libalpm uses the one function for
/// all of them. A second copy would be a second chance for these rules to drift.
#[must_use]
pub fn matches_any(patterns: &[String], text: &str) -> bool {
    for pattern in patterns.iter().rev() {
        let inverted = pattern.starts_with('!');
        // `_alpm_fnmatch_patterns` strips one leading character for either sigil: `!` because
        // it was consumed as the inversion marker, `\` because it escapes a literal one.
        let bare = if inverted || pattern.starts_with('\\') {
            pattern.get(1..).unwrap_or_default()
        } else {
            pattern.as_str()
        };
        let hit = glob::Pattern::new(bare).map_or(bare == text, |compiled| compiled.matches(text));
        if hit {
            return !inverted;
        }
    }
    false
}

/// An ordered set of sync repositories — `pacman.conf`'s file order, which **is** repository
/// priority.
#[derive(Clone, Debug, Default)]
pub struct SyncRepos<'a> {
    repos: Vec<SyncRepo<'a>>,
    ignores: IgnoreList<'a>,
}

impl<'a> SyncRepos<'a> {
    /// Builds a priority-ordered set from `repos`, given in `pacman.conf`'s file order.
    /// Ignores nothing until [`Self::with_ignores`] is applied.
    #[must_use]
    pub fn new(repos: impl IntoIterator<Item = SyncRepo<'a>>) -> Self {
        Self { repos: repos.into_iter().collect(), ignores: IgnoreList::default() }
    }

    /// Applies `pacman.conf`'s `IgnorePkg`/`IgnoreGroup` to every subsequent
    /// [`Self::find_literal_satisfier`] call.
    #[must_use]
    pub fn with_ignores(mut self, ignores: IgnoreList<'a>) -> Self {
        self.ignores = ignores;
        self
    }

    /// Finds `dep`'s highest-priority literal match: the first repository, in file order, whose
    /// `Usage` includes `Install` or `Upgrade` and that carries a package named exactly
    /// `dep.name`, satisfying `dep.version_requirement` (if any), and not ignored per
    /// [`Self::with_ignores`]. See the module doc for the libalpm step this mirrors and what it
    /// excludes.
    #[must_use]
    pub fn find_literal_satisfier(&self, dep: &PackageRelation) -> Option<Resolved<'a>> {
        self.repos
            .iter()
            .filter(|repo| {
                repo.usage.contains(DbUsage::INSTALL) || repo.usage.contains(DbUsage::UPGRADE)
            })
            .find_map(|repo| {
                let package = repo.database.get(&dep.name)?;
                // The name matched by construction, so only the version half is left; see
                // `depcmp` for the `_alpm_depcmp_literal` rule both callers share.
                let satisfies = depcmp::version_satisfies(package.version(), dep);
                if !satisfies || self.ignores.ignores(package) {
                    return None;
                }
                Some(Resolved { repo: repo.database.name(), package })
            })
    }

    /// Finds every package satisfying `dep`: [`Self::find_literal_satisfier`] first, and if that
    /// finds nothing usable, every package across every repository whose `%PROVIDES%` satisfies
    /// `dep` — real libalpm's `ALPM_QUESTION_SELECT_PROVIDER` list, without the prompt. See the
    /// module doc for the exact two-step control flow this mirrors. Empty when nothing
    /// satisfies `dep` anywhere.
    #[must_use]
    pub fn find_satisfiers(&self, dep: &RelationOrSoname) -> Vec<Resolved<'a>> {
        if let RelationOrSoname::Relation(relation) = dep
            && let Some(literal) = self.find_literal_satisfier(relation)
        {
            return vec![literal];
        }
        self.find_providers(dep)
    }

    /// The `%PROVIDES%`-based step: every `Usage`-gated, non-ignored, non-literally-named
    /// package across every configured repository whose `%PROVIDES%` satisfies `dep`, in
    /// repository-then-scan order. See [`Self::find_satisfiers`]/the module doc for why a
    /// literally-named package is excluded here regardless of its own version.
    fn find_providers(&self, dep: &RelationOrSoname) -> Vec<Resolved<'a>> {
        self.repos
            .iter()
            .filter(|repo| {
                repo.usage.contains(DbUsage::INSTALL) || repo.usage.contains(DbUsage::UPGRADE)
            })
            .flat_map(|repo| {
                repo.database.iter().filter_map(move |package| {
                    if is_literally_named(dep, package) || self.ignores.ignores(package) {
                        return None;
                    }
                    package
                        .provides()
                        .iter()
                        .any(|provided| depcmp::provides_satisfies(provided, dep))
                        .then(|| Resolved { repo: repo.database.name(), package })
                })
            })
            .collect()
    }
}

/// Whether `package`'s own name is `dep`'s name — the case `resolvedep`'s `%PROVIDES%` step
/// explicitly excludes (`pkg->name_hash != dep->name_hash` in `deps.c`), since self-satisfaction
/// is entirely the literal step's job. Never true for a soname `dep`: a soname is not a package
/// name.
fn is_literally_named(dep: &RelationOrSoname, package: &RepoPackage) -> bool {
    matches!(dep, RelationOrSoname::Relation(relation) if relation.name == *package.name())
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
    use crate::fixture::{BuiltScenario, PackageSpec, RepoFixture, Scenario};

    /// Every repository in `scenario`, gated on `Usage = All`.
    ///
    /// [`Scenario`] deliberately carries no `Usage`: that is a `pacman.conf` policy, not a
    /// property of the packages, and the tests that exercise the gate set it per repository
    /// themselves.
    fn sync_repos(scenario: &BuiltScenario) -> SyncRepos<'_> {
        SyncRepos::new(scenario.repos().iter().map(|db| SyncRepo::new(DbUsage::ALL, db)))
    }

    /// A minimal, valid v2 repository `desc`, with `name`/`version` substituted in.
    fn repo_desc_text(name: &str, version: &str) -> String {
        format!(
            "\
%FILENAME%
{name}-{version}-x86_64.pkg.tar.zst

%NAME%
{name}

%BASE%
{name}

%VERSION%
{version}

%DESC%
An example package

%CSIZE%
1234

%ISIZE%
5678

%SHA256SUM%
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

%ARCH%
x86_64

%BUILDDATE%
1733737242

%PACKAGER%
Foobar McFooface <foobar@mcfooface.org>

"
        )
    }

    fn repo_db(fixture: &RepoFixture, file_name: &str, packages: &[(&str, &str)]) -> RepoDatabase {
        let entries: Vec<(String, Vec<u8>)> = packages
            .iter()
            .map(|(name, version)| {
                (format!("{name}-{version}/desc"), repo_desc_text(name, version).into_bytes())
            })
            .collect();
        let entry_refs: Vec<(&str, &[u8])> =
            entries.iter().map(|(path, content)| (path.as_str(), content.as_slice())).collect();
        let path = fixture.write_gzip_archive(file_name, &entry_refs);
        RepoDatabase::open(path).unwrap()
    }

    /// A single-package repo whose `desc` carries `%GROUPS%`, for [`IgnoreList`]'s group half.
    fn repo_db_with_group(
        fixture: &RepoFixture,
        file_name: &str,
        name: &str,
        version: &str,
        group: &str,
    ) -> RepoDatabase {
        let mut desc = repo_desc_text(name, version);
        desc.push_str(&format!("%GROUPS%\n{group}\n\n"));
        let path = fixture
            .write_gzip_archive(file_name, &[(&format!("{name}-{version}/desc"), desc.as_bytes())]);
        RepoDatabase::open(path).unwrap()
    }

    /// A single-package repo whose `desc` carries `%PROVIDES%`, for soname resolution tests.
    fn repo_db_with_provides(
        fixture: &RepoFixture,
        file_name: &str,
        name: &str,
        version: &str,
        provides: &[&str],
    ) -> RepoDatabase {
        let mut desc = repo_desc_text(name, version);
        desc.push_str("%PROVIDES%\n");
        for entry in provides {
            desc.push_str(entry);
            desc.push('\n');
        }
        desc.push('\n');
        let path = fixture
            .write_gzip_archive(file_name, &[(&format!("{name}-{version}/desc"), desc.as_bytes())]);
        RepoDatabase::open(path).unwrap()
    }

    fn dep(s: &str) -> PackageRelation {
        s.parse().unwrap()
    }

    fn relation(s: &str) -> RelationOrSoname {
        s.parse().unwrap()
    }

    #[test]
    fn finds_a_package_in_the_only_configured_repo() {
        let scenario = Scenario::new().repo("core", [PackageSpec::new("foo", "1.0.0-1")]).build();
        let repos = sync_repos(&scenario);

        let resolved = repos.find_literal_satisfier(&dep("foo")).unwrap();

        assert_eq!(resolved.repo().as_str(), "core");
        assert_eq!(resolved.package().version().to_string(), "1.0.0-1");
    }

    #[test]
    fn the_earlier_listed_repo_wins_when_both_carry_the_name() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("foo", "1.0.0-1")])
            .repo("extra", [PackageSpec::new("foo", "2.0.0-1")])
            .build();
        let repos = sync_repos(&scenario);

        let resolved = repos.find_literal_satisfier(&dep("foo")).unwrap();

        assert_eq!(
            resolved.repo().as_str(),
            "core",
            "the earlier-listed repo must win even though the later one has a newer version"
        );
    }

    #[test]
    fn a_repo_without_install_or_upgrade_usage_is_skipped() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let extra = repo_db(&fixture, "extra.db", &[("foo", "2.0.0-1")]);
        let repos = SyncRepos::new([
            SyncRepo::new(DbUsage::SYNC, &core), // no Install/Upgrade: not a valid target source
            SyncRepo::new(DbUsage::ALL, &extra),
        ]);

        let resolved = repos.find_literal_satisfier(&dep("foo")).unwrap();

        assert_eq!(
            resolved.repo().as_str(),
            "extra",
            "core must be skipped: its Usage lacks Install/Upgrade"
        );
    }

    #[test]
    fn a_repo_with_search_only_usage_still_never_matches() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::SEARCH, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo")).is_none());
    }

    #[test]
    fn returns_none_when_no_repo_has_the_name() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("bar", "1.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo")).is_none());
    }

    #[test]
    fn an_empty_repo_set_matches_nothing() {
        let repos = SyncRepos::new([]);
        assert!(repos.find_literal_satisfier(&dep("foo")).is_none());
    }

    #[test]
    fn without_with_ignores_nothing_is_ignored() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo")).is_some());
    }

    #[test]
    fn a_package_matching_ignore_pkg_is_skipped_in_every_repo_that_carries_it() {
        // Unlike Usage, IgnorePkg matches by name alone — it is global, not per repository, so
        // a name ignored once is ignored everywhere it appears, not just the earliest listing.
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let extra = repo_db(&fixture, "extra.db", &[("foo", "2.0.0-1")]);
        let ignore_pkg = vec!["foo".to_owned()];
        let repos = SyncRepos::new([
            SyncRepo::new(DbUsage::ALL, &core),
            SyncRepo::new(DbUsage::ALL, &extra),
        ])
        .with_ignores(IgnoreList::new(&ignore_pkg, &[]));

        assert!(repos.find_literal_satisfier(&dep("foo")).is_none());
    }

    #[test]
    fn ignore_pkg_does_not_affect_an_unrelated_name() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1"), ("bar", "1.0.0-1")]);
        let ignore_pkg = vec!["foo".to_owned()];
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)])
            .with_ignores(IgnoreList::new(&ignore_pkg, &[]));

        assert!(repos.find_literal_satisfier(&dep("foo")).is_none());
        assert!(repos.find_literal_satisfier(&dep("bar")).is_some());
    }

    #[test]
    fn ignore_pkg_is_matched_as_a_glob_pattern() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo-utils", "1.0.0-1")]);
        let ignore_pkg = vec!["foo-*".to_owned()];
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)])
            .with_ignores(IgnoreList::new(&ignore_pkg, &[]));

        assert!(repos.find_literal_satisfier(&dep("foo-utils")).is_none());
    }

    /// The pattern list, exercised directly rather than through `IgnorePkg`.
    mod fnmatch_patterns {
        use super::super::matches_any;

        fn patterns(list: &[&str]) -> Vec<String> {
            list.iter().map(|entry| (*entry).to_owned()).collect()
        }

        #[test]
        fn a_plain_list_selects_what_it_matches() {
            let list = patterns(&["usr/share/icons/*", "etc/foo.conf"]);
            assert!(matches_any(&list, "usr/share/icons/hicolor"));
            assert!(matches_any(&list, "etc/foo.conf"));
            assert!(!matches_any(&list, "usr/bin/foo"));
        }

        /// The idiom two real hooks on an Arch system are built out of: select a directory,
        /// then de-select everything below it. The whole point is that the second pattern
        /// wins over the first, so a forward `any()` gets it exactly backwards.
        #[test]
        fn an_inverted_pattern_deselects_what_an_earlier_one_selected() {
            let list = patterns(&["usr/share/icons/*", "!usr/share/icons/*/?*"]);

            assert!(matches_any(&list, "usr/share/icons/hicolor"), "the directory itself");
            assert!(
                !matches_any(&list, "usr/share/icons/hicolor/48x48/apps/foo.png"),
                "a file below it was selected; the ! was ignored or the scan ran forwards"
            );
        }

        /// The scan stops at the first pattern that matches, counting from the end, so order
        /// decides the answer. Reversing the same two patterns reverses the verdict.
        #[test]
        fn the_last_matching_pattern_decides() {
            let deny_then_allow = patterns(&["!usr/lib/*", "usr/lib/*"]);
            let allow_then_deny = patterns(&["usr/lib/*", "!usr/lib/*"]);

            assert!(matches_any(&deny_then_allow, "usr/lib/libc.so"));
            assert!(!matches_any(&allow_then_deny, "usr/lib/libc.so"));
        }

        /// A leading literal `!` or `\` is escaped with a backslash, which is stripped before
        /// matching — otherwise a path really called `!odd` could not be named at all.
        #[test]
        fn a_backslash_escapes_a_literal_leading_sigil() {
            assert!(matches_any(&patterns(&[r"\!odd"]), "!odd"));
            assert!(!matches_any(&patterns(&[r"\!odd"]), r"\!odd"));
        }

        /// An empty list selects nothing, which is what an absent directive means.
        #[test]
        fn an_empty_list_selects_nothing() {
            assert!(!matches_any(&[], "anything"));
        }

        /// A pattern `glob` refuses to compile falls back to an exact comparison rather than
        /// matching everything.
        #[test]
        fn a_malformed_pattern_is_compared_literally() {
            let list = patterns(&["foo[bar"]);
            assert!(matches_any(&list, "foo[bar"));
            assert!(!matches_any(&list, "foob"));
        }
    }

    #[test]
    fn a_package_in_an_ignored_group_is_skipped() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("foo", "1.0.0-1").groups(["base-devel"])])
            .build();
        let ignore_group = vec!["base-devel".to_owned()];
        let repos = sync_repos(&scenario).with_ignores(IgnoreList::new(&[], &ignore_group));

        assert!(repos.find_literal_satisfier(&dep("foo")).is_none());
    }

    #[test]
    fn a_package_in_an_unrelated_group_is_not_ignored() {
        let fixture = RepoFixture::new();
        let core = repo_db_with_group(&fixture, "core.db", "foo", "1.0.0-1", "base-devel");
        let ignore_group = vec!["some-other-group".to_owned()];
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)])
            .with_ignores(IgnoreList::new(&[], &ignore_group));

        assert!(repos.find_literal_satisfier(&dep("foo")).is_some());
    }

    #[test]
    fn a_malformed_ignore_pattern_falls_back_to_an_exact_match() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let ignore_pkg = vec!["[unbalanced".to_owned()];
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)])
            .with_ignores(IgnoreList::new(&ignore_pkg, &[]));

        assert!(
            repos.find_literal_satisfier(&dep("foo")).is_some(),
            "an invalid glob must not accidentally ignore an unrelated exact name"
        );
    }

    #[test]
    fn a_bare_name_still_matches_any_version() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo")).is_some());
    }

    #[test]
    fn an_exact_version_constraint_matches_the_same_version() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo=1.0.0-1")).is_some());
    }

    #[test]
    fn an_exact_version_constraint_rejects_a_different_pkgrel() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo=1.0.0-2")).is_none());
    }

    #[test]
    fn an_exact_constraint_with_no_pkgrel_matches_any_pkgrel() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-3")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(
            repos.find_literal_satisfier(&dep("foo=1.0.0")).is_some(),
            "a constraint with no pkgrel must be satisfied regardless of the package's pkgrel, \
             mirroring dep_vercmp/parseEVR"
        );
    }

    #[test]
    fn a_greater_or_equal_constraint_is_satisfied_by_a_newer_version() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "2.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo>=1.0.0-1")).is_some());
    }

    #[test]
    fn a_less_than_constraint_rejects_a_newer_version() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "2.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo<1.0.0-1")).is_none());
    }

    #[test]
    fn a_greater_than_constraint_rejects_the_same_version() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo>1.0.0-1")).is_none());
    }

    #[test]
    fn a_less_than_or_equal_constraint_is_satisfied_by_the_same_version() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo<=1.0.0-1")).is_some());
    }

    #[test]
    fn a_less_than_or_equal_constraint_rejects_a_newer_version() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "2.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo<=1.0.0-1")).is_none());
    }

    #[test]
    fn an_epoch_outranks_a_numerically_lower_pkgver() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1:0.5.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(
            repos.find_literal_satisfier(&dep("foo>=1.0.0-1")).is_some(),
            "epoch 1 must outrank epoch 0's 1.0.0, matching alpm_pkg_vercmp/parseEVR"
        );
    }

    #[test]
    fn a_required_epoch_rejects_a_package_with_no_epoch() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "2.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(
            repos.find_literal_satisfier(&dep("foo>=1:1.0.0-1")).is_none(),
            "a missing epoch defaults to 0, matching parseEVR, so epoch 0's 2.0.0 cannot satisfy \
             an epoch->=1 constraint despite a numerically higher pkgver"
        );
    }

    #[test]
    fn a_version_mismatch_falls_through_to_a_lower_priority_repo_that_satisfies_it() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let extra = repo_db(&fixture, "extra.db", &[("foo", "2.0.0-1")]);
        let repos = SyncRepos::new([
            SyncRepo::new(DbUsage::ALL, &core),
            SyncRepo::new(DbUsage::ALL, &extra),
        ]);

        let resolved = repos.find_literal_satisfier(&dep("foo>=2.0.0-1")).unwrap();

        assert_eq!(
            resolved.repo().as_str(),
            "extra",
            "core's version does not satisfy the constraint"
        );
    }

    #[test]
    fn a_version_mismatch_in_every_repo_resolves_to_nothing() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_literal_satisfier(&dep("foo>=2.0.0-1")).is_none());
    }

    #[test]
    fn find_satisfiers_returns_the_single_literal_match_without_a_provides_scan() {
        let fixture = RepoFixture::new();
        let core = repo_db(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        let matches = repos.find_satisfiers(&relation("foo>=1.0.0-1"));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].repo().as_str(), "core");
        assert_eq!(matches[0].package().name().as_ref(), "foo");
    }

    #[test]
    fn a_literal_match_wins_even_when_another_package_explicitly_provides_the_same_thing() {
        let fixture = RepoFixture::new();
        let core = repo_db_with_provides(&fixture, "core.db", "foo", "1.0.0-1", &["foo=1.0.0-1"]);
        let extra =
            repo_db_with_provides(&fixture, "extra.db", "decoy", "1.0.0-1", &["foo=1.0.0-1"]);
        let repos = SyncRepos::new([
            SyncRepo::new(DbUsage::ALL, &core),
            SyncRepo::new(DbUsage::ALL, &extra),
        ]);

        let matches = repos.find_satisfiers(&relation("foo"));

        assert_eq!(
            matches.len(),
            1,
            "step 1 (literal) returning a match must short-circuit step 2 (provides) entirely"
        );
        assert_eq!(matches[0].package().name().as_ref(), "foo");
    }

    #[test]
    fn a_named_provide_satisfies_a_bare_dependency_with_no_literal_package() {
        let fixture = RepoFixture::new();
        let core =
            repo_db_with_provides(&fixture, "core.db", "libimpl", "1.0.0-1", &["virtual-foo"]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        let matches = repos.find_satisfiers(&relation("virtual-foo"));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].package().name().as_ref(), "libimpl");
    }

    #[test]
    fn an_unversioned_named_provide_does_not_satisfy_a_versioned_dependency() {
        let fixture = RepoFixture::new();
        let core =
            repo_db_with_provides(&fixture, "core.db", "libimpl", "1.0.0-1", &["virtual-foo"]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(
            repos.find_satisfiers(&relation("virtual-foo>=1.0.0")).is_empty(),
            "_alpm_depcmp_provides never lets an unversioned provide satisfy a versioned dependency"
        );
    }

    #[test]
    fn an_exact_versioned_named_provide_satisfies_a_compatible_constraint() {
        let fixture = RepoFixture::new();
        let core = repo_db_with_provides(
            &fixture,
            "core.db",
            "libimpl",
            "1.0.0-1",
            &["virtual-foo=2.0.0"],
        );
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        let matches = repos.find_satisfiers(&relation("virtual-foo>=1.0.0"));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].package().name().as_ref(), "libimpl");
    }

    #[test]
    fn an_exact_versioned_named_provide_rejects_an_incompatible_constraint() {
        let fixture = RepoFixture::new();
        let core = repo_db_with_provides(
            &fixture,
            "core.db",
            "libimpl",
            "1.0.0-1",
            &["virtual-foo=1.0.0"],
        );
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_satisfiers(&relation("virtual-foo>=2.0.0")).is_empty());
    }

    #[test]
    fn a_literally_named_package_is_excluded_from_its_own_provides_scan() {
        let fixture = RepoFixture::new();
        // "foo" is 1.0.0-1, which fails a `>=2.0.0` constraint, but explicitly (and unusually)
        // lists a newer self-provide that would satisfy the same constraint if it were
        // considered — it must not be, matching resolvedep's `pkg->name_hash != dep->name_hash`
        // guard.
        let core = repo_db_with_provides(&fixture, "core.db", "foo", "1.0.0-1", &["foo=3.0.0"]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_satisfiers(&relation("foo>=2.0.0")).is_empty());
    }

    #[test]
    fn multiple_named_providers_across_repos_are_all_returned_in_priority_order() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("impl-a", "1.0.0-1").provides(["virtual-foo"])])
            .repo("extra", [PackageSpec::new("impl-b", "1.0.0-1").provides(["virtual-foo"])])
            .build();
        let repos = sync_repos(&scenario);

        let matches = repos.find_satisfiers(&relation("virtual-foo"));

        let names: Vec<_> =
            matches.iter().map(|resolved| resolved.package().name().as_ref()).collect();
        assert_eq!(names, ["impl-a", "impl-b"]);
    }

    #[test]
    fn a_sonamev2_dependency_is_satisfied_by_an_identical_provide() {
        let fixture = RepoFixture::new();
        let core = repo_db_with_provides(
            &fixture,
            "core.db",
            "example",
            "1.0.0-1",
            &["lib:libexample.so.1"],
        );
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        let matches = repos.find_satisfiers(&relation("lib:libexample.so.1"));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].package().name().as_ref(), "example");
    }

    #[test]
    fn a_sonamev2_dependency_rejects_a_provide_with_a_different_version() {
        let fixture = RepoFixture::new();
        let core = repo_db_with_provides(
            &fixture,
            "core.db",
            "example",
            "1.0.0-1",
            &["lib:libexample.so.1"],
        );
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(
            repos.find_satisfiers(&relation("lib:libexample.so.2")).is_empty(),
            "a soname match must be exact, not compatible-range like a version constraint"
        );
    }

    #[test]
    fn a_sonamev1_dependency_is_satisfied_by_an_identical_provide() {
        let fixture = RepoFixture::new();
        let core = repo_db_with_provides(
            &fixture,
            "core.db",
            "example",
            "1.0.0-1",
            &["example.so=1.0.0-64"],
        );
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        let matches = repos.find_satisfiers(&relation("example.so=1.0.0-64"));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].package().name().as_ref(), "example");
    }

    #[test]
    fn a_sonamev1_request_does_not_match_an_otherwise_equivalent_sonamev2_provide() {
        // Same shared object and version, but a different `alpm-soname` format on each side —
        // the literal `RelationOrSoname` equality this relies on treats them as distinct.
        let fixture = RepoFixture::new();
        let core = repo_db_with_provides(
            &fixture,
            "core.db",
            "example",
            "1.0.0-1",
            &["lib:libexample.so.1"],
        );
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_satisfiers(&relation("libexample.so=1-64")).is_empty());
    }

    #[test]
    fn a_soname_dependency_with_no_matching_provide_resolves_to_nothing() {
        let fixture = RepoFixture::new();
        let core = repo_db_with_provides(&fixture, "core.db", "example", "1.0.0-1", &[]);
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

        assert!(repos.find_satisfiers(&relation("lib:libexample.so.1")).is_empty());
    }

    #[test]
    fn a_repo_without_install_or_upgrade_usage_is_skipped_for_soname_resolution() {
        let fixture = RepoFixture::new();
        let core = repo_db_with_provides(
            &fixture,
            "core.db",
            "example",
            "1.0.0-1",
            &["lib:libexample.so.1"],
        );
        let repos = SyncRepos::new([SyncRepo::new(DbUsage::SEARCH, &core)]);

        assert!(repos.find_satisfiers(&relation("lib:libexample.so.1")).is_empty());
    }

    #[test]
    fn a_soname_provider_matching_ignore_pkg_is_excluded_while_the_other_remains() {
        let fixture = RepoFixture::new();
        let core = repo_db_with_provides(
            &fixture,
            "core.db",
            "example",
            "1.0.0-1",
            &["lib:libexample.so.1"],
        );
        let extra = repo_db_with_provides(
            &fixture,
            "extra.db",
            "other-example",
            "1.0.0-1",
            &["lib:libexample.so.1"],
        );
        let ignore_pkg = vec!["example".to_owned()];
        let repos = SyncRepos::new([
            SyncRepo::new(DbUsage::ALL, &core),
            SyncRepo::new(DbUsage::ALL, &extra),
        ])
        .with_ignores(IgnoreList::new(&ignore_pkg, &[]));

        let matches = repos.find_satisfiers(&relation("lib:libexample.so.1"));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].package().name().as_ref(), "other-example");
    }

    #[test]
    fn multiple_soname_providers_across_repos_are_all_returned_in_priority_order() {
        let fixture = RepoFixture::new();
        let core = repo_db_with_provides(
            &fixture,
            "core.db",
            "example",
            "1.0.0-1",
            &["lib:libexample.so.1"],
        );
        let extra = repo_db_with_provides(
            &fixture,
            "extra.db",
            "other-example",
            "2.0.0-1",
            &["lib:libexample.so.1"],
        );
        let repos = SyncRepos::new([
            SyncRepo::new(DbUsage::ALL, &core),
            SyncRepo::new(DbUsage::ALL, &extra),
        ]);

        let matches = repos.find_satisfiers(&relation("lib:libexample.so.1"));

        let names: Vec<_> =
            matches.iter().map(|resolved| resolved.package().name().as_ref()).collect();
        assert_eq!(names, ["example", "other-example"]);
    }
}
