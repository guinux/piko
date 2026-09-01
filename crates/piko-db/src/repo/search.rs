//! Ranking a repository database's packages against one or more free-text search terms.
//!
//! See [`crate::search`] for [`MatchKind`] itself and the equivalent local-database
//! implementation this mirrors.

use alpm_types::RelationOrSoname;

use super::package::RepoPackage;
use crate::search::MatchKind;

/// One package that matched a search query, together with why it matched.
///
/// See [`super::RepoDatabase::search`].
pub type SearchHit<'a> = (&'a RepoPackage, MatchKind);

/// Scores every package in `packages` against `terms`, returning only those that matched
/// **every** term.
///
/// Comparisons are case-insensitive. Blank (or all-whitespace) terms are dropped. If nothing
/// is left after that — an empty `terms`, or every term blank — nothing matches. "No term" is
/// never treated as an automatic pass. Each package appears at most once, scored by the single
/// highest [`MatchKind`] any one of its (all-matching) terms achieved. The AND requirement
/// above already guarantees every term matched *something*, so this score is purely a ranking
/// signal: a package that matches one term exactly stays ranked at [`MatchKind::ExactName`]
/// even if a second term only matched its description. Results are sorted most-relevant-first,
/// then by name to break ties deterministically.
pub(crate) fn search<'a, 'q>(
    packages: &'a [RepoPackage],
    terms: impl IntoIterator<Item = &'q str>,
) -> Vec<SearchHit<'a>> {
    let terms: Vec<String> = terms
        .into_iter()
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
        .collect();
    if terms.is_empty() {
        return Vec::new();
    }

    let mut hits: Vec<SearchHit<'a>> = packages
        .iter()
        .filter_map(|package| combined_match(package, &terms).map(|kind| (package, kind)))
        .collect();

    hits.sort_by(|(left, left_kind), (right, right_kind)| {
        right_kind.cmp(left_kind).then_with(|| left.name().cmp(right.name()))
    });
    hits
}

/// The best [`MatchKind`] achieved across `terms`, if `package` matches every one of them.
///
/// `terms` must already be trimmed, lowercased, and non-empty. Returns `None` as soon as any
/// term fails to match at all — the AND requirement — without evaluating the remaining terms.
///
/// The package's own lowercased text is built **here**, once, rather than inside
/// [`best_match`] per term. Matching is case-insensitive, so lowercasing the name, every
/// `%PROVIDES%` entry, the description, and every group once per (package, term) pair would
/// allocate `terms.len()` times more than the search needs. On the real `extra` repository
/// (about 15 000 packages), a three-term search allocates a third as much this way.
fn combined_match(package: &RepoPackage, terms: &[String]) -> Option<MatchKind> {
    let name = package.name().as_ref().to_lowercase();

    // An exact name match outranks everything and needs nothing from `desc`. A search whose
    // every term hits the name never builds a `Searchable`.
    let searchable =
        (!terms.iter().all(|term| *term == name)).then(|| Searchable::from_package(package));

    let mut best: Option<MatchKind> = None;
    for term in terms {
        let kind = best_match(&name, searchable.as_ref(), term)?;
        best = Some(best.map_or(kind, |current| current.max(kind)));
    }
    best
}

/// A package's searchable `desc` text, lowercased once.
struct Searchable {
    provides: Vec<String>,
    description: String,
    groups: Vec<String>,
}

impl Searchable {
    fn from_package(package: &RepoPackage) -> Self {
        Self {
            // Only `Relation` entries carry a package name to match against. A `%PROVIDES%`
            // soname is not one and is never matched here.
            provides: package
                .provides()
                .iter()
                .filter_map(|provide| match provide {
                    RelationOrSoname::Relation(relation) => {
                        Some(relation.name.as_ref().to_lowercase())
                    }
                    _ => None,
                })
                .collect(),
            // `%PROVIDES%` and `%GROUPS%` are free. `%DESC%` is one of the deferred fields, so
            // searching descriptions is what forces the full parse. A package whose deferred
            // `desc` will not parse stays searchable by name, provides, and groups rather than
            // dropping out of results entirely. The failure is not swallowed: `RepoPackage::desc`
            // still returns it, cached, on every access. A load failure must always surface on
            // access and never look like an empty result — this is that rule at work. `search`
            // itself has no channel to report the failure through; that is the caller's job.
            description: package
                .desc()
                .map(|desc| desc.description().as_ref().to_lowercase())
                .unwrap_or_default(),
            groups: package.groups().iter().map(|group| group.to_lowercase()).collect(),
        }
    }
}

/// The single highest-ranked way a package matches `query`, if any.
///
/// `name`, `query`, and everything in `searchable` must already be trimmed and lowercased.
/// `searchable` is `None` only when the caller already knows `name == query` for every term.
/// That case outranks anything `desc` could contribute.
fn best_match(name: &str, searchable: Option<&Searchable>, query: &str) -> Option<MatchKind> {
    if name == query {
        // Nothing else could outrank this, so `desc` needs no inspection.
        return Some(MatchKind::ExactName);
    }

    let searchable = searchable?;

    [
        searchable
            .provides
            .iter()
            .any(|provide| provide == query)
            .then_some(MatchKind::ExactProvides),
        name.starts_with(query).then_some(MatchKind::NameStartsWith),
        name.contains(query).then_some(MatchKind::NameContains),
        searchable.description.contains(query).then_some(MatchKind::DescriptionContains),
        searchable.groups.iter().any(|group| group == query).then_some(MatchKind::ExactGroup),
    ]
    .into_iter()
    .flatten()
    .max()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::sync::Arc;

    use super::{
        super::{eager, package::FilesSource, repo_name::RepoName},
        *,
    };
    use crate::{entry_name::EntryName, limits::Limits};

    /// Builds a package the way [`super::super::database`] does: eager fields parsed now, and
    /// the text retained for the deferred parse. Going through the real path keeps these tests
    /// honest about which accessor is free and which one loads.
    fn package(name: &str, desc_text: &str) -> RepoPackage {
        let entry = EntryName::parse(&format!("{name}-1.0.0-1")).unwrap();
        let eager = eager::parse(desc_text).unwrap();
        let files =
            Arc::new(FilesSource::unavailable(RepoName::parse("test").unwrap(), Limits::default()));
        RepoPackage::new(entry, eager, desc_text.into(), files)
    }

    /// Scores one package against one query, the way [`combined_match`] would.
    ///
    /// This does the lowercasing `combined_match` hoists, so these tests keep exercising the
    /// tier logic itself rather than the caching around it. `query` is lowercased here because
    /// `search` guarantees that of every term it passes down.
    fn best_match_of(package: &RepoPackage, query: &str) -> Option<MatchKind> {
        let name = package.name().as_ref().to_lowercase();
        let searchable = Searchable::from_package(package);
        best_match(&name, Some(&searchable), &query.to_lowercase())
    }

    /// A minimal, valid v2 `desc` — no `%MD5SUM%` — with `name`/`description` substituted in,
    /// and optional `%PROVIDES%`/`%GROUPS%` sections appended.
    fn desc_text(name: &str, description: &str, extra: &str) -> String {
        format!(
            "\
%FILENAME%
{name}-1.0.0-1-x86_64.pkg.tar.zst

%NAME%
{name}

%BASE%
{name}

%VERSION%
1.0.0-1

%DESC%
{description}

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

{extra}"
        )
    }

    #[test]
    fn exact_name_outranks_everything_else() {
        let text = desc_text("foo", "unrelated text", "%PROVIDES%\nfoo\n\n");
        let pkg = package("foo", &text);

        assert_eq!(best_match_of(&pkg, "foo"), Some(MatchKind::ExactName));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let text = desc_text("foo", "unrelated", "");
        let packages = [package("foo", &text)];

        let hits = search(&packages, ["FOO"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::ExactName));
    }

    #[test]
    fn exact_provides_outranks_name_prefix() {
        // "foobar" starts with "foo" (NameStartsWith), but also exactly provides "foo". The
        // exact-provides match must win.
        let text = desc_text("foobar", "unrelated", "%PROVIDES%\nfoo\n\n");
        let pkg = package("foobar", &text);

        assert_eq!(best_match_of(&pkg, "foo"), Some(MatchKind::ExactProvides));
    }

    #[test]
    fn name_starts_with_outranks_name_contains() {
        let text = desc_text("foobar", "unrelated", "");
        let pkg = package("foobar", &text);

        assert_eq!(best_match_of(&pkg, "foo"), Some(MatchKind::NameStartsWith));
    }

    #[test]
    fn name_contains_is_found_mid_string() {
        let text = desc_text("libfoobar", "unrelated", "");
        let pkg = package("libfoobar", &text);

        assert_eq!(best_match_of(&pkg, "foo"), Some(MatchKind::NameContains));
    }

    #[test]
    fn description_contains_is_the_fallback() {
        let text = desc_text("bar", "a package about foo things", "");
        let pkg = package("bar", &text);

        assert_eq!(best_match_of(&pkg, "foo"), Some(MatchKind::DescriptionContains));
    }

    #[test]
    fn exact_group_matches_but_ranks_lowest() {
        let text = desc_text("bar", "unrelated", "%GROUPS%\nfoo\n\n");
        let pkg = package("bar", &text);

        assert_eq!(best_match_of(&pkg, "foo"), Some(MatchKind::ExactGroup));
    }

    #[test]
    fn a_group_substring_is_not_a_match() {
        let text = desc_text("bar", "unrelated", "%GROUPS%\nfoobar\n\n");
        let pkg = package("bar", &text);

        assert_eq!(best_match_of(&pkg, "foo"), None);
    }

    #[test]
    fn no_match_returns_none() {
        let text = desc_text("bar", "unrelated", "");
        let pkg = package("bar", &text);

        assert_eq!(best_match_of(&pkg, "zzz"), None);
    }

    #[test]
    fn search_ignores_a_blank_query() {
        let text = desc_text("foo", "unrelated", "");
        let packages = [package("foo", &text)];

        assert!(search(&packages, ["   "]).is_empty());
    }

    #[test]
    fn search_ignores_an_empty_term_list() {
        let text = desc_text("foo", "unrelated", "");
        let packages = [package("foo", &text)];

        assert!(search(&packages, []).is_empty());
    }

    #[test]
    fn search_drops_blank_terms_from_a_mixed_list() {
        let text = desc_text("foo", "unrelated", "");
        let packages = [package("foo", &text)];

        let hits = search(&packages, ["foo", "  "]);
        assert_eq!(hits.first().map(|(pkg, _)| pkg.name().as_ref()), Some("foo"));
    }

    #[test]
    fn search_sorts_most_relevant_first_then_by_name() {
        let exact = package("foo", &desc_text("foo", "unrelated", ""));
        let prefix_b = package("foobar", &desc_text("foobar", "unrelated", ""));
        let prefix_a = package("fooalpha", &desc_text("fooalpha", "unrelated", ""));
        let packages = [prefix_b, exact, prefix_a];

        let hits = search(&packages, ["foo"]);
        let names: Vec<&str> = hits.iter().map(|(pkg, _)| pkg.name().as_ref()).collect();

        assert_eq!(names, ["foo", "fooalpha", "foobar"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::ExactName));
    }

    #[test]
    fn search_skips_packages_with_no_match() {
        let matching = package("foo", &desc_text("foo", "unrelated", ""));
        let not_matching = package("bar", &desc_text("bar", "unrelated", ""));
        let packages = [matching, not_matching];

        let hits = search(&packages, ["foo"]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits.first().map(|(pkg, _)| pkg.name().as_ref()), Some("foo"));
    }

    #[test]
    fn search_requires_every_term_to_match() {
        // Matches "foo" (name) but not "zzz" anywhere. Must be excluded.
        let partial = package("foo", &desc_text("foo", "unrelated", ""));
        // Matches both "foo" (name) and "bar" (description).
        let full = package("foobase", &desc_text("foobase", "something about bar", ""));
        let packages = [partial, full];

        let hits = search(&packages, ["foo", "bar"]);
        let names: Vec<&str> = hits.iter().map(|(pkg, _)| pkg.name().as_ref()).collect();

        assert_eq!(names, ["foobase"]);
    }

    #[test]
    fn search_scores_by_the_best_tier_any_term_achieved() {
        // Exactly matches "firefox" (ExactName) and only description-contains "browser"
        // (DescriptionContains). The combined score must stay at ExactName, not drop to
        // DescriptionContains.
        let exact_plus_weak =
            package("firefox", &desc_text("firefox", "a fast private safe web browser", ""));
        // Only ever description-contains both terms.
        let weak_plus_weak =
            package("other", &desc_text("other", "a firefox compatible web browser", ""));
        let packages = [weak_plus_weak, exact_plus_weak];

        let hits = search(&packages, ["firefox", "browser"]);
        let names: Vec<&str> = hits.iter().map(|(pkg, _)| pkg.name().as_ref()).collect();

        assert_eq!(names, ["firefox", "other"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::ExactName));
    }
}
