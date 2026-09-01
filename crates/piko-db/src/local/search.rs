//! Searching the local database.
//!
//! The repository equivalent is [`crate::repo::search`]. Both rank hits with the shared
//! [`MatchKind`](crate::search::MatchKind), so a user sees one ordering regardless of which
//! database answered.

use alpm_types::RelationOrSoname;

use crate::{local::package::LocalPackage, search::MatchKind};

/// One installed package that matched a search query, together with why it matched.
///
/// See [`LocalDatabase::search`](crate::LocalDatabase::search).
pub type LocalSearchHit<'a> = (&'a LocalPackage, MatchKind);

/// Scores every package in `packages` against `terms`, returning only those that matched
/// **every** term.
///
/// Comparisons are case-insensitive. Blank (or all-whitespace) terms are dropped; if nothing
/// is left after that — an empty `terms`, or every term blank — nothing matches, rather than
/// treating "no term" as an automatic pass. Each package appears at most once, scored by the
/// single highest [`MatchKind`] any one of its (all-matching) terms achieved. Results are
/// sorted most-relevant-first, then by name to break ties deterministically.
///
/// A package whose `desc` cannot be read is treated as matching nothing beyond an exact name
/// — see [`best_match`].
pub(crate) fn search<'a, 'q>(
    packages: &'a [LocalPackage],
    terms: impl IntoIterator<Item = &'q str>,
) -> Vec<LocalSearchHit<'a>> {
    let terms: Vec<String> = terms
        .into_iter()
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
        .collect();
    if terms.is_empty() {
        return Vec::new();
    }

    let mut hits: Vec<LocalSearchHit<'a>> = packages
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
/// `%PROVIDES%` entry, the description and every group once per (package, term) pair would
/// cost `terms.len()` times more allocation than the search needs.
fn combined_match(package: &LocalPackage, terms: &[String]) -> Option<MatchKind> {
    let name = package.name().as_ref().to_lowercase();

    // An exact name match outranks everything and needs no `desc` at all, so a search whose
    // every term hits it never reads one. `desc` is lazy and fallible; see `Searchable`.
    let searchable = if terms.iter().all(|term| *term == name) {
        None
    } else {
        package.desc().ok().map(|desc| Searchable::from_desc(&desc))
    };

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
    fn from_desc(desc: &crate::local::desc_compat::DescView<'_>) -> Self {
        Self {
            // Only `Relation` entries carry a package name to match against; a `%PROVIDES%`
            // soname is not one, and was never matched here.
            provides: desc
                .provides()
                .iter()
                .filter_map(|provide| match provide {
                    RelationOrSoname::Relation(relation) => {
                        Some(relation.name.as_ref().to_lowercase())
                    }
                    _ => None,
                })
                .collect(),
            description: desc.description().as_ref().to_lowercase(),
            groups: desc.groups().iter().map(|group| group.to_lowercase()).collect(),
        }
    }
}

/// The single highest-ranked way a package matches `query`, if any.
///
/// `name`, `query` and everything in `searchable` must already be trimmed and lowercased.
///
/// An exact name match is checked first and needs no `desc` at all. Anything beyond that —
/// `%PROVIDES%`, `%DESC%`, `%GROUPS%` — needs [`LocalPackage::desc`], which is lazy and can
/// fail (a corrupt, missing or oversized `desc` file); `searchable` is `None` when it did.
/// piko normally surfaces every such failure rather than treating it as absence. This
/// function is a deliberate, narrow exception, scoped to this best-effort bulk search only: a
/// package whose `desc` cannot be read simply matches nothing beyond an exact name. Calling
/// [`LocalPackage::desc`] directly on that package still fails loudly, as always; nothing
/// about its own caching behavior changes.
fn best_match(name: &str, searchable: Option<&Searchable>, query: &str) -> Option<MatchKind> {
    if name == query {
        // Nothing else could outrank this, so there is no reason to also inspect `desc`.
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
    use super::*;
    use crate::{fixture::DbFixture, local::database::LocalDatabase};

    /// A minimal, valid v1 `desc` — every mandatory field — with `name`/`description`
    /// substituted in, and optional `%PROVIDES%`/`%GROUPS%` sections appended.
    fn desc_text(name: &str, description: &str, extra: &str) -> String {
        format!(
            "\
%NAME%
{name}

%VERSION%
1.0.0-1

%BASE%
{name}

%DESC%
{description}

%URL%
https://example.org/

%ARCH%
x86_64

%BUILDDATE%
1733737242

%INSTALLDATE%
1733737243

%PACKAGER%
Foobar McFooface <foobar@mcfooface.org>

%SIZE%
123

%VALIDATION%
pgp

{extra}"
        )
    }

    fn open_with_packages(entries: &[(&str, &str)]) -> DbFixture {
        let fixture = DbFixture::new();
        for (name, desc) in entries {
            fixture.package(&format!("{name}-1.0.0-1")).desc(desc).build();
        }
        fixture
    }

    #[test]
    fn exact_name_outranks_everything_else() {
        let text = desc_text("foo", "unrelated text", "%PROVIDES%\nfoo\n\n");
        let fixture = open_with_packages(&[("foo", &text)]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["foo"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::ExactName));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let text = desc_text("foo", "unrelated", "");
        let fixture = open_with_packages(&[("foo", &text)]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["FOO"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::ExactName));
    }

    #[test]
    fn exact_provides_outranks_name_prefix() {
        // "foobar" starts with "foo" (NameStartsWith), but also exactly provides "foo",
        // which must win.
        let text = desc_text("foobar", "unrelated", "%PROVIDES%\nfoo\n\n");
        let fixture = open_with_packages(&[("foobar", &text)]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["foo"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::ExactProvides));
    }

    #[test]
    fn name_starts_with_outranks_name_contains() {
        let text = desc_text("foobar", "unrelated", "");
        let fixture = open_with_packages(&[("foobar", &text)]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["foo"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::NameStartsWith));
    }

    #[test]
    fn name_contains_is_found_mid_string() {
        let text = desc_text("libfoobar", "unrelated", "");
        let fixture = open_with_packages(&[("libfoobar", &text)]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["foo"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::NameContains));
    }

    #[test]
    fn description_contains_is_the_fallback() {
        let text = desc_text("bar", "a package about foo things", "");
        let fixture = open_with_packages(&[("bar", &text)]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["foo"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::DescriptionContains));
    }

    #[test]
    fn exact_group_matches_but_ranks_lowest() {
        let text = desc_text("bar", "unrelated", "%GROUPS%\nfoo\n\n");
        let fixture = open_with_packages(&[("bar", &text)]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["foo"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::ExactGroup));
    }

    #[test]
    fn a_group_substring_is_not_a_match() {
        let text = desc_text("bar", "unrelated", "%GROUPS%\nfoobar\n\n");
        let fixture = open_with_packages(&[("bar", &text)]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert!(db.search(["foo"]).is_empty());
    }

    #[test]
    fn search_ignores_a_blank_query() {
        let text = desc_text("foo", "unrelated", "");
        let fixture = open_with_packages(&[("foo", &text)]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert!(db.search(["   "]).is_empty());
    }

    #[test]
    fn search_ignores_an_empty_term_list() {
        let text = desc_text("foo", "unrelated", "");
        let fixture = open_with_packages(&[("foo", &text)]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert!(db.search([]).is_empty());
    }

    #[test]
    fn search_sorts_most_relevant_first_then_by_name() {
        let fixture = open_with_packages(&[
            ("foobar", &desc_text("foobar", "unrelated", "")),
            ("foo", &desc_text("foo", "unrelated", "")),
            ("fooalpha", &desc_text("fooalpha", "unrelated", "")),
        ]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["foo"]);
        let names: Vec<&str> = hits.iter().map(|(pkg, _)| pkg.name().as_ref()).collect();

        assert_eq!(names, ["foo", "fooalpha", "foobar"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::ExactName));
    }

    #[test]
    fn search_requires_every_term_to_match() {
        let fixture = open_with_packages(&[
            // Matches "foo" (name) but not "bar" anywhere — must be excluded.
            ("foo", &desc_text("foo", "unrelated", "")),
            // Matches both "foo" (name) and "bar" (description).
            ("foobase", &desc_text("foobase", "something about bar", "")),
        ]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["foo", "bar"]);
        let names: Vec<&str> = hits.iter().map(|(pkg, _)| pkg.name().as_ref()).collect();

        assert_eq!(names, ["foobase"]);
    }

    #[test]
    fn search_scores_by_the_best_tier_any_term_achieved() {
        let fixture = open_with_packages(&[
            // Only ever description-contains both terms.
            ("other", &desc_text("other", "a firefox compatible web browser", "")),
            // Exactly matches "firefox" and only description-contains "browser" — the
            // combined score must stay at ExactName, not drop to DescriptionContains.
            ("firefox", &desc_text("firefox", "a fast private safe web browser", "")),
        ]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["firefox", "browser"]);
        let names: Vec<&str> = hits.iter().map(|(pkg, _)| pkg.name().as_ref()).collect();

        assert_eq!(names, ["firefox", "other"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::ExactName));
    }

    #[test]
    fn search_skips_a_package_whose_desc_cannot_be_read() {
        let fixture = open_with_packages(&[("good", &desc_text("good", "mentions foo", ""))]);
        fixture.package("bad-1.0.0-1").desc("not a valid desc at all").build();
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["foo"]);
        let names: Vec<&str> = hits.iter().map(|(pkg, _)| pkg.name().as_ref()).collect();

        assert_eq!(names, ["good"], "the package with an unreadable desc must be silently skipped");
    }

    /// A search that an exact name match already answers must not read `desc` at all — the
    /// same "identity is free" property `LocalDatabase::open` has, extended to search.
    #[test]
    fn an_exact_name_search_reads_no_desc() {
        let fixture = open_with_packages(&[
            ("foo", &desc_text("foo", "unrelated", "")),
            ("bar", &desc_text("bar", "unrelated", "")),
        ]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["foo"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::ExactName));

        let foo = db.get_str("foo").unwrap();
        assert!(!foo.is_desc_loaded(), "an exact name match must not force a desc read");
    }

    /// The multi-term case: every term hitting the name exactly still needs no `desc`, but a
    /// term that does not must still be able to consult one.
    #[test]
    fn a_term_beyond_an_exact_name_match_still_consults_desc() {
        let fixture = open_with_packages(&[("foo", &desc_text("foo", "a web browser", ""))]);
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["foo", "browser"]);
        assert_eq!(
            hits.first().map(|(_, kind)| *kind),
            Some(MatchKind::ExactName),
            "the best tier across terms still wins"
        );
        assert!(
            db.get_str("foo").unwrap().is_desc_loaded(),
            "the second term can only be answered from desc"
        );
    }

    #[test]
    fn search_still_finds_a_corrupt_desc_package_by_exact_name() {
        let fixture = DbFixture::new();
        fixture.package("bad-1.0.0-1").desc("not a valid desc at all").build();
        let db = LocalDatabase::open(fixture.path()).unwrap();

        let hits = db.search(["bad"]);
        let names: Vec<&str> = hits.iter().map(|(pkg, _)| pkg.name().as_ref()).collect();

        assert_eq!(names, ["bad"]);
        assert_eq!(hits.first().map(|(_, kind)| *kind), Some(MatchKind::ExactName));
    }
}
