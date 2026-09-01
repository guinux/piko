//! How a package matched a search query.
//!
//! [`MatchKind`] is shared between the local and repository searches, so both rank hits the
//! same way. The ordering a user sees does not depend on which database answered. The
//! searches themselves differ, because the two package types do, and live in
//! [`crate::local::search`] and [`crate::repo::search`]. [`hide_installed`] combines the two.

use crate::local::{LocalDatabase, LocalPackage};
use crate::repo::{RepoDatabase, RepoPackage, SearchHit};

/// How a package matched a single search term.
///
/// Variants are declared least-relevant first, so the derived [`Ord`] ranks
/// [`MatchKind::ExactName`] highest. [`LocalDatabase::search`](crate::LocalDatabase::search)
/// and [`RepoDatabase::search`](crate::repo::RepoDatabase::search) both sort hits by this
/// order, most relevant first. A package that matches a single term in more than one way is
/// scored by its single best match. A search with several terms requires every term to match;
/// the per-term [`MatchKind`]s then combine by taking the best of them. See those methods for
/// the exact rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum MatchKind {
    /// The query exactly matches one of the package's `%GROUPS%`.
    ExactGroup,
    /// The package's `%DESC%` contains the query.
    DescriptionContains,
    /// The package name contains the query.
    NameContains,
    /// The package name starts with the query.
    NameStartsWith,
    /// The query exactly matches the name of one of the package's `%PROVIDES%`.
    ExactProvides,
    /// The query exactly matches the package name.
    ExactName,
}

/// Drops a repository search hit whenever `installed` already has a package of that name.
///
/// [`LocalDatabase::search`] and [`crate::repo::RepoDatabase::search`] each match
/// independently against their own database. A package that is both installed and present in
/// a repository is found by both. piko's `search` subcommand shows it once, as the local hit,
/// and calls this function to drop the repository one. The check is by name alone, not by
/// whether the local search matched the same terms. An installed package hides its repository
/// entry even when only the repository's description matches a term the installed one's does
/// not.
#[must_use]
pub fn hide_installed<'a>(
    hits: Vec<SearchHit<'a>>,
    installed: &LocalDatabase,
) -> Vec<SearchHit<'a>> {
    hits.into_iter().filter(|(package, _)| installed.get(package.name()).is_none()).collect()
}

/// Which database answered a name lookup that checked installed packages before any repository.
#[derive(Debug)]
pub enum LocalOrRepo<'a> {
    /// `name` is installed.
    Local(&'a LocalPackage),
    /// `name` is not installed, but present in `dbs[.0]`.
    Repo(usize, &'a RepoPackage),
}

/// Resolves `name` against `local` first, then `dbs` in file (priority) order.
///
/// `piko files` and `piko info` both default to this rule when neither `--installed` nor
/// `--repo` narrows the source: check what is already on the system before any repository,
/// and among repositories prefer the one `pacman.conf` lists first. This function holds the
/// only copy of that rule, rather than letting each call site keep its own near-identical
/// copy. The same logic appearing at more than one call site is a sign it belongs in a shared
/// function instead.
#[must_use]
pub fn resolve_installed_or_repo<'a>(
    local: &'a LocalDatabase,
    dbs: &'a [RepoDatabase],
    name: &str,
) -> Option<LocalOrRepo<'a>> {
    if let Some(package) = local.get_str(name) {
        return Some(LocalOrRepo::Local(package));
    }
    dbs.iter()
        .enumerate()
        .find_map(|(index, db)| db.get_str(name).map(|package| (index, package)))
        .map(|(index, package)| LocalOrRepo::Repo(index, package))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::fixture::{DbFixture, RepoFixture};
    use crate::repo::RepoDatabase;

    fn local_db(fixture: &DbFixture, packages: &[&str]) -> LocalDatabase {
        for name in packages {
            fixture.package(&format!("{name}-1.0.0-1")).with_defaults().build();
        }
        LocalDatabase::open(fixture.path()).unwrap()
    }

    /// A minimal, valid v2 repository `desc`, with `name` substituted in.
    fn repo_desc_text(name: &str) -> String {
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

    fn repo_db(fixture: &RepoFixture, packages: &[&str]) -> RepoDatabase {
        let entries: Vec<(String, Vec<u8>)> = packages
            .iter()
            .map(|name| (format!("{name}-1.0.0-1/desc"), repo_desc_text(name).into_bytes()))
            .collect();
        let entry_refs: Vec<(&str, &[u8])> =
            entries.iter().map(|(path, content)| (path.as_str(), content.as_slice())).collect();
        let path = fixture.write_gzip_archive("core.db", &entry_refs);
        RepoDatabase::open(path).unwrap()
    }

    #[test]
    fn drops_a_repo_hit_for_an_installed_package() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &["foo"]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, &["foo", "foobar"]);

        let hits = hide_installed(repo.search(["foo"]), &local);
        let names: Vec<&str> = hits.iter().map(|(pkg, _)| pkg.name().as_ref()).collect();

        assert_eq!(names, ["foobar"], "foo is installed, so its repo hit must be dropped");
    }

    #[test]
    fn keeps_every_hit_when_nothing_is_installed() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, &["foo", "foobar"]);

        let hits = hide_installed(repo.search(["foo"]), &local);
        let names: Vec<&str> = hits.iter().map(|(pkg, _)| pkg.name().as_ref()).collect();

        assert_eq!(names, ["foo", "foobar"]);
    }
}
