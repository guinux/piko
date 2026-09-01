//! Checking installed packages against repository databases: available updates, and packages
//! known to no repository at all.
//!
//! [`check_updates`] mirrors what `pacman -Qu` reports. For each installed package, it asks:
//! is a newer version available in a repository? Version comparison reuses
//! [`alpm_types::FullVersion`]'s `Ord`, which implements the same epoch/`pkgver`/`pkgrel`
//! algorithm as libalpm's `alpm_pkg_vercmp` (`version.c`). There is nothing to reimplement
//! here.
//!
//! [`foreign`] mirrors `pacman -Qm`: the inverse presence check, with no version comparison at
//! all.

use crate::{
    local::{database::LocalDatabase, package::LocalPackage},
    repo::{RepoDatabase, RepoPackage},
};

/// An installed package for which a newer version is available in a repository.
///
/// See [`crate::LocalDatabase::check_updates`].
#[derive(Clone, Copy, Debug)]
pub struct Update<'a> {
    installed: &'a LocalPackage,
    available: &'a RepoPackage,
}

impl<'a> Update<'a> {
    /// The installed package.
    #[must_use]
    pub const fn installed(&self) -> &'a LocalPackage {
        self.installed
    }

    /// The newer version available in a repository.
    #[must_use]
    pub const fn available(&self) -> &'a RepoPackage {
        self.available
    }
}

/// Checks every package in `local` against `repos`, returning those with a newer version
/// available.
///
/// For a name present in more than one of `repos`, the **first** repository in `repos` that
/// carries it is used. `repos`' order stands in for repository priority, the same as
/// `pacman.conf`'s `[repo]` section order (see [`crate::config::PacmanConfig`]). Callers
/// should pass repositories already in their intended priority order. Unlike
/// [`crate::resolve::SyncRepos::find_literal_satisfier`], this applies no `Usage` gate at
/// all, matching libalpm's own `alpm_sync_get_new_version` (`sync.c`). `pacman -Qu` is built
/// on that function, and it never consults a repository's `Usage` directive. A package
/// installed locally but absent from every given repository is skipped, matching
/// `pacman -Qu`'s treatment of foreign/locally-built packages. Only a strictly newer version
/// counts as an update; an equal or older repository version is not reported.
///
/// The comparison only ever needs each package's name and version. Both are free on
/// [`LocalPackage`] (from the entry directory name, no `desc` read) and already eager on
/// [`RepoPackage`], so this touches no local `desc` file at all.
///
/// Results are sorted by name (the same order [`crate::LocalDatabase`] iterates in).
pub(crate) fn check_updates<'a>(
    local: &'a LocalDatabase,
    repos: impl IntoIterator<Item = &'a RepoDatabase>,
) -> Vec<Update<'a>> {
    let repos: Vec<&RepoDatabase> = repos.into_iter().collect();

    local
        .iter()
        .filter_map(|installed| {
            let available = repos.iter().find_map(|repo| repo.get(installed.name()))?;
            (available.version() > installed.version()).then_some(Update { installed, available })
        })
        .collect()
}

/// Every installed package whose name is not found in any of `repos` — mirrors `pacman -Qm`.
///
/// Applies no `Usage` gate, for the same reason [`check_updates`] doesn't: a repository not
/// gated for installs can still declare that a name is known to it. Unlike [`check_updates`],
/// there is no version to prefer between repositories when a name is present in more than
/// one. Only "known to at least one" versus "known to none" matters here.
///
/// Results are sorted by name (the same order [`crate::LocalDatabase`] iterates in).
pub(crate) fn foreign<'a>(
    local: &'a LocalDatabase,
    repos: impl IntoIterator<Item = &'a RepoDatabase>,
) -> Vec<&'a LocalPackage> {
    let repos: Vec<&RepoDatabase> = repos.into_iter().collect();

    local
        .iter()
        .filter(|installed| repos.iter().all(|repo| repo.get(installed.name()).is_none()))
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
    use crate::{
        LocalDatabase,
        fixture::{DbFixture, RepoFixture},
    };

    fn local_db(fixture: &DbFixture, packages: &[(&str, &str)]) -> LocalDatabase {
        for (name, version) in packages {
            fixture.package(&format!("{name}-{version}")).with_defaults().build();
        }
        LocalDatabase::open(fixture.path()).unwrap()
    }

    /// Builds a minimal, valid v2 repository `desc`, with `name`/`version` substituted in.
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

    #[test]
    fn finds_a_package_with_a_newer_repo_version() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[("foo", "1.0.0-1")]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, "core.db", &[("foo", "1.0.0-2")]);

        let updates = local.check_updates([&repo]);

        assert_eq!(updates.len(), 1);
        let update = updates.first().unwrap();
        assert_eq!(update.installed().name().as_ref(), "foo");
        assert_eq!(update.installed().version().to_string(), "1.0.0-1");
        assert_eq!(update.available().version().to_string(), "1.0.0-2");
    }

    #[test]
    fn skips_a_package_already_up_to_date() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[("foo", "1.0.0-1")]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, "core.db", &[("foo", "1.0.0-1")]);

        assert!(local.check_updates([&repo]).is_empty());
    }

    #[test]
    fn skips_a_package_newer_locally_than_in_any_repo() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[("foo", "2.0.0-1")]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, "core.db", &[("foo", "1.0.0-1")]);

        assert!(local.check_updates([&repo]).is_empty());
    }

    #[test]
    fn skips_a_package_absent_from_every_repo() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[("foo", "1.0.0-1")]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, "core.db", &[("bar", "1.0.0-1")]);

        assert!(local.check_updates([&repo]).is_empty());
    }

    #[test]
    fn uses_the_first_repo_in_priority_order_that_has_the_package() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[("foo", "1.0.0-1")]);

        let repo_fixture = RepoFixture::new();
        let first = repo_db(&repo_fixture, "core.db", &[("foo", "1.2.0-1")]);
        let second = repo_db(&repo_fixture, "extra.db", &[("foo", "1.5.0-1")]);

        let updates = local.check_updates([&first, &second]);

        let update = updates.first().unwrap();
        assert_eq!(
            update.available().version().to_string(),
            "1.2.0-1",
            "the earlier-listed repo must win even though the later one has a newer version"
        );
    }

    #[test]
    fn results_are_sorted_by_name() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[("zeta", "1.0.0-1"), ("alpha", "1.0.0-1")]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, "core.db", &[("zeta", "2.0.0-1"), ("alpha", "2.0.0-1")]);

        let updates = local.check_updates([&repo]);
        let names: Vec<&str> =
            updates.iter().map(|update| update.installed().name().as_ref()).collect();

        assert_eq!(names, ["alpha", "zeta"]);
    }

    #[test]
    fn an_epoch_bump_counts_as_an_update() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[("foo", "1.0.0-1")]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, "core.db", &[("foo", "1:0.5.0-1")]);

        let updates = local.check_updates([&repo]);
        assert_eq!(
            updates.len(),
            1,
            "an epoch bump outranks a numerically lower pkgver, matching alpm_pkg_vercmp"
        );
    }

    #[test]
    fn a_package_absent_from_every_repo_is_foreign() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[("foo", "1.0.0-1")]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, "core.db", &[("bar", "1.0.0-1")]);

        let foreign = local.foreign([&repo]);
        assert_eq!(foreign.len(), 1);
        assert_eq!(foreign.first().unwrap().name().as_ref(), "foo");
    }

    #[test]
    fn a_package_present_in_any_repo_is_not_foreign() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[("foo", "1.0.0-1"), ("bar", "1.0.0-1")]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, "core.db", &[("foo", "1.0.0-1")]);

        let foreign = local.foreign([&repo]);
        assert_eq!(foreign.len(), 1);
        assert_eq!(foreign.first().unwrap().name().as_ref(), "bar");
    }

    #[test]
    fn a_version_mismatch_alone_does_not_make_a_package_foreign() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[("foo", "1.0.0-1")]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, "core.db", &[("foo", "9.0.0-1")]);

        assert!(
            local.foreign([&repo]).is_empty(),
            "presence by name is all -Qm checks; unlike check_updates, there is no version \
             comparison"
        );
    }

    #[test]
    fn foreign_results_are_sorted_by_name() {
        let local_fixture = DbFixture::new();
        let local = local_db(&local_fixture, &[("zeta", "1.0.0-1"), ("alpha", "1.0.0-1")]);
        let repo_fixture = RepoFixture::new();
        let repo = repo_db(&repo_fixture, "core.db", &[("unrelated", "1.0.0-1")]);

        let names: Vec<&str> =
            local.foreign([&repo]).iter().map(|package| package.name().as_ref()).collect();

        assert_eq!(names, ["alpha", "zeta"]);
    }
}
