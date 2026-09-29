//! What the plan says an incoming package is, set against what its archive says.

use std::fmt::Display;

use alpm_pkginfo::PackageInfo;
use piko_db::EntryName;
use piko_db::solve::Solvable;

/// The fields of a planned package that its archive's `.PKGINFO` must repeat.
///
/// These are the fields `check_pkg_matches_db` (`sync.c:1113`) compares after the name and
/// the version: the installed size, `%DEPENDS%`, `%CONFLICTS%`, `%REPLACES%`, `%PROVIDES%` and
/// `%GROUPS%`. The name and the version are not here. The step's `PackageFileName` carries
/// them for every install, whether or not the plan supplied an `Expected`.
///
/// Each list is compared as a multiset of rendered entries: order does not matter, and a
/// repeated entry does. That is `alpm_list_cmp_unsorted` (`alpm_list.c:512`) over
/// `dep_not_equal` (`sync.c:1089`). `dep_not_equal` compares a relation's name, operator and
/// version as strings, which is what comparing the rendered `name<op>version` text does. Both
/// sides are parsed by the same `alpm-types` types, so the same text renders the same way.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Expected {
    installed_size: u64,
    depends: Vec<String>,
    conflicts: Vec<String>,
    replaces: Vec<String>,
    provides: Vec<String>,
    groups: Vec<String>,
    /// The entry the plan expects to find installed under the same name, which the install
    /// replaces, or `None` for a fresh install. Not part of the archive comparison.
    replaced: Option<EntryName>,
}

impl Expected {
    /// What `candidate`'s own metadata says: its repository `desc`, or, for a package file
    /// named on the command line, the `.PKGINFO` the plan read.
    ///
    /// # Errors
    ///
    /// The `piko_db` error if the candidate's `%DEPENDS%` cannot be read. A repository
    /// candidate converts it on first access.
    pub fn of(candidate: &Solvable<'_>) -> piko_db::Result<Self> {
        Ok(Self {
            installed_size: candidate.installed_size(),
            depends: rendered(candidate.depends()?),
            conflicts: rendered(candidate.conflicts()),
            replaces: rendered(candidate.replaces()),
            provides: rendered(candidate.provides()),
            groups: rendered(candidate.groups()),
            replaced: None,
        })
    }

    /// This expectation, for an install that replaces the installed entry `replaced`.
    #[must_use]
    pub fn replacing(mut self, replaced: EntryName) -> Self {
        self.replaced = Some(replaced);
        self
    }

    /// The installed entry the plan expects this install to replace, or `None` when the plan
    /// expects the name not to be installed.
    #[must_use]
    pub const fn replaced(&self) -> Option<&EntryName> {
        self.replaced.as_ref()
    }

    /// The installed size, `%ISIZE%` or the `.PKGINFO`'s `size`.
    #[must_use]
    pub const fn installed_size(&self) -> u64 {
        self.installed_size
    }

    /// What an archive's `.PKGINFO` says.
    #[must_use]
    pub fn of_archive(info: &PackageInfo) -> Self {
        crate::pkginfo::either_version!(info, |v| Self {
            installed_size: v.size,
            depends: rendered(&v.depend),
            conflicts: rendered(&v.conflict),
            replaces: rendered(&v.replaces),
            provides: rendered(&v.provides),
            groups: rendered(&v.group),
            replaced: None,
        })
    }

    /// The fields where `found` differs from this expectation, named as `.PKGINFO` names them.
    ///
    /// Every field is compared, as `check_pkg_matches_db` does, and every difference is named.
    /// An error that names them all at once tells a stale cache file from a substituted one.
    #[must_use]
    pub fn differences(&self, found: &Self) -> Vec<&'static str> {
        let fields = [
            ("size", self.installed_size == found.installed_size),
            ("depend", self.depends == found.depends),
            ("conflict", self.conflicts == found.conflicts),
            ("replaces", self.replaces == found.replaces),
            ("provides", self.provides == found.provides),
            ("group", self.groups == found.groups),
        ];
        fields.into_iter().filter(|(_, same)| !same).map(|(name, _)| name).collect()
    }
}

/// `items`, rendered and sorted, so two lists compare as multisets.
fn rendered<T: Display>(items: impl IntoIterator<Item = T>) -> Vec<String> {
    let mut rendered: Vec<String> = items.into_iter().map(|item| item.to_string()).collect();
    rendered.sort_unstable();
    rendered
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn expected() -> Expected {
        Expected {
            installed_size: 4,
            depends: rendered(["glibc", "bash>=5"]),
            conflicts: Vec::new(),
            replaces: Vec::new(),
            provides: rendered(["libfoo.so=1-64"]),
            groups: rendered(["base"]),
            replaced: None,
        }
    }

    /// Order is not a difference. `repo-add` copies each list in `.PKGINFO` order, but nothing
    /// promises it.
    #[test]
    fn the_same_entries_in_another_order_match() {
        let reordered = Expected { depends: rendered(["bash>=5", "glibc"]), ..expected() };
        assert!(expected().differences(&reordered).is_empty());
    }

    /// A repeated entry is a difference: the lists are multisets, not sets.
    #[test]
    fn a_repeated_entry_is_a_difference() {
        let repeated = Expected { depends: rendered(["glibc", "bash>=5", "glibc"]), ..expected() };
        assert_eq!(expected().differences(&repeated), ["depend"]);
    }

    /// Every differing field is named, not only the first.
    #[test]
    fn every_differing_field_is_named() {
        let found = Expected {
            installed_size: 5,
            depends: rendered(["glibc"]),
            groups: Vec::new(),
            ..expected()
        };
        assert_eq!(expected().differences(&found), ["size", "depend", "group"]);
    }

    /// A version bound is part of the entry, as `dep_not_equal` compares it.
    #[test]
    fn another_version_bound_is_a_difference() {
        let found = Expected { depends: rendered(["glibc", "bash>=4"]), ..expected() };
        assert_eq!(expected().differences(&found), ["depend"]);
    }
}
