//! `%GROUPS%` membership: which packages each group holds, for `pacman -Qg` and `pacman -Sg`.
//!
//! Both listings read the same index. So a group is found, its members are ordered, and a group
//! no package carries is told apart the same way on either side, whichever frontend lists them.

use std::collections::BTreeMap;

use crate::{LocalDatabase, LocalPackage, SharedError, repo::RepoDatabase, repo::RepoPackage};

/// Every group some package carries, with its members.
///
/// Groups come in name order. Inside a group, members come in package-name order, and packages
/// of the same name keep the order they were read in: repository priority order, for
/// [`repo_group_index`]. pacman prints its group cache in scan order instead. A sorted index is
/// what makes two runs over one database list the same way.
#[derive(Debug)]
pub struct GroupIndex<'a, P> {
    groups: BTreeMap<String, Vec<&'a P>>,
}

impl<'a, P> GroupIndex<'a, P> {
    /// Builds the index from `(group, member)` pairs, then sorts each group by `name`.
    fn build(
        pairs: impl IntoIterator<Item = (&'a str, &'a P)>,
        name: impl Fn(&P) -> String,
    ) -> Self {
        let mut groups: BTreeMap<String, Vec<&'a P>> = BTreeMap::new();
        for (group, member) in pairs {
            groups.entry(group.to_owned()).or_default().push(member);
        }
        for members in groups.values_mut() {
            // A stable sort, so packages of one name keep the order they were read in.
            members.sort_by_cached_key(|member| name(member));
        }
        Self { groups }
    }

    /// Every group name, in name order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.groups.keys().map(String::as_str)
    }

    /// Each member of each group `wanted` names, as `(group, member)`, in index order. Every
    /// group's members when `wanted` is empty.
    pub fn members<'s>(
        &'s self,
        wanted: &'s [String],
    ) -> impl Iterator<Item = (&'s str, &'a P)> + 's {
        self.groups
            .iter()
            .filter(move |(group, _)| wanted.is_empty() || wanted.contains(group))
            .flat_map(|(group, members)| {
                members.iter().map(move |member| (group.as_str(), *member))
            })
    }

    /// The names in `wanted` that no package carries as a group, in the order given.
    #[must_use]
    pub fn missing<'w>(&self, wanted: &'w [String]) -> Vec<&'w str> {
        wanted
            .iter()
            .filter(|name| !self.groups.contains_key(name.as_str()))
            .map(String::as_str)
            .collect()
    }
}

/// The groups the installed packages carry, `pacman -Qg`'s index.
///
/// `%GROUPS%` is read from the eager tier ([`LocalPackage::eager`]), never the typed parse. The
/// typed parse also converts `%LICENSE%`, `%PACKAGER%` and the checksums, so one of them that
/// does not convert would drop a package from every group it carries. libalpm reads the
/// sections one by one, and lists it.
///
/// A package whose `desc` cannot be read, or whose relation sections do not parse, carries no
/// group here. It is returned beside the index, with its error, so the caller can say which
/// packages the listing is missing.
#[must_use]
pub fn local_group_index(
    local: &LocalDatabase,
) -> (GroupIndex<'_, LocalPackage>, Vec<(&LocalPackage, SharedError)>) {
    let mut pairs = Vec::new();
    let mut unreadable = Vec::new();
    for package in local {
        match package.eager() {
            Ok(eager) => {
                pairs.extend(eager.groups().iter().map(|group| (group.as_str(), package)));
            }
            Err(error) => unreadable.push((package, error)),
        }
    }
    (GroupIndex::build(pairs, |package| package.name().to_string()), unreadable)
}

/// The groups the packages of `repos` carry, `pacman -Sg`'s index.
///
/// A repository package's `%GROUPS%` is one of the eagerly converted fields, so nothing here can
/// fail to parse.
#[must_use]
pub fn repo_group_index<'a>(
    repos: impl IntoIterator<Item = &'a RepoDatabase>,
) -> GroupIndex<'a, RepoPackage> {
    let pairs = repos
        .into_iter()
        .flat_map(|db| db.iter())
        .flat_map(|package| package.groups().iter().map(move |group| (group.as_str(), package)));
    GroupIndex::build(pairs, |package| package.name().to_string())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::fixture::{PackageSpec, Scenario};

    fn names(wanted: &[&str]) -> Vec<String> {
        wanted.iter().map(|name| (*name).to_owned()).collect()
    }

    /// Group by group, then member by member, whatever order the packages were read in.
    #[test]
    fn members_come_sorted_by_group_then_by_name() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("zsh", "1.0.0-1").groups(["shells", "base"]))
            .installed(PackageSpec::new("bash", "1.0.0-1").groups(["shells"]))
            .installed(PackageSpec::new("acl", "1.0.0-1").groups(["base"]))
            .build();
        let (index, unreadable) = local_group_index(scenario.local());

        assert!(unreadable.is_empty());
        assert_eq!(index.names().collect::<Vec<_>>(), ["base", "shells"]);
        let listed: Vec<(&str, String)> = index
            .members(&[])
            .map(|(group, package)| (group, package.name().to_string()))
            .collect();
        assert_eq!(
            listed,
            [
                ("base", "acl".to_owned()),
                ("base", "zsh".to_owned()),
                ("shells", "bash".to_owned()),
                ("shells", "zsh".to_owned()),
            ]
        );
    }

    #[test]
    fn a_named_group_lists_its_members_only_and_an_absent_one_is_missing() {
        let scenario = Scenario::new()
            .repo(
                "core",
                [
                    PackageSpec::new("editor", "1.0.0-1").groups(["tools"]),
                    PackageSpec::new("shell", "1.0.0-1").groups(["base"]),
                ],
            )
            .build();
        let index = repo_group_index(scenario.repos());
        let wanted = names(&["tools", "games"]);

        let listed: Vec<String> =
            index.members(&wanted).map(|(_, package)| package.name().to_string()).collect();
        assert_eq!(listed, ["editor"]);
        assert_eq!(index.missing(&wanted), ["games"]);
    }

    /// A `%PACKAGER%` the typed parse refuses does not take the package out of its groups.
    #[test]
    fn a_desc_only_the_typed_parse_refuses_keeps_its_groups() {
        let db = crate::fixture::DbFixture::new();
        let refused = crate::fixture::MINIMAL_DESC_V1.replacen(
            "Foobar McFooface <foobar@mcfooface.org>",
            "Some One <not-an-email>",
            1,
        ) + "%GROUPS%\ntools\n\n";
        db.package("foo-1.0.0-1").desc(&refused).files(crate::fixture::MINIMAL_FILES).build();
        let local = LocalDatabase::open(db.path()).unwrap();
        let package = local.iter().next().unwrap();
        assert!(package.desc().is_err(), "the fixture must carry a typed parse the parser refuses");

        let (index, unreadable) = local_group_index(&local);

        assert!(unreadable.is_empty());
        assert_eq!(index.names().collect::<Vec<_>>(), ["tools"]);
    }

    /// One name in two repositories keeps repository priority order inside its group.
    #[test]
    fn packages_of_one_name_keep_repository_order() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("editor", "1.0.0-1").groups(["tools"])])
            .repo("extra", [PackageSpec::new("editor", "2.0.0-1").groups(["tools"])])
            .build();
        let index = repo_group_index(scenario.repos());

        let versions: Vec<String> =
            index.members(&[]).map(|(_, package)| package.version().to_string()).collect();
        assert_eq!(versions, ["1.0.0-1", "2.0.0-1"]);
    }
}
