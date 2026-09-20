//! The reverse file lookup: which installed package owns this path?
//!
//! Two callers ask it, for different reasons. File-conflict detection asks about a path a
//! transaction is about to write ([`crate::conflict`]). A user asks about a path already on the
//! system, which is `pacman -Qo`. Both questions reduce to one scan of the installed set, so
//! [`Owners`] serves both.
//!
//! # The index
//!
//! [`Owners`] holds every installed package's file list, in database order, with a name index
//! beside it. It is built on the first query rather than in the constructor, because building it
//! reads every installed package's `files` file. Most transactions never reach a rule that needs
//! one. See [`crate::conflict`]'s "What it costs" note for the measurement behind the name index.
//!
//! Build one [`Owners`] per command, not one per path. The scan is linear, but the read behind it
//! is what costs, and it happens once.
//!
//! # Resolving a path before asking
//!
//! `%FILES%` spells a path relative to the installation root, with a trailing `/` on a directory.
//! A user types an absolute path, a relative one, or a bare program name. [`Owners::query`]
//! bridges the two, transcribing `query_fileowner` (pacman's `query.c:138`). The order of its
//! steps decides which key is searched, so it belongs here rather than in a front end: a second
//! front end must reach the same answer without re-deriving it.

use std::path::{Path, PathBuf};

use piko_db::LocalDatabase;

use crate::{
    conflict::filelist::FileList,
    error::{Error, Result},
};

/// The installed set, in database order, with a name index beside it.
///
/// The two are **not** redundant. Collapsing them into a `HashMap` alone would be a
/// behavioural change, not a simplification. [`Owners::owner_of`] answers with the *first*
/// package owning a path, as `_alpm_find_file_owner` does. The order a walk sees has to be the
/// database's, not a hash's.
#[derive(Debug)]
struct Installed {
    /// Every installed package and its file list, in database order.
    packages: Vec<(String, FileList)>,
    /// Where each name sits in `packages`.
    by_name: std::collections::HashMap<String, usize>,
}

/// Who owns what, loaded from the local database only once something asks.
///
/// Deliberately not built in the constructor. Most transactions never reach a rule that needs
/// it, and building it forces every installed package's `files` to be read.
#[derive(Debug)]
pub struct Owners<'db> {
    local: &'db LocalDatabase,
    loaded: Option<Installed>,
}

impl<'db> Owners<'db> {
    /// An index over `local`, reading nothing yet.
    #[must_use]
    pub const fn new(local: &'db LocalDatabase) -> Self {
        Self { local, loaded: None }
    }

    /// The installed set, reading it on the first call.
    fn installed(&mut self) -> &Installed {
        let local = self.local;
        self.loaded.get_or_insert_with(|| {
            let packages: Vec<(String, FileList)> = local
                .iter()
                .map(|package| {
                    // A package whose `files` cannot be read contributes an empty list. This is
                    // the safe direction: it makes paths look unowned, which produces a
                    // conflict rather than suppressing one.
                    let files = package
                        .file_list()
                        .map(|paths| {
                            FileList::new(
                                paths.iter().map(|path| path.to_string_lossy().into_owned()),
                            )
                        })
                        .unwrap_or_default();
                    (package.name().to_string(), files)
                })
                .collect();
            // First occurrence wins, so the index agrees with the ordered walk about which
            // package a name refers to. A local database cannot hold two entries of one name.
            // This choice only matters for staying honest about what the index means.
            let mut by_name = std::collections::HashMap::with_capacity(packages.len());
            for (index, (name, _)) in packages.iter().enumerate() {
                by_name.entry(name.clone()).or_insert(index);
            }
            Installed { packages, by_name }
        })
    }

    /// Every installed package and its file list, in database order.
    pub fn all(&mut self) -> &[(String, FileList)] {
        &self.installed().packages
    }

    /// The first installed package owning `path` exactly, as `_alpm_find_file_owner` does.
    ///
    /// `path` is relative to the installation root, with a trailing `/` if it is a directory.
    pub fn owner_of(&mut self, path: &str) -> Option<String> {
        self.all().iter().find(|(_, files)| files.contains(path)).map(|(name, _)| name.clone())
    }

    /// Every installed package owning `path` exactly.
    pub fn owners_of(&mut self, path: &str) -> Vec<String> {
        self.all()
            .iter()
            .filter(|(_, files)| files.contains(path))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Whether any installed package owns `path` exactly.
    pub fn anyone_owns(&mut self, path: &str) -> bool {
        self.all().iter().any(|(_, files)| files.contains(path))
    }

    /// The file list of an installed package, if it is installed.
    ///
    /// Indexed rather than scanned, and that is not premature. This is the one accessor asked
    /// per **path and per target**: [`crate::conflict`]'s `examine` consults it once for every
    /// other target in the transaction. So a linear scan would put the whole installed set
    /// inside two nested loops. See that module's "What it costs" note for the measurement.
    pub(crate) fn files_of(&mut self, name: &str) -> Option<&FileList> {
        let installed = self.installed();
        let index = *installed.by_name.get(name)?;
        installed.packages.get(index).map(|(_, files)| files)
    }

    /// Resolves `target` and names every installed package that owns it.
    ///
    /// `root` is the installation root. `search_path` is consulted only for a target that holds
    /// no `/` and does not exist as given — the caller supplies the `PATH` entries, in order,
    /// because reading the environment is a front end's decision and not this crate's.
    ///
    /// A file names its first owner only, and a directory names all of them. That is pacman's
    /// loop condition. The two cases differ because two packages sharing a directory is
    /// ordinary, while two packages owning one file is a broken database.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyOwnerTarget`] for an empty target. Nothing else fails. Three outcomes
    /// return an [`Answer`] with no owners instead: a path outside `root`, a path that does
    /// not exist, and a path nothing ships. Each one answers the question that was asked.
    pub fn query(&mut self, root: &Path, target: &str, search_path: &[PathBuf]) -> Result<Answer> {
        let query = resolve(root, target, search_path)?;
        let owners = if query.relative.is_empty() {
            // The root itself, which no package lists.
            Vec::new()
        } else if query.is_directory {
            self.owners_of(&query.relative)
        } else {
            self.owner_of(&query.relative).into_iter().collect()
        };
        Ok(Answer { query, owners })
    }
}

/// An owner query's target, resolved against the host filesystem and the installation root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query {
    /// The absolute path an answer names: canonicalized, with a directory's trailing `/`.
    pub resolved: String,
    /// The same path relative to the installation root, which is the form `%FILES%` spells.
    ///
    /// Empty when the target resolved to the root itself, and empty when it resolved outside
    /// the root. Both mean no package can own it.
    pub relative: String,
    /// The target as a refusal names it: after trailing slashes come off, and after a
    /// `search_path` hit replaced it.
    ///
    /// pacman reports the resolved path on success and this one on a refusal. A refusal may
    /// be the resolution itself failing. Echoing a half-resolved path would then name
    /// something the caller never typed.
    pub named: String,
    /// Whether the path names a directory.
    pub is_directory: bool,
}

/// A target, resolved, with every installed package that owns it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Answer {
    /// What the target resolved to.
    pub query: Query,
    /// The owning packages, in database order. Empty when nothing owns the path.
    pub owners: Vec<String>,
}

/// Resolves `target` to the key `%FILES%` would spell for it.
///
/// # Errors
///
/// [`Error::EmptyOwnerTarget`] for an empty target.
fn resolve(root: &Path, target: &str, search_path: &[PathBuf]) -> Result<Query> {
    if target.is_empty() {
        return Err(Error::EmptyOwnerTarget);
    }

    // A trailing `/` makes `lstat` dereference a symlinked directory. So this removes it before
    // the call and restores it after. Removing it never empties the string: `/` stays `/`.
    let mut named = target;
    let mut is_directory = false;
    while let Some(shorter) = named.strip_suffix('/') {
        if shorter.is_empty() {
            break;
        }
        named = shorter;
        is_directory = true;
    }
    let mut named = named.to_owned();

    let mut metadata = std::fs::symlink_metadata(&named).ok();
    if metadata.is_none()
        && !named.contains('/')
        && let Some((found, at)) = search_path_for(&named, search_path)
    {
        named = at;
        metadata = Some(found);
    }

    // The metadata is the one `lstat` produced, so a symlink to a directory is a file here. It
    // is a distinct entry in `%FILES%`, and the package owning the link is rarely the package
    // owning its target.
    if let Some(metadata) = &metadata {
        is_directory = metadata.is_dir();
    }

    let resolved = canonicalize_partially(&named);
    let prefix = root_prefix(root);
    let relative = resolved.strip_prefix(&prefix).unwrap_or("").to_owned();

    let mut resolved = resolved;
    let mut relative = relative;
    if is_directory && !resolved.ends_with('/') {
        resolved.push('/');
        if !relative.is_empty() {
            relative.push('/');
        }
    }

    Ok(Query { resolved, relative, named, is_directory })
}

/// The first `search_path` entry holding `name`, with the path it was found at.
///
/// Existence is the whole test, matching pacman. A target found this way need not be
/// executable, and need not be the file a shell would run.
fn search_path_for(name: &str, search_path: &[PathBuf]) -> Option<(std::fs::Metadata, String)> {
    for directory in search_path {
        // An empty `PATH` entry means the working directory to a shell. This skips it: the
        // caller already tries the target as given, which is the same lookup.
        if directory.as_os_str().is_empty() {
            continue;
        }
        let candidate = directory.join(name);
        if let Ok(metadata) = std::fs::symlink_metadata(&candidate) {
            return Some((metadata, candidate.to_string_lossy().into_owned()));
        }
    }
    None
}

/// Canonicalizes every component of `path` except the last, as `lrealpath` does.
///
/// The final component is never dereferenced. So the answer for `/usr/bin/vi` names the package
/// owning that symlink, not the package owning what it points at. Both are entries in `%FILES%`,
/// and the question names the one the caller typed.
///
/// A relative path resolves against the working directory, because that is what canonicalizing
/// its parent does. The caller applies the installation root afterwards, as a prefix test.
///
/// This returns a path it cannot canonicalize unchanged. So a target under a directory that does
/// not exist still reaches the prefix test.
fn canonicalize_partially(path: &str) -> String {
    let as_path = Path::new(path);
    let display = |resolved: PathBuf| resolved.to_string_lossy().into_owned();

    // `file_name` is `None` for `/`, `.`, `..`, and any path ending in `..`. Each of those
    // names a directory rather than an entry inside one, so the whole path is resolved.
    let Some(base) = as_path.file_name() else {
        return std::fs::canonicalize(as_path).map_or_else(|_| path.to_owned(), display);
    };

    let parent = as_path.parent().filter(|parent| !parent.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    std::fs::canonicalize(parent)
        .map_or_else(|_| path.to_owned(), |parent| display(parent.join(base)))
}

/// The installation root as a prefix, canonicalized and ending in `/`.
///
/// libalpm gives every directory option a trailing slash (`canonicalize_path`, `handle.c:417`),
/// which is what lets the prefix come off by length alone and leave a relative path behind.
fn root_prefix(root: &Path) -> String {
    let canonical = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let mut prefix = canonical.to_string_lossy().into_owned();
    if !prefix.ends_with('/') {
        prefix.push('/');
    }
    prefix
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use piko_db::fixture::DbFixture;

    /// A local database holding `packages`, each with the file list given.
    fn database(packages: &[(&str, &[&str])]) -> (DbFixture, LocalDatabase) {
        let fixture = DbFixture::new();
        for (entry, files) in packages {
            let body = std::iter::once("%FILES%".to_owned())
                .chain(files.iter().map(|path| (*path).to_owned()))
                .collect::<Vec<_>>()
                .join("\n");
            fixture.package(entry).with_defaults().files(&format!("{body}\n")).build();
        }
        let local = LocalDatabase::open(fixture.path()).unwrap();
        (fixture, local)
    }

    /// An installation root holding the directories and files named.
    ///
    /// A path ending in `/` is created as a directory, and every other one as an empty file with
    /// its parents. That mirrors the `%FILES%` convention the database side uses.
    fn root(entries: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for entry in entries {
            let path = dir.path().join(entry.trim_end_matches('/'));
            if entry.ends_with('/') {
                std::fs::create_dir_all(&path).unwrap();
            } else {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).unwrap();
                }
                std::fs::write(&path, b"").unwrap();
            }
        }
        dir
    }

    /// The owners of one absolute path, with no `PATH` to fall back on.
    fn owners_of_path(local: &LocalDatabase, root: &Path, target: &Path) -> Vec<String> {
        let mut owners = Owners::new(local);
        owners.query(root, &target.to_string_lossy(), &[]).unwrap().owners
    }

    #[test]
    fn a_file_names_its_owner() {
        let (_keep, local) = database(&[("foo-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/foo"])]);
        let root = root(&["usr/bin/foo"]);
        assert_eq!(owners_of_path(&local, root.path(), &root.path().join("usr/bin/foo")), ["foo"]);
    }

    /// Two packages sharing a directory is ordinary, so a directory names all of its owners.
    #[test]
    fn a_directory_names_every_owner() {
        let (_keep, local) = database(&[
            ("foo-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/foo"]),
            ("bar-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/bar"]),
        ]);
        let root = root(&["usr/bin/"]);
        let mut named = owners_of_path(&local, root.path(), &root.path().join("usr/bin"));
        named.sort_unstable();
        assert_eq!(named, ["bar", "foo"]);
    }

    /// A broken database can record two owners for one file. Only the first is named, because
    /// that is the entry every other part of the system also acts on.
    #[test]
    fn a_file_with_two_owners_names_only_the_first() {
        let (_keep, local) = database(&[
            ("aaa-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/shared"]),
            ("zzz-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/shared"]),
        ]);
        let root = root(&["usr/bin/shared"]);
        assert_eq!(
            owners_of_path(&local, root.path(), &root.path().join("usr/bin/shared")),
            ["aaa"]
        );
    }

    /// `usr/bin` and `usr/bin/` are one question. The slash comes off, and the `lstat` puts it
    /// back.
    #[test]
    fn a_trailing_slash_changes_nothing() {
        let (_keep, local) = database(&[("foo-1.0.0-1", &["usr/", "usr/bin/"])]);
        let root = root(&["usr/bin/"]);
        let mut owners = Owners::new(&local);
        let plain = format!("{}/usr/bin", root.path().display());
        let slashed = format!("{plain}/");
        let first = owners.query(root.path(), &plain, &[]).unwrap();
        let second = owners.query(root.path(), &slashed, &[]).unwrap();
        assert_eq!(first.owners, ["foo"]);
        assert_eq!(first.query.relative, "usr/bin/");
        assert_eq!(first.query, second.query);
        assert_eq!(first.owners, second.owners);
    }

    /// A symlink is its own entry in `%FILES%`. The package owning the link is named, and the
    /// link is not followed to ask about its target.
    #[test]
    fn a_symlink_to_a_directory_is_asked_about_as_a_file() {
        let (_keep, local) = database(&[
            ("link-1.0.0-1", &["usr/", "usr/lib"]),
            ("real-1.0.0-1", &["usr/", "usr/lib64/"]),
        ]);
        let root = root(&["usr/lib64/"]);
        std::os::unix::fs::symlink("lib64", root.path().join("usr/lib")).unwrap();

        let answer = owners_of_path(&local, root.path(), &root.path().join("usr/lib"));
        assert_eq!(answer, ["link"], "the symlink's own entry has no trailing slash");
    }

    #[test]
    fn a_path_nothing_ships_has_no_owner() {
        let (_keep, local) = database(&[("foo-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/foo"])]);
        let root = root(&["usr/bin/stray"]);
        assert!(owners_of_path(&local, root.path(), &root.path().join("usr/bin/stray")).is_empty());
    }

    /// Outside the root is an answer, not a failure. The path may well exist and be owned by
    /// another root's database.
    #[test]
    fn a_path_outside_the_root_has_no_owner() {
        let (_keep, local) = database(&[("foo-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/foo"])]);
        let root = root(&["usr/bin/foo"]);
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("foo"), b"").unwrap();

        let answer = Owners::new(&local)
            .query(root.path(), &outside.path().join("foo").to_string_lossy(), &[])
            .unwrap();
        assert!(answer.owners.is_empty());
        assert!(answer.query.relative.is_empty());
    }

    /// The root itself is never listed in any `%FILES%`, so it has no owner and costs no scan.
    #[test]
    fn the_root_itself_has_no_owner() {
        let (_keep, local) = database(&[("foo-1.0.0-1", &["usr/", "usr/bin/"])]);
        let root = root(&["usr/"]);
        let answer =
            Owners::new(&local).query(root.path(), &root.path().to_string_lossy(), &[]).unwrap();
        assert!(answer.owners.is_empty());
        assert!(answer.query.relative.is_empty());
    }

    /// A bare program name is looked up in the search path, the way `pacman -Qo vim` works.
    #[test]
    fn a_bare_name_is_found_through_the_search_path() {
        let (_keep, local) = database(&[("foo-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/foo"])]);
        let root = root(&["usr/bin/foo"]);
        let search = vec![
            // An empty entry, and a directory with a trailing slash, both of which a real `PATH`
            // holds. Neither may derail the lookup.
            PathBuf::new(),
            root.path().join("usr/sbin/"),
            root.path().join("usr/bin/"),
        ];

        let answer = Owners::new(&local).query(root.path(), "foo", &search).unwrap();
        assert_eq!(answer.owners, ["foo"]);
        assert_eq!(answer.query.relative, "usr/bin/foo");
        assert_eq!(answer.query.named, root.path().join("usr/bin/foo").to_string_lossy());
    }

    /// Existence is the whole test. An entry earlier in the search path wins even where a shell
    /// would pass it over.
    #[test]
    fn the_first_search_path_entry_holding_the_name_wins() {
        let (_keep, local) = database(&[
            ("early-1.0.0-1", &["usr/", "usr/sbin/", "usr/sbin/foo"]),
            ("late-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/foo"]),
        ]);
        let root = root(&["usr/sbin/foo", "usr/bin/foo"]);
        let search = vec![root.path().join("usr/sbin"), root.path().join("usr/bin")];

        assert_eq!(
            Owners::new(&local).query(root.path(), "foo", &search).unwrap().owners,
            ["early"]
        );
    }

    /// The search path is consulted only for a target with no `/` in it. A relative path that
    /// does not exist stays a relative path.
    #[test]
    fn a_target_holding_a_slash_never_reaches_the_search_path() {
        let (_keep, local) = database(&[("foo-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/foo"])]);
        let root = root(&["usr/bin/foo"]);
        let search = vec![root.path().join("usr/bin")];

        let answer = Owners::new(&local).query(root.path(), "./foo", &search).unwrap();
        assert!(answer.owners.is_empty());
    }

    #[test]
    fn an_empty_target_is_the_one_failure() {
        let (_keep, local) = database(&[("foo-1.0.0-1", &["usr/"])]);
        let root = root(&["usr/"]);
        assert!(matches!(
            Owners::new(&local).query(root.path(), "", &[]),
            Err(Error::EmptyOwnerTarget)
        ));
    }

    /// A package whose `files` cannot be read owns nothing, rather than owning everything or
    /// failing the query. The safe direction is the same one conflict detection takes.
    #[test]
    fn an_unreadable_file_list_owns_nothing() {
        let fixture = DbFixture::new();
        fixture.package("foo-1.0.0-1").with_defaults().files("this is not a files file\n").build();
        let local = LocalDatabase::open(fixture.path()).unwrap();
        let root = root(&["usr/bin/foo"]);
        assert!(owners_of_path(&local, root.path(), &root.path().join("usr/bin/foo")).is_empty());
    }

    /// The index is read once, however many targets are asked about.
    #[test]
    fn the_index_is_built_once_for_many_targets() {
        let (_keep, local) = database(&[("foo-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/foo"])]);
        let root = root(&["usr/bin/foo"]);
        let mut owners = Owners::new(&local);
        assert!(owners.loaded.is_none());
        for _ in 0..3 {
            owners
                .query(root.path(), &root.path().join("usr/bin/foo").to_string_lossy(), &[])
                .unwrap();
        }
        assert_eq!(owners.installed().packages.len(), 1);
    }
}
