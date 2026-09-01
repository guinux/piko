//! The local database: a scanned collection of installed packages.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use alpm_types::Name;

use crate::{
    desc_compat::UnknownSectionPolicy,
    diagnostics::Sink,
    entry_name::{EntryName, EntryNameError},
    error::{Error, IoAction, Result},
    fs_util,
    limits::Limits,
    local::{package::LocalPackage, schema_version},
};

/// Something suspicious found while scanning, which did not stop the scan.
///
/// Diagnostics are **returned** rather than logged. A library that writes to stderr is
/// unusable from a TUI or a daemon, so the decision of how — and whether — to show these
/// belongs to the caller.
#[derive(Debug)]
#[non_exhaustive]
pub enum Diagnostic {
    /// A directory entry whose name is not valid UTF-8, and so cannot be a package name.
    NonUtf8Entry {
        /// The raw name, as the operating system reported it.
        name: OsString,
    },

    /// A directory whose name is not a valid `<name>-<version>` entry name.
    InvalidEntryName {
        /// The directory name.
        name: String,
        /// Why it was rejected.
        source: EntryNameError,
    },

    /// An entry that is a symlink to a directory rather than a directory.
    ///
    /// libalpm follows these; piko does not. See [`LocalDatabase::open`].
    SymlinkedEntry {
        /// The directory name.
        name: String,
    },

    /// Two entry directories claim the same package name.
    ///
    /// Only the first, in sorted order, is kept.
    DuplicateEntry {
        /// The package name claimed twice.
        name: Name,
        /// The entry directory that was kept.
        kept: String,
        /// The entry directory that was ignored.
        ignored: String,
    },
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonUtf8Entry { name } => {
                write!(f, "database entry {name:?} is not valid UTF-8, ignoring it")
            }
            Self::InvalidEntryName { name, source } => {
                write!(f, "invalid name for database entry {name:?}: {source}")
            }
            Self::SymlinkedEntry { name } => {
                write!(f, "database entry {name:?} is a symlink, ignoring it")
            }
            Self::DuplicateEntry { name, kept, ignored } => {
                write!(
                    f,
                    "duplicated database entry for {name}: keeping {kept}, ignoring {ignored}"
                )
            }
        }
    }
}

/// How to open a [`LocalDatabase`].
///
/// ```
/// use piko_db::{Limits, OpenOptions, UnknownSectionPolicy};
///
/// let options = OpenOptions::new()
///     .limits(Limits::default())
///     .unknown_sections(UnknownSectionPolicy::Reject)
///     .require_schema_version(false);
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenOptions {
    limits: Limits,
    unknown_sections: UnknownSectionPolicy,
    require_schema_version: RequireSchemaVersion,
}

/// Wrapper giving [`OpenOptions::require_schema_version`] a `true` default.
#[derive(Clone, Copy, Debug)]
struct RequireSchemaVersion(bool);

impl Default for RequireSchemaVersion {
    fn default() -> Self {
        Self(true)
    }
}

impl OpenOptions {
    /// Default options: standard limits, tolerate unknown sections, require the schema
    /// version file.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the resource limits applied to every file read.
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets what happens when a `desc` file contains an unrecognised `%SECTION%`.
    #[must_use]
    pub const fn unknown_sections(mut self, policy: UnknownSectionPolicy) -> Self {
        self.unknown_sections = policy;
        self
    }

    /// Sets whether a valid `ALPM_DB_VERSION` file is required.
    ///
    /// Defaults to `true`. Turning it off is for inspecting a database fragment that has no
    /// version marker. It does not make an unsupported version readable — it only skips the
    /// check entirely.
    #[must_use]
    pub const fn require_schema_version(mut self, required: bool) -> Self {
        self.require_schema_version = RequireSchemaVersion(required);
        self
    }
}

/// An open local package database.
///
/// Opening scans the directory once and parses entry names; no file inside an entry is read.
/// Per-package metadata is loaded on demand — see [`LocalPackage`].
///
/// The package set is immutable and the type is `Send + Sync`, so a `&LocalDatabase` may be
/// shared freely across threads.
#[derive(Debug)]
pub struct LocalDatabase {
    root: PathBuf,
    /// Sorted by package name, and unique on it.
    packages: Box<[LocalPackage]>,
    diagnostics: Box<[Diagnostic]>,
    /// How many diagnostics were found beyond [`Limits::max_diagnostics`] and so not kept.
    diagnostics_dropped: usize,
}

impl LocalDatabase {
    /// Opens the database at `root` with default [`OpenOptions`].
    ///
    /// `root` is the database directory itself, e.g. `/var/lib/pacman/local`.
    ///
    /// # Errors
    ///
    /// See [`LocalDatabase::open_with`].
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(root, OpenOptions::new())
    }

    /// Opens the database at `root`.
    ///
    /// The scan mirrors libalpm's `local_db_populate`: `.` and `..` are skipped, anything
    /// that is not a directory is skipped silently (which is what filters out
    /// `ALPM_DB_VERSION`), and an unparseable name is reported and skipped.
    ///
    /// It diverges in two deliberate ways:
    ///
    /// - A symlink to a directory is **not** followed. libalpm's `is_dir` uses a following
    ///   `stat`, so a symlinked entry is accepted there; here it is reported and skipped,
    ///   because it is a redirection primitive with no legitimate use in a database.
    /// - On a duplicate package name, the entry kept is the first in **sorted** order.
    ///   libalpm keeps the first in `readdir` order, which is filesystem-dependent and so
    ///   not reproducible.
    ///
    /// # Errors
    ///
    /// - [`Error::SchemaVersion`] if `ALPM_DB_VERSION` is missing or unsupported, unless
    ///   [`OpenOptions::require_schema_version`] was turned off. A missing file is not an
    ///   error when `root` is also empty or does not exist yet — see
    ///   [`schema_version::root_is_unpopulated`]. That database is read as having zero
    ///   packages; nothing is written to create it, which stays `piko-db-write`'s job.
    /// - [`Error::Io`] if `root` cannot be listed.
    /// - [`Error::TooManyEntries`] if the directory holds more **packages** than
    ///   [`Limits::max_entries`] allows. Entries that are not packages — `ALPM_DB_VERSION`,
    ///   `db.lck`, a stray file, a badly-named directory — consume none of that budget; they
    ///   are bounded by [`Limits::max_diagnostics`] instead, which never fails the open.
    ///
    /// Problems with individual entries are reported through
    /// [`diagnostics`](LocalDatabase::diagnostics) and do not fail the open.
    pub fn open_with(root: impl AsRef<Path>, options: OpenOptions) -> Result<Self> {
        let root = root.as_ref();

        // Set only when the schema version file is missing for a reason that is not
        // corruption: nothing has been written into `root` at all yet. `root` itself may
        // still not exist in that case, which `scan` below must not treat as an error.
        let mut bootstrapping = false;

        if options.require_schema_version.0
            && let Err(error) = schema_version::check(root, &options.limits)
        {
            let missing = matches!(
                &error,
                Error::SchemaVersion(schema_version::SchemaVersionError::Missing { .. })
            );
            bootstrapping = missing && schema_version::root_is_unpopulated(root)?;
            if !bootstrapping {
                return Err(error);
            }
        }

        let mut diagnostics = Sink::new(&options.limits);
        let mut packages = if bootstrapping && !fs_util::exists_no_follow(root) {
            Vec::new()
        } else {
            Self::scan(root, options, &mut diagnostics)?
        };

        // Sorting by name gives reproducible iteration and lets `get` binary-search. Ties
        // are broken by the raw directory name so that duplicate detection, and therefore
        // which entry wins, does not depend on readdir order.
        packages.sort_by(|left, right| {
            left.name()
                .cmp(right.name())
                .then_with(|| left.entry().as_str().cmp(right.entry().as_str()))
        });

        Self::drop_duplicates(&mut packages, &mut diagnostics);

        let (diagnostics, diagnostics_dropped) = diagnostics.finish();

        Ok(Self {
            root: root.to_path_buf(),
            packages: packages.into_boxed_slice(),
            diagnostics,
            diagnostics_dropped,
        })
    }

    /// Reads the directory and turns every valid entry into a [`LocalPackage`].
    fn scan(
        root: &Path,
        options: OpenOptions,
        diagnostics: &mut Sink<Diagnostic>,
    ) -> Result<Vec<LocalPackage>> {
        let entries =
            std::fs::read_dir(root).map_err(|source| Error::io(root, IoAction::ReadDir, source))?;

        let mut packages = Vec::new();

        for entry in entries {
            let entry = entry.map_err(|source| Error::io(root, IoAction::ReadDir, source))?;

            let raw_name = entry.file_name();
            let Some(name) = raw_name.to_str() else {
                diagnostics.push(|| Diagnostic::NonUtf8Entry { name: raw_name });
                continue;
            };

            let path = entry.path();
            if !fs_util::is_real_directory(&path)? {
                // Not a directory. This is the silent skip that filters out `ALPM_DB_VERSION`
                // and any stray file, exactly as libalpm does. Report only the suspicious
                // case: an entry that would have been a directory if followed.
                if path.is_dir() {
                    diagnostics.push(|| Diagnostic::SymlinkedEntry { name: name.to_owned() });
                }
                continue;
            }

            match EntryName::parse(name) {
                Ok(parsed) => {
                    // Checked here, not at the top of the loop, so the bound counts packages
                    // rather than directory entries. `ALPM_DB_VERSION` is always present and
                    // always enumerated, so counting entries would reject a database holding
                    // exactly `max_entries` packages. Whether it did would then depend on
                    // readdir order — the same nondeterminism `drop_duplicates` avoids.
                    if packages.len() >= options.limits.max_entries {
                        return Err(Error::TooManyEntries {
                            path: root.to_path_buf(),
                            max: options.limits.max_entries,
                        });
                    }
                    packages.push(LocalPackage::new(
                        parsed,
                        path,
                        options.limits,
                        options.unknown_sections,
                    ));
                }
                Err(source) => diagnostics
                    .push(|| Diagnostic::InvalidEntryName { name: name.to_owned(), source }),
            }
        }

        Ok(packages)
    }

    /// Removes entries whose package name repeats, keeping the first of each run.
    ///
    /// `packages` must already be sorted by name.
    fn drop_duplicates(packages: &mut Vec<LocalPackage>, diagnostics: &mut Sink<Diagnostic>) {
        let mut kept: Option<(Name, String)> = None;

        packages.retain(|package| match &kept {
            Some((name, kept_entry)) if name == package.name() => {
                diagnostics.push(|| Diagnostic::DuplicateEntry {
                    name: name.clone(),
                    kept: kept_entry.clone(),
                    ignored: package.entry().as_str().to_owned(),
                });
                false
            }
            _ => {
                kept = Some((package.name().clone(), package.entry().as_str().to_owned()));
                true
            }
        });
    }

    /// The database directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Looks up an installed package by name.
    #[must_use]
    pub fn get(&self, name: &Name) -> Option<&LocalPackage> {
        self.packages
            .binary_search_by(|package| package.name().cmp(name))
            .ok()
            .and_then(|index| self.packages.get(index))
    }

    /// Looks up an installed package by name, parsing `name` first.
    ///
    /// Returns `None` if `name` is not a valid package name.
    #[must_use]
    pub fn get_str(&self, name: &str) -> Option<&LocalPackage> {
        name.parse::<Name>().ok().and_then(|name| self.get(&name))
    }

    /// Iterates over installed packages, ordered by name.
    pub fn iter(&self) -> std::slice::Iter<'_, LocalPackage> {
        self.packages.iter()
    }

    /// The number of installed packages.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.packages.len()
    }

    /// Whether the database holds no packages.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// Problems found while scanning that did not prevent the database from opening.
    ///
    /// Bounded by [`Limits::max_diagnostics`]; see
    /// [`diagnostics_dropped`](LocalDatabase::diagnostics_dropped) for what that bound hid.
    #[must_use]
    pub const fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// How many further problems were found beyond [`Limits::max_diagnostics`] and so are not
    /// in [`diagnostics`](LocalDatabase::diagnostics).
    ///
    /// Non-zero only for a database holding thousands of unusable entries, which is not a
    /// shape a real system takes. It is reported rather than silently truncated so a caller
    /// is never left believing it has seen every problem.
    #[must_use]
    pub const fn diagnostics_dropped(&self) -> usize {
        self.diagnostics_dropped
    }

    /// Searches for packages matching every one of `terms`, ranked by relevance.
    ///
    /// A package must match **all** of `terms` (AND, not OR) to be included at all.
    /// Searching `["firefox", "browser"]` only returns packages that independently satisfy
    /// both. See [`search::MatchKind`](crate::search::MatchKind) for the six ways a single
    /// term can match, and their relative ranking, highest first: an exact name match, an
    /// exact match against one of its `%PROVIDES%`, a name prefix, a name substring, a
    /// description substring, or an exact group match. Comparisons are case-insensitive.
    /// Blank terms are dropped; if nothing is left after that, nothing matches. Each package
    /// appears at most once, scored by the single highest
    /// [`search::MatchKind`](crate::search::MatchKind) any one of its terms achieved. Results
    /// are sorted most-relevant-first, then by name to break ties deterministically.
    ///
    /// A package whose `desc` cannot be read is excluded from anything beyond an exact name
    /// match, rather than surfacing the read failure. Elsewhere in piko, a load failure must
    /// always surface on access and never look like an empty result — this function makes a
    /// deliberate, narrow exception, scoped to this best-effort bulk search only. Calling
    /// [`LocalPackage::desc`] directly on that package still fails loudly, as always; nothing
    /// about its own caching behavior changes.
    #[must_use]
    pub fn search<'q>(
        &self,
        terms: impl IntoIterator<Item = &'q str>,
    ) -> Vec<crate::local::search::LocalSearchHit<'_>> {
        crate::local::search::search(&self.packages, terms)
    }

    /// Checks every installed package against `repos`, returning those with a newer version
    /// available — mirrors `pacman -Qu`.
    ///
    /// See [`crate::updates::check_updates`] for the exact rules: repository priority is
    /// `repos`' own order (piko does not parse `pacman.conf`), a package absent from every
    /// repository is skipped, and version comparison reuses
    /// [`alpm_types::FullVersion`]'s `Ord` — the same algorithm as libalpm's
    /// `alpm_pkg_vercmp` (`version.c`).
    #[must_use]
    pub fn check_updates<'a>(
        &'a self,
        repos: impl IntoIterator<Item = &'a crate::repo::RepoDatabase>,
    ) -> Vec<crate::updates::Update<'a>> {
        crate::updates::check_updates(self, repos)
    }

    /// Every installed package whose name is not found in any of `repos` — mirrors
    /// `pacman -Qm`.
    ///
    /// See [`crate::updates::foreign`] for the exact rule: no `Usage` gate, and a name present
    /// in more than one repository counts the same as a name present in exactly one.
    #[must_use]
    pub fn foreign<'a>(
        &'a self,
        repos: impl IntoIterator<Item = &'a crate::repo::RepoDatabase>,
    ) -> Vec<&'a LocalPackage> {
        crate::updates::foreign(self, repos)
    }
}

impl<'a> IntoIterator for &'a LocalDatabase {
    type Item = &'a LocalPackage;
    type IntoIter = std::slice::Iter<'a, LocalPackage>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
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
        fixture::{DbFixture, MINIMAL_DESC_V1},
        local::schema_version::SchemaVersionError,
    };

    fn names(db: &LocalDatabase) -> Vec<&str> {
        db.iter().map(|package| package.name().as_ref()).collect()
    }

    #[test]
    fn is_send_and_sync() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LocalDatabase>();
    }

    #[test]
    fn opens_an_empty_database() {
        let fixture = DbFixture::new();
        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        assert!(db.diagnostics().is_empty());
    }

    #[test]
    fn finds_packages_and_orders_them_by_name() {
        let fixture = DbFixture::new();
        for entry in ["zlib-1.3.1-2", "acl-2.3.2-1", "linux-6.12.1-1"] {
            fixture.package(entry).with_defaults().build();
        }

        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert_eq!(names(&db), ["acl", "linux", "zlib"]);
        assert!(db.diagnostics().is_empty(), "{:?}", db.diagnostics());
    }

    /// The headline property: opening must not read any package metadata.
    #[test]
    fn opening_loads_no_package_metadata() {
        let fixture = DbFixture::new();
        fixture.package("foo-1.0.0-1").with_defaults().build();

        let db = LocalDatabase::open(fixture.path()).unwrap();
        let package = db.get_str("foo").unwrap();

        assert_eq!(package.version().to_string(), "1.0.0-1");
        assert!(!package.is_desc_loaded());
        assert!(!package.is_files_loaded());
        assert!(!package.is_mtree_loaded());
    }

    /// `ALPM_DB_VERSION` is a file, so the same rule that ignores stray files handles it —
    /// no special case, and no diagnostic.
    #[test]
    fn the_schema_version_file_is_not_mistaken_for_a_package() {
        let fixture = DbFixture::new();
        fixture.package("foo-1.0.0-1").with_defaults().build();
        fixture.stray_file("db.lck", "");

        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert_eq!(names(&db), ["foo"]);
        assert!(db.diagnostics().is_empty(), "{:?}", db.diagnostics());
    }

    #[test]
    fn a_missing_schema_version_file_is_corruption_once_something_else_is_there() {
        let fixture = DbFixture::without_schema_version();
        fixture.package("foo-1.0.0-1").with_defaults().build();

        let err = LocalDatabase::open(fixture.path()).unwrap_err();

        assert!(
            matches!(err, Error::SchemaVersion(SchemaVersionError::Missing { .. })),
            "got {err:?}"
        );
    }

    #[test]
    fn a_missing_schema_version_file_is_tolerated_when_the_directory_is_empty() {
        let fixture = DbFixture::without_schema_version();

        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert!(db.is_empty());
        assert!(db.diagnostics().is_empty());
    }

    #[test]
    fn a_missing_schema_version_file_is_tolerated_when_root_does_not_exist_yet() {
        let fixture = DbFixture::without_schema_version();
        let root = fixture.path().join("local");

        let db = LocalDatabase::open(&root).unwrap();

        assert!(db.is_empty());
        assert!(db.diagnostics().is_empty());
    }

    #[test]
    fn refuses_an_unsupported_schema_version() {
        let fixture = DbFixture::new();
        fixture.write_schema_version("10");

        let err = LocalDatabase::open(fixture.path()).unwrap_err();
        assert!(
            matches!(err, Error::SchemaVersion(SchemaVersionError::Unsupported { found: 10, .. })),
            "got {err:?}"
        );
    }

    #[test]
    fn the_schema_version_check_can_be_skipped() {
        let fixture = DbFixture::without_schema_version();
        fixture.package("foo-1.0.0-1").with_defaults().build();

        let db = LocalDatabase::open_with(
            fixture.path(),
            OpenOptions::new().require_schema_version(false),
        )
        .unwrap();

        assert_eq!(names(&db), ["foo"]);
    }

    /// One bad directory must not make the rest of the system unreadable.
    #[test]
    fn an_invalid_entry_name_is_reported_and_skipped() {
        let fixture = DbFixture::new();
        fixture.package("foo-1.0.0-1").with_defaults().build();
        fixture.package("not-a-package").build();
        fixture.package(".hidden-1.0.0-1").build();

        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert_eq!(names(&db), ["foo"]);
        assert_eq!(db.diagnostics().len(), 2, "{:?}", db.diagnostics());
        assert!(db.diagnostics().iter().all(|d| matches!(d, Diagnostic::InvalidEntryName { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_entry_is_reported_and_skipped() {
        let fixture = DbFixture::new();
        let real = fixture.package("foo-1.0.0-1").with_defaults().build();
        std::os::unix::fs::symlink(&real, fixture.path().join("evil-1.0.0-1")).unwrap();

        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert_eq!(names(&db), ["foo"], "the symlinked entry must not be followed");
        assert!(
            matches!(db.diagnostics().first(), Some(Diagnostic::SymlinkedEntry { .. })),
            "got {:?}",
            db.diagnostics()
        );
    }

    /// A dangling symlink is not a directory either way. It should be ignored quietly,
    /// not reported as a redirection attempt.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_is_skipped_silently() {
        let fixture = DbFixture::new();
        std::os::unix::fs::symlink(
            fixture.path().join("nowhere"),
            fixture.path().join("foo-1.0.0-1"),
        )
        .unwrap();

        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert!(db.is_empty());
        assert!(db.diagnostics().is_empty(), "{:?}", db.diagnostics());
    }

    /// Two directories can hold the same package at different versions. Only one may win,
    /// and which one must not depend on the filesystem's readdir order.
    #[test]
    fn a_duplicate_package_name_keeps_the_first_in_sorted_order() {
        let fixture = DbFixture::new();
        fixture.package("foo-2.0.0-1").with_defaults().build();
        fixture.package("foo-1.0.0-1").with_defaults().build();

        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert_eq!(db.len(), 1);
        assert_eq!(db.get_str("foo").map(|p| p.version().to_string()), Some("1.0.0-1".to_owned()));
        assert!(
            matches!(
                db.diagnostics().first(),
                Some(Diagnostic::DuplicateEntry { kept, ignored, .. })
                    if kept == "foo-1.0.0-1" && ignored == "foo-2.0.0-1"
            ),
            "got {:?}",
            db.diagnostics()
        );
    }

    #[test]
    fn duplicate_detection_survives_three_way_collisions() {
        let fixture = DbFixture::new();
        for entry in ["foo-3.0.0-1", "foo-1.0.0-1", "foo-2.0.0-1", "bar-1.0.0-1"] {
            fixture.package(entry).with_defaults().build();
        }

        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert_eq!(names(&db), ["bar", "foo"]);
        assert_eq!(db.diagnostics().len(), 2);
    }

    #[test]
    fn lookup_finds_and_misses_correctly() {
        let fixture = DbFixture::new();
        for entry in ["acl-2.3.2-1", "linux-6.12.1-1", "zlib-1.3.1-2"] {
            fixture.package(entry).with_defaults().build();
        }

        let db = LocalDatabase::open(fixture.path()).unwrap();

        for name in ["acl", "linux", "zlib"] {
            assert_eq!(db.get_str(name).map(|p| p.name().as_ref()), Some(name));
        }
        assert!(db.get_str("absent").is_none());
        assert!(db.get_str("not a valid name!").is_none());
    }

    #[test]
    fn refuses_a_database_with_too_many_entries() {
        let fixture = DbFixture::new();
        for index in 0..4 {
            fixture.package(&format!("pkg{index}-1.0.0-1")).with_defaults().build();
        }

        let err = LocalDatabase::open_with(
            fixture.path(),
            OpenOptions::new().limits(Limits { max_entries: 2, ..Limits::default() }),
        )
        .unwrap_err();

        assert!(matches!(err, Error::TooManyEntries { max: 2, .. }), "got {err:?}");
    }

    /// The bound counts packages, not directory entries. `ALPM_DB_VERSION` is always present
    /// and always enumerated, so counting entries would reject a database holding exactly
    /// `max_entries` packages — and whether it did would depend on readdir order.
    #[test]
    fn a_database_with_exactly_max_entries_packages_opens() {
        let fixture = DbFixture::new();
        for index in 0..2 {
            fixture.package(&format!("pkg{index}-1.0.0-1")).with_defaults().build();
        }
        fixture.stray_file("db.lck", "");

        let db = LocalDatabase::open_with(
            fixture.path(),
            OpenOptions::new().limits(Limits { max_entries: 2, ..Limits::default() }),
        )
        .unwrap();

        assert_eq!(names(&db), ["pkg0", "pkg1"]);
    }

    /// Non-package entries must consume none of the package budget, however many there are.
    #[test]
    fn unusable_entries_do_not_count_against_max_entries() {
        let fixture = DbFixture::new();
        fixture.package("foo-1.0.0-1").with_defaults().build();
        for index in 0..20 {
            fixture.package(&format!("invalid{index}")).build();
        }

        let db = LocalDatabase::open_with(
            fixture.path(),
            OpenOptions::new().limits(Limits { max_entries: 1, ..Limits::default() }),
        )
        .unwrap();

        assert_eq!(names(&db), ["foo"]);
        assert_eq!(db.diagnostics().len(), 20);
    }

    /// A flood of unusable entries produces a diagnostic per entry, which `max_entries` does
    /// not bound — that is `max_diagnostics`' job, and it must not fail the open.
    #[test]
    fn diagnostics_are_bounded_and_the_overflow_is_counted() {
        let fixture = DbFixture::new();
        fixture.package("foo-1.0.0-1").with_defaults().build();
        for index in 0..20 {
            fixture.package(&format!("invalid{index}")).build();
        }

        let db = LocalDatabase::open_with(
            fixture.path(),
            OpenOptions::new().limits(Limits { max_diagnostics: 5, ..Limits::default() }),
        )
        .unwrap();

        assert_eq!(names(&db), ["foo"], "the readable package must still be readable");
        assert_eq!(db.diagnostics().len(), 5);
        assert_eq!(db.diagnostics_dropped(), 15);
    }

    #[test]
    fn nothing_is_dropped_when_diagnostics_stay_under_the_bound() {
        let fixture = DbFixture::new();
        fixture.package("foo-1.0.0-1").with_defaults().build();
        fixture.package("not-a-package").build();

        let db = LocalDatabase::open(fixture.path()).unwrap();

        assert_eq!(db.diagnostics().len(), 1);
        assert_eq!(db.diagnostics_dropped(), 0);
    }

    #[test]
    fn a_missing_database_directory_reports_its_path() {
        let fixture = DbFixture::new();
        let missing = fixture.path().join("absent");

        let err =
            LocalDatabase::open_with(&missing, OpenOptions::new().require_schema_version(false))
                .unwrap_err();

        assert!(matches!(err, Error::Io { action: IoAction::ReadDir, .. }), "got {err:?}");
        assert!(err.to_string().contains("absent"));
    }

    /// Options must reach the packages they configure, not just the scan.
    #[test]
    fn open_options_propagate_to_packages() {
        let fixture = DbFixture::new();
        let desc = format!("{MINIMAL_DESC_V1}%FUTURE%\nvalue\n\n");
        fixture.package("foo-1.0.0-1").desc(&desc).build();

        let tolerant = LocalDatabase::open(fixture.path()).unwrap();
        assert!(tolerant.get_str("foo").unwrap().desc().is_ok());

        let strict = LocalDatabase::open_with(
            fixture.path(),
            OpenOptions::new().unknown_sections(UnknownSectionPolicy::Reject),
        )
        .unwrap();
        assert!(strict.get_str("foo").unwrap().desc().is_err());
    }

    /// Packages must be forceable from several threads at once.
    #[test]
    fn packages_can_be_loaded_concurrently() {
        let fixture = DbFixture::new();
        for index in 0..16 {
            fixture.package(&format!("pkg{index}-1.0.0-1")).with_defaults().build();
        }

        let db = LocalDatabase::open(fixture.path()).unwrap();
        let db = &db;

        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(move || {
                    for package in db {
                        package.load_all().unwrap();
                    }
                });
            }
        });

        assert!(db.iter().all(LocalPackage::is_desc_loaded));
    }

    #[test]
    fn into_iterator_matches_iter() {
        let fixture = DbFixture::new();
        fixture.package("foo-1.0.0-1").with_defaults().build();

        let db = LocalDatabase::open(fixture.path()).unwrap();
        let collected: Vec<_> = (&db).into_iter().map(|p| p.name().as_ref()).collect();

        assert_eq!(collected, names(&db));
    }

    #[test]
    fn diagnostics_render_readably() {
        let text = Diagnostic::SymlinkedEntry { name: "evil-1-1".to_owned() }.to_string();
        assert_eq!(text, r#"database entry "evil-1-1" is a symlink, ignoring it"#);
    }
}
