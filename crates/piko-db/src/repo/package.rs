//! A single package described by a repository database entry.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::Arc,
};

use alpm_common::MetadataFile as _;
use alpm_repo_db::{desc::RepoDescFile, files::RepoFilesV1};
use alpm_types::{
    CompressedSize, FullVersion, Group, InstalledSize, Name, PackageRelation, RelationOrSoname,
};

use super::{
    archive::{self, ArchiveItem},
    desc_compat::RepoDescView,
    eager::EagerFields,
    files_arena::{FilesArena, PathIter},
    repo_name::RepoName,
};
use crate::{
    desc_compat::{self, TakenFields},
    entry_name::EntryName,
    error::{Error, SharedError},
    lazy::Lazy,
    limits::Limits,
};

/// A repository `desc` entry's full typed parse, plus the fields kept beside it.
///
/// `%URL%` and `%PACKAGER%` are taken out of the text before the upstream parse, so a value
/// their typed conversion refuses cannot make the entry unreadable. See
/// [`crate::desc_compat::take_fields`].
#[derive(Debug)]
pub(crate) struct LoadedDesc {
    desc: RepoDescFile,
    taken: TakenFields,
}

/// Where a package's file list comes from, and the shared, lazily-built store for it.
///
/// One instance is shared (via [`Arc`]) across every [`RepoPackage`] in a
/// [`super::RepoDatabase`]. The file list for *any* package requires decompressing the
/// *whole* `.files` archive — there is no random access into a gzip-over-tar stream.
/// Building it once, on first use, and sharing the result is what makes opening `<repo>.db`
/// and never calling [`RepoPackage::file_list`] cost nothing beyond the `desc` pass.
#[derive(Debug)]
pub(crate) struct FilesSource {
    lazy: Lazy<FilesArena>,
    /// The `.files` archive to load from. `None` means `<repo>.db` was opened with no
    /// sibling `<repo>.files` at all — every [`RepoPackage::file_list`] call then fails with
    /// [`Error::FilesUnavailable`], cached the same way any other failure is.
    archive_path: Option<PathBuf>,
    limits: Limits,
    repo: RepoName,
}

impl FilesSource {
    /// A source with no `.files` archive at all.
    pub(crate) fn unavailable(repo: RepoName, limits: Limits) -> Self {
        Self { lazy: Lazy::new(), archive_path: None, limits, repo }
    }

    /// A source backed by `archive_path`, not yet loaded.
    pub(crate) fn deferred(repo: RepoName, archive_path: PathBuf, limits: Limits) -> Self {
        Self { lazy: Lazy::new(), archive_path: Some(archive_path), limits, repo }
    }

    /// A source whose arena has already been built — the `.files`-only variant, where the
    /// requirement is to populate everything in the same pass as `desc`, not to defer it.
    pub(crate) fn preloaded(repo: RepoName, limits: Limits, arena: FilesArena) -> Self {
        let source = Self { lazy: Lazy::new(), archive_path: None, limits, repo };
        // Seeding the slot here, instead of special-casing an already-built arena
        // everywhere else, keeps `file_list` a single code path regardless of variant.
        let _ = source.lazy.get_or_load(|| Ok(arena));
        source
    }

    fn arena(&self) -> std::result::Result<&FilesArena, SharedError> {
        self.lazy.get_or_load(|| self.load())
    }

    fn load(&self) -> crate::error::Result<FilesArena> {
        let Some(archive_path) = &self.archive_path else {
            return Err(Error::FilesUnavailable { repo: self.repo.clone() });
        };

        let mut arena = FilesArena::new();
        archive::walk(
            archive_path,
            &self.limits,
            |item| {
                let ArchiveItem::Files { entry, text } = item else { return Ok(()) };
                // A member that fails to parse here is dropped, not fatal to the whole load.
                // One malformed `files` entry must not make every other package's file list
                // unreachable. It surfaces later as `Error::FilesMissingForPackage` for that
                // one package specifically.
                if let Ok(parsed) = RepoFilesV1::from_str(&text) {
                    // A same-archive duplicate keeps the first entry. There is nowhere to
                    // report it from here, for the same reason `on_skip` below discards its
                    // diagnostics — `RepoDatabase::diagnostics()` was finalised at open time.
                    let _ = arena.insert(
                        archive_path,
                        entry.name().clone(),
                        entry.version().clone(),
                        parsed.as_ref(),
                        self.limits.repo_inflated_bytes,
                    )?;
                }
                Ok(())
            },
            |_skip| {
                // Diagnostics from a lazily-loaded `.files` archive are not collected. By the
                // time this runs, `RepoDatabase::diagnostics()` has already been finalised
                // from the eager `desc` pass. A member skipped here still shows up
                // indirectly, as `FilesMissingForPackage` for whichever package it belonged
                // to.
            },
        )?;

        Ok(arena)
    }

    /// Returns the file list for each of `packages`, touching as little of the `.files`
    /// archive as the requested set allows.
    ///
    /// If the shared arena is already loaded — successfully or not, from an earlier
    /// [`RepoPackage::file_list`] call, or because this repository's variant preloads
    /// everything at open time — every lookup is served from that cache with no further I/O.
    /// This includes replaying a cached failure instead of retrying it, matching [`Lazy`]'s
    /// contract. Otherwise this performs one dedicated walk via [`archive::walk_matching`],
    /// scoped to exactly `packages`' names.
    ///
    /// That walk is **never** written back into the shared cache. It may cover only part of
    /// the archive, and the cache's contract is "the whole thing or nothing". A later
    /// request for a different package must still see an unloaded slot, not a false
    /// [`Error::FilesMissingForPackage`].
    pub(crate) fn file_lists_for(
        &self,
        packages: &[&RepoPackage],
    ) -> Vec<(Name, std::result::Result<Vec<PathBuf>, SharedError>)> {
        if packages.is_empty() {
            return Vec::new();
        }

        if let Some(cached) = self.lazy.get() {
            return match cached {
                Ok(arena) => packages
                    .iter()
                    .map(|package| (package.name().clone(), collect_file_list(arena, package)))
                    .collect(),
                Err(shared) => packages
                    .iter()
                    .map(|package| (package.name().clone(), Err(SharedError::clone(&shared))))
                    .collect(),
            };
        }

        let Some(archive_path) = &self.archive_path else {
            let shared = SharedError::new(Error::FilesUnavailable { repo: self.repo.clone() });
            return packages
                .iter()
                .map(|package| (package.name().clone(), Err(SharedError::clone(&shared))))
                .collect();
        };

        let wanted: HashSet<&Name> = packages.iter().map(|package| package.name()).collect();
        let mut arena = FilesArena::new();
        let walk_result =
            archive::walk_matching(archive_path, &self.limits, &wanted, |entry, text| {
                // As in `load`: a member that fails to parse here is dropped, not fatal — it
                // surfaces as `Error::FilesMissingForPackage` for that one package.
                if let Ok(parsed) = RepoFilesV1::from_str(&text) {
                    let _ = arena.insert(
                        archive_path,
                        entry.name().clone(),
                        entry.version().clone(),
                        parsed.as_ref(),
                        self.limits.repo_inflated_bytes,
                    )?;
                }
                Ok(())
            });

        if let Err(error) = walk_result {
            let shared = SharedError::new(error);
            return packages
                .iter()
                .map(|package| (package.name().clone(), Err(SharedError::clone(&shared))))
                .collect();
        }

        packages
            .iter()
            .map(|package| (package.name().clone(), collect_file_list(&arena, package)))
            .collect()
    }
}

/// Looks `package` up in `arena`, collecting its paths into an owned `Vec` since `arena` may
/// be a temporary, walk-scoped one that does not outlive the caller.
fn collect_file_list(
    arena: &FilesArena,
    package: &RepoPackage,
) -> std::result::Result<Vec<PathBuf>, SharedError> {
    arena
        .file_list(package.name(), package.version())
        .map(|paths| paths.map(Path::to_path_buf).collect())
        .map_err(SharedError::new)
}

/// A single package described by a repository database.
///
/// The name and version are known as soon as the database is opened, from the entry directory
/// name in the archive, exactly as [`crate::LocalPackage`] does.
///
/// # Two tiers of `desc`
///
/// Reading the archive at all requires decompressing it, so every `desc` entry's **text** is
/// in memory by the time a package exists. Converting that text to typed values is a separate
/// cost, and a large one: measured at 67% of the whole open against this machine's real
/// `extra.db`. The conversion is split for this reason.
///
/// - **Eager** — [`Self::depends`], [`Self::provides`], [`Self::conflicts`],
///   [`Self::replaces`], [`Self::groups`], [`Self::compressed_size`],
///   [`Self::installed_size`]. Infallible and free after open. [`crate::solve::Universe`]
///   reads these fields for *every* candidate, so deferring them would buy nothing. See
///   [`super::eager`].
/// - **Deferred** — everything else, through [`Self::desc`], which parses the retained text
///   on first access and caches the outcome exactly as [`crate::LocalPackage::desc`] does.
///
/// The file list is a third tier — see [`FilesSource`] — because it may require decompressing
/// a *second*, much larger archive that has not been touched yet.
pub struct RepoPackage {
    entry: EntryName,
    eager: EagerFields,
    /// The `desc` text, already filtered of unknown sections, retained to back [`Self::desc`].
    raw: Box<str>,
    /// `%DEPENDS%`, converted on first access from the range [`EagerFields`] recorded.
    ///
    /// A third tier between the eager fields and the full `desc`. It is the only section
    /// that needed one — see [`crate::eager::Depends`] for why it is worth deferring.
    depends: Lazy<Box<[RelationOrSoname]>>,
    desc: Lazy<LoadedDesc>,
    files: Arc<FilesSource>,
}

impl std::fmt::Debug for RepoPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoPackage")
            .field("entry", &self.entry)
            .field("desc_loaded", &self.desc.is_loaded())
            .field("files_loaded", &self.files.lazy.is_loaded())
            .finish_non_exhaustive()
    }
}

impl RepoPackage {
    pub(crate) fn new(
        entry: EntryName,
        eager: EagerFields,
        raw: Box<str>,
        files: Arc<FilesSource>,
    ) -> Self {
        Self { entry, eager, raw, depends: Lazy::new(), desc: Lazy::new(), files }
    }

    /// The shared file-list source every package in the same database holds an `Arc` to.
    ///
    /// Used by [`super::database::RepoDatabase::file_lists`] to reach the batch lookup on
    /// [`FilesSource`] without going through any one package's own [`Self::file_list`].
    pub(crate) const fn files_source(&self) -> &Arc<FilesSource> {
        &self.files
    }

    /// The package name, from the entry directory name in the archive.
    ///
    /// Free: forces no load.
    #[must_use]
    pub const fn name(&self) -> &Name {
        self.entry.name()
    }

    /// The package version, from the entry directory name in the archive.
    ///
    /// Free: forces no load.
    #[must_use]
    pub const fn version(&self) -> &FullVersion {
        self.entry.version()
    }

    /// The parsed entry directory name.
    #[must_use]
    pub const fn entry(&self) -> &EntryName {
        &self.entry
    }

    /// `%DEPENDS%`, the run-time dependencies, converted on first access.
    ///
    /// The one relation section that is **not** free: see [`crate::eager::Depends`]. The
    /// conversion reads a byte range recorded at open, not the whole entry. Its outcome is
    /// cached — including a failure — exactly as [`Self::desc`]'s is.
    ///
    /// # Errors
    ///
    /// [`Error::RepoDescFields`] if an entry does not parse. A malformed *eager* section
    /// produces [`super::RepoDiagnostic::InvalidDesc`] at open and drops the package. This
    /// deferred section instead keeps the package and fails here — the same rule every other
    /// deferred section follows.
    pub fn depends(&self) -> std::result::Result<&[RelationOrSoname], SharedError> {
        self.depends
            .get_or_load(|| {
                crate::eager::parse_depends(&self.raw, self.eager.depends_text()).map_err(
                    |source| Error::RepoDescFields {
                        package: self.name().clone(),
                        source: Box::new(source),
                    },
                )
            })
            .map(|depends| &**depends)
    }

    /// `%PROVIDES%`.
    ///
    /// Free: parsed at open, forces no load.
    #[must_use]
    pub fn provides(&self) -> &[RelationOrSoname] {
        self.eager.provides()
    }

    /// `%CONFLICTS%`.
    ///
    /// Free: parsed at open, forces no load.
    #[must_use]
    pub fn conflicts(&self) -> &[PackageRelation] {
        self.eager.conflicts()
    }

    /// `%REPLACES%`.
    ///
    /// Free: parsed at open, forces no load.
    #[must_use]
    pub fn replaces(&self) -> &[PackageRelation] {
        self.eager.replaces()
    }

    /// `%GROUPS%`.
    ///
    /// Free: parsed at open, forces no load.
    #[must_use]
    pub fn groups(&self) -> &[Group] {
        self.eager.groups()
    }

    /// `%CSIZE%`, the compressed package file's size in bytes.
    ///
    /// Free: parsed at open, forces no load.
    #[must_use]
    pub const fn compressed_size(&self) -> CompressedSize {
        self.eager.compressed_size
    }

    /// `%ISIZE%`, the installed size in bytes.
    ///
    /// Free: parsed at open, forces no load.
    #[must_use]
    pub const fn installed_size(&self) -> InstalledSize {
        self.eager.installed_size
    }

    /// The fully parsed `desc` entry, for every field the eager accessors above do not cover.
    ///
    /// Parses the retained text on first access and caches the outcome — including a
    /// failure. The same failure returns on every later call, rather than retrying.
    ///
    /// # Errors
    ///
    /// [`Error::RepoDescUnparsable`] if the text does not parse as an
    /// [`alpm_repo_db::desc::RepoDescFile`]. A `desc` malformed in one of the *eager* sections
    /// never reaches here: it is dropped during the scan with
    /// [`super::RepoDiagnostic::InvalidDesc`].
    pub fn desc(&self) -> std::result::Result<RepoDescView<'_>, SharedError> {
        self.desc
            .get_or_load(|| {
                let (text, taken) = desc_compat::take_fields(&self.raw);
                let desc = RepoDescFile::from_str_with_schema(&text, None).map_err(|source| {
                    Error::RepoDescUnparsable {
                        entry: self.entry.as_str().to_owned(),
                        source: Box::new(source),
                    }
                })?;
                Ok(LoadedDesc { desc, taken })
            })
            .map(|loaded| RepoDescView::new(&loaded.desc, &loaded.taken))
    }

    /// Whether the deferred `desc` parse has already run.
    ///
    /// Exists for the same reason [`crate::LocalPackage::is_desc_loaded`] does: proving, from
    /// outside the crate, that opening a database does not parse what it should not.
    #[must_use]
    pub fn is_desc_loaded(&self) -> bool {
        self.desc.is_loaded()
    }

    /// The paths owned by this package, loading and caching the whole `.files` archive on
    /// first access — by any package, since the store is shared.
    ///
    /// # Errors
    ///
    /// - [`Error::FilesUnavailable`] if this database was opened as `<repo>.db` with no
    ///   sibling `<repo>.files`.
    /// - [`Error::FilesMissingForPackage`] if the `.files` archive has no entry for this
    ///   package at all.
    /// - [`Error::FilesVersionSkew`] if the `.files` archive has this package at a
    ///   **different version** than this database. `<repo>.db` and `<repo>.files` are
    ///   refreshed independently by pacman (`-Sy` versus `-Fy`) and routinely disagree —
    ///   measured at 12 of `core`'s 296 packages on the machine this was developed against.
    ///   Serving the wrong build's paths silently would be worse than refusing outright.
    pub fn file_list(&self) -> std::result::Result<PathIter<'_>, SharedError> {
        let arena = self.files.arena()?;
        arena.file_list(self.name(), self.version()).map_err(SharedError::new)
    }

    /// Whether the shared file-list arena has already been loaded.
    ///
    /// Since the arena is shared across every package in the database (see
    /// [`FilesSource`]), this reflects the database's state, not just this one package's.
    /// It exists for the same reason [`crate::LocalPackage::is_desc_loaded`] does: proving,
    /// from outside the crate, that opening a database does not load what it should not.
    #[must_use]
    pub fn is_files_loaded(&self) -> bool {
        self.files.lazy.is_loaded()
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

    fn entry(raw: &str) -> EntryName {
        EntryName::parse(raw).unwrap()
    }

    fn a_repo_name() -> RepoName {
        RepoName::parse("core").unwrap()
    }

    #[test]
    fn is_send_and_sync() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RepoPackage>();
    }

    #[test]
    fn file_list_reports_unavailable_when_there_is_no_files_archive() {
        let files = Arc::new(FilesSource::unavailable(a_repo_name(), Limits::default()));
        let package = package_at("foo", "1.0.0-1", files);

        let err = package.file_list().unwrap_err();
        assert!(matches!(&*err, Error::FilesUnavailable { .. }), "got {err:?}");
    }

    #[test]
    fn a_preloaded_source_serves_without_any_further_io() {
        let mut arena = FilesArena::new();
        arena
            .insert(
                std::path::Path::new("x"),
                Name::from_str("foo").unwrap(),
                FullVersion::from_str("1.0.0-1").unwrap(),
                &[std::path::PathBuf::from("usr/bin/foo")],
                1024,
            )
            .unwrap();

        let files = Arc::new(FilesSource::preloaded(a_repo_name(), Limits::default(), arena));
        let package = package_at("foo", "1.0.0-1", files);

        let found: Vec<_> = package.file_list().unwrap().collect();
        assert_eq!(found, [std::path::Path::new("usr/bin/foo")]);
    }

    /// Builds a package the way [`super::super::database`] does: eager fields parsed now,
    /// the text retained to back the deferred parse.
    fn package_at(name: &str, version: &str, files: Arc<FilesSource>) -> RepoPackage {
        let eager = super::super::eager::parse(MINIMAL_DESC).unwrap();
        RepoPackage::new(entry(&format!("{name}-{version}")), eager, MINIMAL_DESC.into(), files)
    }

    #[test]
    fn file_lists_for_serves_a_preloaded_source_with_no_further_io() {
        let mut arena = FilesArena::new();
        arena
            .insert(
                Path::new("x"),
                Name::from_str("foo").unwrap(),
                FullVersion::from_str("1.0.0-1").unwrap(),
                &[PathBuf::from("usr/bin/foo")],
                1024,
            )
            .unwrap();
        arena
            .insert(
                Path::new("x"),
                Name::from_str("bar").unwrap(),
                FullVersion::from_str("2.0.0-1").unwrap(),
                &[PathBuf::from("usr/bin/bar")],
                1024,
            )
            .unwrap();

        let files = Arc::new(FilesSource::preloaded(a_repo_name(), Limits::default(), arena));
        let foo = package_at("foo", "1.0.0-1", Arc::clone(&files));
        let bar = package_at("bar", "2.0.0-1", Arc::clone(&files));

        let results = files.file_lists_for(&[&foo, &bar]);

        assert_eq!(results.len(), 2);
        let foo_paths = results.iter().find(|(name, _)| name.as_ref() == "foo").unwrap();
        assert_eq!(foo_paths.1.as_ref().unwrap(), &[PathBuf::from("usr/bin/foo")]);
        let bar_paths = results.iter().find(|(name, _)| name.as_ref() == "bar").unwrap();
        assert_eq!(bar_paths.1.as_ref().unwrap(), &[PathBuf::from("usr/bin/bar")]);
    }

    #[test]
    fn file_lists_for_performs_a_fresh_walk_without_caching_the_partial_result() {
        let fixture = crate::fixture::RepoFixture::new();
        let archive_path = fixture.write_gzip_archive(
            "core.files",
            &[
                ("foo-1.0.0-1/files", b"%FILES%\nusr/\nusr/bin/\nusr/bin/foo\n\n"),
                ("bar-2.0.0-1/files", b"%FILES%\nusr/\nusr/bin/\nusr/bin/bar\n\n"),
            ],
        );

        let files = Arc::new(FilesSource::deferred(a_repo_name(), archive_path, Limits::default()));
        let foo = package_at("foo", "1.0.0-1", Arc::clone(&files));

        let mut results = files.file_lists_for(&[&foo]);
        assert_eq!(results.len(), 1);
        let (name, result) = results.pop().unwrap();
        assert_eq!(name.as_ref(), "foo");
        assert_eq!(
            result.unwrap(),
            [PathBuf::from("usr/"), PathBuf::from("usr/bin/"), PathBuf::from("usr/bin/foo")]
        );

        // A batch lookup must never populate the shared, whole-database cache: it may have
        // covered only part of the archive, and a later request for `bar` must still trigger
        // its own load rather than see a false `FilesMissingForPackage` from a partial arena.
        assert!(!foo.is_files_loaded(), "a targeted walk must not mark the shared arena loaded");
    }

    #[test]
    fn file_lists_for_reuses_an_already_loaded_arena_with_no_further_io() {
        let fixture = crate::fixture::RepoFixture::new();
        let archive_path = fixture.write_gzip_archive(
            "core.files",
            &[("foo-1.0.0-1/files", b"%FILES%\nusr/\nusr/bin/\nusr/bin/foo\n\n")],
        );

        let files =
            Arc::new(FilesSource::deferred(a_repo_name(), archive_path.clone(), Limits::default()));
        let foo = package_at("foo", "1.0.0-1", Arc::clone(&files));

        // Force the full, shared load once, the ordinary way.
        assert!(foo.file_list().is_ok());
        assert!(foo.is_files_loaded());

        // Now remove the archive from disk entirely: if the batch path re-walked it, this
        // would fail with an I/O error instead of serving the cached answer.
        std::fs::remove_file(&archive_path).unwrap();

        let mut results = files.file_lists_for(&[&foo]);
        assert_eq!(results.len(), 1);
        let (name, result) = results.pop().unwrap();
        assert_eq!(name.as_ref(), "foo");
        assert_eq!(
            result.unwrap(),
            [PathBuf::from("usr/"), PathBuf::from("usr/bin/"), PathBuf::from("usr/bin/foo")]
        );
    }

    #[test]
    fn file_lists_for_replays_a_cached_failure_instead_of_retrying() {
        let files = Arc::new(FilesSource::deferred(
            a_repo_name(),
            PathBuf::from("/nonexistent/core.files"),
            Limits::default(),
        ));
        let foo = package_at("foo", "1.0.0-1", Arc::clone(&files));

        let first = foo.file_list().unwrap_err();
        let results = files.file_lists_for(&[&foo]);

        assert_eq!(results.len(), 1);
        let second = results.into_iter().next().unwrap().1.unwrap_err();
        assert!(
            SharedError::ptr_eq(&first, &second),
            "the same cached failure must be reused, not retried"
        );
    }

    #[test]
    fn file_lists_for_reports_version_skew_rather_than_missing() {
        let fixture = crate::fixture::RepoFixture::new();
        let archive_path = fixture.write_gzip_archive(
            "core.files",
            &[("foo-2.0.0-1/files", b"%FILES%\nusr/\nusr/bin/\nusr/bin/foo\n\n")],
        );

        let files = Arc::new(FilesSource::deferred(a_repo_name(), archive_path, Limits::default()));
        // The database itself says `foo` is at 1.0.0-1, but the archive holds 2.0.0-1.
        let foo = package_at("foo", "1.0.0-1", Arc::clone(&files));

        let results = files.file_lists_for(&[&foo]);
        let (_, result) = results.into_iter().next().unwrap();
        assert!(matches!(&*result.unwrap_err(), Error::FilesVersionSkew { .. }));
    }

    /// A minimal, well-formed v2 `desc`, as text. A package is built from this text.
    const MINIMAL_DESC: &str = "%FILENAME%\nfoo-1.0.0-1-x86_64.pkg.tar.zst\n\n\
         %NAME%\nfoo\n\n\
         %BASE%\nfoo\n\n\
         %VERSION%\n1.0.0-1\n\n\
         %DESC%\nAn example package\n\n\
         %CSIZE%\n1\n\n\
         %ISIZE%\n1\n\n\
         %SHA256SUM%\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n\
         %URL%\nhttps://example.org/\n\n\
         %ARCH%\nx86_64\n\n\
         %BUILDDATE%\n1\n\n\
         %PACKAGER%\nFoobar McFooface <foobar@mcfooface.org>\n\n";

    /// The deferred parse must not have run merely because a package exists.
    #[test]
    fn opening_a_package_does_not_parse_its_deferred_desc() {
        let files = Arc::new(FilesSource::unavailable(a_repo_name(), Limits::default()));
        let package = package_at("foo", "1.0.0-1", files);

        assert!(!package.is_desc_loaded(), "desc must not be parsed until asked for");
        let _ = package.depends();
        let _ = package.provides();
        let _ = package.groups();
        let _ = package.compressed_size();
        assert!(!package.is_desc_loaded(), "the eager accessors must not force the parse");

        assert!(package.desc().is_ok());
        assert!(package.is_desc_loaded(), "asking for desc must load it");
    }

    /// `%DEPENDS%` is deferred like the rest of `desc`, so a package malformed only there is
    /// kept at open and fails when its dependencies are read — cached, not retried.
    #[test]
    fn a_malformed_depends_fails_on_access_and_is_cached() {
        let text = format!("{MINIMAL_DESC}%DEPENDS%\nbash>=\n\n");
        let files = Arc::new(FilesSource::unavailable(a_repo_name(), Limits::default()));
        let Ok(eager) = super::super::eager::parse(&text) else {
            panic!("a malformed %DEPENDS% must not fail the open")
        };
        let package = RepoPackage::new(entry("foo-1.0.0-1"), eager, text.into(), files);

        assert_eq!(package.compressed_size(), 1, "the eager fields still work");

        let first = package.depends().unwrap_err();
        let second = package.depends().unwrap_err();
        assert!(matches!(&*first, Error::RepoDescFields { .. }), "got {first:?}");
        assert!(Arc::ptr_eq(&first, &second), "the failure must be cached, not retried");
        assert!(!package.is_desc_loaded(), "a %DEPENDS% failure must not force the full parse");
    }

    /// A `desc` that is well-formed in its eager sections but broken in a deferred one is
    /// kept, and reports the failure identically on every access rather than retrying it.
    #[test]
    fn a_deferred_parse_failure_is_cached_not_retried() {
        // `%PACKAGER%` is mandatory to `alpm-repo-db` but is not one of the eager fields, so
        // removing it produces exactly the split this test is about.
        let text =
            MINIMAL_DESC.replace("%PACKAGER%\nFoobar McFooface <foobar@mcfooface.org>\n\n", "");
        let files = Arc::new(FilesSource::unavailable(a_repo_name(), Limits::default()));
        let eager = super::super::eager::parse(&text).unwrap();
        let package = RepoPackage::new(entry("foo-1.0.0-1"), eager, text.into(), files);

        assert_eq!(package.compressed_size(), 1, "the eager fields still work");

        let first = package.desc().unwrap_err();
        let second = package.desc().unwrap_err();
        assert!(matches!(&*first, Error::RepoDescUnparsable { .. }), "got {first:?}");
        assert!(SharedError::ptr_eq(&first, &second), "the failure must be cached, not retried");
    }
}
