//! A repository (sync) database: the packages described by one `.db` or `.files` archive.

use std::{
    cell::RefCell,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use alpm_repo_db::files::RepoFilesV1;
use alpm_types::Name;

use super::{
    archive::{self, ArchiveItem, SkipReason, Skipped},
    desc_compat,
    files_arena::FilesArena,
    package::{FilesSource, RepoPackage},
    repo_name::RepoName,
    search::{self, SearchHit},
};
use crate::{
    desc_compat::{UnknownSection, UnknownSectionPolicy},
    diagnostics::Sink,
    eager::{RelationBudget, ScanError},
    entry_name::EntryNameError,
    error::{Error, IoAction, Result, SharedError},
    limits::Limits,
};

/// One package's file-list lookup result, as returned by [`RepoDatabase::file_lists`].
pub type FileListEntry = (Name, std::result::Result<Vec<PathBuf>, SharedError>);

/// Which repository database variant was opened.
///
/// Per [alpm-repo-db], _default_ carries only `desc` entries. _Default with files_ carries `desc`
/// **and** `files`. The [`RepoDatabase`] variant follows from what the archive actually contains,
/// never from the file name. The archive is the only thing that cannot be wrong about its own
/// contents.
///
/// [alpm-repo-db]: https://alpm.archlinux.page/specifications/alpm-repo-db.7.html
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Variant {
    /// One `desc` per package. File lists come from a sibling `.files` archive, or are
    /// unavailable.
    Default,
    /// `desc` **and** `files` per package, both loaded from the one archive that was opened.
    DefaultWithFiles,
}

/// Something suspicious found while reading a repository archive, which did not stop the open.
///
/// Mirrors [`crate::Diagnostic`] for the same reason. It is returned, never logged, so the caller
/// decides how to present it, and whether to.
#[derive(Debug)]
#[non_exhaustive]
pub enum RepoDiagnostic {
    /// A tar member's path was not valid UTF-8.
    NonUtf8Path {
        /// A placeholder, since the real path could not be decoded.
        path: String,
    },
    /// A tar member's path was not `<name>-<version>/desc` or `<name>-<version>/files`.
    UnexpectedShape {
        /// The member's path.
        path: String,
    },
    /// A tar member's directory component was not a valid entry name.
    InvalidEntryName {
        /// The member's path.
        path: String,
        /// Why it was rejected.
        source: EntryNameError,
    },
    /// A tar member was a symlink, hard link, device node or FIFO, not a regular file.
    NotARegularFile {
        /// The member's path.
        path: String,
    },
    /// The same tar member path appeared more than once in the archive.
    DuplicateMember {
        /// The repeated path. Only the first occurrence was read.
        path: String,
    },
    /// A `desc` member could not be parsed, so that package was dropped.
    ///
    /// Unlike the local database, a repository package's `desc` is read eagerly, because
    /// reading the archive at all requires decompressing it. So there is no lazy slot to
    /// carry a per-package failure in. One bad `desc` must not make the other thousands
    /// unreadable, so the package is dropped and reported here instead.
    InvalidDesc {
        /// The entry directory name of the dropped package.
        entry: String,
        /// The underlying parse failure.
        ///
        /// A [`super::DescFieldError`], not an `alpm_repo_db::Error`. The full typed parse is
        /// deferred to [`super::RepoPackage::desc`]. So the only `desc` failure that can still drop
        /// a package at open time is one in a field read eagerly. A failure in a deferred section
        /// surfaces as [`Error::RepoDescUnparsable`] on access instead.
        source: crate::eager::DescFieldError,
    },
    /// A `files` member could not be parsed.
    ///
    /// The package itself is **not** dropped — its `desc` may still be valid. Its file list becomes
    /// permanently unavailable instead, surfaced as [`Error::FilesMissingForPackage`] when asked
    /// for.
    InvalidFiles {
        /// The entry directory name whose `files` member failed to parse.
        entry: String,
        /// The underlying parse failure.
        source: alpm_repo_db::files::Error,
    },
    /// A `desc` contained a section this build does not recognise.
    UnknownDescSection {
        /// The entry directory name.
        entry: String,
        /// The section that was dropped.
        section: UnknownSection,
    },
    /// Two entry directories in this archive claim the same package name.
    ///
    /// Only the first, in scan order, is kept. This mirrors
    /// [`crate::Diagnostic::DuplicateEntry`], with one difference. The order here is the archive's
    /// own member order, because a tar stream cannot be sorted before it is fully read.
    DuplicatePackage {
        /// The package name claimed twice.
        name: Name,
        /// The entry directory that was kept.
        kept: String,
        /// The entry directory that was ignored.
        ignored: String,
    },
}

impl std::fmt::Display for RepoDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonUtf8Path { path } => write!(f, "archive member {path:?} is not valid UTF-8"),
            Self::UnexpectedShape { path } => {
                write!(f, "archive member {path:?} is not a <name>-<version>/desc or /files entry")
            }
            Self::InvalidEntryName { path, source } => {
                write!(f, "invalid entry name in archive member {path:?}: {source}")
            }
            Self::NotARegularFile { path } => {
                write!(f, "archive member {path:?} is not a regular file, ignoring it")
            }
            Self::DuplicateMember { path } => {
                write!(f, "archive member {path:?} appears more than once; only the first was read")
            }
            Self::InvalidDesc { entry, source } => {
                write!(f, "{entry}: failed to parse desc, dropping the package: {source}")
            }
            Self::InvalidFiles { entry, source } => {
                write!(f, "{entry}: failed to parse files: {source}")
            }
            Self::UnknownDescSection { entry, section } => {
                write!(f, "{entry}: unknown section %{}% on line {}", section.keyword, section.line)
            }
            Self::DuplicatePackage { name, kept, ignored } => {
                write!(
                    f,
                    "duplicated package {name} in archive: keeping {kept}, ignoring {ignored}"
                )
            }
        }
    }
}

/// How to open a [`RepoDatabase`].
///
/// ```
/// use piko_db::{Limits, UnknownSectionPolicy, repo::RepoOpenOptions};
///
/// let options = RepoOpenOptions::new()
///     .limits(Limits::default())
///     .unknown_sections(UnknownSectionPolicy::Reject);
/// ```
#[derive(Clone, Default)]
pub struct RepoOpenOptions {
    limits: Limits,
    unknown_sections: UnknownSectionPolicy,
    check: Option<ArchiveCheck>,
}

/// A test run on a repository archive before any of its bytes are read.
///
/// It gets the path of the archive about to be read, and refuses it with an error of its own.
/// The typical check is a signature check. An accepted archive comes back with the time the
/// check can vouch it was made, a verified signature's creation time, or `None`. The database
/// keeps it: see [`RepoDatabase::publication`].
pub type ArchiveCheck = Arc<
    dyn Fn(
            &Path,
        )
            -> std::result::Result<Option<SystemTime>, Box<dyn std::error::Error + Send + Sync>>
        + Send
        + Sync,
>;

impl std::fmt::Debug for RepoOpenOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoOpenOptions")
            .field("limits", &self.limits)
            .field("unknown_sections", &self.unknown_sections)
            .field("check", &self.check.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

impl RepoOpenOptions {
    /// Default options: standard limits, tolerate unknown `desc` sections.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the resource limits applied while reading the archive.
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets what happens when a `desc` entry contains an unrecognised `%SECTION%`.
    #[must_use]
    pub const fn unknown_sections(mut self, policy: UnknownSectionPolicy) -> Self {
        self.unknown_sections = policy;
        self
    }

    /// Sets the test run on each archive before it is read.
    ///
    /// It covers every archive the database reads: the one opened, and a sibling `<repo>.files`
    /// when its file lists are first asked for. libalpm validates a database when it registers
    /// it, before it reads a package out of it (`be_sync.c:758`). A check here runs at the same
    /// point, so the decompressor and the parsers never see bytes the check refuses.
    #[must_use]
    pub fn check(mut self, check: ArchiveCheck) -> Self {
        self.check = Some(check);
        self
    }
}

/// Runs `check` on `path`, if there is one, and returns the time it vouched for.
pub(super) fn run_check(check: Option<&ArchiveCheck>, path: &Path) -> Result<Option<SystemTime>> {
    match check {
        Some(check) => check(path).map_err(|source| Error::ArchiveRefused { source }),
        None => Ok(None),
    }
}

/// An open repository (sync) database.
///
/// Opening decompresses and walks the archive **once**, parsing every `desc` on the way through. A
/// gzip-over-tar stream allows no random access. So enumerating packages at all already costs a
/// full decompression, and parsing each `desc` while already there costs little more. File lists
/// are the exception. See [`RepoPackage::file_list`] for why they are loaded lazily and shared,
/// rather than eagerly like `desc`.
///
/// The package set is immutable and the type is `Send + Sync`, so a `&RepoDatabase` may be
/// shared freely across threads.
#[derive(Debug)]
pub struct RepoDatabase {
    repo: RepoName,
    variant: Variant,
    path: PathBuf,
    /// Sorted by package name, and unique on it.
    packages: Box<[RepoPackage]>,
    diagnostics: Box<[RepoDiagnostic]>,
    /// How many diagnostics were found beyond [`Limits::max_diagnostics`] and so not kept.
    diagnostics_dropped: usize,
    /// The newest member modification time in the archive, recorded during the open.
    newest_member_time: Option<u64>,
    /// The time the [`ArchiveCheck`] vouched for when it accepted the archive.
    signed_at: Option<SystemTime>,
    /// The same `Arc` every [`RepoPackage`] in `packages` holds a clone of. Kept here too so
    /// [`Self::file_lists`] can recognise a package that was **not** produced by this
    /// database — see there.
    files_source: Arc<FilesSource>,
}

impl RepoDatabase {
    /// Opens an explicit `.db` or `.files` archive with default [`RepoOpenOptions`].
    ///
    /// The repository name is derived from the file name itself (`core.db` → `core`). Every real
    /// repository archive is named exactly `<repo>.db` or `<repo>.files`. The name never comes from
    /// the archive's own contents, which carry no repository name at all.
    ///
    /// The [`Variant`] **is** taken from the archive's own contents; see [`Variant`]. Say `path` is
    /// a `.db` archive and a sibling `<repo>.files` sits next to it. That sibling is then wired up
    /// for deferred loading, exactly as [`RepoDatabase::open_repo`] does. So opening
    /// `/var/lib/pacman/sync/core.db` directly gets the same lazy file-list behavior as
    /// opening it through a directory and repository name. Only its *presence* is checked at
    /// open time — one stat, not a read. Its contents are read on the first
    /// [`RepoPackage::file_list`] call, if ever.
    ///
    /// # Errors
    ///
    /// See [`RepoDatabase::open_with`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(path, RepoOpenOptions::new())
    }

    /// Opens an explicit `.db` or `.files` archive.
    ///
    /// # Errors
    ///
    /// - [`Error::UnrecognisedArchiveName`] if `path`'s file name is not `<repo>.db` or
    ///   `<repo>.files`.
    /// - [`Error::UnsupportedCompression`] if the archive's compression is not gzip, zstd or
    ///   none.
    /// - [`Error::LimitExceeded`] if the archive, or any one member, exceeds the configured
    ///   [`Limits`].
    /// - [`Error::TooManyEntries`] if the archive holds more packages than
    ///   [`Limits::repo_max_packages`] allows. Detected during the walk, so the rest of an
    ///   oversized archive is never decompressed or parsed.
    /// - [`Error::TooManyRelations`] if the archive's `desc` members together hold more
    ///   relation entries than [`Limits::repo_max_relations`] allows. Each entry is counted
    ///   before it is parsed.
    /// - [`Error::TooManyPaths`] or [`Error::TooManyEntryPaths`] if its `files` members exceed
    ///   [`Limits::repo_max_paths`] or [`Limits::repo_entry_paths`].
    /// - [`Error::Io`] if the archive cannot be opened or read.
    ///
    /// Problems with individual entries are reported through
    /// [`diagnostics`](RepoDatabase::diagnostics) and do not fail the open.
    pub fn open_with(path: impl AsRef<Path>, options: RepoOpenOptions) -> Result<Self> {
        let path = path.as_ref();
        let repo = repo_name_from_path(path)?;
        Self::build(path, repo, options, sibling_files_path(path))
    }

    /// Opens the database for `repo` inside `dir`, preferring `<repo>.db`.
    ///
    /// If `<repo>.db` exists, this opens it and defers file lists to a sibling
    /// `<repo>.files`. That sibling loads only when [`RepoPackage::file_list`] is actually
    /// called, and the load is shared across every package. If `<repo>.db` does not exist, this
    /// falls back to `<repo>.files`. That single archive already carries both `desc` and `files`, so
    /// everything is populated in that one pass.
    ///
    /// # Errors
    ///
    /// As [`RepoDatabase::open_with`]. If neither `<repo>.db` nor `<repo>.files` exists, that same
    /// "file not found" error names `<repo>.db`. That is the name the caller actually asked to open,
    /// and `<repo>.files` is only ever an internal fallback.
    pub fn open_repo(dir: impl AsRef<Path>, repo: &RepoName) -> Result<Self> {
        Self::open_repo_with(dir, repo, RepoOpenOptions::new())
    }

    /// As [`RepoDatabase::open_repo`], with explicit [`RepoOpenOptions`].
    ///
    /// # Errors
    ///
    /// As [`RepoDatabase::open_repo`].
    pub fn open_repo_with(
        dir: impl AsRef<Path>,
        repo: &RepoName,
        options: RepoOpenOptions,
    ) -> Result<Self> {
        let path = Self::locate(dir.as_ref(), repo)?;
        Self::open_with(path, options)
    }

    /// The archive [`RepoDatabase::open_repo`] opens for `repo` in `dir`: `<repo>.db`, or
    /// `<repo>.files` when `<repo>.db` does not exist.
    ///
    /// Only the presence of each is tested, with one `stat` each. Nothing is read.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if `<repo>.db` cannot be tested, or if neither archive exists. When neither
    /// exists, the error names `<repo>.db`, as [`RepoDatabase::open_repo`] documents.
    pub fn locate(dir: &Path, repo: &RepoName) -> Result<PathBuf> {
        let db_path = dir.join(format!("{repo}.db"));
        let db_error = match std::fs::metadata(&db_path) {
            Ok(_) => return Ok(db_path),
            Err(error) => error,
        };
        if db_error.kind() != ErrorKind::NotFound {
            return Err(Error::io(db_path, IoAction::Open, db_error));
        }

        // `.db` itself does not exist. Some repositories publish only the combined `.files`
        // archive, so try that before giving up. If `.files` is missing too, report the `.db`
        // error rather than this one. `.db` is the name every caller actually asked for.
        // `.files` is an internal fallback the caller never requested. Blaming it makes a plain
        // "no such repository" read as if piko needed a file list just to search.
        let files_path = dir.join(format!("{repo}.files"));
        match std::fs::metadata(&files_path) {
            Ok(_) => Ok(files_path),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                Err(Error::io(db_path, IoAction::Open, db_error))
            }
            Err(error) => Err(Error::io(files_path, IoAction::Open, error)),
        }
    }

    /// Walks `path` once, building the package list. If the archive turns out to carry `files`
    /// members, it builds the shared file-list arena in the same pass.
    ///
    /// `deferred_files_path` is the sibling `<repo>.files` to wire up for a lazy load. Only
    /// [`RepoDatabase::open_repo_with`] ever sets it. It takes effect only if `path` itself carried
    /// no `files` members, which means it was a plain `.db` archive.
    fn build(
        path: &Path,
        repo: RepoName,
        options: RepoOpenOptions,
        deferred_files_path: Option<PathBuf>,
    ) -> Result<Self> {
        let signed_at = run_check(options.check.as_ref(), path)?;

        let mut entries: Vec<StagedDesc> = Vec::new();
        let mut arena = FilesArena::new();
        let mut saw_files_member = false;
        // Shared, not `&mut`, because `on_item` and `on_skip` are two separate closures that
        // both need to push diagnostics. They cannot both hold a `&mut Sink` at once. They can
        // both hold a `&RefCell<Sink<_>>`, and borrow it mutably only for the push.
        let diagnostics = RefCell::new(Sink::new(&options.limits));
        // One budget for the whole archive, because the bound is on the sum over its packages.
        let mut relations = RelationBudget::new(options.limits.repo_max_relations);

        let newest_member_time = archive::walk(
            path,
            &options.limits,
            |item| {
                handle_item(
                    item,
                    &options,
                    &mut entries,
                    &mut arena,
                    &mut relations,
                    &diagnostics,
                    &mut saw_files_member,
                    path,
                )
            },
            |skipped| diagnostics.borrow_mut().push(|| translate_skip(skipped)),
        )?;

        let mut diagnostics = diagnostics.into_inner();

        // A stable sort by name alone: of two entries of one name, the first in archive order
        // stays first, and `drop_duplicates` keeps it, as the files arena does.
        entries.sort_by(|left, right| left.entry.name().cmp(right.entry.name()));
        crate::diagnostics::drop_duplicates(
            &mut entries,
            |staged| &staged.entry,
            &mut diagnostics,
            |name, kept, ignored| RepoDiagnostic::DuplicatePackage { name, kept, ignored },
        );

        let (variant, files_source) = if saw_files_member {
            (Variant::DefaultWithFiles, FilesSource::preloaded(repo.clone(), options.limits, arena))
        } else if let Some(deferred) = deferred_files_path {
            (
                Variant::Default,
                FilesSource::deferred(repo.clone(), deferred, options.limits, options.check),
            )
        } else {
            (Variant::Default, FilesSource::unavailable(repo.clone(), options.limits))
        };
        let files_source = Arc::new(files_source);

        let packages: Box<[RepoPackage]> = entries
            .into_iter()
            .map(|staged| {
                RepoPackage::new(staged.entry, staged.eager, staged.raw, Arc::clone(&files_source))
            })
            .collect();

        let (diagnostics, diagnostics_dropped) = diagnostics.finish();

        Ok(Self {
            repo,
            variant,
            path: path.to_path_buf(),
            packages,
            diagnostics,
            diagnostics_dropped,
            newest_member_time,
            signed_at,
            files_source,
        })
    }

    /// The repository name this database was opened for.
    #[must_use]
    pub const fn name(&self) -> &RepoName {
        &self.repo
    }

    /// Which variant the opened archive turned out to be.
    #[must_use]
    pub const fn variant(&self) -> Variant {
        self.variant
    }

    /// The archive path that was actually opened.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The newest modification time of any member of the opened archive, in seconds since the
    /// Unix epoch.
    ///
    /// `repo-add` writes a new entry at the time it runs and keeps the time of every entry it
    /// copies. So this is when the repository last published a package. Measured on `core.db`
    /// and `extra.db`, it matches the mirror's `Last-Modified` to within one second. `None`
    /// means every member carries time zero, which some reproducible archive builders write.
    ///
    /// It is authenticated only as far as the archive is. For an unsigned database, the mirror
    /// chose it. See [`crate::repo::freshness`] for how it is used.
    #[must_use]
    pub const fn newest_member_time(&self) -> Option<u64> {
        self.newest_member_time
    }

    /// When this database was published, as [`crate::repo::freshness::Publication`] dates it.
    ///
    /// The signature time comes from the [`ArchiveCheck`] that accepted the archive, before it
    /// was read. So it dates the same bytes the packages came from, with no second check. With
    /// no check, or a check that vouched for no time, the newest member time dates it.
    #[must_use]
    pub fn publication(&self) -> Option<super::freshness::Publication> {
        super::freshness::Publication::new(self.signed_at, self.newest_member_time)
    }

    /// Looks up a package by name.
    #[must_use]
    pub fn get(&self, name: &Name) -> Option<&RepoPackage> {
        self.packages
            .binary_search_by(|package| package.name().cmp(name))
            .ok()
            .and_then(|index| self.packages.get(index))
    }

    /// Looks up a package by name, parsing `name` first.
    ///
    /// Returns `None` if `name` is not a valid package name.
    #[must_use]
    pub fn get_str(&self, name: &str) -> Option<&RepoPackage> {
        name.parse::<Name>().ok().and_then(|name| self.get(&name))
    }

    /// Iterates over packages, ordered by name.
    pub fn iter(&self) -> std::slice::Iter<'_, RepoPackage> {
        self.packages.iter()
    }

    /// The number of packages in this database.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.packages.len()
    }

    /// Whether the database holds no packages.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// Problems found while reading the archive that did not prevent it from opening.
    ///
    /// Bounded by [`Limits::max_diagnostics`]; see
    /// [`diagnostics_dropped`](RepoDatabase::diagnostics_dropped) for what that bound hid.
    #[must_use]
    pub const fn diagnostics(&self) -> &[RepoDiagnostic] {
        &self.diagnostics
    }

    /// How many further problems were found beyond [`Limits::max_diagnostics`] and so are not
    /// in [`diagnostics`](RepoDatabase::diagnostics).
    ///
    /// Non-zero only for an archive holding thousands of unusable members, which is not a
    /// shape a real repository takes. It is reported rather than silently truncated so a
    /// caller is never left believing it has seen every problem.
    #[must_use]
    pub const fn diagnostics_dropped(&self) -> usize {
        self.diagnostics_dropped
    }

    /// Returns the file list for each of `packages`, touching as little of the `.files`
    /// archive as the requested set allows.
    ///
    /// Calling [`RepoPackage::file_list`] on every package in a loop force-loads and caches the
    /// shared file-list arena for the *whole* repository. This does not. It performs, or
    /// reuses, a walk scoped to exactly `packages`. Prefer it when only a handful of a large
    /// repository's packages are actually needed. Resolving a dependency set is that case, rather
    /// than listing everything.
    ///
    /// The result preserves `packages`' order, including repeats, if `packages` names the same one
    /// twice. Each package's own entry can independently be [`Error::FilesUnavailable`],
    /// [`Error::FilesMissingForPackage`] or [`Error::FilesVersionSkew`]. Those are the same errors
    /// [`RepoPackage::file_list`] returns, for the same reasons. It can also be
    /// [`Error::ForeignPackage`]. That means the package passed in was not produced by *this*
    /// database, and so does not share its `.files` archive at all.
    #[must_use]
    pub fn file_lists<'a>(
        &self,
        packages: impl IntoIterator<Item = &'a RepoPackage>,
    ) -> Vec<FileListEntry> {
        // Every `RepoPackage` this database produced shares the identical `Arc` below. It is
        // built once in `build` and cloned into each one. A package that does not share it came
        // from a different `RepoDatabase`, or a different `open` of the same archive. It must
        // never be resolved against this one's arena. Doing so would silently cross two
        // repositories' file lists. That is the same class of mistake the `.db`/`.files`
        // version-skew check catches one layer down, before any archive is even touched.
        let (ours, foreign): (Vec<_>, Vec<_>) = packages
            .into_iter()
            .enumerate()
            .partition(|(_, package)| Arc::ptr_eq(package.files_source(), &self.files_source));

        let mut tagged: Vec<(usize, FileListEntry)> = foreign
            .into_iter()
            .map(|(index, package)| {
                let name = package.name().clone();
                let error = SharedError::new(Error::ForeignPackage { name: name.clone() });
                (index, (name, Err(error)))
            })
            .collect();

        let ours_indices: Vec<usize> = ours.iter().map(|(index, _)| *index).collect();
        let ours_packages: Vec<&RepoPackage> =
            ours.into_iter().map(|(_, package)| package).collect();
        let resolved = self.files_source.file_lists_for(&ours_packages);
        tagged.extend(ours_indices.into_iter().zip(resolved));

        tagged.sort_by_key(|(index, _)| *index);
        tagged.into_iter().map(|(_, item)| item).collect()
    }

    /// Searches for packages matching every one of `terms`, ranked by relevance.
    ///
    /// A package must match **all** of `terms` (AND, not OR) to be included at all. Searching
    /// `["firefox", "browser"]` only returns packages that independently satisfy both. See
    /// [`crate::MatchKind`] for the six ways a single term can match, and their relative ranking.
    /// Highest first: an exact name match, then an exact match against one of its `%PROVIDES%`.
    /// Then a name prefix, a name substring, a description substring, and an exact group match.
    /// Comparisons are
    /// case-insensitive. Blank terms are dropped; if nothing is left after that, nothing matches.
    /// Each package appears at most once, scored by the single highest [`crate::MatchKind`] any one
    /// of its terms achieved. Results are sorted most-relevant-first, then by name to break ties
    /// deterministically.
    #[must_use]
    pub fn search<'q>(&self, terms: impl IntoIterator<Item = &'q str>) -> Vec<SearchHit<'_>> {
        search::search(&self.packages, terms)
    }
}

impl<'a> IntoIterator for &'a RepoDatabase {
    type Item = &'a RepoPackage;
    type IntoIter = std::slice::Iter<'a, RepoPackage>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// One `desc` member staged during the archive walk, before packages are built.
///
/// Holds the *eager* fields already parsed, and the filtered text they came from. That text
/// is what [`RepoPackage`] retains to back its deferred [`RepoPackage::desc`].
#[derive(Debug)]
struct StagedDesc {
    entry: crate::entry_name::EntryName,
    eager: super::eager::EagerFields,
    raw: Box<str>,
}

/// Handles one item from the archive walk: a `desc` is parsed and staged, a `files` member is
/// inserted into the in-progress arena.
#[expect(
    clippy::too_many_arguments,
    reason = "an internal helper threading the build's local state through one callback; splitting it would need a struct with the same fields"
)]
fn handle_item(
    item: ArchiveItem,
    options: &RepoOpenOptions,
    entries: &mut Vec<StagedDesc>,
    arena: &mut FilesArena,
    relations: &mut RelationBudget,
    diagnostics: &RefCell<Sink<RepoDiagnostic>>,
    saw_files_member: &mut bool,
    archive_path: &Path,
) -> Result<()> {
    use std::str::FromStr as _;

    match item {
        ArchiveItem::Desc { entry, text } => {
            // Enforced here rather than after the walk. The bound exists to stop the
            // allocation, so it must fire before every `desc` in an oversized archive gets
            // parsed. `on_item`'s `Result` exists for exactly this: it aborts the walk,
            // leaving the rest of the archive undecompressed.
            if entries.len() >= options.limits.repo_max_packages {
                return Err(Error::TooManyEntries {
                    path: archive_path.to_path_buf(),
                    max: options.limits.repo_max_packages,
                });
            }

            let (filtered, unknown) = match options.unknown_sections {
                UnknownSectionPolicy::Reject => (text, Vec::new()),
                UnknownSectionPolicy::Warn => crate::desc_compat::filter_unknown_sections(
                    &text,
                    desc_compat::is_known_section,
                ),
            };

            // Only the fields every package needs are converted here. The rest stay as text
            // and are parsed on first access to `RepoPackage::desc`. That split accounts for
            // 67% of this open's cost on a real repository. See `super::eager` for the
            // measurement, and for why deferring *everything* would not have worked.
            match super::eager::parse(&filtered, relations) {
                Ok(eager) => {
                    let mut diagnostics = diagnostics.borrow_mut();
                    for section in unknown {
                        diagnostics.push(|| RepoDiagnostic::UnknownDescSection {
                            entry: entry.as_str().to_owned(),
                            section,
                        });
                    }
                    drop(diagnostics);
                    entries.push(StagedDesc { entry, eager, raw: filtered.into_boxed_str() });
                }
                Err(ScanError::Field(source)) => {
                    diagnostics.borrow_mut().push(|| RepoDiagnostic::InvalidDesc {
                        entry: entry.as_str().to_owned(),
                        source,
                    });
                }
                // Not a diagnostic: the budget is the archive's, so the next `desc` would parse
                // past it. The open fails, as it does for `repo_max_packages`.
                Err(ScanError::Budget { max }) => {
                    return Err(Error::TooManyRelations { path: archive_path.to_path_buf(), max });
                }
            }
        }
        ArchiveItem::Files { entry, text } => {
            *saw_files_member = true;
            match RepoFilesV1::from_str(&text) {
                Ok(parsed) => {
                    // A second entry of one name is dropped here and reported once, by
                    // `drop_duplicates`, which keeps the same entry.
                    arena.insert(
                        archive_path,
                        entry.name().clone(),
                        entry.version().clone(),
                        parsed.as_ref(),
                        options.limits.repo_inflated_bytes,
                        options.limits.repo_max_paths,
                    )?;
                }
                Err(source) => {
                    diagnostics.borrow_mut().push(|| RepoDiagnostic::InvalidFiles {
                        entry: entry.as_str().to_owned(),
                        source,
                    });
                }
            }
        }
    }
    Ok(())
}

/// If `path` names a `.db` archive and a sibling `<repo>.files` exists next to it, returns
/// that sibling's path.
///
/// Only presence is checked here — one `stat`, not a read — so this does not compromise
/// laziness. The sibling's contents are read on the first [`RepoPackage::file_list`] call, if
/// one is ever made. A `.files` path returns `None`, because it already carries everything a
/// sibling could offer, so there is nothing to defer to.
fn sibling_files_path(path: &Path) -> Option<PathBuf> {
    let stem = path.file_name()?.to_str()?.strip_suffix(".db")?;
    let candidate = path.with_file_name(format!("{stem}.files"));
    candidate.is_file().then_some(candidate)
}

/// Derives a repository name from an archive path's file name.
///
/// Every real repository archive is named exactly `<repo>.db` or `<repo>.files`. This was confirmed
/// against `/var/lib/pacman/sync` on the machine this was developed against. There the files are
/// plain names with no further suffix, compression included. It is therefore how
/// [`RepoDatabase::open`] learns the repository name without a redundant parameter, since the
/// archive's own contents carry no such name.
fn repo_name_from_path(path: &Path) -> Result<RepoName> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::UnrecognisedArchiveName { path: path.to_path_buf() })?;

    let stem = file_name
        .strip_suffix(".files")
        .or_else(|| file_name.strip_suffix(".db"))
        .ok_or_else(|| Error::UnrecognisedArchiveName { path: path.to_path_buf() })?;

    RepoName::parse(stem).map_err(|_| Error::UnrecognisedArchiveName { path: path.to_path_buf() })
}

/// Turns a low-level archive skip into a caller-facing diagnostic.
fn translate_skip(skipped: Skipped) -> RepoDiagnostic {
    match skipped.reason {
        SkipReason::NonUtf8Path => RepoDiagnostic::NonUtf8Path { path: skipped.path },
        SkipReason::UnexpectedShape => RepoDiagnostic::UnexpectedShape { path: skipped.path },
        SkipReason::InvalidEntryName(source) => {
            RepoDiagnostic::InvalidEntryName { path: skipped.path, source }
        }
        SkipReason::NotARegularFile => RepoDiagnostic::NotARegularFile { path: skipped.path },
        SkipReason::Duplicate => RepoDiagnostic::DuplicateMember { path: skipped.path },
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::fixture::RepoFixture;

    fn is_send_and_sync<T: Send + Sync>() {}

    #[test]
    fn repo_database_is_send_and_sync() {
        is_send_and_sync::<RepoDatabase>();
    }

    /// A minimal, valid v2 repository `desc`, with `name`/`version` substituted in.
    fn desc_text(name: &str, version: &str) -> String {
        format!(
            "%FILENAME%\n{name}-{version}-x86_64.pkg.tar.zst\n\n\
             %NAME%\n{name}\n\n\
             %BASE%\n{name}\n\n\
             %VERSION%\n{version}\n\n\
             %DESC%\nAn example package\n\n\
             %CSIZE%\n1234\n\n\
             %ISIZE%\n5678\n\n\
             %SHA256SUM%\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n\
             %URL%\nhttps://example.org/\n\n\
             %ARCH%\nx86_64\n\n\
             %BUILDDATE%\n1733737242\n\n\
             %PACKAGER%\nFoobar McFooface <foobar@mcfooface.org>\n\n"
        )
    }

    /// Writes an archive holding one `desc` per `(name, version)` pair.
    fn archive_of(fixture: &RepoFixture, file_name: &str, packages: &[(&str, &str)]) -> PathBuf {
        let entries: Vec<(String, Vec<u8>)> = packages
            .iter()
            .map(|(name, version)| {
                (format!("{name}-{version}/desc"), desc_text(name, version).into_bytes())
            })
            .collect();
        let refs: Vec<(&str, &[u8])> =
            entries.iter().map(|(path, body)| (path.as_str(), body.as_slice())).collect();
        fixture.write_gzip_archive(file_name, &refs)
    }

    /// The counterpart to the local database's own boundary case: an archive holding exactly
    /// `repo_max_packages` packages must open.
    #[test]
    fn an_archive_with_exactly_the_maximum_package_count_opens() {
        let fixture = RepoFixture::new();
        let path = archive_of(&fixture, "core.db", &[("foo", "1.0.0-1"), ("bar", "2.0.0-1")]);

        let db = RepoDatabase::open_with(
            &path,
            RepoOpenOptions::new().limits(Limits { repo_max_packages: 2, ..Limits::default() }),
        )
        .unwrap();

        assert_eq!(db.len(), 2);
    }

    /// The duplicate report must name the entry that was kept, not echo back the discarded
    /// one. The two directories carry different versions, so `kept` and `ignored` differ.
    #[test]
    fn a_duplicate_files_member_names_the_entry_that_was_kept() {
        let fixture = RepoFixture::new();
        let first = desc_text("foo", "1.0.0-1");
        let second = desc_text("foo", "2.0.0-1");
        let path = fixture.write_gzip_archive(
            "core.files",
            &[
                ("foo-1.0.0-1/desc", first.as_bytes()),
                ("foo-1.0.0-1/files", b"%FILES%\nusr/\n\n"),
                ("foo-2.0.0-1/desc", second.as_bytes()),
                ("foo-2.0.0-1/files", b"%FILES%\nusr/\nusr/bin/\n\n"),
            ],
        );

        let db = RepoDatabase::open(&path).unwrap();

        let duplicates: Vec<(&str, &str)> = db
            .diagnostics()
            .iter()
            .filter_map(|diagnostic| match diagnostic {
                RepoDiagnostic::DuplicatePackage { kept, ignored, .. } => {
                    Some((kept.as_str(), ignored.as_str()))
                }
                _ => None,
            })
            .collect();

        assert!(!duplicates.is_empty(), "a duplicate must be reported: {:?}", db.diagnostics());
        for (kept, ignored) in duplicates {
            assert_ne!(kept, ignored, "a duplicate report must name two distinct entries");
            assert_eq!(kept, "foo-1.0.0-1", "the first member in archive order wins");
            assert_eq!(ignored, "foo-2.0.0-1");
        }
    }

    /// With the higher version first in the archive, the `desc` side and the files arena keep
    /// the same entry, the first in archive order. The kept package then reads its own file
    /// list, and the pair is reported once.
    #[test]
    fn both_sides_keep_the_first_duplicate_in_archive_order() {
        let fixture = RepoFixture::new();
        let first = desc_text("foo", "2.0.0-1");
        let second = desc_text("foo", "1.0.0-1");
        let path = fixture.write_gzip_archive(
            "core.files",
            &[
                ("foo-2.0.0-1/desc", first.as_bytes()),
                ("foo-2.0.0-1/files", b"%FILES%\nusr/\nusr/bin/\n\n"),
                ("foo-1.0.0-1/desc", second.as_bytes()),
                ("foo-1.0.0-1/files", b"%FILES%\nusr/\n\n"),
            ],
        );

        let db = RepoDatabase::open(&path).unwrap();

        let foo = db.get(&"foo".parse().unwrap()).unwrap();
        assert_eq!(foo.version().to_string(), "2.0.0-1");
        assert_eq!(foo.file_list().unwrap().count(), 2, "the kept package reads its own files");
        let duplicates: Vec<(&str, &str)> = db
            .diagnostics()
            .iter()
            .filter_map(|diagnostic| match diagnostic {
                RepoDiagnostic::DuplicatePackage { kept, ignored, .. } => {
                    Some((kept.as_str(), ignored.as_str()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(duplicates, [("foo-2.0.0-1", "foo-1.0.0-1")]);
    }

    #[test]
    fn nothing_is_dropped_when_diagnostics_stay_under_the_bound() {
        let fixture = RepoFixture::new();
        let path = archive_of(&fixture, "core.db", &[("foo", "1.0.0-1")]);

        let db = RepoDatabase::open(&path).unwrap();

        assert!(db.diagnostics().is_empty(), "{:?}", db.diagnostics());
        assert_eq!(db.diagnostics_dropped(), 0);
    }

    /// A configured repository name can match neither archive, through a typo or a repository that
    /// was never synced. The error must then name `<repo>.db`, the name the caller actually asked
    /// for. `<repo>.files` is only ever tried as an internal fallback. Naming it instead would make
    /// a missing repository look like a file-list-specific failure.
    #[test]
    fn a_wholly_absent_repository_is_blamed_on_db_not_files() {
        let fixture = RepoFixture::new();
        let repo = RepoName::parse("nonexistent").unwrap();

        let error = RepoDatabase::open_repo(fixture.path(), &repo).unwrap_err();

        assert!(error.to_string().ends_with("nonexistent.db"), "got {error}");
    }

    /// A repository published only as `<repo>.files` (no separate `.db`) must still open —
    /// the fallback this error-reporting change must not break.
    #[test]
    fn falls_back_to_files_when_db_is_absent() {
        let fixture = RepoFixture::new();
        let repo = RepoName::parse("core").unwrap();
        archive_of(&fixture, "core.files", &[("foo", "1.0.0-1")]);

        let db = RepoDatabase::open_repo(fixture.path(), &repo).unwrap();

        assert_eq!(db.len(), 1);
    }

    /// A check that refuses every archive whose name ends in `suffix`, and records every path
    /// it was asked about.
    fn refusing(suffix: &'static str) -> (ArchiveCheck, Arc<std::sync::Mutex<Vec<PathBuf>>>) {
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&asked);
        let check: ArchiveCheck = Arc::new(move |path: &Path| {
            record.lock().unwrap().push(path.to_path_buf());
            if path.to_string_lossy().ends_with(suffix) {
                Err("refused by the test".into())
            } else {
                Ok(None)
            }
        });
        (check, asked)
    }

    /// The archive is not a tar stream at all, so any read of it fails on the bytes. A refusal
    /// is what comes back, so the check ran before the decompressor saw them.
    #[test]
    fn a_refused_archive_is_never_read() {
        let fixture = RepoFixture::new();
        let path = fixture.path().join("core.db");
        std::fs::write(&path, b"not an archive").unwrap();
        let (check, asked) = refusing(".db");

        let repo = RepoName::parse("core").unwrap();
        let error = RepoDatabase::open_repo_with(
            fixture.path(),
            &repo,
            RepoOpenOptions::new().check(check),
        )
        .unwrap_err();

        assert!(matches!(error, Error::ArchiveRefused { .. }), "got {error:?}");
        assert_eq!(error.to_string(), "refused by the test");
        assert_eq!(*asked.lock().unwrap(), [path]);
    }

    /// The `.files`-only fallback is the archive read, so it is the one checked.
    #[test]
    fn the_files_fallback_is_checked_before_it_is_read() {
        let fixture = RepoFixture::new();
        let path = fixture.path().join("core.files");
        std::fs::write(&path, b"not an archive").unwrap();
        let (check, asked) = refusing(".files");

        let repo = RepoName::parse("core").unwrap();
        let error = RepoDatabase::open_repo_with(
            fixture.path(),
            &repo,
            RepoOpenOptions::new().check(check),
        )
        .unwrap_err();

        assert!(matches!(error, Error::ArchiveRefused { .. }), "got {error:?}");
        assert_eq!(*asked.lock().unwrap(), [path]);
    }

    /// The sibling `.files` is read later than the `.db`, on the first file-list request. It is
    /// checked then, on both ways in, and the open itself does not check it.
    #[test]
    fn the_files_sibling_is_checked_when_its_file_lists_are_first_read() {
        let fixture = RepoFixture::new();
        let db_path = archive_of(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        let files_path = fixture.path().join("core.files");
        std::fs::write(&files_path, b"not an archive").unwrap();
        let (check, asked) = refusing(".files");

        let db = RepoDatabase::open_with(&db_path, RepoOpenOptions::new().check(check)).unwrap();
        assert_eq!(*asked.lock().unwrap(), std::slice::from_ref(&db_path));

        let package = db.get_str("foo").unwrap();
        let batch = db.file_lists([package]);
        let Some((_, Err(error))) = batch.first() else { panic!("got {batch:?}") };
        assert!(matches!(**error, Error::ArchiveRefused { .. }), "got {error:?}");

        let Err(error) = package.file_list() else { panic!("a refused archive was read") };
        assert!(matches!(*error, Error::ArchiveRefused { .. }), "got {error:?}");

        assert_eq!(*asked.lock().unwrap(), [db_path, files_path.clone(), files_path]);
    }

    /// With no `<repo>.db`, [`RepoDatabase::locate`] names `<repo>.files`; with neither, the
    /// error names `<repo>.db`.
    #[test]
    fn locate_prefers_db_then_files() {
        let fixture = RepoFixture::new();
        let repo = RepoName::parse("core").unwrap();

        let error = RepoDatabase::locate(fixture.path(), &repo).unwrap_err();
        assert!(error.to_string().ends_with("core.db"), "got {error}");

        let files = archive_of(&fixture, "core.files", &[("foo", "1.0.0-1")]);
        assert_eq!(RepoDatabase::locate(fixture.path(), &repo).unwrap(), files);

        let db = archive_of(&fixture, "core.db", &[("foo", "1.0.0-1")]);
        assert_eq!(RepoDatabase::locate(fixture.path(), &repo).unwrap(), db);
    }
}
