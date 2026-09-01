//! Error types for the local database layer.
//!
//! There is a single crate-level [`Error`]. Every I/O failure carries the
//! [`std::path::PathBuf`] it happened on and the [`IoAction`] that was attempted. A bare
//! "No such file or directory" is not actionable in a package manager.

use std::{fmt, path::PathBuf, sync::Arc};

use alpm_types::{FullVersion, Name};

use crate::{
    limits::Limit,
    repo::{RepoName, RepoNameError},
};

/// A [`Result`](std::result::Result) with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A reference-counted [`Error`].
///
/// Lazily loaded data caches its failure so a broken entry is not re-read on every access
/// (the same idea as libalpm's sticky `INFRQ_ERROR` bit). Caching a failure means handing out
/// the same error repeatedly. [`Error`] cannot be [`Clone`], because [`std::io::Error`] is
/// not. Sharing it behind an [`Arc`] resolves that and keeps the clone cheap.
pub type SharedError = Arc<Error>;

/// The filesystem operation that failed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum IoAction {
    /// Opening a file.
    Open,
    /// Reading from an open file.
    Read,
    /// Querying a path's metadata.
    Metadata,
    /// Listing a directory.
    ReadDir,
    /// Decompressing a file's contents.
    Decompress,
}

impl IoAction {
    /// The verb phrase used in error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Read => "read",
            Self::Metadata => "stat",
            Self::ReadDir => "list directory",
            Self::Decompress => "decompress",
        }
    }
}

impl fmt::Display for IoAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error produced while reading a local database.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A filesystem operation failed.
    #[error("failed to {action} {}", path.display())]
    Io {
        /// The path the operation was attempted on.
        path: PathBuf,
        /// The operation that was attempted.
        action: IoAction,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// A file was larger than the configured [`Limits`](crate::Limits) allow.
    ///
    /// The read is refused rather than truncated. A truncated `files` list would look like a
    /// package that owns fewer files than it does — worse than no answer at all.
    #[error("{} exceeds the {limit} size limit of {max} bytes", path.display())]
    LimitExceeded {
        /// The path that was too large.
        path: PathBuf,
        /// Which limit was hit.
        limit: Limit,
        /// The configured maximum, in bytes.
        max: u64,
    },

    /// A path that must be a regular file was something else — a FIFO, a device node, a
    /// symlink, or a directory.
    #[error("{} is not a regular file", path.display())]
    NotARegularFile {
        /// The offending path.
        path: PathBuf,
    },

    // This is a reader's enum. Lock, wrong-lock, and record variants live in `piko-db-write`
    // instead, alongside the writer that actually produces them.
    /// A file that must be UTF-8 was not.
    #[error("{} is not valid UTF-8", path.display())]
    NotUtf8 {
        /// The offending path.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::str::Utf8Error,
    },

    // Note: there is deliberately no `EntryName` variant here. A directory whose name is not
    // a valid entry name is not a failure of the database. It is one bad directory among many
    // good ones, so it is reported as `Diagnostic::InvalidEntryName` and the scan continues.
    // Callers parsing a name directly get `EntryNameError` itself.
    /// The `ALPM_DB_VERSION` file is missing, unreadable, or holds an unsupported version.
    //
    // `transparent` rather than `"{0}"`: with `#[from]` the inner error is also the
    // `source`. A formatter that walks the cause chain would otherwise print the same
    // sentence twice.
    #[error(transparent)]
    SchemaVersion(#[from] crate::local::schema_version::SchemaVersionError),

    /// The database contains more entries than [`Limits::max_entries`](crate::Limits::max_entries).
    #[error("database at {} has more than {max} entries", path.display())]
    TooManyEntries {
        /// The database directory.
        path: PathBuf,
        /// The configured maximum.
        max: usize,
    },

    /// The installed set plus every configured repository together offer more candidate
    /// packages than
    /// [`Limits::solve_max_solvables`](crate::Limits::solve_max_solvables).
    ///
    /// A count rather than a size. This mirrors [`Error::TooManyEntries`] rather than
    /// [`Error::LimitExceeded`].
    #[error("planning would consider more than {max} candidate packages")]
    TooManySolvables {
        /// The configured maximum.
        max: usize,
    },

    /// The encoding exceeded
    /// [`Limits::solve_max_clauses`](crate::Limits::solve_max_clauses).
    #[error("planning would emit more than {max} clauses")]
    TooManyClauses {
        /// The configured maximum.
        max: usize,
    },

    /// The solver exceeded
    /// [`Limits::solve_max_conflicts`](crate::Limits::solve_max_conflicts).
    ///
    /// Reported rather than searched past. A clause set crafted to make the search diverge
    /// then costs a bounded amount of work instead of hanging the process.
    #[error("dependency solving gave up after {max} conflicts")]
    SolveBudgetExhausted {
        /// The configured maximum.
        max: usize,
    },

    /// An installed package's `desc` could not be read while building a planning universe.
    ///
    /// Unlike a scan diagnostic, this is fatal. A transaction cannot be planned against an
    /// installed set that cannot be read in full. An unreadable entry is indistinguishable
    /// from an absent one at exactly the moment that difference decides whether a package is
    /// installed, upgraded, or left alone.
    #[error("cannot plan: failed to read the installed package {name}")]
    PlanLocalDescUnreadable {
        /// The installed package whose `desc` could not be read.
        name: Name,
        /// The underlying failure.
        #[source]
        source: SharedError,
    },

    /// A repository candidate's `%DEPENDS%` could not be converted while planning.
    ///
    /// Fatal for the same reason [`Self::PlanLocalDescUnreadable`] is. A candidate whose
    /// dependencies cannot be read cannot be reasoned about. Treating it as having none would
    /// let the solver install something that does not work.
    ///
    /// The section is converted on demand rather than at open, so a malformed `%DEPENDS%`
    /// surfaces here.
    #[error("cannot plan: failed to read the dependencies of {name}")]
    PlanRepoDependsUnreadable {
        /// The candidate whose `%DEPENDS%` could not be converted.
        name: Name,
        /// The underlying failure.
        #[source]
        source: SharedError,
    },

    /// A `desc` file could not be parsed.
    #[error("failed to parse {}", path.display())]
    Desc {
        /// The path of the `desc` file.
        path: PathBuf,
        /// The underlying parse failure.
        #[source]
        source: alpm_db::Error,
    },

    /// A `desc` file's eager sections could not be read.
    ///
    /// Separate from [`Self::Desc`] because it comes from a different parser. The relation
    /// sections and `%REASON%` go through [`crate::eager`], not `alpm-db`'s typed conversion.
    /// Only the latter can produce an `alpm_db::Error`.
    #[error("failed to read the dependency sections of {}", path.display())]
    DescFields {
        /// The path of the `desc` file.
        path: PathBuf,
        /// The underlying failure. Boxed for the reason [`Self::RepoDescFields`] documents.
        #[source]
        source: Box<crate::eager::DescFieldError>,
    },

    /// A repository `desc`'s deferred `%DEPENDS%` section could not be converted.
    ///
    /// Named by package rather than by path. A repository `desc` is a member inside an
    /// archive, and the archive is no longer open by the time this can happen.
    #[error("failed to read the dependencies of {package}")]
    RepoDescFields {
        /// The package whose `%DEPENDS%` is malformed.
        package: Name,
        /// The underlying failure.
        ///
        /// Boxed. `DescFieldError::InvalidEntry` carries an `alpm_types::Error`, large enough
        /// that inlining it here would widen every `Result` in the crate. Clippy's
        /// `result_large_err` catches exactly that.
        #[source]
        source: Box<crate::eager::DescFieldError>,
    },

    /// A `files` file could not be parsed.
    #[error("failed to parse {}", path.display())]
    Files {
        /// The path of the `files` file.
        path: PathBuf,
        /// The underlying parse failure.
        #[source]
        source: alpm_db::files::Error,
    },

    /// An `mtree` file could not be parsed.
    #[error("failed to parse {}", path.display())]
    Mtree {
        /// The path of the `mtree` file.
        path: PathBuf,
        /// The underlying parse failure.
        #[source]
        source: alpm_mtree::Error,
    },

    /// [`crate::local::LocalPackage::verify_files`] was given a root `alpm_common::InputPath`
    /// refuses to compare files against — not absolute, or not a directory.
    #[error("{} is not usable as an installation root", path.display())]
    InvalidVerifyRoot {
        /// The root that was rejected.
        path: PathBuf,
        /// The underlying reason.
        #[source]
        source: alpm_common::Error,
    },

    /// An archive's file name is not `<repo>.db` or `<repo>.files`.
    ///
    /// [`crate::repo::RepoDatabase::open`] derives the repository name from the file name
    /// itself. The archive's own contents carry no such name.
    #[error("{} is not named <repo>.db or <repo>.files", path.display())]
    UnrecognisedArchiveName {
        /// The archive path with the unrecognised name.
        path: PathBuf,
    },

    /// A repository archive uses a compression format `alpm-compress` does not implement.
    ///
    /// The [alpm-repo-db] spec also allows `.Z`, `.lrz`, `.lz`, `.lz4` and `.lzo`; only
    /// gzip, zstd, xz and bzip2 are supported.
    ///
    /// [alpm-repo-db]: https://alpm.archlinux.page/specifications/alpm-repo-db.7.html
    #[error("{} does not use a supported compression format", path.display())]
    UnsupportedCompression {
        /// The archive that could not be identified.
        path: PathBuf,
    },

    /// A `<repo>.db` database was opened with no sibling `<repo>.files`, so file lists are
    /// not available at all.
    #[error("{repo} has no {repo}.files sibling archive; file lists are unavailable")]
    FilesUnavailable {
        /// The repository that has no `.files` archive.
        repo: RepoName,
    },

    /// A repository `desc` entry's deferred sections could not be parsed.
    ///
    /// Only the sections [`crate::repo::RepoPackage`] reads eagerly are parsed at open time.
    /// The rest are converted on first access to [`desc`](crate::repo::RepoPackage::desc),
    /// which is where this surfaces. A `desc` malformed in an *eager* section never produces
    /// this. That package is dropped during the scan instead, with
    /// [`crate::repo::RepoDiagnostic::InvalidDesc`].
    ///
    /// The source is boxed because `alpm_repo_db::Error` carries a rendered `winnow`
    /// diagnostic. Inlining it pushes `Result<_, Error>` past clippy's `result_large_err`
    /// threshold — the same thing that already happened once, recorded on
    /// [`Error::FilesVersionSkew`]'s doc comment.
    #[error("{entry}: failed to parse desc")]
    RepoDescUnparsable {
        /// The entry directory name of the package whose `desc` could not be parsed.
        entry: String,
        /// The underlying parse failure.
        #[source]
        source: Box<alpm_repo_db::Error>,
    },

    /// A package's file list is absent from the `.files` archive that was consulted.
    ///
    /// Distinct from [`Error::FilesVersionSkew`]. Here the package simply is not there,
    /// rather than present at a different build.
    #[error("{name} is not present in the .files archive")]
    FilesMissingForPackage {
        /// The package that has no entry in the `.files` archive.
        name: Name,
    },

    /// A package's file list belongs to a different build than the one it was requested for.
    ///
    /// `<repo>.db` and `<repo>.files` are refreshed independently by pacman (`-Sy` versus
    /// `-Fy`), so they routinely disagree about which build of a package is current. Measured
    /// at 12 of 296 packages between `core.db` and `core.files` on the machine this was
    /// developed against. Serving the wrong build's paths silently would be worse than
    /// refusing outright, so this is an error rather than a best-effort answer.
    #[error(
        "{name} is at {db_version} in the database but {files_version} in the .files \
         archive; refusing to serve a file list from a different build"
    )]
    FilesVersionSkew {
        /// The package whose file list is stale.
        name: Name,
        /// The version recorded in the database that was opened.
        ///
        /// Boxed, along with `files_version`. This is the largest variant of `Error` by far —
        /// two `FullVersion`s inline pushed every `Result<_, Error>` in the crate past
        /// clippy's `result_large_err` threshold — and this variant is rare.
        db_version: Box<FullVersion>,
        /// The version found in the `.files` archive.
        files_version: Box<FullVersion>,
    },

    /// A package passed to [`crate::repo::RepoDatabase::file_lists`] was not produced by that
    /// same database, and so does not share its `.files` archive.
    ///
    /// Resolving it anyway would silently mix two repositories' file lists. This is the same
    /// class of mistake [`Error::FilesVersionSkew`] exists to catch one layer down, caught
    /// here before any archive is even touched.
    #[error("{name} was not opened as part of this database")]
    ForeignPackage {
        /// The package that does not belong to the database it was looked up against.
        name: Name,
    },

    /// A `pacman.conf`-style directive appeared before any `[section]` header.
    #[error("{} line {line}: directive must belong to a section", path.display())]
    ConfigDirectiveOutsideSection {
        /// The config file being parsed.
        path: PathBuf,
        /// The 1-based line number of the offending directive.
        line: usize,
    },

    /// A recognized configuration directive had a value it does not accept.
    ///
    /// Covers every "recognized key, invalid value" case (`ParallelDownloads`, `SigLevel`,
    /// `Usage`, `CleanMethod`, ...) with one variant rather than one per directive. All render
    /// the same shape of message, mirroring `conf.c`'s own
    /// `"config file %s, line %d: invalid value for '%s' : '%s'"`.
    #[error(
        "{} line {line}: invalid value for '{directive}': '{value}' ({reason})",
        path.display()
    )]
    ConfigInvalidDirective {
        /// The config file being parsed.
        path: PathBuf,
        /// The 1-based line number of the offending directive.
        line: usize,
        /// The directive name, e.g. `SigLevel`.
        directive: String,
        /// The value that was rejected.
        value: String,
        /// Why the value was rejected.
        reason: String,
    },

    /// An `Include` chain nested more than 10 levels deep.
    ///
    /// Matches `conf.c`'s `config_max_recursion`; this is a cycle guard, not a policy limit.
    #[error("{} line {line}: Include exceeded the maximum recursion depth of 10", path.display())]
    ConfigIncludeDepthExceeded {
        /// The config file being parsed.
        path: PathBuf,
        /// The 1-based line number of the offending `Include`.
        line: usize,
    },

    /// A `[section]` header in a config file is not a valid repository name.
    #[error("{} line {line}: '{name}' is not a valid repository name", path.display())]
    ConfigInvalidRepoName {
        /// The config file being parsed.
        path: PathBuf,
        /// The 1-based line number of the offending section header.
        line: usize,
        /// The rejected section name.
        name: String,
        /// Why it was rejected.
        #[source]
        source: RepoNameError,
    },
}

impl Error {
    /// Builds an [`Error::Io`] for `path`.
    pub(crate) fn io(path: impl Into<PathBuf>, action: IoAction, source: std::io::Error) -> Self {
        Self::Io { path: path.into(), action, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Lazy` stores an `Arc<Error>` in a `OnceLock` shared across threads.
    #[test]
    fn error_is_send_sync_static() {
        const fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Error>();
        assert_send_sync::<SharedError>();
    }

    #[test]
    fn io_errors_name_the_path_and_the_action() {
        let err = Error::io(
            "/var/lib/pacman/local/foo-1-1/desc",
            IoAction::Open,
            std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert_eq!(err.to_string(), "failed to open /var/lib/pacman/local/foo-1-1/desc");
    }

    /// The cause chain must reach the underlying `io::Error`, since that carries the errno a
    /// caller may want to match on.
    #[test]
    fn io_errors_preserve_their_source() {
        let err =
            Error::io("/x", IoAction::Read, std::io::Error::from(std::io::ErrorKind::NotFound));
        let source = std::error::Error::source(&err).map(ToString::to_string);
        assert!(source.as_deref().is_some_and(|s| s.contains("not found")), "{source:?}");
    }
}
