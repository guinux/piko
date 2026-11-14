//! Error types for the commit engine.
//!
//! This is deliberately a separate enum from [`piko_db::Error`], not an extension of it. The
//! two crates fail in different ways for different reasons. A reader fails to *understand*
//! something. A commit engine fails to *change* something. A caller must be able to tell "the
//! database is corrupt" from "the cache is missing a package". Matching on variants of one
//! type should not be what it takes.

use std::{fmt, path::PathBuf};

/// A [`Result`](std::result::Result) with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// How many file conflicts [`Error::FileConflicts`] names before summarising the rest.
const MAX_SHOWN: usize = 10;

/// A path in a message, with anything that could drive a terminal escaped.
///
/// A member path, a `.PKGINFO` value quoted in a parse error and a file name on disk are all
/// chosen outside piko, and every message here can reach a terminal. See
/// [`fn@piko_db::printable`].
fn shown(path: &std::path::Path) -> String {
    piko_db::printable_path(path)
}

/// A reason in a message, escaped as [`shown`] escapes a path.
fn said(reason: &str) -> String {
    piko_db::printable(reason)
}

/// The filesystem operation that failed.
///
/// This mirrors `piko_db::IoAction`, and is separate for the same reason the error type is.
/// The verbs a commit engine needs are not the verbs a reader needs, and will diverge further
/// once extraction lands.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum IoAction {
    /// Querying a path's metadata.
    Metadata,
    /// Opening a file.
    Open,
    /// Reading from an open file.
    Read,
    /// Creating a directory.
    CreateDir,
    /// Decompressing a file's contents.
    Decompress,
    /// Creating a file.
    Create,
    /// Writing to an open file.
    Write,
    /// Removing a file.
    Remove,
    /// Renaming a file over another.
    Rename,
    /// Flushing a file or directory to stable storage.
    Sync,
    /// Changing a path's ownership.
    Chown,
}

impl IoAction {
    /// The verb phrase used in error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "stat",
            Self::Open => "open",
            Self::Read => "read",
            Self::CreateDir => "create directory",
            Self::Decompress => "decompress",
            Self::Create => "create",
            Self::Write => "write",
            Self::Remove => "remove",
            Self::Rename => "rename onto",
            Self::Sync => "flush to disk",
            Self::Chown => "change ownership of",
        }
    }
}

impl fmt::Display for IoAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error produced while committing a transaction.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A filesystem operation failed.
    #[error("failed to {action} {}", shown(path))]
    Io {
        /// The path the operation was attempted on.
        path: PathBuf,
        /// The operation that was attempted.
        action: IoAction,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// No configured source could supply a package file.
    ///
    /// The message names every directory that was searched, and every candidate that was
    /// found but rejected. "package not found in cache" without those details turns into a
    /// support thread. To the user, a cache entry that is a dangling symlink looks exactly
    /// like an absent file. So does a directory with the right name.
    #[error(
        "{file_name} is not available from any configured source (searched {}{})",
        searched.iter().map(|p| shown(p)).collect::<Vec<_>>().join(", "),
        if skipped.is_empty() {
            String::new()
        } else {
            format!("; rejected {}", skipped.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))
        }
    )]
    NotAvailable {
        /// The package file that was looked for.
        file_name: String,
        /// Every directory that was searched, in the order they were searched.
        searched: Vec<PathBuf>,
        /// Candidates that existed but were not usable.
        skipped: Vec<crate::source::Skipped>,
    },

    /// A package member is neither a regular file, a directory, a symbolic link nor a hard
    /// link.
    ///
    /// The extraction writes those four kinds only. A device node, a FIFO, a contiguous or
    /// sparse file, or a pax global header would otherwise reach the disk as a regular file.
    #[error(
        "{}: {} is a {kind}; piko installs regular files, directories and links only",
        shown(path),
        shown(member)
    )]
    UnsupportedMemberType {
        /// The package archive.
        path: PathBuf,
        /// The member's path, as the archive spells it.
        member: PathBuf,
        /// What the member's type byte names.
        kind: &'static str,
    },

    /// A hard link member names a target that is not a file the same package ships before it.
    ///
    /// A hard link is the one member that reaches a file by name. With a target outside the
    /// package, it would give a second name to a file that is already on the system.
    #[error(
        "{}: the hard link {} names {}, which is not an earlier member of the package",
        shown(path),
        shown(member),
        shown(target)
    )]
    HardLinkOutsidePackage {
        /// The package archive.
        path: PathBuf,
        /// The hard link's path, as the archive spells it.
        member: PathBuf,
        /// The target it names.
        target: PathBuf,
    },

    /// A member's owner is not a user and group id the kernel can set.
    ///
    /// An id is 32 bits, and `u32::MAX` is `-1`, which `chown` reads as "leave unchanged". A
    /// tar header can hold a larger number. Narrowed to some default, it would give the file an
    /// owner the archive never named: root, or the extracting user.
    #[error(
        "{} is owned by {uid}:{gid}, which is not a user and group id piko can set",
        shown(member)
    )]
    UnusableMemberOwner {
        /// The member's path, as the archive spells it.
        member: PathBuf,
        /// The user id the archive records.
        uid: u64,
        /// The group id the archive records.
        gid: u64,
    },

    /// An archive named a path that could escape the installation root.
    ///
    /// This is refused on the path alone, before any filesystem access — see
    /// [`crate::rootfs::components`].
    #[error("{} is not a safe path to extract: {reason}", shown(path))]
    UnsafeArchivePath {
        /// The path as the archive spelled it.
        path: PathBuf,
        /// What was wrong with it.
        reason: crate::rootfs::UnsafePath,
    },

    /// Resolving an archive path left the installation root, or would have.
    ///
    /// This is distinct from [`Error::UnsafeArchivePath`]: the path itself is fine, and the
    /// *filesystem* is what redirects it. It is the case a string check cannot catch, and the
    /// reason resolution walks with `openat`.
    #[error(
        "{} would be extracted outside the installation root: {} — {reason}",
        shown(path),
        shown(component)
    )]
    PathEscapesRoot {
        /// The path as the archive spelled it.
        path: PathBuf,
        /// The component that redirects it.
        component: PathBuf,
        /// Why that component cannot be descended through.
        reason: &'static str,
    },

    /// A package archive exceeded one of [`crate::extract::PackageLimits`].
    ///
    /// This is a count or a size, named rather than enumerated. The bounds here are few, and
    /// their names are the whole message.
    #[error("{} exceeds the {limit} limit of {max}", shown(path))]
    PackageLimitExceeded {
        /// The package that was too large.
        path: PathBuf,
        /// Which bound was hit.
        limit: &'static str,
        /// The configured maximum.
        max: u64,
    },

    /// A package archive uses a compression format piko does not decode.
    ///
    /// This is determined by sniffing the magic bytes, not by the file name. See
    /// [`piko_db::compression`] for which formats are decoded and why.
    #[error("{} uses {format}; piko reads gzip, zstd and uncompressed packages only", shown(path))]
    UnsupportedCompression {
        /// The archive that was refused.
        path: PathBuf,
        /// What its leading bytes identify it as.
        format: piko_db::compression::Unsupported,
    },

    /// A planned package's file name declares a compression format piko does not decode.
    ///
    /// Raised by [`crate::plan::check_compression`] from the `%FILENAME%` a repository
    /// publishes, or from the last component of a package URL, so the package is refused
    /// before it is downloaded. Each entry is the file name and the format it declares.
    #[error(
        "cannot install {}: piko reads gzip, zstd and uncompressed packages only",
        packages.iter().map(|(name, format)| format!("{name} ({format})"))
            .collect::<Vec<_>>().join(", ")
    )]
    UnsupportedPackageCompression {
        /// Every refused file name, with the format its suffix declares.
        packages: Vec<(String, piko_db::compression::Unsupported)>,
    },

    /// An archive member cannot be extracted, and the transaction must stop.
    ///
    /// Currently this is only the "a directory is in the way of a file" case. libalpm also
    /// treats that as fatal (`add.c:290`) rather than removing the directory. That directory
    /// may hold files belonging to another package, or to nobody.
    #[error("cannot extract {}: {reason:?}", shown(path))]
    ExtractionRefused {
        /// The member's path as the archive spells it.
        path: PathBuf,
        /// Why it was refused.
        reason: crate::extract::decision::RefuseReason,
    },

    /// The transaction would write files it does not own.
    ///
    /// Every conflict is carried, not just the first. A user who has to resolve these by hand
    /// needs the whole list. Finding them one transaction at a time is the behavior that makes
    /// `--overwrite` look like the only way forward.
    ///
    /// The message shows the first few and counts the rest. A package that collides with
    /// another can collide on thousands of paths, and a wall of them buries the summary.
    #[error(
        "the transaction would overwrite {} file(s) it does not own:\n  {}{}",
        conflicts.len(),
        conflicts.iter().take(MAX_SHOWN).map(ToString::to_string).collect::<Vec<_>>().join("\n  "),
        match conflicts.len().saturating_sub(MAX_SHOWN) {
            0 => String::new(),
            more => format!("\n  ... and {more} more"),
        }
    )]
    FileConflicts {
        /// Every conflict found, in the order they were detected.
        conflicts: Vec<crate::conflict::FileConflict>,
    },

    /// An installed entry this transaction needs cannot be read.
    ///
    /// This is kept distinct from [`Error::Io`] because the failure is not the filesystem's.
    /// The entry is there and readable, and its *contents* do not parse.
    ///
    /// Removal must fail loudly here rather than proceeding on what it managed to read. A
    /// package's `files` is the only record of what it owns. With an unreadable one, the
    /// removal would delete nothing, report success, and drop the database entry. That
    /// orphans every file the package installed, with nothing left to say who owned them.
    /// That is
    /// principle 3 ("cached failures, not cached emptiness") applied where it matters most.
    #[error("the installed entry {entry} cannot be read: {}", said(reason))]
    UnreadableEntry {
        /// The entry directory name, `<name>-<version>`.
        entry: String,
        /// What could not be read, and why.
        reason: String,
    },

    /// A `PreTransaction` hook with `AbortOnFail` did not succeed.
    ///
    /// The system is untouched: this is raised from the pre-transaction phase, before the
    /// first step runs. That is exactly what `alpm-hooks(5)` restricts `AbortOnFail` to
    /// `PreTransaction` for.
    ///
    /// The cause travels with the error, in two parts. `reason` says what went wrong.
    /// `output` says what the hook printed before it failed.
    ///
    /// The error carries both, because a failed commit returns no report. Without them, the
    /// user learns that a hook stopped the transaction and nothing more. A hook that never ran
    /// prints nothing at all. `reason` is then the only part that names the cause.
    #[error(
        "the transaction was stopped by the hook {hook}, which sets AbortOnFail: it {}{}",
        said(reason),
        if output.is_empty() { String::new() } else { format!("\n  {}", output.join("\n  ")) }
    )]
    HookAborted {
        /// The hook's file name.
        hook: String,
        /// Why it did not succeed, from [`crate::hook::Run::failure_reason`].
        reason: String,
        /// What the hook printed before it failed.
        output: Vec<String>,
    },

    /// A trusted hook file or hook directory could not be read or parsed when the
    /// `PreTransaction` hooks were read, so the transaction was not started.
    ///
    /// The file can hold a hook that must run before the transaction, or one that sets
    /// `AbortOnFail`. libalpm refuses the transaction for the same reason (`hook.c:625`).
    #[error(
        "the transaction was not started, because the PreTransaction hooks could not all be read:{}",
        problems.iter().map(|problem| format!("\n  {}", said(problem))).collect::<String>()
    )]
    HooksUnusable {
        /// Each problem, as [`crate::hook::Problem`] displays it.
        problems: Vec<String>,
    },

    /// The transaction stopped because [`crate::Transaction::cancel`]'s flag was raised.
    ///
    /// `completed` is zero for a stop during verification. Nothing is applied there, and no
    /// journal exists yet.
    ///
    /// During the commit, the flag is read before a step starts, never inside one. So no step
    /// is half applied. The steps counted here completed, and the journal names them. The
    /// remaining steps were not attempted. The system is then left part-way through the
    /// transaction. That is the same state a failed step leaves it in.
    #[error("the transaction was cancelled after {completed} of {total} steps")]
    Cancelled {
        /// How many steps ran to the end.
        completed: usize,
        /// How many steps the transaction planned.
        total: usize,
    },

    /// A package's signature does not satisfy the configured `SigLevel`.
    ///
    /// The package is intact as far as piko knows. What failed is the *policy*. This is
    /// distinct from [`Error::SignatureUncheckable`] because the two call for opposite
    /// responses. This one means do not install the package. That one means fix the keyring.
    #[error("{}: {}", shown(package), said(reason))]
    SignatureRejected {
        /// The package file that was refused.
        package: PathBuf,
        /// Which rule refused it, and which key was involved.
        reason: String,
        /// Whether the refusal is that the package has no signature at all.
        ///
        /// libalpm's `ALPM_ERR_PKG_MISSING_SIG`, set apart from a signature that was read and
        /// refused. The second removes a cache file; the first does not.
        unsigned: bool,
    },

    /// A package's signature could not be checked at all.
    ///
    /// This means a broken or missing keyring, or a GnuPG that would not run. It is
    /// deliberately **not** treated as a failed signature: doing so would refuse valid
    /// packages and blame them for a local misconfiguration. Equally it is not a pass. piko
    /// has no opinion on a package it could not check, so the transaction stops.
    #[error("cannot check the signature of {}: {}", shown(package), said(reason))]
    SignatureUncheckable {
        /// The package file that could not be checked.
        package: PathBuf,
        /// What went wrong.
        reason: String,
    },

    /// A package file's SHA-256 is not the one its repository database publishes.
    ///
    /// libalpm's `ALPM_ERR_PKG_INVALID_CHECKSUM`. The file is damaged, or it is not the build
    /// the database describes. Either way, it is not installed.
    #[error("{}: {}", shown(package), said(reason))]
    ChecksumMismatch {
        /// The package file that was refused.
        package: PathBuf,
        /// Both digests, and what became of the file.
        reason: String,
    },

    /// Writing the local database entry failed.
    #[error(transparent)]
    Database(#[from] piko_db_write::Error),

    /// The local database could not be opened.
    ///
    /// This is boxed, and that is not incidental. `piko_db::Error` is 104 bytes against this
    /// enum's 112, both measured. Nesting it inline would make every other variant pay for
    /// this one. A box costs one pointer and keeps the error whole and typed.
    /// Stringifying with `to_string()` would flatten it into an `Error::Io` carrying an
    /// opaque string. A caller wanting to know *which* `piko_db` failure it was could not
    /// recover that at any depth.
    ///
    /// This uses `Box` rather than the `Arc` [`Error::RepositoryPackageUnreadable`] uses. That
    /// one comes out of a `piko_db` lazy loader, which caches its failure behind an `Arc` and
    /// hands out clones. This one is raised fresh by `LocalDatabase::open` and shared with
    /// nobody.
    ///
    /// **The pointer is visible in the chain.** `#[source]` on a `Box<T>` yields the box, not
    /// its contents. A caller walking [`std::error::Error::source`] downcasts to
    /// `Box<piko_db::Error>` rather than to `piko_db::Error`. That is the same shape
    /// [`Error::RepositoryPackageUnreadable`] already has with its `Arc`, and the price of not
    /// growing the enum. `Display` is unaffected, so nothing a user reads changes.
    #[error("the local database at {} cannot be opened", shown(path))]
    LocalDatabaseUnreadable {
        /// The `<dbpath>/local` directory that could not be opened.
        path: PathBuf,
        /// Why it could not be.
        #[source]
        source: Box<piko_db::Error>,
    },

    /// A filesystem this transaction writes to cannot hold it, or cannot be written to at all.
    ///
    /// Raised only when `CheckSpace` is configured. Both lists are carried whole, for the
    /// reason [`Error::FileConflicts`] carries every conflict. Naming one partition at a time
    /// makes the user free space, re-run, and be told about the next one.
    ///
    /// The estimate is approximate by construction. It models the peak at package boundaries,
    /// not at file boundaries. So a refusal here means "this does not fit with libalpm's
    /// margin", not "this would fill the disk to the last byte".
    #[error(
        "the transaction does not fit:\n  {}",
        too_full.iter().take(MAX_SHOWN).map(ToString::to_string)
            .chain(read_only.iter().take(MAX_SHOWN)
                .map(|path| format!("{} is mounted read only", shown(path))))
            .collect::<Vec<_>>()
            .join("\n  ")
    )]
    DiskSpace {
        /// Every filesystem whose free space is short of the peak this transaction needs.
        too_full: Vec<crate::space::PartitionSpace>,
        /// Every filesystem this transaction touches that is mounted read only.
        read_only: Vec<PathBuf>,
    },

    /// The kernel's mount table cannot be read, or describes a different system.
    ///
    /// Only the disk-space check needs it, so this is reachable only under `CheckSpace`.
    /// libalpm returns a bare `-1` here without setting an error code at all. That leaves its
    /// caller reporting "unexpected error". piko names the path and the reason instead.
    #[error("the mount table at {} cannot be used: {}", shown(path), said(reason))]
    MountTableUnreadable {
        /// The file that was read, or the path that could not be placed on any filesystem.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },

    /// No configured cache directory can receive a download.
    #[error(
        "no configured cache directory can be written into ({})",
        rejected.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
    )]
    NoWritableCacheDir {
        /// Every directory considered, and why each one was refused.
        rejected: Vec<crate::source::RejectedCacheDir>,
    },

    /// The installed packages changed between the plan and `verify`, which holds `db.lck`.
    ///
    /// The plan is computed and confirmed before the lock is taken, so another package manager
    /// can change the database in between. A step that removes or upgrades the wrong version
    /// would delete files the database no longer lists, so the transaction stops and asks for a
    /// new plan.
    #[error(
        "{name} changed since the plan: the plan expects {}, and {} is installed; plan again",
        planned.as_deref().unwrap_or("it not to be installed"),
        installed.as_deref().unwrap_or("nothing")
    )]
    PlanStale {
        /// The package name.
        name: String,
        /// The entry the plan expected to find installed, or `None` for a fresh install.
        planned: Option<String>,
        /// The entry installed now, or `None` when the name is not installed.
        installed: Option<String>,
    },

    /// A source was configured with a path that cannot be used.
    #[error("{} is not a usable package source: {}", shown(path), said(reason))]
    UnusableSource {
        /// The offending path.
        path: PathBuf,
        /// Why it cannot be used.
        reason: String,
    },

    /// Downloading a package failed.
    #[error(transparent)]
    Download(#[from] piko_net::Error),

    /// A [`piko_db::solve::Plan`] named a package the `Universe` it was solved against does not
    /// know about.
    ///
    /// [`crate::plan::TransactionPlan::new`] runs immediately after the plan was assembled over the
    /// same `Universe`, so this is not a normal, expected failure mode. It exists so a caller
    /// fails loudly instead of building a transaction that names garbage.
    #[error("the plan names a package the universe does not know (id {id:?}) — this is a bug")]
    PlanInconsistent {
        /// The id the plan named.
        id: piko_db::solve::SolvableId,
    },

    /// A removal plan holds a step that is not a removal.
    ///
    /// [`crate::plan::TransactionPlan::from_removal`] refuses it. A removal-only request
    /// restricts the candidates to what is installed, so the solver has nothing to install.
    /// Reaching this means that invariant broke, and the commit engine would carry out whatever
    /// the step is.
    #[error("the removal plan contains a step that is not a removal")]
    NotARemoval,

    /// A plan step names a candidate with no repository package to install from.
    ///
    /// `Plan::assemble` only emits `Install`/`Change` for a candidate that is not already the
    /// installed copy, so this is unreachable unless that invariant broke.
    #[error("{name} has no repository candidate to install from — this is a bug")]
    NoRepositoryCandidate {
        /// The package name.
        name: String,
    },

    /// A repository candidate's `desc` could not be read while turning a plan into steps.
    #[error("{name} could not be read from its repository")]
    RepositoryPackageUnreadable {
        /// The package name.
        name: String,
        /// The underlying read failure. This is an [`std::sync::Arc`] because `piko_db`'s lazy
        /// loaders cache a failure behind one rather than re-reading on every access.
        #[source]
        source: std::sync::Arc<piko_db::Error>,
    },

    /// A package was built for an architecture this machine is not configured to run.
    ///
    /// libalpm's `check_arch` (`trans.c:69`), which applies to every package a transaction
    /// adds: a file named on the command line, and a repository package by its `%ARCH%`.
    #[error(
        "not built for {}: {}",
        configured.join(" or "),
        packages.join(", ")
    )]
    WrongArchitecture {
        /// Each refused package, spelled `name (architecture)`.
        packages: Vec<String>,
        /// Every architecture `pacman.conf` configures.
        configured: Vec<String>,
    },

    /// Two command-line targets name the same package.
    ///
    /// `ALPM_ERR_TRANS_DUP_TARGET` (`add.c:49`) and `ALPM_ERR_TRANS_DUP_FILENAME`
    /// (`sync.c:470`) are one question for a file target. Its package name and its file name
    /// are the same string.
    #[error("{package} is named twice: {} and {}", shown(first), shown(second))]
    DuplicateTarget {
        /// The package file name both targets render.
        package: String,
        /// The first path that named it.
        first: PathBuf,
        /// The second.
        second: PathBuf,
    },

    /// A package URL cannot be turned into a download.
    ///
    /// piko fetches a URL through the same request a repository package uses, which addresses
    /// a file by an `alpm_types::PackageFileName` under a server. A URL whose last component
    /// is not such a name has nothing to fetch.
    #[error("cannot fetch {url}: {}", said(reason))]
    InvalidPackageUrl {
        /// The URL as the user wrote it, without the user information in front of its host.
        url: String,
        /// Why it cannot be used.
        reason: String,
    },

    /// A target names a package URL, and the caller asked for no download.
    ///
    /// [`crate::file_target::load_targets`] returns this under
    /// [`crate::file_target::Urls::Refuse`]. A command that must change nothing, such as a
    /// preview, cannot read a package it would first have to download.
    #[error("cannot read {} without downloading it", said(url))]
    UrlNotLoaded {
        /// The URL as the user wrote it, without the user information in front of its host.
        url: String,
    },

    /// The keyring a verification policy needs could not be opened.
    ///
    /// This is raised only when something actually asks for checking — see
    /// [`crate::plan::TransactionPlan::new`]. A system with no usable keyring can still run a
    /// transaction whose effective policy needs nothing from it.
    #[error("cannot open the GnuPG keyring at {}", shown(path))]
    KeyringUnusable {
        /// The configured `GPGDir`.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: piko_sig::Error,
    },

    /// A transaction journal exists, but this build cannot read it.
    ///
    /// The file is there, so a previous run wrote it and did not finish. What that run
    /// recorded is unknown, and so is the state of the system. So this refuses a transaction
    /// the same way a readable journal does. It is never read as "no journal".
    #[error("{} records a transaction that cannot be read: {reason}", shown(path))]
    JournalUnreadable {
        /// The journal file.
        path: PathBuf,
        /// Why it cannot be read.
        reason: crate::journal::Unreadable,
    },

    /// A planned package has no configured source to take its download servers and signature
    /// policy from.
    ///
    /// Its repository is not among the configured ones, or it is a package file that is not
    /// among the named files. Refused rather than checked under `[options]`' `SigLevel`, which
    /// may check nothing where the repository's own policy asks for a signature.
    #[error("{package} has no configured source: {}", said(reason))]
    UnconfiguredSource {
        /// The package's name.
        package: String,
        /// What is missing.
        reason: String,
    },

    /// A transaction journal is there, so a previous transaction did not finish.
    ///
    /// A new transaction is refused rather than written over it. What state the system is in
    /// is unknown, and the journal is the only record of which steps ran and which one was
    /// half applied. [`crate::journal::read`] reads it.
    #[error("{} records an unfinished transaction", shown(path))]
    UnfinishedTransaction {
        /// The journal file.
        path: PathBuf,
    },

    /// An owner query was given an empty path.
    ///
    /// The one way [`crate::owner::Owners::query`] can fail. Every other outcome, including a
    /// path outside the installation root, is an answer that names no owner.
    #[error("an owner query needs a path, and was given an empty string")]
    EmptyOwnerTarget,
}

impl Error {
    /// Builds an [`Error::Io`] for `path`.
    pub(crate) fn io(path: impl Into<PathBuf>, action: IoAction, source: std::io::Error) -> Self {
        Self::Io { path: path.into(), action, source }
    }

    /// Builds an [`Error::LocalDatabaseUnreadable`] for `path`, boxing the cause.
    pub(crate) fn local_db(path: impl Into<PathBuf>, source: piko_db::Error) -> Self {
        Self::LocalDatabaseUnreadable { path: path.into(), source: Box::new(source) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The commit engine will hand errors between threads once extraction is parallel. A
    /// bound that is not asserted is a bound that quietly disappears.
    #[test]
    fn error_is_send_sync_static() {
        const fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Error>();
    }

    /// A member path and a reason are chosen by the package. Neither reaches a terminal with a
    /// control character left in it.
    #[test]
    fn text_from_a_package_is_escaped_in_a_message() {
        let unsafe_path = Error::UnsafeArchivePath {
            path: PathBuf::from("usr/\u{1b}]52;c;cHduZWQ=\u{7}"),
            reason: crate::rootfs::UnsafePath::CurrentDirectory,
        };
        let message = unsafe_path.to_string();
        assert!(!message.contains('\u{1b}') && !message.contains('\u{7}'), "{message:?}");
        assert!(message.contains("usr/\\u{1b}]52"), "{message:?}");

        let unusable = Error::UnusableSource {
            path: PathBuf::from("foo.pkg.tar"),
            reason: "its .PKGINFO is unreadable: bad line\nWarning: forged".to_owned(),
        };
        let message = unusable.to_string();
        assert!(!message.contains('\n'), "{message:?}");
    }

    #[test]
    fn not_available_names_where_it_looked() {
        let err = Error::NotAvailable {
            file_name: "foo-1.0.0-1-x86_64.pkg.tar.zst".to_owned(),
            searched: vec![PathBuf::from("/var/cache/pacman/pkg")],
            skipped: Vec::new(),
        };
        let message = err.to_string();
        assert!(message.contains("foo-1.0.0-1-x86_64.pkg.tar.zst"), "{message}");
        assert!(message.contains("/var/cache/pacman/pkg"), "{message}");
    }

    /// A rejected candidate must reach the message. That is the whole point of tracking it.
    #[test]
    fn not_available_names_what_it_rejected() {
        let err = Error::NotAvailable {
            file_name: "foo-1.0.0-1-x86_64.pkg.tar.zst".to_owned(),
            searched: vec![PathBuf::from("/cache")],
            skipped: vec![crate::source::Skipped {
                path: PathBuf::from("/cache/foo-1.0.0-1-x86_64.pkg.tar.zst"),
                reason: crate::source::SkipReason::NotARegularFile,
            }],
        };
        let message = err.to_string();
        assert!(message.contains("not a regular file"), "{message}");
    }
}
