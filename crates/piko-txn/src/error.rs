//! Error types for the commit engine.
//!
//! This is deliberately a separate enum from [`piko_db::Error`], not an extension of it. The
//! two crates fail in different ways for different reasons: a reader fails to *understand*
//! something, a commit engine fails to *change* something. A caller that wants to distinguish
//! "the database is corrupt" from "the cache is missing a package" should not have to match on
//! variants of one type to do it.

use std::{fmt, path::PathBuf};

/// A [`Result`](std::result::Result) with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// How many file conflicts [`Error::FileConflicts`] names before summarising the rest.
const MAX_SHOWN: usize = 10;

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

    /// No configured source could supply a package file.
    ///
    /// The message names every directory that was searched, and every candidate that was
    /// found but rejected. "package not found in cache" without those details turns into a
    /// support thread. A cache entry that is a dangling symlink, or a directory with the right
    /// name, looks exactly like an absent file to the user.
    #[error(
        "{file_name} is not available from any configured source (searched {}{})",
        searched.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "),
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

    /// An archive named a path that could escape the installation root.
    ///
    /// This is refused on the path alone, before any filesystem access — see
    /// [`crate::rootfs::components`].
    #[error("{} is not a safe path to extract: {reason}", path.display())]
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
        path.display(),
        component.display()
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
    #[error("{} exceeds the {limit} limit of {max}", path.display())]
    PackageLimitExceeded {
        /// The package that was too large.
        path: PathBuf,
        /// Which bound was hit.
        limit: &'static str,
        /// The configured maximum.
        max: u64,
    },

    /// A package archive uses a compression format `alpm-compress` does not implement.
    ///
    /// This is determined by sniffing the magic bytes, not by the file name.
    #[error("{} does not use a supported compression format", path.display())]
    UnsupportedCompression {
        /// The archive that could not be identified.
        path: PathBuf,
    },

    /// An archive member cannot be extracted, and the transaction must stop.
    ///
    /// Currently this is only the "a directory is in the way of a file" case. libalpm also
    /// treats that as fatal (`add.c:290`) rather than removing the directory: it may hold
    /// files belonging to another package, or to nobody.
    #[error("cannot extract {}: {reason:?}", path.display())]
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
    /// package's `files` is the only record of what it owns. An unreadable one means the
    /// removal would delete nothing, report success, and drop the database entry — orphaning
    /// every file the package installed, with nothing left to say who owned them. That is
    /// principle 3 ("cached failures, not cached emptiness") applied where it matters most.
    #[error("the installed entry {entry} cannot be read: {reason}")]
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
    /// `PreTransaction` for. The hook's own output is in the report, so the caller can say
    /// *why* it failed as well as that it did.
    #[error(
        "the transaction was stopped by the hook {hook}, which sets AbortOnFail{}",
        if output.is_empty() { String::new() } else { format!("\n  {}", output.join("\n  ")) }
    )]
    HookAborted {
        /// The hook's file name.
        hook: String,
        /// What the hook printed before it failed.
        ///
        /// This is carried in the error rather than left in the report, because the report is
        /// not returned when the commit fails. Without it, the user is told a hook stopped the
        /// transaction with no way to find out why.
        output: Vec<String>,
    },

    /// A package's signature does not satisfy the configured `SigLevel`.
    ///
    /// The package is intact as far as piko knows; what failed is the *policy*. This is
    /// distinct from [`Error::SignatureUncheckable`] because the two call for opposite
    /// responses: this one means do not install the package, that one means fix the keyring.
    #[error("{}: {reason}", package.display())]
    SignatureRejected {
        /// The package file that was refused.
        package: PathBuf,
        /// Which rule refused it, and which key was involved.
        reason: String,
    },

    /// A package's signature could not be checked at all.
    ///
    /// This means a broken or missing keyring, or a GnuPG that would not run. It is
    /// deliberately **not** treated as a failed signature: doing so would refuse valid
    /// packages and blame them for a local misconfiguration. Equally it is not a pass. piko
    /// has no opinion on a package it could not check, so the transaction stops.
    #[error("cannot check the signature of {}: {reason}", package.display())]
    SignatureUncheckable {
        /// The package file that could not be checked.
        package: PathBuf,
        /// What went wrong.
        reason: String,
    },

    /// Writing the local database entry failed.
    #[error(transparent)]
    Database(#[from] piko_db_write::Error),

    /// The local database could not be opened.
    ///
    /// This is boxed, and that is not incidental. `piko_db::Error` is 104 bytes against this
    /// enum's 112 (both measured), so nesting it inline would make every other variant pay for
    /// this one. That is the trade [`Error::InvalidEntryName`] documents avoiding by
    /// stringifying. A box costs one pointer and keeps the error whole and typed. Stringifying
    /// with `to_string()` instead would flatten it into an `Error::Io` carrying an opaque
    /// string, unrecoverable at any depth by a caller that wanted to know *which* `piko_db`
    /// failure it was.
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
    #[error("the local database at {} cannot be opened", path.display())]
    LocalDatabaseUnreadable {
        /// The `<dbpath>/local` directory that could not be opened.
        path: PathBuf,
        /// Why it could not be.
        #[source]
        source: Box<piko_db::Error>,
    },

    /// A source was configured with a path that cannot be used.
    #[error("{} is not a usable package source: {reason}", path.display())]
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
    /// [`crate::plan::install_steps`] runs immediately after the plan was assembled over the
    /// same `Universe`, so this is not a normal, expected failure mode. It exists so a caller
    /// fails loudly instead of building a transaction that names garbage.
    #[error("the plan names a package the universe does not know (id {id:?}) — this is a bug")]
    PlanInconsistent {
        /// The id the plan named.
        id: piko_db::solve::SolvableId,
    },

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

    /// A plan named a package whose name and version cannot form a valid entry name.
    ///
    /// The reason is stringified rather than carrying [`piko_db::EntryNameError`] itself. This
    /// is the same trade [`Error::SignatureRejected`] makes, and for the same reason: nesting
    /// it would make every variant of this enum pay for that one's size.
    #[error("{name} has no usable entry name: {reason}")]
    InvalidEntryName {
        /// The package name.
        name: String,
        /// Why the name and version could not form one.
        reason: String,
    },

    /// The keyring a verification policy needs could not be opened.
    ///
    /// This is raised only when something actually asks for checking — see
    /// [`crate::plan::verification_from`]. A system with no usable keyring can still run a
    /// transaction whose effective policy needs nothing from it.
    #[error("cannot open the GnuPG keyring at {}", path.display())]
    KeyringUnusable {
        /// The configured `GPGDir`.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: piko_sig::Error,
    },
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
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// The commit engine will hand errors between threads once extraction is parallel. A
    /// bound that is not asserted is a bound that quietly disappears.
    #[test]
    fn error_is_send_sync_static() {
        const fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Error>();
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
