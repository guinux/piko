//! Progress events for a download, reported through an optional, caller-supplied callback.
//!
//! An event duplicates no information the returned `Result<Outcome>` does not already carry.
//! [`crate::Refresher::refresh`] takes no callback, and produces the same effect without one.
//! Nothing here may be used to decide anything. See
//! [`crate::Refresher::refresh_with_progress`].
//!
//! # Events are per-file, and several files can be in flight
//!
//! A sink is called from whichever worker owns the transfer, so with `ParallelDownloads > 1`
//! events for different files interleave. So every event does one of two things. It names its
//! file, as [`Event::Started`] and [`Event::Downloaded`] do. Or it is safe to add up across
//! files, as [`Event::Progress`] is. That one reports a delta rather than a running total, for
//! exactly this reason. A sink that needs to know which transfers are live pairs `Started`
//! with `Downloaded` by file name.

/// One thing happening while a database or a package is fetched.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Event {
    /// A file's transfer is starting.
    Started {
        /// The file being fetched, e.g. `core.db` or `foo-1.0.0-1-x86_64.pkg.tar.zst`.
        file: String,
        /// What kind of file this is.
        kind: Kind,
        /// `Content-Length`, when the server disclosed one.
        ///
        /// Display-only. [`crate::refresh::Limits::max_bytes`] is enforced against bytes
        /// actually received, never against this field. A mirror's header is a claim, not a
        /// fact.
        total: Option<u64>,
    },
    /// More bytes have arrived for a file that is in flight.
    Progress {
        /// What kind of file they arrived for. A sink can then leave a `.sig` out of a
        /// total it is showing for the package or database beside it.
        kind: Kind,
        /// Bytes received since the previous event for this file — a delta, not a running
        /// total.
        ///
        /// A total becomes unusable the moment two files are in flight at once. A sink adds
        /// several files' bytes into one figure. It cannot subtract the previous value of a
        /// file it did not last hear from. Summing deltas needs no per-file bookkeeping.
        bytes: u64,
    },
    /// A file's bytes are fully received into a temporary, not yet verified or installed.
    /// The live database is still the old one. See [`Event::Installed`].
    Downloaded {
        /// The file whose transfer finished, matching the [`Event::Started`] that opened it.
        file: String,
        /// What kind of file it was.
        kind: Kind,
    },
    /// The database (and its signature, if any) verified and were renamed into place.
    ///
    /// This is the only event that means "done" — the same point
    /// [`crate::refresh::Outcome::Updated`] is returned for.
    Installed,
}

/// Which file an [`Event`] refers to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Kind {
    /// A repository database.
    Database,
    /// A detached signature, for a database or a package.
    Signature,
    /// A package archive.
    Package,
}
