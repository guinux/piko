//! Downloading and refreshing repository databases.
//!
//! This is its own crate for the same reason `piko-sig` is: it owns a dependency nothing else
//! should have. A reader has no business opening a socket. Keeping HTTP here makes the
//! readers' dependency trees say so.
//!
//! # The ordering is the security property
//!
//! `pacman -Sy` verifies a database when it downloads it, and this mirrors that. The sequence
//! in [`refresh`] is not incidental:
//!
//! 1. Stream the download into a temporary beside the destination
//!    ([`piko_db_write::AtomicFile`]), leaving the live database untouched.
//! 2. Download the detached signature into a second temporary.
//! 3. Verify the temporary against the temporary signature.
//! 4. Only then rename both into place.
//!
//! A rejected download costs nothing: the temporaries are removed on drop, and the previous,
//! known-good database is still there. The reverse order — install then verify — would let a
//! bad download replace a good database and be merely reported. That is the failure mode this
//! feature exists to prevent.
//!
//! Package archives are downloaded the same way (see [`refresh::Refresher::fetch_package`]),
//! with one deliberate difference: there is nothing to verify at download time. A database's
//! `SigLevel` is one value, but a package's applicable policy can differ per repository. The
//! check that matters happens later, against whichever policy actually applies. This crate
//! only fetches bytes and, when asked, the package's own detached `.sig` alongside it.
//!
//! # Concurrency is a fetch phase, never a verification path
//!
//! [`Refresher::refresh_all`] and [`Refresher::fetch_packages`] run several transfers at once.
//! `pacman.conf`'s `ParallelDownloads` decides how many (see [`Concurrency`], which also
//! explains why the number is clamped here rather than where it is parsed). What they
//! parallelize is the fetching. Each file still walks the four steps above on its own, in
//! order, and a batch returns one result per input in input order, so a caller reports
//! failures in configuration order regardless of how the transfers finished.
//!
//! Cancellation is checked before a worker claims its next file, before each request is
//! issued, and once per 64 KiB of body. A worker already inside a connect or a TLS handshake
//! when the signal lands still waits that request out. [`refresh::Limits::timeout`] bounds it,
//! and `Refresher`'s connect timeout is deliberately much shorter than its overall one, so a
//! cancellation is prompt rather than instant.
//!
//! # What is deliberately not here
//!
//! - **Resumed or segmented downloads.** pacman does the first. Neither changes correctness,
//!   and both add failure modes to a path that must be trustworthy before it is fast.
//! - **A disk-space check.** Nothing here inspects free space before writing.
//! - **`Include`d mirrorlists.** Already handled: `piko_db::config` resolves `Server` and
//!   `CacheServer` with `$repo`/`$arch` substituted before this crate sees them.

pub mod cancel;
pub mod concurrency;
pub mod error;
mod pool;
pub mod progress;
pub mod refresh;

pub use cancel::Cancel;
pub use concurrency::Concurrency;
pub use error::{Error, Result};
pub use progress::{Event, Kind};
pub use refresh::{Outcome, PackageFetch, Refresher, RepoRefresh, refresh};
