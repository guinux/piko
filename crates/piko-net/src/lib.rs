//! Downloading and refreshing repository databases.
//!
//! This is its own crate for the same reason `piko-sig` is: it owns a dependency nothing else
//! should have. A reader has no business opening a socket. Keeping HTTP here makes the
//! readers' dependency trees say so.
//!
//! # The ordering is the security property
//!
//! `pacman -Sy` verifies a database when it downloads it, and this mirrors that. The sequence in
//! [`fn@refresh`] is not incidental:
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
//! Package archives are downloaded the same way (see [`Refresher::fetch_package`]),
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
//! when the signal lands still waits that request out. [`Limits::timeout`] bounds it,
//! and `Refresher`'s connect timeout is deliberately much shorter than its overall one, so a
//! cancellation is prompt rather than instant.
//!
//! # Stability
//!
//! Each public item has one path, from the crate root. An item hidden from this documentation
//! is there for this workspace's tests and fuzz targets, and is not part of the stable
//! interface. Three rules say which types a later release can extend without a breaking
//! change:
//!
//! - **A result, a report, a diagnostic or a failure is `#[non_exhaustive]`.** A later release
//!   can add a variant or a field. Match it with a wildcard arm, as the example below does
//!   for [`Outcome`].
//! - **A decision, and a closed set, are exhaustive.** A new variant changes what every caller
//!   must do, so it must break the build of each caller. Example: [`DatabaseKind`].
//! - **An input struct is exhaustive, with public fields:** [`Limits`], [`FreshnessPolicy`],
//!   [`RepoRefresh`]. It has a `Default` when a default value means something, as for options
//!   and limits. An input with optional fields is `#[non_exhaustive]` instead, with a
//!   constructor and `with_` methods: [`PackageFetch`].
//!
//! # Example
//!
//! Refreshing one repository, the way `pacman -Sy` does. The keyring is opened once and lent
//! to every refresh; a [`Policy`](piko_sig::Policy) of `SigLevel = Never` would pass `None`
//! instead and verify nothing.
//!
//! ```rust,no_run
//! use std::path::Path;
//!
//! use piko_net::{Cancel, Outcome, Refresher};
//! use piko_sig::{Keyring, Policy};
//! use piko_db::config::SigLevel;
//!
//! let keyring = Keyring::open("/etc/pacman.d/gnupg")?;
//!
//! // A database is judged by the `DATABASE*` half of the repository's resolved `SigLevel`.
//! let policy = Policy::for_database(SigLevel::default());
//!
//! // Installed on the CLI's `SIGINT` handler. Checked once per 64 KiB.
//! let cancel = Cancel::new();
//!
//! // `-Sy` holds the database lock for the whole refresh, as libalpm's `alpm_db_update` does.
//! let lock = piko_db_write::DbLock::acquire(Path::new("/var/lib/pacman"))?;
//!
//! let refresher = Refresher::default();
//! let refreshed = refresher.refresh(
//!     Path::new("/var/lib/pacman/sync"),
//!     &lock,
//!     "core",
//!     &["https://mirror.example/core/os/x86_64".to_owned()],
//!     Some(&keyring),
//!     policy,
//!     false, // `force`: pacman's second `-y`, which skips the conditional request.
//!     &cancel,
//! )?;
//!
//! match refreshed.outcome {
//!     // `core.db` was downloaded, verified against `core.db.sig`, then renamed into place.
//!     Outcome::Updated => println!("core updated"),
//!     // A `304`. The live database was never touched.
//!     Outcome::UpToDate => println!("core already current"),
//!     // Every server offered an older `core.db`. The installed one stays.
//!     Outcome::Kept => println!("core kept"),
//!     // `Outcome` is `#[non_exhaustive]`: a later release can add an outcome.
//!     _ => println!("core refreshed"),
//! }
//! // Servers passed over, and a database older than the age limit, are reported here.
//! for note in &refreshed.notes {
//!     println!("{note:?}");
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # A signature proves origin, not freshness
//!
//! A mirror can serve an old but correctly signed database, or keep serving the same one.
//! So a refresh also compares the date of what it downloads with the date of what is
//! installed, refuses an older database, and moves on to the next server. It warns about a
//! database older than an age limit, after asking a few more servers for a newer one. See
//! [`FreshnessPolicy`] for the two levels of protection this gives, and for why an older database
//! moves on to the next server while a bad signature does not.
//!
//! # Every request runs in a confined helper
//!
//! The code that parses a mirror's answer runs before the signature check. So a [`Refresher`]
//! given a [`Sandbox`] makes each request in a helper process that cannot write a file, start a
//! program, or reach an unexpected port, and runs as `DownloadUser`, or `nobody`, under root. The helper sends
//! the body back on a pipe, and everything above happens in the caller's process. See
//! [`Sandbox`].
//!
//! # What is deliberately not here
//!
//! - **Resumed or segmented downloads.** pacman does the first. Neither changes correctness,
//!   and both add failure modes to a path that must be trustworthy before it is fast.
//! - **A disk-space check.** `CheckSpace` is answered a layer up, by `piko_txn`'s `space`
//!   module: the batch this crate is handed has already been weighed against the destination
//!   filesystem. Nothing here inspects free space on its own.
//! - **`Include`d mirrorlists.** Already handled: `piko_db::config` resolves `Server` and
//!   `CacheServer` with `$repo`/`$arch` substituted before this crate sees them.

mod cancel;
mod concurrency;
mod error;
mod freshness;
mod health;
mod pool;
mod progress;
mod refresh;
mod sandbox;
mod targets;
mod transport;

pub use cancel::Cancel;
pub use concurrency::Concurrency;
pub use error::{Error, Result, without_credentials};
pub use freshness::{FreshnessNote, FreshnessPolicy, Refreshed};
pub use progress::{Event, Kind};
pub use refresh::{DatabaseKind, Limits, Outcome, PackageFetch, Refresher, RepoRefresh, refresh};
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use sandbox::fuzzing;
#[doc(hidden)]
pub use sandbox::{FALLBACK_USER, confine_self};
pub use sandbox::{Sandbox, run_helper_if_requested};
pub use targets::RefreshTargets;
