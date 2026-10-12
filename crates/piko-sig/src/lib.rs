//! OpenPGP signature verification for piko, against a GnuPG keyring.
//!
//! This is its own crate for the same reason `piko-txn` is: it is the only part of piko that
//! links GPGME and therefore the only part that runs GnuPG. A reader has no business being
//! able to.
//!
//! It splits the way every consequential rule in this workspace splits:
//!
//! - [`Keyring`] asks GnuPG what it thinks of a detached signature. It touches a disk and a
//!   subprocess and decides nothing.
//! - [`decide`] is a pure function from those answers plus a [`Policy`] to accept or reject.
//!   It needs no keyring, so every rule can be enumerated in tests.
//!
//! # Verifying is not the same as passing
//!
//! [`Error`] means piko could not obtain an answer — a missing keyring, a GnuPG that would not
//! run. A file that fails verification is not an error. It is
//! [`Verdict::Rejected`], carrying which rule refused it and which key was involved.
//! Collapsing the two is how a package manager ends up either refusing valid packages or, far
//! worse, installing unverified ones because a broken keyring looked like a pass.
//!
//! # Trust comes from GnuPG, deliberately
//!
//! piko does not compute the web of trust. `SigLevel`'s `TrustedOnly` is defined in terms of
//! GnuPG's model — `trustdb.gpg`, ownertrust, marginal versus full validity — and libalpm
//! verifies through GPGME for that reason (`signing.c`). Reimplementing it would be the
//! riskiest code in this project. Two measurements settled the choice:
//!
//! - A pure-Rust alternative (rpgp) verifies real Arch signatures correctly. But it silently
//!   drops every subkey when reading `/etc/pacman.d/gnupg/pubring.gpg`. It parses 0 against
//!   the 308 packet-level subkeys `gpg` reports there, because the keyring interleaves 3417
//!   GnuPG ring-trust packets. Arch packagers sign with subkeys, so roughly 30% of a real
//!   cache finds no signing key, and no error is raised.
//! - GPGME, over the same corpus, returned `good` with `Full` validity for every package.
//!
//! # Stability
//!
//! Each public item has one path, from the crate root. An item hidden from this documentation
//! is there for `piko-sig-write` and this workspace's tests, and is not part of the stable
//! interface. Three rules say which types a later release can extend without a breaking
//! change:
//!
//! - **A result, a report, a diagnostic or a failure is `#[non_exhaustive]`:**
//!   [`SignatureOutcome`], [`Rejection`], [`Checked`], [`Error`]. A later release can add a
//!   variant or a field. Match it with a wildcard arm.
//! - **A decision, and a closed set, are exhaustive.** A new variant changes what every caller
//!   must do, so it must break the build of each caller: [`Verdict`].
//! - **An input struct is exhaustive, with public fields:** [`Policy`]. It has a `Default`
//!   when a default value means something. [`Policy`] has none: its all-`false` value checks
//!   nothing, and a policy that checks nothing is never a default.
//!
//! # Example
//!
//! Checking one package file against the keyring, under the `SigLevel` its repository resolved
//! to. `check` looks for `<path>.sig` beside the file — [`signature_path`] spells that rule.
//!
//! ```rust,no_run
//! use std::path::Path;
//!
//! use piko_sig::{Keyring, Policy, Verdict};
//! use piko_db::config::SigLevel;
//!
//! let keyring = Keyring::open("/etc/pacman.d/gnupg")?;
//! let package = Path::new("/var/cache/pacman/pkg/tree-2.2.1-1-x86_64.pkg.tar.zst");
//!
//! // `Err` means no answer could be obtained. A refusal is a `Verdict`, not an error.
//! match keyring.check(package, Policy::for_package(SigLevel::default()))? {
//!     Verdict::Accepted { verified: true } => println!("signature checked and trusted"),
//!     Verdict::Accepted { verified: false } => println!("policy asked for no check"),
//!     Verdict::Rejected(reason) => println!("refused: {reason:?}"),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Scope
//!
//! Verification only. Fetching a missing key from a keyserver or WKD (libalpm's
//! `_alpm_key_import`) is not here. Importing a key on demand to make a failing signature pass
//! is a trust decision, and piko will not make it silently on a user's behalf.
//!
//! Administering a keyring — importing a vendor's keys, granting them trust, generating piko's
//! own signing key — is a different, explicit, human-invoked action, and lives in the sibling
//! `piko-sig-write` crate for the same reason `piko-db-write` sits beside `piko-db`: a crate
//! that only needs to verify (`piko-txn`) should not gain the ability to mutate a keyring
//! merely by linking this one.

mod decision;
mod error;
mod keyring;

pub use decision::{Policy, Rejection, SignatureOutcome, Status, Trust, Verdict, decide};
pub use error::{Error, Result};
#[doc(hidden)]
pub use keyring::open_context;
pub use keyring::{
    Checked, Keyring, MAX_SIGNATURE_BYTES, signature_path, verify_database, verify_database_dated,
};
