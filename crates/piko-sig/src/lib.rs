//! OpenPGP signature verification for piko, against a GnuPG keyring.
//!
//! This is its own crate for the same reason `piko-txn` is: it is the only part of piko that
//! links GPGME and therefore the only part that runs GnuPG. A reader has no business being
//! able to.
//!
//! It splits the way every consequential rule in this workspace splits:
//!
//! - [`keyring`] asks GnuPG what it thinks of a detached signature. It touches a disk and a
//!   subprocess and decides nothing.
//! - [`decision`] is a pure function from those answers plus a `SigLevel` to accept or reject.
//!   It needs no keyring, so every rule can be enumerated in tests.
//!
//! # Verifying is not the same as passing
//!
//! [`Error`] means piko could not obtain an answer — a missing keyring, a GnuPG that would not
//! run. A file that fails verification is not an error. It is
//! [`decision::Verdict::Rejected`], carrying which rule refused it and which key was involved.
//! Collapsing the two is how a package manager ends up either refusing valid packages or, far
//! worse, installing unverified ones because a broken keyring looked like a pass.
//!
//! # Trust comes from GnuPG, deliberately
//!
//! piko does not compute the web of trust. `SigLevel`'s `TrustedOnly` is defined in terms of
//! GnuPG's model — `trustdb.gpg`, ownertrust, marginal versus full validity — and libalpm
//! verifies through GPGME for that reason (`signing.c`). Reimplementing it would be the
//! riskiest code in this project. See [`keyring`] for the two measurements that settled the
//! choice.
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

pub mod decision;
pub mod error;
pub mod keyring;

pub use decision::{Policy, Rejection, SignatureOutcome, Status, Trust, Verdict, decide};
pub use error::{Error, Result};
pub use keyring::{Keyring, open_context, signature_path, verify_database};
