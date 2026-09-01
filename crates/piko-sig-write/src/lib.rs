//! Administers a GnuPG keyring: creates it, imports keys into it, and grants them trust.
//!
//! This is a separate crate from `piko-sig`, not a module inside it, so a verifier cannot link
//! an administrator. `piko-txn`'s `Transaction::verify` has no legitimate need to import a key
//! or edit trust. A crate boundary turns that from a code-review question into a compile error
//! — the same rule `piko-db-write` already applies to `piko-db`.
//!
//! The dependency runs one way. This crate reads through `piko_sig::open_context` to bind a
//! GPGME context to a directory — the one piece of setup identical on both sides of the split
//! — and otherwise never references `piko-sig`'s verification path. `piko-sig` never
//! references this crate.
//!
//! # Why GPGME, never a `gpg` subprocess
//!
//! `piko-sig` chose GPGME over a pure-Rust OpenPGP library because `SigLevel`'s `TrustedOnly`
//! is defined in terms of GnuPG's own trust computation, and a pure-Rust parse of a real
//! keyring silently dropped every subkey. That same reasoning rules out the other common
//! shortcut: `pacman-key` itself is a shell script driving the `gpg` binary as a subprocess.
//! This crate does not do that. Every operation here — key generation, import, local signing,
//! ownertrust, disabling a key — goes through `gpgme`'s C API bindings, the same library
//! `piko-sig` already links, so administering a keyring adds no new binary dependency and no
//! subprocess/argv attack surface.
//!
//! # What is not here
//!
//! No keyserver or WKD lookups (`gpg --recv-keys`/`--refresh-keys`), and no interactive trust
//! editing (`gpg --edit-key`'s REPL). Both need a human or a network in the loop that this
//! crate deliberately does not assume; see `piko-key`'s own scope notes.

pub mod admin;
mod edit;
pub mod error;
pub mod populate;

pub use admin::{ImportSummary, InitOutcome, KeyInfo, KeyringAdmin, OwnerTrust};
pub use error::{Error, Result};
pub use populate::{PopulateSummary, discover_keyrings};
