//! End-to-end verification against a keyring built for the test.
//!
//! ```text
//! cargo test -p piko-sig --test signed_database
//! ```
//!
//! # Why this exists alongside `sig_real_system.rs`
//!
//! That test uses the real pacman keyring and the real package cache. This is the strongest
//! evidence available *for packages*, but it cannot cover repository databases at all. This
//! machine has **no `.db.sig` files** in `/var/lib/pacman/sync`, so there is nothing real to
//! check against, and no way to observe a rejection.
//!
//! So this test builds its own world instead: a throwaway GnuPG home, a generated key, and a
//! file signed with it. This buys three things the real-system test cannot:
//!
//! - a *positive* case for a signed database, which does not exist on this machine;
//! - a **tampered** database, which no real signature can produce;
//! - a signature from a key that is simply *not in the keyring*, the case a user hits the day
//!   a repository rotates its signing key.
//!
//! It is hermetic: a `tempfile::TempDir` for everything, and no network. It does need `gpg` on
//! `PATH` to create the key, and it skips rather than fails when `gpg` is absent, the same way
//! every other environment-dependent test here does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use piko_db::config::SigLevel;
use piko_sig::{Keyring, Policy, Rejection, Verdict, signature_path};

/// A GnuPG home with one generated, ultimately-trusted key.
///
/// Ultimate trust is what a locally generated key gets by default. This is what makes the
/// `TrustedOnly` half of the policy meaningful here: the signature is not merely valid, it is
/// valid *and trusted*. That pair is what `decide` looks at.
struct Signer {
    home: tempfile::TempDir,
}

impl Signer {
    /// Creates a keyring and a signing key inside it, or `None` if gpg is unavailable.
    fn new() -> Option<Self> {
        let home = tempfile::tempdir().ok()?;
        // 0700: gpg refuses to use a world-readable home, and says so only in a warning.
        std::fs::set_permissions(home.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .ok()?;

        let output = Command::new("gpg")
            .args(["--homedir"])
            .arg(home.path())
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                // ed25519 so key creation does not wait on entropy.
                "--quick-generate-key",
                "piko test signer <test@example.invalid>",
                "ed25519",
                "sign",
                "never",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            eprintln!(
                "skipping: could not create a test key: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return None;
        }
        Some(Self { home })
    }

    fn path(&self) -> &Path {
        self.home.path()
    }

    /// Writes a detached signature for `file`, beside it.
    fn sign(&self, file: &Path) -> bool {
        Command::new("gpg")
            .args(["--homedir"])
            .arg(self.home.path())
            .args(["--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""])
            .arg("--output")
            .arg(signature_path(file))
            .arg("--detach-sign")
            .arg(file)
            .output()
            .is_ok_and(|output| output.status.success())
    }
}

/// A file standing in for a repository database. Its contents do not matter to a signature.
fn database(dir: &Path, bytes: &[u8]) -> PathBuf {
    let path = dir.join("core.db");
    std::fs::write(&path, bytes).unwrap();
    path
}

/// pacman's default for databases is Optional. `Required` is what `-Sy` over an untrusted
/// mirror should use, and is the interesting policy to test.
fn required() -> Policy {
    Policy::for_database(SigLevel::DATABASE)
}

#[test]
fn a_signed_database_is_accepted_and_reports_that_it_verified() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"%FILES%\nnot really a database\n");
    assert!(signer.sign(&db), "signing failed");

    let keyring = Keyring::open(signer.path()).unwrap();
    assert_eq!(keyring.check(&db, required()).unwrap(), Verdict::Accepted { verified: true });
}

/// The case that matters: a mirror serving a modified database with the original signature.
#[test]
fn a_tampered_database_is_rejected() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"%FILES%\nnot really a database\n");
    assert!(signer.sign(&db), "signing failed");

    // The signature stays. The database changes underneath it.
    std::fs::write(&db, b"%FILES%\nsomething else entirely\n").unwrap();

    let keyring = Keyring::open(signer.path()).unwrap();
    let verdict = keyring.check(&db, required()).unwrap();
    assert!(
        matches!(verdict, Verdict::Rejected(_)),
        "a modified database was accepted: {verdict:?}"
    );
}

/// A database signed by a key the keyring has never seen. This is not the same as an invalid
/// signature and must not be reported as one. It is what a rotated repository key looks like,
/// and the message decides whether the user imports a key or suspects an attack.
#[test]
fn a_database_signed_by_an_unknown_key_is_rejected_as_unknown() {
    let Some(signer) = Signer::new() else { return };
    let Some(stranger) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"%FILES%\ncontents\n");
    assert!(stranger.sign(&db), "signing failed");

    // Verified against the *other* keyring, which does not hold the signing key.
    let keyring = Keyring::open(signer.path()).unwrap();
    let verdict = keyring.check(&db, required()).unwrap();
    assert!(
        matches!(verdict, Verdict::Rejected(Rejection::KeyUnknown { .. })),
        "expected an unknown-key rejection, got {verdict:?}"
    );
}

/// An unsigned database follows the policy. `Optional` is pacman's default for databases,
/// which is why an unsigned `core.db` does not stop the world on a stock system.
#[test]
fn an_unsigned_database_follows_the_policy() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"%FILES%\ncontents\n");
    let keyring = Keyring::open(signer.path()).unwrap();

    assert_eq!(
        keyring.check(&db, required()).unwrap(),
        Verdict::Rejected(Rejection::MissingRequired)
    );

    let optional = Policy::for_database(SigLevel::DATABASE | SigLevel::DATABASE_OPTIONAL);
    assert_eq!(keyring.check(&db, optional).unwrap(), Verdict::Accepted { verified: false });
}

/// `SigLevel = Never` accepts without consulting GnuPG at all, including a database whose
/// signature is outright bad. This is the observable difference from `Optional`.
#[test]
fn a_disabled_policy_does_not_consult_the_keyring() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"%FILES%\ncontents\n");
    std::fs::write(signature_path(&db), b"this is not a signature").unwrap();

    let keyring = Keyring::open(signer.path()).unwrap();
    let never = Policy::for_database(SigLevel::default());
    assert!(!never.check, "the default SigLevel should not ask for a database check");
    assert_eq!(keyring.check(&db, never).unwrap(), Verdict::Accepted { verified: false });
}
