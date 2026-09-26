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
use piko_sig::{Keyring, Policy, Rejection, Verdict, signature_path, verify_database_dated};

/// A GnuPG home with one generated, ultimately-trusted key.
///
/// Ultimate trust is what a locally generated key gets by default. That is what makes the
/// `TrustedOnly` half of the policy meaningful here. The signature is not merely valid. It is
/// valid *and trusted*. That pair is what `decide` looks at.
struct Signer {
    home: tempfile::TempDir,
}

impl Signer {
    /// Creates a keyring and a signing key inside it, or `None` if gpg is unavailable.
    fn new() -> Option<Self> {
        Self::generate(&[], "never")
    }

    /// As [`Signer::new`], with a key created two years ago that expired one year later.
    ///
    /// Returns the key's creation time too. A signature made shortly after it is one made
    /// while the key was valid.
    fn expired() -> Option<(Self, u64)> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?;
        let created = now.as_secs().checked_sub(2 * 365 * 24 * 3_600)?;
        let signer = Self::generate(&["--faked-system-time", &format!("{created}!")], "1y")?;
        Some((signer, created))
    }

    /// Creates a keyring with one signing key expiring after `expiry`, with `extra` gpg options.
    fn generate(extra: &[&str], expiry: &str) -> Option<Self> {
        let home = tempfile::tempdir().ok()?;
        // 0700: gpg refuses to use a world-readable home, and says so only in a warning.
        std::fs::set_permissions(home.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .ok()?;

        let output = Command::new("gpg")
            .args(["--homedir"])
            .arg(home.path())
            .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
            .args(extra)
            .args([
                // ed25519 so key creation does not wait on entropy.
                "--quick-generate-key",
                "piko test signer <test@example.invalid>",
                "ed25519",
                "sign",
                expiry,
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
        self.sign_with(file, &[])
    }

    /// As [`Signer::sign`], with the signature's creation time fixed to `unix_seconds`.
    ///
    /// gpg's `--faked-system-time <seconds>!` freezes its clock, which is how a test makes an
    /// older and a newer signature of one repository without waiting between them.
    fn sign_at(&self, file: &Path, unix_seconds: u64) -> bool {
        self.sign_with(file, &["--faked-system-time", &format!("{unix_seconds}!")])
    }

    /// Disables the signing key, as `piko key populate` does for a `-revoked` entry.
    fn disable(&self) -> bool {
        self.edit_key("disable\nquit\n")
    }

    /// Runs `script` through `gpg --edit-key` on the signing key.
    fn edit_key(&self, script: &str) -> bool {
        use std::io::Write as _;
        let Ok(mut child) = Command::new("gpg")
            .args(["--homedir"])
            .arg(self.home.path())
            .args(["--batch", "--command-fd", "0", "--edit-key", "test@example.invalid"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            return false;
        };
        let written =
            child.stdin.take().is_some_and(|mut stdin| stdin.write_all(script.as_bytes()).is_ok());
        written && child.wait().is_ok_and(|status| status.success())
    }

    /// Revokes the signing key with the revocation certificate GnuPG wrote when it created
    /// the key.
    ///
    /// GnuPG prefixes that certificate's armor header with `:` so it cannot be imported by
    /// accident. Removing the prefix is the documented way to use it.
    fn revoke(&self) -> bool {
        let Ok(mut entries) = std::fs::read_dir(self.home.path().join("openpgp-revocs.d")) else {
            return false;
        };
        let Some(Ok(entry)) = entries.next() else { return false };
        let Ok(text) = std::fs::read_to_string(entry.path()) else { return false };
        let certificate = self.home.path().join("revoke.asc");
        if std::fs::write(&certificate, text.replace(":-----BEGIN", "-----BEGIN")).is_err() {
            return false;
        }
        Command::new("gpg")
            .args(["--homedir"])
            .arg(self.home.path())
            .args(["--batch", "--import"])
            .arg(&certificate)
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn sign_with(&self, file: &Path, extra: &[&str]) -> bool {
        Command::new("gpg")
            .args(["--homedir"])
            .arg(self.home.path())
            .args(["--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""])
            .args(extra)
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

/// A good signature over a SHA-1 digest is refused and named, although GnuPG reports it good:
/// SHA-1 collisions let one signature cover two files. The same key over SHA-256 is accepted.
#[test]
fn a_signature_over_a_weak_digest_is_refused() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"%FILES%\nnot really a database\n");
    let keyring = Keyring::open(signer.path()).unwrap();

    assert!(signer.sign_with(&db, &["--digest-algo", "SHA1"]), "signing failed");
    let verdict = keyring.check(&db, required()).unwrap();
    assert!(
        matches!(&verdict, Verdict::Rejected(Rejection::WeakDigest { algorithm: "SHA1", .. })),
        "got {verdict:?}"
    );

    assert!(signer.sign_with(&db, &["--digest-algo", "SHA256"]), "signing failed");
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
/// signature, and must not be reported as one. It is what a rotated repository key looks like.
/// The message decides whether the user imports a key or suspects an attack.
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

/// The signature's own creation time is the date a mirror cannot forge. It must come back from
/// the check exactly as the signer set it.
#[test]
fn an_accepted_signature_reports_when_it_was_made() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"a database signed at a known time\n");
    // The key must exist at the faked time, so the time is after the key was generated.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let signed = now + 3_600;
    assert!(signer.sign_at(&db, signed), "signing failed");

    let checked = verify_database_dated(&db, signer.path(), SigLevel::DATABASE).unwrap();
    assert_eq!(checked.verdict, Verdict::Accepted { verified: true });
    assert_eq!(
        checked.signed_at,
        std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(signed))
    );
}

/// An unsigned database under `Optional` is accepted, but carries no date: there is no
/// signature to take one from.
#[test]
fn an_unsigned_database_has_no_signature_time() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"unsigned\n");

    let checked =
        verify_database_dated(&db, signer.path(), SigLevel::DATABASE | SigLevel::DATABASE_OPTIONAL)
            .unwrap();
    assert_eq!(checked.verdict, Verdict::Accepted { verified: false });
    assert_eq!(checked.signed_at, None);
}

/// GnuPG reports a signature from a disabled key as good and fully trusted. `gpg --verify` only
/// notes the flag. So a verifier that reads the signature alone accepts it, and disabling a key
/// — `piko key populate`'s whole answer to a `-revoked` entry — changes nothing. libalpm reads
/// the flag off the key (`signing.c:695`), and so must piko.
#[test]
fn a_signature_from_a_disabled_key_is_rejected() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"signed, then the key is disabled\n");
    assert!(signer.sign(&db), "signing failed");
    let keyring = Keyring::open(signer.path()).unwrap();
    assert_eq!(keyring.check(&db, required()).unwrap(), Verdict::Accepted { verified: true });

    assert!(signer.disable(), "disabling the key failed");

    // The most permissive policy that still checks: nothing may excuse a disabled key.
    let permissive = Policy { check: true, optional: true, marginal_ok: true, unknown_ok: true };
    let verdict = keyring.check(&db, permissive).unwrap();
    assert!(
        matches!(verdict, Verdict::Rejected(Rejection::KeyDisabled { .. })),
        "a disabled key's signature was not refused: {verdict:?}"
    );
}

/// A revoked key is refused, and named as revoked rather than as an invalid signature.
#[test]
fn a_signature_from_a_revoked_key_is_rejected_as_revoked() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"signed, then the key is revoked\n");
    assert!(signer.sign(&db), "signing failed");
    assert!(signer.revoke(), "revoking the key failed");

    let keyring = Keyring::open(signer.path()).unwrap();
    let verdict = keyring.check(&db, required()).unwrap();
    assert!(
        matches!(verdict, Verdict::Rejected(Rejection::KeyRevoked { .. })),
        "expected a revoked-key rejection, got {verdict:?}"
    );
}

/// The peak resident set size of this process, in bytes, from `/proc/self/status`.
fn peak_rss() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

/// Verifying streams the file into GnuPG. A mirror chooses how large a package is, up to
/// `max_package_bytes`, so memory that grows with the file lets it exhaust memory before the
/// signature is judged. A 256 MiB sparse file costs no disk and no time to create; buffered,
/// it raises the peak by its full size.
#[test]
fn verifying_a_large_file_does_not_hold_it_in_memory() {
    const SIZE: u64 = 256 * 1024 * 1024;
    let Some(signer) = Signer::new() else { return };
    let Some(before) = peak_rss() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = work.path().join("large.db");
    std::fs::File::create(&db).unwrap().set_len(SIZE).unwrap();
    assert!(signer.sign(&db), "signing failed");

    let keyring = Keyring::open(signer.path()).unwrap();
    assert_eq!(keyring.check(&db, required()).unwrap(), Verdict::Accepted { verified: true });

    let grown = peak_rss().unwrap().saturating_sub(before);
    assert!(grown < SIZE / 4, "verifying a {SIZE}-byte file raised the peak by {grown} bytes");
}

/// A FIFO where the signed file should be is refused, not opened for a read that blocks until
/// a writer appears.
#[test]
fn a_fifo_in_place_of_the_signed_file_is_refused_without_blocking() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"signed\n");
    assert!(signer.sign(&db), "signing failed");
    std::fs::remove_file(&db).unwrap();
    let made = Command::new("mkfifo").arg(&db).status().is_ok_and(|status| status.success());
    if !made {
        return;
    }

    let keyring = Keyring::open(signer.path()).unwrap();
    // A regression hangs here rather than failing, and the test harness reports the hang.
    let result = keyring.check(&db, required());
    assert!(result.is_err(), "a FIFO was verified: {result:?}");
}

/// Only an absent `.sig` means "unsigned". A directory at that path is not a signature, and
/// under `Optional` reading it as "none" would accept the file unverified.
#[test]
fn a_signature_path_that_is_not_a_file_is_an_error_not_an_absence() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"unsigned, with a directory for a signature\n");
    std::fs::create_dir(signature_path(&db)).unwrap();

    let keyring = Keyring::open(signer.path()).unwrap();
    let optional = Policy::for_database(SigLevel::DATABASE | SigLevel::DATABASE_OPTIONAL);
    let result = keyring.check(&db, optional);
    assert!(result.is_err(), "a directory was read as a missing signature: {result:?}");
}

/// A signature made while the key was valid, verified after the key expired. GnuPG reports it
/// as `EXPKEYSIG` with no trust status at all, so the key's own ultimate trust does not reach
/// the verdict. `TrustedOnly` refuses it, and only a policy that accepts unknown trust takes it.
#[test]
fn an_expired_key_is_refused_by_trusted_only_and_accepted_by_trust_all() {
    let Some((signer, created)) = Signer::expired() else { return };
    let work = tempfile::tempdir().unwrap();
    let db = database(work.path(), b"signed the hour after the key was made\n");
    assert!(signer.sign_at(&db, created + 3_600), "signing failed");

    let keyring = Keyring::open(signer.path()).unwrap();
    let verdict = keyring.check(&db, required()).unwrap();
    assert!(
        matches!(verdict, Verdict::Rejected(Rejection::UnknownTrust { .. })),
        "expected an unknown-trust rejection, got {verdict:?}"
    );

    let trust_all = Policy { check: true, optional: false, marginal_ok: true, unknown_ok: true };
    assert_eq!(keyring.check(&db, trust_all).unwrap(), Verdict::Accepted { verified: true });
}

/// A package with its signature in memory, as a repository database publishes it in
/// `%PGPSIG%`, and no `.sig` beside it.
fn package_signed_in_memory(signer: &Signer, dir: &Path, bytes: &[u8]) -> (PathBuf, Vec<u8>) {
    let package = dir.join("foo-1.0.0-1-x86_64.pkg.tar.zst");
    std::fs::write(&package, bytes).unwrap();
    assert!(signer.sign(&package), "signing failed");
    let signature = std::fs::read(signature_path(&package)).unwrap();
    std::fs::remove_file(signature_path(&package)).unwrap();
    (package, signature)
}

/// A signature held in memory verifies the file it signs, with no `.sig` on disk. The same
/// signature over changed bytes is refused.
#[test]
fn a_signature_held_in_memory_verifies_the_file_it_signs() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let (package, signature) = package_signed_in_memory(&signer, work.path(), b"package");
    let keyring = Keyring::open(signer.path()).unwrap();
    let policy = Policy::for_package(SigLevel::PACKAGE);

    assert_eq!(
        keyring.check_bytes(&package, &signature, policy).unwrap(),
        Verdict::Accepted { verified: true }
    );

    std::fs::write(&package, b"another package").unwrap();
    let verdict = keyring.check_bytes(&package, &signature, policy).unwrap();
    assert!(matches!(verdict, Verdict::Rejected(_)), "a changed file was accepted: {verdict:?}");
}

/// A signature held in memory is the only one read. A good `.sig` beside the file does not
/// make up for a signature in memory that does not match.
#[test]
fn a_signature_held_in_memory_ignores_the_sig_beside_the_file() {
    let Some(signer) = Signer::new() else { return };
    let work = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let (_, signature_of_other) = package_signed_in_memory(&signer, other.path(), b"other");
    let package = work.path().join("foo-1.0.0-1-x86_64.pkg.tar.zst");
    std::fs::write(&package, b"package").unwrap();
    assert!(signer.sign(&package), "signing failed");
    let keyring = Keyring::open(signer.path()).unwrap();
    let policy = Policy::for_package(SigLevel::PACKAGE);

    assert_eq!(keyring.check(&package, policy).unwrap(), Verdict::Accepted { verified: true });
    let verdict = keyring.check_bytes(&package, &signature_of_other, policy).unwrap();
    assert!(matches!(verdict, Verdict::Rejected(_)), "the .sig on disk was read: {verdict:?}");
}

/// A policy that asks for nothing does not run GnuPG, even over a signature that is not one.
#[test]
fn a_signature_held_in_memory_is_not_read_when_the_policy_asks_for_nothing() {
    let work = tempfile::tempdir().unwrap();
    let package = database(work.path(), b"package");
    let keyring = Keyring::open(work.path()).unwrap();
    let never = Policy::for_package(SigLevel::default());
    assert!(!never.check, "the default SigLevel should not ask for a package check");

    assert_eq!(
        keyring.check_bytes(&package, b"not a signature", never).unwrap(),
        Verdict::Accepted { verified: false }
    );
}
