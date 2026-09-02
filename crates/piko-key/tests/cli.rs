//! Runs the `piko-key` binary against a throwaway keyring.
//!
//! Only the real process reaches two of the behaviors here. The confirmation prompt reads
//! `std::io::stdin()` directly, so an answer needs a child process and a pipe. The default
//! value of `--secret` is a fact about argument parsing, which no library test can observe.
//!
//! Every test skips if GnuPG cannot be reached, as `piko-sig-write`'s own tests do. The keys
//! are ed25519, not `init`'s RSA-4096. These tests exercise the CLI's decisions, not key
//! generation, and `key_real_system.rs` already covers key generation.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::Duration,
};

/// The same value as `piko_sig_write::admin::MASTER_KEY_USERID`, which is `pub(crate)`.
/// Repeated here rather than exported. These tests must not be able to change the library's
/// own identity string.
const MASTER_KEY_USERID: &str = "piko Local Keyring Master Key <piko@localhost>";

/// Builds a keyring with piko's master key, and one imported public key per entry in
/// `foreign`.
///
/// Returns the keyring path and the foreign fingerprints, in the order given. Returns `None`
/// if GnuPG cannot be reached.
fn keyring(foreign: &[&str]) -> Option<(PathBuf, Vec<String>)> {
    let home = new_home()?;
    let mut context = piko_sig::open_context(&home).ok()?;
    context
        .create_key_with_flags(
            MASTER_KEY_USERID,
            "ed25519",
            Duration::ZERO,
            gpgme::CreateKeyFlags::CERT | gpgme::CreateKeyFlags::NOPASSWD,
        )
        .ok()?;

    let mut fingerprints = Vec::with_capacity(foreign.len());
    for user_id in foreign {
        // This generates each foreign key in its own keyring, and imports only its public
        // key. The admin keyring therefore holds no secret key for it. Otherwise `delete`
        // would refuse it, and the `--secret` test below would test nothing.
        let vendor_home = new_home()?;
        let mut vendor = piko_sig::open_context(&vendor_home).ok()?;
        let generated = vendor
            .create_key_with_flags(
                *user_id,
                "ed25519",
                Duration::ZERO,
                gpgme::CreateKeyFlags::SIGN | gpgme::CreateKeyFlags::NOPASSWD,
            )
            .ok()?;
        let fingerprint = generated.fingerprint().ok()?.to_owned();
        let key = vendor.get_key(&fingerprint).ok()?;
        let mut exported = gpgme::Data::new().ok()?;
        vendor.export_keys([&key], gpgme::ExportMode::empty(), &mut exported).ok()?;
        context.import(exported.try_into_bytes()?).ok()?;
        fingerprints.push(fingerprint);
    }
    Some((home, fingerprints))
}

/// Creates a new GnuPG home directory at mode `0700`.
///
/// This leaks the directory rather than dropping it, as `piko-sig-write`'s unit tests do. Each
/// home is unique, GnuPG keeps an agent running against it, and the OS reclaims `/tmp`.
fn new_home() -> Option<PathBuf> {
    let dir = tempfile::tempdir().ok()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).ok()?;
    let path = dir.path().to_path_buf();
    std::mem::forget(dir);
    Some(path)
}

/// Runs `piko-key --gpgdir <home> <args…>` and writes `stdin` to the confirmation prompt.
fn run(home: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_piko-key"))
        .arg("--gpgdir")
        .arg(home)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A decline answers for one key, not for the whole command line. piko must still offer
/// every key named after it.
#[test]
fn declining_one_key_skips_only_that_key() {
    let Some((home, keys)) =
        keyring(&["first <one@example.invalid>", "second <two@example.invalid>"])
    else {
        return;
    };
    let (first, second) = (&keys[0], &keys[1]);

    let output = run(&home, &["lsign-key", first, second], "n\ny\n");
    let printed = stdout(&output);

    assert!(printed.contains(&format!("skipped {first}")), "{printed}");
    assert!(printed.contains(&format!("locally signed {second}")), "{printed}");
    assert!(!printed.contains(&format!("locally signed {first}")), "{printed}");
    // A decline is not a failure. `crates/piko` ends a declined transaction the same way.
    assert!(output.status.success(), "{output:?}");
}

/// A closed stdin declines every prompt. piko signs nothing, and reports no error.
#[test]
fn an_unattended_run_declines_rather_than_proceeding() {
    let Some((home, keys)) = keyring(&["lone <lone@example.invalid>"]) else { return };

    let output = run(&home, &["lsign-key", &keys[0]], "");
    let printed = stdout(&output);

    assert!(printed.contains(&format!("skipped {}", keys[0])), "{printed}");
    assert!(output.status.success(), "{output:?}");
}

/// `--secret` defaults to off, so piko refuses its own master key and names it in the error.
/// That key signs every local certification in the keyring. pacman-key's `--delete` deletes
/// public keys only, for the same reason (`pacman-key.sh.in:392`).
#[test]
fn delete_refuses_a_secret_key_without_the_secret_flag() {
    let Some((home, _)) = keyring(&[]) else { return };
    let master = master_fingerprint(&home);

    let output = run(&home, &["delete", &master, "--noconfirm"], "");
    let message = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{output:?}");
    assert!(message.contains("has a secret key"), "{message}");
    assert!(message.contains("--secret"), "{message}");

    let listed = stdout(&run(&home, &["list-keys"], ""));
    assert!(listed.contains(&master), "the master key must survive: {listed}");
}

/// A key with no secret key still deletes without the flag.
#[test]
fn delete_still_removes_a_public_key_without_the_secret_flag() {
    let Some((home, keys)) = keyring(&["doomed <doomed@example.invalid>"]) else { return };

    let output = run(&home, &["delete", &keys[0], "--noconfirm"], "");
    assert!(output.status.success(), "{output:?}");

    let listed = stdout(&run(&home, &["list-keys"], ""));
    assert!(!listed.contains(&keys[0]), "{listed}");
}

/// Builds a keyring, and a file signed by a vendor key that keyring knows but does not trust.
///
/// Returns the keyring path, the detached signature, and the vendor fingerprint. The signed
/// file sits next to the signature, so `piko-key verify <sig>` finds it on its own. `None` if
/// GnuPG cannot be reached.
fn signed_file() -> Option<(PathBuf, PathBuf, String)> {
    let home = new_home()?;
    let mut context = piko_sig::open_context(&home).ok()?;
    context
        .create_key_with_flags(
            MASTER_KEY_USERID,
            "ed25519",
            Duration::ZERO,
            gpgme::CreateKeyFlags::CERT | gpgme::CreateKeyFlags::NOPASSWD,
        )
        .ok()?;

    let vendor_home = new_home()?;
    let mut vendor = piko_sig::open_context(&vendor_home).ok()?;
    let generated = vendor
        .create_key_with_flags(
            "vendor <vendor@example.invalid>",
            "ed25519",
            Duration::ZERO,
            gpgme::CreateKeyFlags::SIGN | gpgme::CreateKeyFlags::NOPASSWD,
        )
        .ok()?;
    let fingerprint = generated.fingerprint().ok()?.to_owned();
    let key = vendor.get_key(&fingerprint).ok()?;

    let mut exported = gpgme::Data::new().ok()?;
    vendor.export_keys([&key], gpgme::ExportMode::empty(), &mut exported).ok()?;
    context.import(exported.try_into_bytes()?).ok()?;

    let document = vendor_home.join("payload.txt");
    std::fs::write(&document, b"signed content").ok()?;
    vendor.add_signer(&key).ok()?;
    let mut detached = gpgme::Data::new().ok()?;
    vendor.sign_detached(&b"signed content"[..], &mut detached).ok()?;
    let signature = vendor_home.join("payload.txt.sig");
    std::fs::write(&signature, detached.try_into_bytes()?).ok()?;

    Some((home, signature, fingerprint))
}

/// `verify` reports piko's verdict, not GnuPG's. A valid signature from a key nobody trusts
/// must fail, because `piko install` would refuse the same signature.
#[test]
fn verify_refuses_a_valid_signature_from_an_untrusted_key() {
    let Some((home, signature, fingerprint)) = signed_file() else { return };

    let output = run(&home, &["verify", signature.to_str().unwrap()], "");
    let printed = stdout(&output);
    let message = String::from_utf8_lossy(&output.stderr);

    // The status line still reports what GnuPG found, before the verdict.
    assert!(printed.contains("Valid"), "{printed}");
    assert!(printed.contains(&fingerprint), "{printed}");
    assert!(!output.status.success(), "{output:?}");
    assert!(message.contains("unknown trust"), "{message}");
}

/// The counterpart. `lsign-key` establishes the trust path, and `verify` then accepts.
#[test]
fn verify_accepts_a_signature_once_the_key_is_locally_signed() {
    let Some((home, signature, fingerprint)) = signed_file() else { return };
    assert!(run(&home, &["lsign-key", &fingerprint, "--noconfirm"], "").status.success());

    let output = run(&home, &["verify", signature.to_str().unwrap()], "");
    assert!(output.status.success(), "{output:?} {}", stdout(&output));
    assert!(stdout(&output).contains("Full"), "{}", stdout(&output));
}

/// GnuPG resolves the patterns, so an email address and a lowercase fingerprint both work.
/// A substring filter over the fingerprint alone matches neither.
#[test]
fn list_keys_accepts_every_pattern_gnupg_accepts() {
    let Some((home, keys)) = keyring(&["listed <listed@example.invalid>"]) else { return };
    let fingerprint = &keys[0];

    for pattern in [fingerprint.as_str(), &fingerprint.to_lowercase(), "listed@example.invalid"] {
        let output = run(&home, &["list-keys", pattern], "");
        assert!(output.status.success(), "{pattern}: {output:?}");
        assert!(stdout(&output).contains(fingerprint), "{pattern}: {}", stdout(&output));
    }
}

/// A pattern that matches nothing is a failure, so a script can test for it. An empty keyring
/// with no pattern given is not.
#[test]
fn list_keys_fails_only_when_a_named_pattern_matches_nothing() {
    let Some((home, _)) = keyring(&[]) else { return };

    let missing = run(&home, &["list-keys", "absent@example.invalid"], "");
    assert!(!missing.status.success(), "{missing:?}");
    assert!(stdout(&missing).contains("no matching keys"), "{}", stdout(&missing));

    // No pattern given: the master key is listed, and the command succeeds.
    assert!(run(&home, &["list-keys"], "").status.success());
}

fn master_fingerprint(home: &Path) -> String {
    let mut context = piko_sig::open_context(home).unwrap();
    let key = context.find_secret_keys(["piko@localhost"]).unwrap().next().unwrap().unwrap();
    key.fingerprint().unwrap().to_owned()
}
