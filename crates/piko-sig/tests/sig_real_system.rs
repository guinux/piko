//! Verifies real cached packages against this machine's real pacman keyring.
//!
//! `#[ignore]`d like every real-system test. Run explicitly:
//!
//! ```text
//! cargo test -p piko-sig --test sig_real_system -- --ignored --nocapture
//! ```
//!
//! **Read-only.** Nothing here writes; the keyring and the package cache are inputs.
//!
//! # The oracle
//!
//! Every package in `/var/cache/pacman/pkg` was installed by pacman with
//! `SigLevel = PackageRequired PackageTrustedOnly` in force, so pacman verified each one and
//! found a fully-trusted signature. piko must reach the same verdict on the same files with
//! the same keyring. That is a genuine cross-check rather than piko agreeing with itself.
//!
//! `gpg --verify` provides a second, independent opinion on a sample. This way, a systematic
//! mistake in how piko *interprets* GPGME cannot pass by agreeing with a mistake in how it
//! *calls* GPGME.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use piko_db::config::SigLevel;
use piko_sig::{Keyring, Policy, Rejection, Verdict, decide, signature_path};

const KEYRING: &str = "/etc/pacman.d/gnupg";
const CACHE: &str = "/var/cache/pacman/pkg";

/// How many packages to verify. Each spawns gpg and hashes a whole archive.
const SAMPLE: usize = 120;

/// pacman's effective package policy on a stock Arch system: Required, TrustedOnly.
fn required_trusted() -> Policy {
    Policy::for_package(SigLevel::PACKAGE)
}

/// Cached packages that have a detached signature beside them, spread across the size range.
fn signed_packages() -> Option<Vec<PathBuf>> {
    for path in [KEYRING, CACHE] {
        if !Path::new(path).is_dir() {
            eprintln!("skipping: needs {path}");
            return None;
        }
    }
    let mut found: Vec<(u64, PathBuf)> = std::fs::read_dir(CACHE)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext != "sig") && signature_path(path).is_file()
        })
        .filter_map(|path| std::fs::metadata(&path).ok().map(|m| (m.len(), path)))
        .collect();
    found.sort();
    let step = found.len().div_ceil(SAMPLE).max(1);
    Some(found.into_iter().step_by(step).map(|(_, path)| path).collect())
}

/// The gate: every package pacman installed must verify as fully trusted.
#[test]
#[ignore = "requires a real pacman keyring and package cache"]
fn every_cached_package_verifies_as_pacman_required_it_to() {
    let Some(packages) = signed_packages() else { return };
    if packages.is_empty() {
        eprintln!("skipping: no signed package in the cache");
        return;
    }
    let keyring = Keyring::open(KEYRING).unwrap();
    let policy = required_trusted();

    let mut rejected: Vec<String> = Vec::new();
    let mut checked = 0_usize;
    for package in &packages {
        let signatures = keyring
            .verify_detached(package, &signature_path(package))
            .unwrap_or_else(|error| panic!("could not verify {}: {error}", package.display()));
        match decide(&signatures, policy) {
            Verdict::Accepted { verified } => {
                assert!(verified, "{} was accepted without verifying", package.display());
            }
            Verdict::Rejected(reason) => rejected
                .push(format!("{}: {reason}", package.file_name().unwrap().to_string_lossy())),
        }
        checked += 1;
    }

    println!("verified {checked} packages against {KEYRING}");
    assert!(
        rejected.is_empty(),
        "{} package(s) pacman installed were rejected here:\n  {}",
        rejected.len(),
        rejected.join("\n  ")
    );
}

/// piko's verdict must match `gpg --verify`'s, not merely be self-consistent.
#[test]
#[ignore = "requires a real pacman keyring, package cache and gpg"]
fn the_verdict_agrees_with_gpg_itself() {
    let Some(packages) = signed_packages() else { return };
    if packages.is_empty() {
        return;
    }
    let keyring = Keyring::open(KEYRING).unwrap();
    let policy = required_trusted();

    let mut compared = 0_usize;
    let mut disagreements = Vec::new();
    // gpg is spawned per package, so this half runs over a smaller slice.
    for package in packages.iter().take(20) {
        let signature = signature_path(package);
        let output = Command::new("gpg")
            .args(["--homedir", KEYRING, "--status-fd", "1", "--verify"])
            .arg(&signature)
            .arg(package)
            .output();
        let Ok(output) = output else {
            eprintln!("skipping: gpg is not runnable");
            return;
        };
        let status = String::from_utf8_lossy(&output.stdout);
        // TRUSTED-style status lines are gpg's own machine-readable verdict.
        let gpg_good = status.contains("[GNUPG:] GOODSIG")
            && (status.contains("[GNUPG:] TRUST_FULLY")
                || status.contains("[GNUPG:] TRUST_ULTIMATE"));

        let signatures = keyring.verify_detached(package, &signature).unwrap();
        let piko_good = matches!(decide(&signatures, policy), Verdict::Accepted { .. });

        if gpg_good != piko_good {
            disagreements.push(format!(
                "{}: gpg says {gpg_good}, piko says {piko_good}",
                package.file_name().unwrap().to_string_lossy()
            ));
        }
        compared += 1;
    }

    println!("{compared} packages compared against gpg --verify");
    assert!(disagreements.is_empty(), "{}", disagreements.join("\n  "));
}

/// A tampered package must be rejected. Without this, the whole module could be a no-op that
/// says yes to everything.
#[test]
#[ignore = "requires a real pacman keyring and package cache"]
fn a_modified_package_is_rejected() {
    let Some(packages) = signed_packages() else { return };
    let Some(source) = packages.first() else { return };
    let keyring = Keyring::open(KEYRING).unwrap();

    // Copy a real package and its signature, then flip one byte of the payload.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join(source.file_name().unwrap());
    std::fs::copy(source, &target).unwrap();
    std::fs::copy(signature_path(source), signature_path(&target)).unwrap();

    let mut bytes = std::fs::read(&target).unwrap();
    let middle = bytes.len() / 2;
    *bytes.get_mut(middle).expect("a real package is not empty") ^= 0xff;
    std::fs::write(&target, &bytes).unwrap();

    let signatures = keyring.verify_detached(&target, &signature_path(&target)).unwrap();
    let verdict = decide(&signatures, required_trusted());
    assert!(
        matches!(verdict, Verdict::Rejected(_)),
        "a package with a flipped byte was accepted: {verdict:?}"
    );
}

/// An unsigned file is refused under Required and allowed under Optional. These are the two
/// halves of the policy that decide whether piko installs something it cannot check.
#[test]
#[ignore = "requires a real pacman keyring"]
fn an_unsigned_file_follows_the_policy() {
    if !Path::new(KEYRING).is_dir() {
        return;
    }
    let keyring = Keyring::open(KEYRING).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("unsigned.pkg.tar");
    std::fs::write(&file, b"not a real package").unwrap();
    // Verifying against a signature that does not exist yields no signatures, not an error.
    std::fs::write(signature_path(&file), b"").unwrap();

    let signatures = keyring.verify_detached(&file, &signature_path(&file)).unwrap_or_default();
    assert_eq!(
        decide(&signatures, Policy::for_package(SigLevel::PACKAGE)),
        Verdict::Rejected(Rejection::MissingRequired)
    );
    let optional = Policy::for_package(SigLevel::PACKAGE | SigLevel::PACKAGE_OPTIONAL);
    assert_eq!(decide(&signatures, optional), Verdict::Accepted { verified: false });
}

/// Reports which trust levels this machine's packages actually carry. This makes a future
/// change that quietly starts accepting marginal or unknown trust visible, not silent.
#[test]
#[ignore = "requires a real pacman keyring and package cache"]
fn trust_levels_on_this_machine_are_reported() {
    let Some(packages) = signed_packages() else { return };
    let keyring = Keyring::open(KEYRING).unwrap();
    let mut levels: BTreeMap<String, usize> = BTreeMap::new();
    for package in packages.iter().take(60) {
        let Ok(signatures) = keyring.verify_detached(package, &signature_path(package)) else {
            continue;
        };
        for signature in &signatures {
            *levels.entry(format!("{:?}/{:?}", signature.status, signature.trust)).or_default() +=
                1;
        }
    }
    println!("status/trust distribution: {levels:?}");
    assert!(!levels.is_empty(), "no signature was examined at all");
}
