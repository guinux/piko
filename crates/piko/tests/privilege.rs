//! Runs each command that changes the system as a user that is not root.
//!
//! The check runs before any path is opened, so these tests need no database, no keyring and no
//! network. Every test skips when the test itself runs as root, because root passes the check.
//! The other half, a user-owned `--root` and `--dbpath` that pass it, is what every test in
//! `side_effects.rs` and `key.rs` already does.

#![allow(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]

use std::process::{Command, Output, Stdio};

/// Runs `piko` with `args` and a pacman.conf that does not exist, so each path falls back to
/// its built-in default.
///
/// Returns `None` when the test runs as root.
fn run_unprivileged(args: &[&str]) -> Option<Output> {
    if rustix::process::geteuid().is_root() {
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_piko"))
        .args(args)
        .arg("--config")
        .arg(dir.path().join("missing.conf"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    Some(output)
}

/// Asserts that `output` is a refusal naming `path`.
fn assert_refused(output: &Output, command: &str, path: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!("piko {command} must run as root to change {path}.")),
        "{stderr}"
    );
}

#[test]
fn a_transaction_into_slash_is_refused_even_with_dbpath_named() {
    let db = tempfile::tempdir().unwrap();
    let db = db.path().to_str().unwrap();
    for command in ["install", "update", "remove"] {
        let Some(output) =
            run_unprivileged(&[command, "--root", "/", "--dbpath", db, "--noconfirm", "foo"])
        else {
            return;
        };
        assert_refused(&output, command, "/");
    }
}

#[test]
fn a_transaction_into_another_root_is_refused_with_the_configured_dbpath() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().to_str().unwrap();
    let Some(output) = run_unprivileged(&["install", "--root", root, "--noconfirm", "foo"]) else {
        return;
    };
    assert_refused(&output, "install", "/var/lib/pacman/");
}

#[test]
fn a_refresh_of_the_configured_dbpath_is_refused() {
    let Some(output) = run_unprivileged(&["refresh"]) else {
        return;
    };
    assert_refused(&output, "refresh", "/var/lib/pacman/");
}

#[test]
fn a_change_to_the_configured_keyring_is_refused_and_a_listing_is_not() {
    let Some(output) = run_unprivileged(&["key", "init"]) else {
        return;
    };
    assert_refused(&output, "key", "/etc/pacman.d/gnupg/");

    let Some(output) = run_unprivileged(&["key", "list-keys"]) else {
        return;
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("must run as root"), "{stderr}");
}
