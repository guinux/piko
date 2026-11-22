//! `--root`, `--dbpath` and `--cachedir` go through `realpath`, as pacman's command line takes
//! them.
//!
//! A path that does not exist is refused before any command runs, so these tests need no
//! database, no keyring and no network.

#![expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]

use std::process::{Command, Output, Stdio};

/// A `piko` command in English, whatever the locale of the machine. The tests compare its
/// output with English text.
fn piko_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_piko"));
    command.env("LC_ALL", "C");
    command
}

/// Runs `piko` with `args` and a pacman.conf that does not exist.
fn run(args: &[&str]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    piko_command()
        .args(args)
        .arg("--config")
        .arg(dir.path().join("missing.conf"))
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// Asserts that `output` refuses `path` as pacman does: `failed to resolve path '<path>'`.
fn assert_unresolved(output: &Output, path: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains(&format!("failed to resolve path '{path}'")), "{stderr}");
}

#[test]
fn a_dbpath_that_does_not_exist_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    let missing = missing.to_str().unwrap();

    assert_unresolved(&run(&["list", "--dbpath", missing]), missing);
}

#[test]
fn a_root_that_does_not_exist_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    let missing = missing.to_str().unwrap();

    for command in ["install", "update", "remove", "merge"] {
        assert_unresolved(&run(&[command, "--root", missing]), missing);
    }
}

#[test]
fn a_cachedir_that_does_not_exist_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    let missing = missing.to_str().unwrap();

    assert_unresolved(&run(&["list", "--cachedir", missing]), missing);
}
