//! A repository's `Usage` decides which commands read it.
//!
//! `alpm_db_search` finds nothing in a repository whose `Usage` leaves out `Search`
//! (`db.c:447`). `--repo` names one repository on purpose, as `pacman -Sl <repo>` does, so it
//! still reads it.

#![expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]

use std::path::{Path, PathBuf};
use std::process::Command;

use piko_db::fixture::RepoFixture;

const PIKO: &str = env!("CARGO_BIN_EXE_piko");

/// A `piko` command in English, whatever the locale of the machine. The tests compare its
/// output with English text.
fn piko_command() -> Command {
    let mut command = Command::new(PIKO);
    command.env("LC_ALL", "C");
    command
}

/// The `desc` of `name`, with the fields a repository reader requires.
fn desc(name: &str) -> String {
    format!(
        "%FILENAME%\n{name}-1.0-1-x86_64.pkg.tar.zst\n\n%NAME%\n{name}\n\n%BASE%\n{name}\n\n\
         %VERSION%\n1.0-1\n\n%DESC%\nfoo tool\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n\
         %SHA256SUM%\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n\
         %ARCH%\nx86_64\n\n%BUILDDATE%\n1\n\n%PACKAGER%\nTest <test@example.invalid>\n\n"
    )
}

/// Writes `<dir>/sync/<repo>.db` holding the single package `name`.
fn repository(dir: &Path, repo: &str, name: &str) {
    let sync = dir.join("sync");
    std::fs::create_dir_all(&sync).unwrap();
    let entry = format!("{name}-1.0-1/desc");
    let fixture = RepoFixture::new();
    let built =
        fixture.write_gzip_archive(&format!("{repo}.db"), &[(&entry, desc(name).as_bytes())]);
    std::fs::copy(built, sync.join(format!("{repo}.db"))).unwrap();
}

/// A `<dbpath>` with `shown` (`Usage = All`) holding `foo`, and `hidden` (`Usage = Install
/// Upgrade`) holding `foobar`.
fn setup(dir: &Path) -> PathBuf {
    repository(dir, "shown", "foo");
    repository(dir, "hidden", "foobar");
    let config = dir.join("pacman.conf");
    std::fs::write(
        &config,
        format!(
            "[options]\nArchitecture = x86_64\nDBPath = {}\nSigLevel = Never\n\n\
             [shown]\nServer = https://example.invalid/$repo\n\n\
             [hidden]\nUsage = Install Upgrade\nServer = https://example.invalid/$repo\n",
            dir.display()
        ),
    )
    .unwrap();
    config
}

/// Runs `piko --config <config> <args>`, and returns its stdout.
fn piko(config: &Path, args: &[&str]) -> String {
    let output = piko_command().arg("--config").arg(config).args(args).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

/// A package only a repository without `Search` usage holds is not found, and the search
/// fails, as `pacman -Ss` does when nothing matches.
#[test]
fn a_search_the_skipped_repository_alone_would_answer_fails() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path());

    let output = piko_command()
        .arg("--config")
        .arg(&config)
        .args(["search", "--repos", "--quiet", "foobar"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[test]
fn a_search_skips_a_repository_without_search_usage() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path());

    assert_eq!(piko(&config, &["search", "--repos", "--quiet", "foo"]), "foo\n");
}

#[test]
fn a_named_repository_is_searched_whatever_its_usage() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path());

    assert_eq!(piko(&config, &["search", "--repo", "hidden", "--quiet", "foo"]), "foobar\n");
}
