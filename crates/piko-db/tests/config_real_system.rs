//! Tests against the live `pacman.conf` of the machine running them.
//!
//! Every test here is `#[ignore]`d, because the machine may not be an ALPM based system.
//! Run them explicitly:
//!
//! ```text
//! cargo test -p piko-db --test config_real_system -- --ignored --nocapture
//! ```
//!
//! Fixture-based tests in `crates/piko-db/src/config/mod.rs` prove piko does what piko
//! intends. This proves those intentions match a real, unsanitised `pacman.conf` — including
//! whatever `Include`d mirrorlist it pulls in.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::path::Path;

use piko_db::{
    config::PacmanConfig,
    repo::RepoDatabase,
    resolve::{IgnoreList, SyncRepo, SyncRepos},
};

const PACMAN_CONF: &str = "/etc/pacman.conf";

/// Opens the system config, or skips the test if this is not an ALPM based system.
fn open_system_config() -> Option<PacmanConfig> {
    if !Path::new(PACMAN_CONF).is_file() {
        eprintln!("skipping: {PACMAN_CONF} does not exist");
        return None;
    }

    match PacmanConfig::open(PACMAN_CONF) {
        Ok(config) => Some(config),
        Err(error) => panic!("failed to open {PACMAN_CONF}: {error}"),
    }
}

#[test]
#[ignore = "requires a real pacman.conf"]
fn opens_the_system_config() {
    let Some(config) = open_system_config() else { return };

    assert!(config.options.db_path.is_absolute());
    assert!(!config.repositories.is_empty(), "expected at least one configured repository");

    for diagnostic in config.diagnostics() {
        println!("diagnostic: {diagnostic}");
    }
    for repo in &config.repositories {
        println!("{}: {} server(s)", repo.name, repo.servers.len());
    }
}

/// Every configured repository must resolve to a non-empty, valid name — the same
/// `RepoName` type the local/repository database readers use.
#[test]
#[ignore = "requires a real pacman.conf"]
fn every_repository_has_a_valid_name() {
    let Some(config) = open_system_config() else { return };

    for repo in &config.repositories {
        assert!(!repo.name.as_str().is_empty());
    }
}

/// This test proves `resolve::IgnoreList` against this machine's actual `IgnorePkg`, not only
/// a fixture. As of writing, `/etc/pacman.conf` here has `IgnorePkg = gedit`. The test skips
/// if that changes, instead of asserting a fact about this machine's config that piko does
/// not control.
#[test]
#[ignore = "requires a real pacman.conf and sync databases"]
fn a_really_ignored_package_never_resolves() {
    let Some(config) = open_system_config() else { return };
    if !config.options.ignore_pkg.iter().any(|pattern| pattern == "gedit") {
        eprintln!("skipping: this machine's pacman.conf no longer has IgnorePkg = gedit");
        return;
    }

    let sync_dir = config.options.db_path.join("sync");
    let mut opened = Vec::new();
    for repo in &config.repositories {
        match RepoDatabase::open_repo(&sync_dir, &repo.name) {
            Ok(db) => opened.push((repo.usage, db)),
            Err(error) => eprintln!("skipping repo {}: {error}", repo.name),
        }
    }
    if opened.is_empty() {
        eprintln!("skipping: no configured repository could be opened");
        return;
    }

    let ignores = IgnoreList::new(&config.options.ignore_pkg, &config.options.ignore_group);
    let repos = SyncRepos::new(opened.iter().map(|(usage, db)| SyncRepo::new(*usage, db)))
        .with_ignores(ignores);

    let gedit: alpm_types::PackageRelation = "gedit".parse().unwrap();
    assert!(
        repos.find_literal_satisfier(&gedit).is_none(),
        "gedit is IgnorePkg'd in pacman.conf but find_literal_satisfier still resolved it"
    );
}
