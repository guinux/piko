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
    config::{DbUsage, PacmanConfig},
    repo::RepoDatabase,
    resolve::{IgnoreList, SyncRepo, SyncRepos},
};

const PACMAN_CONF: &str = "/etc/pacman.conf";

/// Opens the system config, or skips the test if this is not an ALPM based system.
/// Every opened repository, filtered by `ignore_pkg` and `ignore_group`.
fn sync_repos<'a>(
    opened: &'a [(DbUsage, RepoDatabase)],
    ignore_pkg: &'a [String],
    ignore_group: &'a [String],
) -> SyncRepos<'a> {
    SyncRepos::new(opened.iter().map(|(usage, db)| SyncRepo::new(*usage, db)))
        .with_ignores(IgnoreList::new(ignore_pkg, ignore_group))
}

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

/// This test proves `resolve::IgnoreList` against this machine's real repositories, not only
/// a fixture. Every `IgnorePkg` entry of the real `pacman.conf` must stop resolving. A real
/// package that resolves without an ignore list must also stop resolving once one names it,
/// so the test proves something even on a machine that ignores nothing.
#[test]
#[ignore = "requires a real pacman.conf and sync databases"]
fn a_really_ignored_package_never_resolves() {
    let Some(config) = open_system_config() else { return };

    let sync_dir = config.options.db_path.join("sync");
    let mut opened = Vec::new();
    for repo in &config.repositories {
        match RepoDatabase::open_repo(&sync_dir, &repo.name) {
            Ok(db) => opened.push((repo.usage, db)),
            Err(error) => eprintln!("skipping repo {}: {error}", repo.name),
        }
    }
    let Some(sample) = opened.iter().find_map(|(_, db)| db.iter().next()) else {
        eprintln!("skipping: no configured repository could be opened, or all are empty");
        return;
    };
    let sample_name = sample.name().to_string();
    let sample_relation: alpm_types::PackageRelation = sample_name.parse().unwrap();

    let ignore_group = &config.options.ignore_group;

    assert!(
        sync_repos(&opened, &[], ignore_group).find_literal_satisfier(&sample_relation).is_some(),
        "{sample_name}"
    );
    assert!(
        sync_repos(&opened, std::slice::from_ref(&sample_name), ignore_group)
            .find_literal_satisfier(&sample_relation)
            .is_none(),
        "{sample_name} is ignored but find_literal_satisfier still resolved it"
    );

    let configured = sync_repos(&opened, &config.options.ignore_pkg, ignore_group);
    for pattern in &config.options.ignore_pkg {
        let Ok(relation) = pattern.parse::<alpm_types::PackageRelation>() else { continue };
        assert!(
            configured.find_literal_satisfier(&relation).is_none(),
            "{pattern} is IgnorePkg'd in pacman.conf but find_literal_satisfier still resolved it"
        );
    }
    println!("{} IgnorePkg entries checked", config.options.ignore_pkg.len());
}
