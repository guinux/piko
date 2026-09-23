//! The rollback check against real servers: this machine's mirror, and the Arch Linux Archive.
//!
//! ```text
//! cargo test -p piko-net --test freshness_real_system -- --ignored --nocapture
//! ```
//!
//! `#[ignore]`d, because it needs the network, `/etc/pacman.conf` with a `[core]` section, and
//! `date` on `PATH`. It writes only into a `TempDir`.
//!
//! The Archive serves every past day of every repository under a dated URL. So it is a real
//! server that is certain to be behind, which is the one thing a hermetic test has to fake.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{path::Path, process::Command};

use piko_net::{
    Cancel, Concurrency, DatabaseKind, FreshnessNote, FreshnessPolicy, Outcome, Refreshed,
    Refresher, RepoRefresh,
};
use piko_sig::Policy;

/// The `[core]` servers from `/etc/pacman.conf`, or `None` to skip.
fn core_servers() -> Option<Vec<String>> {
    let config = piko_db::config::PacmanConfig::open("/etc/pacman.conf").ok()?;
    let core = config.repositories.into_iter().find(|repo| repo.name.to_string() == "core")?;
    (!core.servers.is_empty()).then_some(core.servers)
}

fn refresh(sync: &Path, servers: &[String], accept_older: bool) -> Refreshed {
    let repos = [RepoRefresh {
        name: "core",
        kind: DatabaseKind::Db,
        servers,
        // Arch signs no database, so there is nothing to verify and no keyring is needed. The
        // archive date decides.
        policy: Policy { check: false, optional: true, marginal_ok: false, unknown_ok: false },
        freshness: FreshnessPolicy { accept_older, ..FreshnessPolicy::default() },
    }];
    Refresher::default()
        .refresh_all(sync, &repos, None, Concurrency::new(1), false, &Cancel::new(), &|_, _| {})
        .pop()
        .unwrap()
        .unwrap()
}

#[test]
#[ignore = "requires the network and a configured [core] repository"]
fn the_archive_is_refused_until_it_is_asked_for() {
    let Some(servers) = core_servers() else {
        eprintln!("skipping: no [core] servers in /etc/pacman.conf");
        return;
    };
    let output = Command::new("date").args(["-u", "-d", "30 days ago", "+%Y/%m/%d"]).output();
    let Ok(output) = output else {
        eprintln!("skipping: date is unavailable");
        return;
    };
    let day = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    let archive = vec![format!("https://archive.archlinux.org/repos/{day}/core/os/x86_64")];

    let sync = tempfile::tempdir().unwrap();
    let current = refresh(sync.path(), &servers, false);
    assert_eq!(current.outcome, Outcome::Updated);
    let installed = std::fs::read(sync.path().join("core.db")).unwrap();
    eprintln!("current core.db: {:?}", current.publication);

    let refused = refresh(sync.path(), &archive, false);
    eprintln!("archive, refused: {:?}", refused.notes);
    assert_eq!(refused.outcome, Outcome::Kept);
    assert_eq!(std::fs::read(sync.path().join("core.db")).unwrap(), installed);

    let accepted = refresh(sync.path(), &archive, true);
    eprintln!("archive, accepted: {:?}", accepted.notes);
    assert_eq!(accepted.outcome, Outcome::Updated);
    assert!(
        accepted.notes.iter().any(|note| matches!(note, FreshnessNote::AcceptedOlder { .. })),
        "{:?}",
        accepted.notes
    );
    let at = |refreshed: &Refreshed| refreshed.publication.unwrap().at;
    assert!(at(&accepted) < at(&current), "the archive is not older");

    // Back to the mirror: a newer database needs no option.
    let restored = refresh(sync.path(), &servers, false);
    assert_eq!(restored.outcome, Outcome::Updated);
    assert_eq!(restored.publication, current.publication);
}
