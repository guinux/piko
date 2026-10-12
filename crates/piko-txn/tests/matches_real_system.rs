//! Compares every cached package with the repository entry of the same file name.
//!
//! Two comparisons, one per test. The first is the `.PKGINFO` check; the second is the
//! `%SHA256SUM%` and `%PGPSIG%` check.
//!
//! `Transaction::verify` refuses an archive whose `.PKGINFO` does not repeat what the plan said:
//! the installed size and the five relation lists `check_pkg_matches_db` compares. Unit tests
//! pin that a difference is found. Only real packages show that none is found where pacman
//! finds none, since a false difference would refuse every install of that package.
//!
//! `#[ignore]`d like every real-system test. Run it explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test matches_real_system -- --ignored --nocapture
//! ```
//!
//! **Read-only.** It reads the sync databases, the package cache and pacman's keyring, and writes
//! nothing.

#![expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]

use std::path::Path;

use piko_db::{
    config::DbUsage, fixture::DbFixture, local::LocalDatabase, repo::RepoDatabase, repo::RepoName,
    solve::Universe, solve::UniverseOptions,
};
use piko_txn::{
    Expected, Published, Validation, Verification, extract::PackageLimits, validate_package,
};

const SYNC_DIR: &str = "/var/lib/pacman/sync";
const CACHE_DIR: &str = "/var/cache/pacman/pkg";
const KEYRING: &str = "/etc/pacman.d/gnupg";

/// The sync databases this machine has, or `None` without a sync directory or a cache.
fn repositories() -> Option<Vec<RepoDatabase>> {
    if !Path::new(SYNC_DIR).is_dir() || !Path::new(CACHE_DIR).is_dir() {
        eprintln!("skipping: no sync databases or no package cache here");
        return None;
    }
    Some(
        ["core", "extra", "multilib"]
            .iter()
            .filter_map(|repo| {
                RepoDatabase::open_repo(SYNC_DIR, &RepoName::parse(repo).unwrap()).ok()
            })
            .collect(),
    )
}

#[test]
#[ignore = "reads this machine's sync databases and package cache"]
fn every_cached_package_repeats_its_repository_entry() {
    let Some(repos) = repositories() else { return };
    let empty = DbFixture::new();
    let local = LocalDatabase::open(empty.path()).unwrap();
    let universe =
        Universe::build(&local, repos.iter().map(|db| (DbUsage::ALL, db)), UniverseOptions::new())
            .unwrap();

    let mut compared = 0_usize;
    let mut differing = Vec::new();
    for candidate in universe.iter() {
        let Some(package) = candidate.as_repository() else { continue };
        let Ok(desc) = package.desc() else { continue };
        let path = Path::new(CACHE_DIR).join(desc.file_name().to_string());
        if !path.is_file() {
            continue;
        }
        let (info, _) = piko_txn::conflict::load_pkginfo(&path, &PackageLimits::default()).unwrap();
        let differences =
            Expected::of(&candidate).unwrap().differences(&Expected::of_archive(&info));
        if !differences.is_empty() {
            differing.push(format!("{}: {}", path.display(), differences.join(", ")));
        }
        compared += 1;
    }

    eprintln!("compared {compared} cached packages with their repository entries");
    if compared == 0 {
        eprintln!("skipping: no cached package matches a repository entry");
        return;
    }
    assert!(differing.is_empty(), "{} differ:\n{}", differing.len(), differing.join("\n"));
}

/// Every cached package passes the validation its repository entry asks for, as pacman
/// validated it: against `%PGPSIG%` under `SigLevel = Required`, and against `%SHA256SUM%`
/// with signature checking off. A false refusal here would refuse every install of that
/// package.
#[test]
#[ignore = "reads this machine's sync databases, package cache and pacman keyring"]
fn every_cached_package_passes_its_repository_validation() {
    let Some(repos) = repositories() else { return };
    let Ok(keyring) = piko_sig::Keyring::open(KEYRING) else {
        eprintln!("skipping: no pacman keyring here");
        return;
    };
    let required = Verification::Enabled {
        keyring,
        policy: piko_sig::Policy::for_package(piko_db::config::SigLevel::PACKAGE),
    };
    let empty = DbFixture::new();
    let local = LocalDatabase::open(empty.path()).unwrap();
    let universe =
        Universe::build(&local, repos.iter().map(|db| (DbUsage::ALL, db)), UniverseOptions::new())
            .unwrap();

    let no_overrides = std::collections::HashMap::new();
    let mut compared = 0_usize;
    let mut signed = 0_usize;
    let mut refused = Vec::new();
    for candidate in universe.iter() {
        let Some(package) = candidate.as_repository() else { continue };
        let Ok(desc) = package.desc() else { continue };
        let file_name = desc.file_name();
        let path = Path::new(CACHE_DIR).join(file_name.to_string());
        if !path.is_file() {
            continue;
        }
        let published = Published::of(&desc);
        compared += 1;
        for (verification, label) in [(&required, "Required"), (&Verification::Disabled, "Never")] {
            let validation =
                validate_package(verification, &no_overrides, Some(&published), file_name, &path);
            match validation {
                Ok(Validation { signature: true, .. }) => signed += 1,
                Ok(Validation { sha256: true, signature: false, .. }) if label == "Never" => {}
                other => refused.push(format!("{} under {label}: {other:?}", path.display())),
            }
        }
    }

    eprintln!("validated {compared} cached packages, {signed} against a database signature");
    if compared == 0 {
        eprintln!("skipping: no cached package matches a repository entry");
        return;
    }
    assert!(refused.is_empty(), "{} refused:\n{}", refused.len(), refused.join("\n"));
}
