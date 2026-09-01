//! Tests the package source against this machine's real pacman cache.
//!
//! Every test here is `#[ignore]`d. The machine may not be an ALPM-based system, and the
//! results depend on what has been downloaded. Run them explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test source_real_system -- --ignored --nocapture
//! ```
//!
//! **Read-only.** These tests never write to the cache or to any real path.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{path::PathBuf, str::FromStr as _};

use alpm_types::PackageFileName;
use piko_db::{LocalDatabase, config::PacmanConfig};
use piko_txn::{CacheDirSource, PackageSource};

const LOCAL_DB: &str = "/var/lib/pacman/local";

/// The cache directories the real `pacman.conf` configures, or `None` to skip.
fn configured_cache_dirs() -> Option<Vec<PathBuf>> {
    let config = match PacmanConfig::open("/etc/pacman.conf") {
        Ok(config) => config,
        Err(error) => {
            eprintln!("skipping: cannot read the system pacman.conf: {error}");
            return None;
        }
    };
    let dirs = config.options.cache_dirs.clone();
    if dirs.iter().all(|dir| !dir.is_dir()) {
        eprintln!("skipping: no configured CacheDir exists: {dirs:?}");
        return None;
    }
    Some(dirs)
}

/// Every package file actually sitting in the cache, by parsed name.
fn cached_package_files(dirs: &[PathBuf]) -> Vec<(PackageFileName, PathBuf)> {
    let mut found = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for entry in entries.flatten() {
            let raw = entry.file_name().to_string_lossy().into_owned();
            // Detached signatures and partial downloads are not packages.
            if raw.ends_with(".sig") || raw.ends_with(".part") {
                continue;
            }
            if let Ok(parsed) = PackageFileName::from_str(&raw) {
                found.push((parsed, entry.path()));
            }
        }
    }
    found
}

/// The lookup must find every package that is genuinely there.
///
/// This tests two claims at once, and both are worth having: `PackageFileName`'s parse and
/// `Display` round-trip across every real filename, and `CacheDirSource` derives the same
/// path the file actually has. A mismatch in either direction shows up as a package the
/// engine believes it must download, while a perfectly good copy sits on disk.
#[test]
#[ignore = "requires a real pacman cache"]
fn every_cached_package_is_locatable() {
    let Some(dirs) = configured_cache_dirs() else { return };
    let cached = cached_package_files(&dirs);
    if cached.is_empty() {
        eprintln!("skipping: the cache is empty");
        return;
    }

    let source = CacheDirSource::new(dirs.clone()).unwrap();
    let mut failures = Vec::new();

    for (file_name, path) in &cached {
        match source.locate(file_name) {
            Ok(location) => {
                if location.path() != path {
                    failures.push(format!(
                        "{file_name}: located {} but the file is {}",
                        location.path().display(),
                        path.display()
                    ));
                }
            }
            Err(error) => failures.push(format!("{file_name}: {error}")),
        }
    }

    println!("{} cached packages, {} not locatable", cached.len(), failures.len());
    for failure in failures.iter().take(10) {
        println!("  {failure}");
    }
    assert!(failures.is_empty(), "{} cached packages were not locatable", failures.len());
    assert!(cached.len() > 10, "expected a populated cache, found {}", cached.len());
}

/// A package that is *not* there must be reported as unavailable rather than located.
///
/// This is the counterpart to the test above. A lookup that answered "yes" unconditionally
/// would pass that one and fail this one.
#[test]
#[ignore = "requires a real pacman cache"]
fn an_absent_package_is_not_located() {
    let Some(dirs) = configured_cache_dirs() else { return };
    let source = CacheDirSource::new(dirs).unwrap();

    let absent =
        PackageFileName::from_str("piko-does-not-exist-99.99.99-1-x86_64.pkg.tar.zst").unwrap();
    let err = source.locate(&absent).unwrap_err();
    println!("{err}");
    assert!(!source.contains(&absent));
}

/// How much of the installed system the cache could actually reinstall offline.
///
/// This is informational, not a hard threshold. How much is cached depends on when the user
/// last ran `pacman -Sc`, which is not something to assert. It runs as a test because the
/// number is the honest answer to "can the commit engine be developed offline against real
/// packages", and it stays checked as the engine grows.
#[test]
#[ignore = "requires a real pacman cache and local database"]
fn reports_how_much_of_the_installed_system_is_cached() {
    let Some(dirs) = configured_cache_dirs() else { return };
    if !std::path::Path::new(LOCAL_DB).is_dir() {
        eprintln!("skipping: {LOCAL_DB} does not exist");
        return;
    }
    let source = CacheDirSource::new(dirs).unwrap();
    let db = LocalDatabase::open(LOCAL_DB).unwrap();

    let mut available = 0_usize;
    let mut missing_examples = Vec::new();
    let total = db.len();

    for package in db.iter() {
        let Ok(desc) = package.desc() else { continue };
        // Zstd because that is what Arch ships today. A package cached under an older
        // compression simply counts as not cached, which is what this test reports.
        let file_name = PackageFileName::new(
            package.name().clone(),
            package.version().clone(),
            desc.architecture().clone(),
            Some(alpm_types::CompressionAlgorithmFileExtension::Zstd),
        );
        if source.contains(&file_name) {
            available += 1;
        } else if missing_examples.len() < 3 {
            missing_examples.push(file_name.to_string());
        }
    }

    println!("{available} of {total} installed packages are cached at their exact version");
    for example in &missing_examples {
        println!("  not cached, e.g. {example}");
    }
    assert!(available > 0, "no installed package is cached; offline development is not possible");
}
