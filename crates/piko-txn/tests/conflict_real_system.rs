//! Runs file-conflict detection against this machine's real filesystem and database.
//!
//! `#[ignore]`d like every real-system test. Run explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test conflict_real_system -- --ignored --nocapture
//! ```
//!
//! **Nothing here writes.** The check is read-only by construction: it `lstat`s paths, reads
//! directories, and reads the local database. The real root is passed as the root because that
//! is the only place the question is interesting. No test in this file can change it.
//!
//! # The oracle, and why the false-positive direction matters most
//!
//! A conflict check that reports nothing is useless. A conflict check that reports too much is
//! *worse than useless*: it refuses correct transactions and teaches the user to reach for
//! `--overwrite`. pacman has run on this machine and installed every one of these packages
//! without complaint. So **every installed package's own archive, checked as an upgrade over
//! itself, must come back clear.** That is a real oracle: pacman's silence.
//!
//! The opposite direction is covered too, by taking a real package's own file and offering it
//! under a different package's name. The conflict must be reported. It must name the true
//! owner, which `pacman -Qo` independently confirms.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};

use alpm_types::PackageFileName;
use piko_db::LocalDatabase;
use piko_txn::{
    RootDir,
    conflict::{self, Blocker, Overwrite, Target, WalkLimits},
    extract::PackageLimits,
};

const LOCAL_DB: &str = "/var/lib/pacman/local";
const CACHE: &str = "/var/cache/pacman/pkg";
const ROOT: &str = "/";

/// How many packages to check.
///
/// The sample deliberately spreads across the size range instead of taking one end. The first
/// cut of this test took the smallest packages and passed on 1056 paths. That sample was too
/// small to catch a shared-directory bug, which is exactly the failure this test exists for.
const SAMPLE: usize = 200;

/// Installed packages whose exact version is sitting in the cache, smallest first.
fn installed_and_cached() -> Option<Vec<PathBuf>> {
    for path in [LOCAL_DB, CACHE] {
        if !Path::new(path).is_dir() {
            eprintln!("skipping: needs {path}");
            return None;
        }
    }
    let db = LocalDatabase::open(LOCAL_DB).unwrap();

    let mut found = Vec::new();
    for package in db.iter() {
        let Ok(desc) = package.desc() else { continue };
        let file_name = PackageFileName::new(
            package.name().clone(),
            package.version().clone(),
            desc.architecture().clone(),
            Some(alpm_types::CompressionAlgorithmFileExtension::Zstd),
        );
        let path = Path::new(CACHE).join(file_name.to_string());
        let Ok(metadata) = std::fs::metadata(&path) else { continue };
        if !metadata.is_file() {
            continue;
        }
        found.push((metadata.len(), path));
    }
    found.sort();
    // Take every nth entry, so the sample covers `libreoffice` as well as `licenses`.
    let step = found.len().div_ceil(SAMPLE).max(1);
    Some(found.into_iter().step_by(step).map(|(_, path)| path).collect())
}

/// The check, with nothing released and the default bounds.
fn check(
    root: &RootDir,
    local: &LocalDatabase,
    targets: &[Target],
    removals: &[String],
) -> conflict::Check {
    conflict::check(root, local, targets, removals, &Overwrite::default(), &WalkLimits::default())
        .unwrap()
}

/// The gate: reinstalling what is already installed must never report a conflict.
///
/// Every one of these packages is on this machine because pacman put it there and found no
/// conflict. A single false positive here is a bug that would refuse a real upgrade.
#[test]
#[ignore = "requires a real pacman cache and local database"]
fn reinstalling_every_cached_package_reports_no_conflict() {
    let Some(packages) = installed_and_cached() else { return };
    if packages.is_empty() {
        eprintln!("skipping: no installed package is cached at its exact version");
        return;
    }

    let local = LocalDatabase::open(LOCAL_DB).unwrap();
    let root = RootDir::open(Path::new(ROOT)).unwrap();

    let mut checked = 0_usize;
    let mut total_paths = 0_usize;
    let mut false_positives: Vec<String> = Vec::new();

    for package in &packages {
        let target = match conflict::load_package(package, &PackageLimits::default()) {
            Ok(loaded) => loaded.target,
            Err(error) => panic!("could not read {}: {error}", package.display()),
        };
        total_paths += target.files.len();

        let result = check(&root, &local, std::slice::from_ref(&target), &[]);
        for conflict in &result.conflicts {
            false_positives.push(format!("{conflict}"));
        }
        checked += 1;
    }

    println!("checked {checked} packages, {total_paths} paths");
    assert!(
        false_positives.is_empty(),
        "{} false positive(s) reinstalling packages pacman installed without complaint:\n  {}",
        false_positives.len(),
        false_positives.join("\n  ")
    );
}

/// The other direction: a real file offered under the wrong package name must be caught.
///
/// The owner piko names must match the owner `pacman -Qo` names.
#[test]
#[ignore = "requires a real pacman database and pacman itself"]
fn a_file_offered_under_the_wrong_name_is_caught_and_the_owner_matches_pacman() {
    if !Path::new(LOCAL_DB).is_dir() {
        eprintln!("skipping: needs {LOCAL_DB}");
        return;
    }
    let local = LocalDatabase::open(LOCAL_DB).unwrap();
    let root = RootDir::open(Path::new(ROOT)).unwrap();

    // Probe with a handful of real, owned, regular files spread across different packages.
    let mut probes: Vec<(String, String)> = Vec::new();
    for package in local.iter().take(400) {
        let Ok(files) = package.file_list() else { continue };
        let Some(file) = files.iter().find(|path| {
            let text = path.to_string_lossy();
            !text.ends_with('/') && Path::new(ROOT).join(&**path).is_file()
        }) else {
            continue;
        };
        probes.push((package.name().to_string(), file.to_string_lossy().into_owned()));
        if probes.len() == 25 {
            break;
        }
    }
    if probes.is_empty() {
        eprintln!("skipping: found no owned regular file to probe with");
        return;
    }

    let mut disagreements = Vec::new();
    for (owner, path) in &probes {
        let target = Target {
            name: "piko-not-a-real-package".to_owned(),
            version: "1.0.0-1".to_owned(),
            files: piko_txn::FileList::new([path.clone()]),
            backups: BTreeSet::new(),
            install_script: None,
        };
        let result = check(&root, &local, &[target], &[]);

        let Some(conflict) = result.conflicts.first() else {
            disagreements.push(format!("{path}: piko reported no conflict; {owner} owns it"));
            continue;
        };
        let Blocker::Filesystem { owner: reported } = &conflict.blocker else {
            disagreements.push(format!("{path}: expected a filesystem blocker, got {conflict}"));
            continue;
        };

        // pacman is the independent oracle for *who* owns it.
        let output = Command::new("pacman").args(["-Qoq", &format!("/{path}")]).output();
        let Ok(output) = output else {
            eprintln!("skipping the ownership half: pacman is not runnable");
            break;
        };
        let expected = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if expected.is_empty() {
            continue;
        }
        // A path can have several owners. piko reports the first, so agreeing with any of
        // pacman's answers is the correct assertion.
        let owners: Vec<&str> = expected.lines().map(str::trim).collect();
        match reported {
            Some(name) if owners.contains(&name.as_str()) => {}
            other => disagreements.push(format!(
                "{path}: piko says {other:?}, pacman -Qo says {}",
                owners.join(", ")
            )),
        }
    }

    println!("probed {} owned files", probes.len());
    assert!(
        disagreements.is_empty(),
        "{} disagreement(s):\n  {}",
        disagreements.len(),
        disagreements.join("\n  ")
    );
}

/// Two real packages installed together must not report each other's shared directories.
///
/// This is the check-1 false-positive gate. Every package on the system ships `usr/`,
/// `usr/lib/`, and similar directories. An intersection that counted directories would report
/// thousands of conflicts on any multi-package transaction.
#[test]
#[ignore = "requires a real pacman cache and local database"]
fn installing_many_real_packages_together_reports_no_shared_directory() {
    let Some(packages) = installed_and_cached() else { return };
    if packages.len() < 2 {
        eprintln!("skipping: needs at least two cached packages");
        return;
    }

    let local = LocalDatabase::open(LOCAL_DB).unwrap();
    let root = RootDir::open(Path::new(ROOT)).unwrap();

    let mut targets = Vec::new();
    for package in packages.iter().rev().take(40) {
        if let Ok(loaded) = conflict::load_package(package, &PackageLimits::default()) {
            targets.push(loaded.target);
        }
    }

    let result = check(&root, &local, &targets, &[]);
    let shared: Vec<String> = result
        .conflicts
        .iter()
        .filter(|conflict| matches!(conflict.blocker, Blocker::Target { .. }))
        .map(ToString::to_string)
        .collect();

    println!("{} packages checked against each other", targets.len());
    assert!(
        shared.is_empty(),
        "{} target-against-target conflict(s) between packages that coexist on this system:\n  {}",
        shared.len(),
        shared.join("\n  ")
    );
}
