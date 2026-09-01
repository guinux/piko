//! Checks the extraction confinement rules against every path this system actually has.
//!
//! Every test here is `#[ignore]`d. Run them explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test rootfs_real_system -- --ignored --nocapture
//! ```
//!
//! **Read-only.** Nothing here creates, modifies, or removes anything. The confinement API
//! used (`components`, `RootDir::resolve_parent`) only ever opens directories for reading.
//!
//! # Why this is worth a test
//!
//! `rootfs` is deliberately stricter than pacman. It refuses `..` components, which
//! libalpm's libarchive flags permit (`ARCHIVE_EXTRACT_SECURE_NODOTDOT` is absent from
//! `add.c:118`), and it refuses to descend through a symlinked directory. Strictness is only
//! a virtue if it does not reject legitimate packages. That claim cannot be settled by
//! reasoning about the spec: Arch really does ship `/bin`, `/lib`, and `/sbin` as symlinks
//! into `usr/`, and a package owning a file under one of those would be un-installable under
//! these rules. So the claim is measured against every path of every installed package.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use piko_db::LocalDatabase;
use piko_txn::{Error, RootDir, rootfs};

const LOCAL_DB: &str = "/var/lib/pacman/local";

/// Every path owned by every installed package.
fn all_installed_paths() -> Option<Vec<PathBuf>> {
    if !Path::new(LOCAL_DB).is_dir() {
        eprintln!("skipping: {LOCAL_DB} does not exist");
        return None;
    }
    let db = LocalDatabase::open(LOCAL_DB).unwrap();
    let mut paths = Vec::new();
    for package in db.iter() {
        let Ok(list) = package.file_list() else { continue };
        paths.extend(list.iter().cloned());
    }
    Some(paths)
}

/// No real package path may be refused by the path rules.
#[test]
#[ignore = "requires a real ALPM local database"]
fn every_installed_path_is_accepted() {
    let Some(paths) = all_installed_paths() else { return };

    let mut refused = Vec::new();
    for path in &paths {
        if let Err(error) = rootfs::components(path) {
            refused.push(format!("{}: {error}", path.display()));
        }
    }

    println!("{} installed paths, {} refused", paths.len(), refused.len());
    for entry in refused.iter().take(10) {
        println!("  {entry}");
    }
    assert!(refused.is_empty(), "{} real paths would be refused", refused.len());
    assert!(paths.len() > 1000, "expected a populated system, found {}", paths.len());
}

/// No real package path may resolve through a symlinked directory on this system.
///
/// This is the rule with a genuine chance of being wrong. `/bin`, `/lib`, `/sbin`, and
/// `/lib64` are symlinks into `usr/` on any modern Arch install. If any package owned a path
/// beginning with one of them, refusing to descend through a symlink would make that package
/// impossible to extract. Measuring says none do: every package addresses `usr/` directly.
/// That is a fact about how Arch packages are built, not a theorem, so this test checks it
/// rather than assuming it.
#[test]
#[ignore = "requires a real ALPM local database"]
fn no_installed_path_resolves_through_a_symlink() {
    let Some(paths) = all_installed_paths() else { return };

    let root = match RootDir::open(Path::new("/")) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("skipping: cannot open /: {error}");
            return;
        }
    };

    // Distinct paths only. Hundreds of thousands of files share a few thousand directories,
    // and each resolution is a walk of syscalls.
    let distinct: BTreeSet<&PathBuf> = paths.iter().collect();

    let mut escapes = Vec::new();
    let mut vanished = 0_usize;
    for path in &distinct {
        match root.resolve_parent(path) {
            Ok(_) => {}
            // The file was removed since the database recorded it, or this (unprivileged)
            // test process cannot read it. Neither says anything about confinement.
            Err(Error::Io { .. }) => vanished += 1,
            Err(error @ Error::PathEscapesRoot { .. }) => escapes.push(error.to_string()),
            Err(error) => escapes.push(error.to_string()),
        }
    }

    println!(
        "{} distinct paths resolved, {escapes} would be refused, {vanished} unreadable or absent",
        distinct.len(),
        escapes = escapes.len()
    );
    for entry in escapes.iter().take(10) {
        println!("  {entry}");
    }
    assert!(
        escapes.is_empty(),
        "{} real paths would be refused as escaping the root",
        escapes.len()
    );
}

/// The confinement must still refuse the attacks, on the real filesystem rather than a
/// fixture. A rule that only holds in a temporary directory is not a rule.
#[test]
#[ignore = "requires a real filesystem"]
fn the_classic_escapes_are_refused_against_the_real_root() {
    let root = match RootDir::open(Path::new("/")) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("skipping: cannot open /: {error}");
            return;
        }
    };

    for attack in ["../etc/passwd", "usr/../../etc/passwd", "/etc/passwd", "etc/../../../root/.ssh"]
    {
        let err = root.resolve_parent(Path::new(attack)).unwrap_err();
        println!("{attack} -> {err}");
        assert!(
            matches!(err, Error::UnsafeArchivePath { .. } | Error::PathEscapesRoot { .. }),
            "{attack} was not refused: {err:?}"
        );
    }
}
