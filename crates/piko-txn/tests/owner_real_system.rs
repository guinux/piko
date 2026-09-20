//! Runs the reverse file lookup against this machine's real database, with `pacman -Qo` as the
//! oracle.
//!
//! `#[ignore]`d like every real-system test. Run explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test owner_real_system -- --ignored --nocapture
//! ```
//!
//! **Nothing here writes.** The lookup `lstat`s paths and reads the local database.
//!
//! # Two oracles of different strength
//!
//! A file names its first owner only, in both implementations. Two packages owning one file is a
//! broken database, and which of them comes first is an ordering neither tool promises. So the
//! assertion for a file is that piko's answer is *among* pacman's.
//!
//! A directory names every owner, in both implementations. That makes **set equality**
//! assertable, and a shared directory has hundreds of owners on this machine. This is the tighter
//! of the two checks. It catches a comparison that confuses `usr/bin` with `usr/bin/`.

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

use piko_db::LocalDatabase;
use piko_txn::owner::Owners;

const LOCAL_DB: &str = "/var/lib/pacman/local";
const ROOT: &str = "/";

/// How many real files to probe.
const SAMPLE: usize = 200;

/// Directories that several hundred packages share on any Arch system.
const SHARED_DIRECTORIES: &[&str] =
    &["/usr/bin/", "/usr/lib/", "/usr/include/", "/usr/share/man/man1/", "/etc/"];

/// The names `pacman -Qoq <path>` reports, or `None` when pacman cannot be run.
fn pacman_owners(path: &str) -> Option<BTreeSet<String>> {
    let output = Command::new("pacman").args(["-Qoq", path]).output().ok()?;
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| line.trim().to_owned())
            .filter(|line| !line.is_empty())
            .collect(),
    )
}

/// The database, or `None` when this machine has none to read.
fn open_local_db() -> Option<LocalDatabase> {
    if !Path::new(LOCAL_DB).is_dir() {
        eprintln!("skipping: needs {LOCAL_DB}");
        return None;
    }
    LocalDatabase::open(LOCAL_DB).ok()
}

/// Real, owned, regular files spread across packages, as absolute paths.
fn owned_regular_files(local: &LocalDatabase) -> Vec<String> {
    let mut probes = Vec::new();
    for package in local.iter() {
        let Ok(files) = package.file_list() else { continue };
        let mut taken = 0;
        for path in files {
            let text = path.to_string_lossy();
            if text.ends_with('/') {
                continue;
            }
            let absolute = Path::new(ROOT).join(&**path);
            // `symlink_metadata`, because the lookup does not dereference the last component
            // either. A dangling symlink is still an owned entry and still a valid probe.
            if std::fs::symlink_metadata(&absolute).is_err() {
                continue;
            }
            probes.push(absolute.to_string_lossy().into_owned());
            taken += 1;
            if taken == 2 {
                break;
            }
        }
        if probes.len() >= SAMPLE {
            break;
        }
    }
    probes.truncate(SAMPLE);
    probes
}

#[test]
#[ignore = "requires a real pacman database and pacman itself"]
fn every_probed_file_names_an_owner_pacman_also_names() {
    let Some(local) = open_local_db() else { return };
    let probes = owned_regular_files(&local);
    if probes.is_empty() {
        eprintln!("skipping: found no owned regular file to probe with");
        return;
    }
    if pacman_owners("/").is_none() {
        eprintln!("skipping: pacman is not runnable");
        return;
    }

    let mut owners = Owners::new(&local);
    let mut disagreements = Vec::new();
    for path in &probes {
        let answer = owners.query(Path::new(ROOT), path, &[]).unwrap();
        let Some(expected) = pacman_owners(path) else { continue };
        if expected.is_empty() {
            continue;
        }
        match answer.owners.first() {
            Some(name) if expected.contains(name) => {}
            other => disagreements.push(format!(
                "{path}: piko says {other:?}, pacman -Qo says {}",
                expected.into_iter().collect::<Vec<_>>().join(", ")
            )),
        }
    }

    println!("probed {} owned files", probes.len());
    assert!(
        disagreements.is_empty(),
        "{} of {} files disagreed:\n{}",
        disagreements.len(),
        probes.len(),
        disagreements.join("\n")
    );
}

/// The tighter check: a directory's owner set must match pacman's exactly.
#[test]
#[ignore = "requires a real pacman database and pacman itself"]
fn a_shared_directory_names_exactly_the_owners_pacman_names() {
    let Some(local) = open_local_db() else { return };
    if pacman_owners("/").is_none() {
        eprintln!("skipping: pacman is not runnable");
        return;
    }

    let mut owners = Owners::new(&local);
    let mut checked = 0;
    for directory in SHARED_DIRECTORIES {
        if !Path::new(directory).is_dir() {
            continue;
        }
        let Some(expected) = pacman_owners(directory) else { continue };
        if expected.is_empty() {
            continue;
        }
        let answer = owners.query(Path::new(ROOT), directory, &[]).unwrap();
        let named: BTreeSet<String> = answer.owners.into_iter().collect();
        assert_eq!(
            named,
            expected,
            "{directory}: piko named {} owners, pacman named {}",
            named.len(),
            expected.len()
        );
        println!("{directory}: {} owners agree", named.len());
        checked += 1;
    }
    assert!(checked > 0, "no shared directory was checkable on this machine");
}

/// A trailing slash is not what decides the question. The directory's own entry is.
#[test]
#[ignore = "requires a real pacman database"]
fn a_directory_answers_the_same_with_and_without_its_trailing_slash() {
    let Some(local) = open_local_db() else { return };
    let mut owners = Owners::new(&local);

    for directory in SHARED_DIRECTORIES {
        if !Path::new(directory).is_dir() {
            continue;
        }
        let slashed = owners.query(Path::new(ROOT), directory, &[]).unwrap();
        let plain = owners.query(Path::new(ROOT), directory.trim_end_matches('/'), &[]).unwrap();
        assert_eq!(slashed, plain, "{directory} answered differently without its slash");
        assert!(slashed.query.is_directory);
        assert!(slashed.query.relative.ends_with('/'));
    }
}

/// A bare program name resolves through the search path, as `pacman -Qo vim` does.
#[test]
#[ignore = "requires a real pacman database and pacman itself"]
fn a_bare_program_name_resolves_through_the_search_path() {
    let Some(local) = open_local_db() else { return };
    let search: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    if search.is_empty() {
        eprintln!("skipping: PATH is unset");
        return;
    }
    if pacman_owners("/").is_none() {
        eprintln!("skipping: pacman is not runnable");
        return;
    }

    let mut owners = Owners::new(&local);
    let mut checked = 0;
    // Programs every Arch system has, from packages that always ship them.
    for name in ["ls", "sh", "pacman"] {
        let answer = owners.query(Path::new(ROOT), name, &search).unwrap();
        if answer.owners.is_empty() {
            continue;
        }
        let Some(expected) = pacman_owners(name) else { continue };
        assert!(
            answer.owners.first().is_some_and(|named| expected.contains(named)),
            "{name}: piko says {:?}, pacman -Qo says {expected:?}",
            answer.owners
        );
        checked += 1;
    }
    assert!(checked > 0, "no probe program was found on the search path");
}
