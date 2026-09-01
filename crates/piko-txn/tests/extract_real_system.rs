//! Extracts real cached packages and checks the result against pacman's own records.
//!
//! `#[ignore]`d like every real-system test. Run explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test extract_real_system -- --ignored --nocapture
//! ```
//!
//! **Everything is extracted into a `tempfile::TempDir`.** The real root is never written to,
//! and the only real paths touched are read-only: the package cache and the local database.
//!
//! # The oracle
//!
//! For a package installed at exactly the version sitting in the cache, pacman has already
//! recorded which paths it owns, in `/var/lib/pacman/local/<entry>/files`. That list was
//! produced by libalpm extracting the same archive. Comparing piko's extraction against it is a
//! genuine cross-check, not piko agreeing with itself. It is the same shape of oracle as
//! diffing `piko plan` against `pacman -Sp`.

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

use alpm_types::PackageFileName;
use piko_db::LocalDatabase;
use piko_txn::{
    Filters, RootDir,
    extract::{
        MemberKind, Ownership, PackageLimits, apply, archive,
        decision::{Disposition, EntryKind},
    },
    install::install,
};

const LOCAL_DB: &str = "/var/lib/pacman/local";
const CACHE: &str = "/var/cache/pacman/pkg";

/// How many packages to extract.
///
/// Extraction is real I/O. A few dozen packages is convincing enough without turning the
/// suite into a disk benchmark.
const SAMPLE: usize = 40;

/// Installed packages whose exact version is in the cache, smallest first.
fn installed_and_cached() -> Option<Vec<(PathBuf, Vec<PathBuf>)>> {
    if !Path::new(LOCAL_DB).is_dir() || !Path::new(CACHE).is_dir() {
        eprintln!("skipping: needs both {LOCAL_DB} and {CACHE}");
        return None;
    }
    let db = LocalDatabase::open(LOCAL_DB).unwrap();

    let mut found = Vec::new();
    for package in db.iter() {
        let Ok(desc) = package.desc() else { continue };
        let Ok(files) = package.file_list() else { continue };
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
        found.push((metadata.len(), path, files.to_vec()));
    }
    found.sort_by_key(|(size, path, _)| (*size, path.clone()));
    Some(found.into_iter().map(|(_, path, files)| (path, files)).take(SAMPLE).collect())
}

/// What piko extracts must be exactly what pacman recorded.
#[test]
#[ignore = "requires a real pacman cache and local database"]
fn extracted_paths_match_what_pacman_recorded() {
    let Some(packages) = installed_and_cached() else { return };
    if packages.is_empty() {
        eprintln!("skipping: no installed package is cached at its exact version");
        return;
    }

    let mut checked = 0_usize;
    let mut total_paths = 0_usize;
    let mut disagreements = Vec::new();

    for (package, recorded) in &packages {
        let target = tempfile::tempdir().unwrap();
        let root = RootDir::open(target.path()).unwrap();
        let mut extracted: BTreeSet<PathBuf> = BTreeSet::new();

        let result = archive::walk(package, &PackageLimits::default(), |member, contents| {
            if member.kind == MemberKind::Metadata {
                return Ok(());
            }
            // A tar orders parent directories first, but a package may omit a directory entry
            // it does not own. Create what is missing so the write lands.
            if let Some(parent) = member.path.parent().filter(|p| p.components().next().is_some()) {
                root.create_dir_all(&parent.join("placeholder"))?;
            }
            apply(&root, member, contents, &Disposition::Extract, Ownership::Inherit)?;

            // Record the path the way pacman's `files` list spells it. Directories carry a
            // trailing slash.
            let mut recorded_form = member.path.clone();
            if member.entry == EntryKind::Directory {
                recorded_form = PathBuf::from(format!("{}/", member.path.display()));
            }
            extracted.insert(recorded_form);
            Ok(())
        });

        if let Err(error) = result {
            disagreements.push(format!("{}: extraction failed: {error}", package.display()));
            continue;
        }

        let expected: BTreeSet<PathBuf> = recorded.iter().cloned().collect();
        if extracted != expected {
            let missing: Vec<_> = expected.difference(&extracted).take(3).collect();
            let extra: Vec<_> = extracted.difference(&expected).take(3).collect();
            disagreements.push(format!(
                "{}: {} extracted vs {} recorded; missing {missing:?}, extra {extra:?}",
                package.file_name().unwrap().to_string_lossy(),
                extracted.len(),
                expected.len()
            ));
            continue;
        }

        total_paths += extracted.len();
        checked += 1;
    }

    println!(
        "{checked} packages extracted, {total_paths} paths, {} disagreements",
        disagreements.len()
    );
    for entry in disagreements.iter().take(10) {
        println!("  {entry}");
    }
    assert!(disagreements.is_empty(), "{} packages disagreed", disagreements.len());
    assert!(checked > 0, "nothing was checked");
}

/// Extracted file contents and modes must match what was recorded.
///
/// The path-set test above would pass even if every file were empty.
#[test]
#[ignore = "requires a real pacman cache"]
fn extracted_files_have_the_right_contents_and_modes() {
    let Some(packages) = installed_and_cached() else { return };
    // The smallest cached package is often a meta-package with no payload at all
    // (`base-devel` owns zero files). That would make this test vacuous.
    let Some((package, _)) = packages.iter().find(|(_, files)| files.len() > 20) else {
        eprintln!("skipping: no cached package has enough files to be worth checking");
        return;
    };

    let target = tempfile::tempdir().unwrap();
    let root = RootDir::open(target.path()).unwrap();

    let mut files = 0_usize;
    let mut symlinks = 0_usize;
    let mut mismatches = Vec::new();

    archive::walk(package, &PackageLimits::default(), |member, contents| {
        if member.kind == MemberKind::Metadata {
            return Ok(());
        }
        if let Some(parent) = member.path.parent().filter(|p| p.components().next().is_some()) {
            root.create_dir_all(&parent.join("placeholder"))?;
        }

        // Keep a copy to compare against. `apply` consumes the reader.
        let mut expected = Vec::new();
        std::io::Read::read_to_end(contents, &mut expected).unwrap();
        apply(&root, member, &mut expected.as_slice(), &Disposition::Extract, Ownership::Inherit)?;

        let written = target.path().join(&member.path);
        if member.is_symlink() {
            symlinks += 1;
            let target_path = std::fs::read_link(&written).unwrap();
            let declared = member.link.as_ref().map(|link| link.target.clone()).unwrap();
            if target_path != declared {
                mismatches.push(format!("{}: symlink target differs", member.path.display()));
            }
        } else if member.entry == EntryKind::Other && !member.is_hard_link() {
            files += 1;
            use std::os::unix::fs::PermissionsExt as _;
            let actual = std::fs::read(&written).unwrap();
            if actual != expected {
                mismatches.push(format!("{}: contents differ", member.path.display()));
            }
            let mode = std::fs::metadata(&written).unwrap().permissions().mode() & 0o7777;
            if mode != member.mode & 0o7777 {
                mismatches.push(format!(
                    "{}: mode {:o} != {:o}",
                    member.path.display(),
                    mode,
                    member.mode & 0o7777
                ));
            }
        }
        Ok(())
    })
    .unwrap();

    println!(
        "{}: {files} files and {symlinks} symlinks verified, {} mismatches",
        package.file_name().unwrap().to_string_lossy(),
        mismatches.len()
    );
    for entry in mismatches.iter().take(10) {
        println!("  {entry}");
    }
    assert!(mismatches.is_empty());
    assert!(files > 0, "no regular files were checked");
}

/// The whole `install` path, checked against pacman's own record of what each package owns.
///
/// The test above drives the pieces by hand. This test drives the composed entry point, the
/// one a transaction actually calls. It compares the paths `install` reports owning with the
/// `files` list libalpm wrote when it installed the same archive.
///
/// The comparison covers the full set, directories included. A tar directory member keeps its
/// trailing slash, exactly how pacman spells it in `files`. So the two sets compare directly,
/// with no normalisation needed.
#[test]
#[ignore = "requires a real pacman cache and local database"]
fn install_reports_the_same_files_pacman_recorded() {
    let Some(packages) = installed_and_cached() else { return };
    if packages.is_empty() {
        eprintln!("skipping: no installed package is cached at its exact version");
        return;
    }

    let mut checked = 0_usize;
    let mut total = 0_usize;
    let mut disagreements = Vec::new();

    for (package, recorded) in &packages {
        let target = tempfile::tempdir().unwrap();
        let root = RootDir::open(target.path()).unwrap();

        let extraction = match install(
            package,
            &root,
            &Filters::default(),
            Ownership::Inherit,
            &PackageLimits::default(),
        ) {
            Ok(extraction) => extraction,
            Err(error) => {
                disagreements.push(format!("{}: {error}", package.display()));
                continue;
            }
        };

        let expected: BTreeSet<&PathBuf> = recorded.iter().collect();
        let owned: BTreeSet<&PathBuf> = extraction.owned.iter().collect();

        if owned != expected {
            let missing: Vec<_> = expected.difference(&owned).take(3).collect();
            let extra: Vec<_> = owned.difference(&expected).take(3).collect();
            disagreements.push(format!(
                "{}: owns {} vs {} recorded; missing {missing:?}, extra {extra:?}",
                package.file_name().unwrap().to_string_lossy(),
                owned.len(),
                expected.len()
            ));
            continue;
        }
        total += owned.len();
        checked += 1;
    }

    println!(
        "{checked} packages installed, {total} paths owned, {} disagreements",
        disagreements.len()
    );
    for entry in disagreements.iter().take(10) {
        println!("  {entry}");
    }
    assert!(disagreements.is_empty(), "{} packages disagreed", disagreements.len());
    assert!(checked > 0);
}
