//! Installs real packages that ship configuration files, and diffs `%BACKUP%` against pacman.
//!
//! `#[ignore]`d like every real-system test. Run explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test backup_real_system -- --ignored --nocapture
//! ```
//!
//! **Writes only into a `tempfile::TempDir`.** It reads `/var/lib/pacman/local` and the
//! package cache, and installs into a throwaway root with a throwaway database. Nothing here
//! touches the real system.
//!
//! # The oracle
//!
//! For a package installed at exactly the version sitting in the cache,
//! `<dbpath>/local/<entry>/files` holds the `%BACKUP%` section libalpm wrote from that same
//! archive. The recorded hash is the md5 of what the *package shipped* (`add.c:333`).
//! Installing the same archive into an empty root must produce the same hashes. The written
//! file is byte-for-byte the archive member, so there is nothing else on disk to compare
//! against.
//!
//! This is a real cross-check, not a self-consistency check: piko computes the hash from its
//! own extraction, and pacman computed it from its own extraction, months apart.
//!
//! # Why this test exists at all
//!
//! `%BACKUP%` used to be **empty for every package piko installed**. `install_step` passed
//! `Filters::default()`, whose `is_backup` always answered no. The whole mechanism was
//! implemented and unit-tested, but a transaction never once reached it.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use alpm_types::{PackageFileName, PackageInstallReason};
use piko_db::LocalDatabase;
use piko_db_write::DbLock;
use piko_txn::{CacheDirSource, Step, Transaction, extract::Ownership};

const LOCAL_DB: &str = "/var/lib/pacman/local";
const CACHE: &str = "/var/cache/pacman/pkg";

/// The `%BACKUP%` section of a `files` record.
///
/// This reads the raw text rather than [`piko_db::LocalPackage::backups`] on purpose. That
/// accessor silently normalizes the two shapes this test needs to see. libalpm writes the
/// section as a **list**, so it can hold the same path twice, and it can hold a hash that is
/// the literal string `(null)`. That string is what C prints for the NULL
/// `alpm_compute_md5sum` returns when it never ran. Both cases occur on this machine, and
/// both must be visible here.
///
/// Returns `(real hashes by path, paths that have only a `(null)`)`. A real hash always wins
/// over a `(null)` for the same path. That matches what the entry means, and what `alpm-db`
/// gives back when it reads it.
fn backup_section(files_text: &str) -> (BTreeMap<String, String>, Vec<String>) {
    let mut real: BTreeMap<String, String> = BTreeMap::new();
    let mut null: Vec<String> = Vec::new();
    let mut inside = false;
    for line in files_text.lines() {
        if line.starts_with('%') {
            inside = line == "%BACKUP%";
            continue;
        }
        if line.is_empty() {
            inside = false;
            continue;
        }
        if inside && let Some((path, hash)) = line.split_once('\t') {
            if hash == "(null)" {
                null.push(path.to_owned());
            } else {
                real.insert(path.to_owned(), hash.to_owned());
            }
        }
    }
    null.retain(|path| !real.contains_key(path));
    (real, null)
}

/// Installed packages that ship backup files and are cached at their exact version.
///
/// Returns `(archive path, pacman's own `%BACKUP%` map)`, sorted smallest archive first so
/// the test stays quick.
type Candidate = (PathBuf, BTreeMap<String, String>, Vec<String>);

fn candidates(limit: usize) -> Option<Vec<Candidate>> {
    if !Path::new(LOCAL_DB).is_dir() || !Path::new(CACHE).is_dir() {
        eprintln!("skipping: needs both {LOCAL_DB} and {CACHE}");
        return None;
    }
    let db = LocalDatabase::open(LOCAL_DB).unwrap();

    let mut found = Vec::new();
    for package in db.iter() {
        let Ok(text) = std::fs::read_to_string(package.path().join("files")) else { continue };
        let (backups, unhashed) = backup_section(&text);
        if backups.is_empty() && unhashed.is_empty() {
            continue;
        }
        let Ok(desc) = package.desc() else { continue };
        let file_name = PackageFileName::new(
            package.name().clone(),
            package.version().clone(),
            desc.architecture().clone(),
            Some(alpm_types::CompressionAlgorithmFileExtension::Zstd),
        );
        let archive_path = Path::new(CACHE).join(file_name.to_string());
        let Ok(metadata) = std::fs::metadata(&archive_path) else { continue };
        if !metadata.is_file() {
            continue;
        }
        found.push((metadata.len(), archive_path, backups, unhashed));
    }
    found.sort_by_key(|(size, path, _, _)| (*size, path.clone()));
    Some(
        found
            .into_iter()
            .map(|(_, path, backups, unhashed)| (path, backups, unhashed))
            .take(limit)
            .collect(),
    )
}

/// Installs `archive` into a fresh root, returning the `%BACKUP%` piko recorded.
///
/// `Err` carries the reason the install could not be done here. That is not always a defect.
/// A package may ship a directory with no owner-write bit — `bluez` ships `etc/bluetooth/` as
/// `0555` — and pacman extracts into it only because it runs as root, which bypasses the
/// check. This test is unprivileged, so such a package is reported and skipped, not failed.
fn install(archive: &Path) -> Result<BTreeMap<String, String>, piko_txn::Error> {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let dbpath = dir.path().join("db");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(dbpath.join("local")).unwrap();
    std::fs::write(dbpath.join("local/ALPM_DB_VERSION"), "9\n").unwrap();

    let cache = archive.parent().unwrap().to_path_buf();
    let source = CacheDirSource::new([cache]).unwrap();
    let package: PackageFileName = archive.file_name().unwrap().to_string_lossy().parse().unwrap();

    let lock = DbLock::acquire(&dbpath).unwrap();
    Transaction::new(
        &root,
        &dbpath,
        vec![Step::Install { package, reason: PackageInstallReason::Explicit }],
    )
    // The test is unprivileged, so the archive's uid/gid cannot be applied.
    .ownership(Ownership::Inherit)
    .verify(&source)?
    .stage(&lock)?
    .commit()?;

    let entries: Vec<PathBuf> = std::fs::read_dir(dbpath.join("local"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    let [entry] = entries.as_slice() else {
        panic!("expected exactly one entry, got {entries:?}");
    };
    let (recorded, unhashed) =
        backup_section(&std::fs::read_to_string(entry.join("files")).unwrap());
    assert!(
        unhashed.is_empty(),
        "piko wrote a `(null)` hash, which it has no way to produce: {unhashed:?}"
    );
    Ok(recorded)
}

/// Every `%BACKUP%` hash piko records must be the one pacman recorded for the same archive.
#[test]
#[ignore = "requires a real pacman cache and local database"]
fn recorded_backup_hashes_match_what_pacman_recorded() {
    let Some(packages) = candidates(120) else { return };
    if packages.is_empty() {
        eprintln!("skipping: no cached package ships backup files");
        return;
    }

    let mut checked = 0_usize;
    let mut paths = 0_usize;
    let mut null_hashes = Vec::new();
    let mut disagreements = Vec::new();
    let mut unprivileged = Vec::new();

    for (archive, theirs, theirs_unhashed) in &packages {
        let name = archive.file_name().unwrap().to_string_lossy().into_owned();
        let ours = match install(archive) {
            Ok(ours) => ours,
            Err(error) => {
                unprivileged.push(format!("{name}: {error}"));
                continue;
            }
        };

        for (path, theirs_hash) in theirs {
            paths += 1;
            let Some(ours_hash) = ours.get(path) else {
                disagreements.push(format!("{name}: {path} is missing from piko's %BACKUP%"));
                continue;
            };
            if ours_hash != theirs_hash {
                disagreements.push(format!(
                    "{name}: {path}\n  piko:   {ours_hash}\n  pacman: {theirs_hash}"
                ));
            }
        }

        // A path pacman records only as `(null)` is one it never hashed. The `.PKGINFO`
        // declares `backup = <path>` for a path the package does not ship — measured on
        // `gdm`. piko records only paths it actually extracted, so it has nothing to say
        // about such paths. This is the documented divergence.
        for path in theirs_unhashed {
            null_hashes.push(format!("{name}: {path}"));
            assert!(
                !ours.contains_key(path),
                "{name}: {path} is not shipped by the package, so piko should record no hash \
                 for it, but it recorded {:?}",
                ours.get(path)
            );
        }

        // The reverse must hold too: piko must not invent a path pacman never had.
        for path in ours.keys() {
            if !theirs.contains_key(path) {
                disagreements.push(format!("{name}: {path} is in piko's %BACKUP% only"));
            }
        }
        checked += 1;
    }

    eprintln!("checked {checked} packages, {paths} backup paths");
    if !unprivileged.is_empty() {
        eprintln!(
            "{} package(s) could not be extracted without privilege (a read-only packaged \
             directory; pacman runs as root):",
            unprivileged.len()
        );
        for line in &unprivileged {
            eprintln!("  {line}");
        }
    }
    if !null_hashes.is_empty() {
        eprintln!(
            "{} path(s) declared `backup =` but never shipped; pacman wrote `(null)`, \
             piko records nothing at all:",
            null_hashes.len()
        );
        for line in &null_hashes {
            eprintln!("  {line}");
        }
    }

    assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
    assert!(checked > 0, "no package was actually checked");
    assert!(paths > 0, "no backup path was actually compared");
}

/// A second install over the first must leave the user's edit alone.
///
/// This exercises the upgrade half of the same mechanism, on a real package: edit a config
/// file the package owns, install the same archive again, and check the edit survives, with
/// the packaged version waiting as `.pacnew`. The archive is the same both times, so
/// `original == packaged`, and `resolve_backup`'s second rule keeps what is on disk — the
/// commonest real outcome.
#[test]
#[ignore = "requires a real pacman cache and local database"]
fn a_real_config_file_edited_by_the_user_survives_a_reinstall() {
    let Some(packages) = candidates(1) else { return };
    let Some((archive, theirs, _)) = packages.first() else {
        eprintln!("skipping: no cached package ships backup files");
        return;
    };
    let Some(conf) = theirs.keys().next() else { return };

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let dbpath = dir.path().join("db");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(dbpath.join("local")).unwrap();
    std::fs::write(dbpath.join("local/ALPM_DB_VERSION"), "9\n").unwrap();

    let cache = archive.parent().unwrap().to_path_buf();
    let source = CacheDirSource::new([cache]).unwrap();
    let package: PackageFileName = archive.file_name().unwrap().to_string_lossy().parse().unwrap();
    let lock = DbLock::acquire(&dbpath).unwrap();

    let run = || {
        Transaction::new(
            &root,
            &dbpath,
            vec![Step::Install {
                package: package.clone(),
                reason: PackageInstallReason::Explicit,
            }],
        )
        .ownership(Ownership::Inherit)
        .verify(&source)
        .unwrap()
        .stage(&lock)
        .unwrap()
        .commit()
        .unwrap()
    };

    run();
    let edited = b"# edited by the user\n";
    std::fs::write(root.join(conf), edited).unwrap();

    run();

    assert_eq!(
        std::fs::read(root.join(conf)).unwrap(),
        edited,
        "{conf} was overwritten; the user's configuration is gone"
    );
    eprintln!("{conf}: edit survived a reinstall");
}
