//! Builds database entries from real packages and diffs them against pacman's own.
//!
//! `#[ignore]`d like every real-system test. Run explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test record_real_system -- --ignored --nocapture
//! ```
//!
//! **Read-only.** Nothing is written; the records are built in memory and compared.
//!
//! # The oracle
//!
//! For a package installed at exactly the version in the cache, `<dbpath>/local/<entry>/desc`
//! is what libalpm wrote from the same `.PKGINFO`. Building the same record from the same
//! input and diffing section by section is a real cross-check.
//!
//! Three sections are excluded: `%INSTALLDATE%`, `%REASON%`, and `%VALIDATION%`. They record
//! the *installation*, not the package, so they legitimately differ.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr as _,
};

use alpm_pkginfo::PackageInfo;
use alpm_types::{PackageFileName, PackageInstallReason, PackageValidation};
use piko_db::LocalDatabase;
use piko_db_write::{Record, RecordKind};
use piko_txn::{
    extract::{MemberKind, PackageLimits, archive},
    record::{self, InstallFacts},
};

const LOCAL_DB: &str = "/var/lib/pacman/local";
const CACHE: &str = "/var/cache/pacman/pkg";

/// Sections that describe the installation rather than the package.
const TRANSACTIONAL: [&str; 3] = ["INSTALLDATE", "REASON", "VALIDATION"];

/// Installed packages whose exact version is cached: (archive, pacman's own `desc` text).
fn installed_and_cached(limit: usize) -> Option<Vec<(PathBuf, String)>> {
    if !Path::new(LOCAL_DB).is_dir() || !Path::new(CACHE).is_dir() {
        eprintln!("skipping: needs both {LOCAL_DB} and {CACHE}");
        return None;
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
        let archive_path = Path::new(CACHE).join(file_name.to_string());
        let Ok(metadata) = std::fs::metadata(&archive_path) else { continue };
        if !metadata.is_file() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(package.path().join("desc")) else { continue };
        found.push((metadata.len(), archive_path, text));
    }
    found.sort_by_key(|(size, path, _)| (*size, path.clone()));
    Some(found.into_iter().map(|(_, path, text)| (path, text)).take(limit).collect())
}

/// Reads a package's `.PKGINFO`, parsed and raw.
fn pkginfo(archive_path: &Path) -> Option<(PackageInfo, String)> {
    let mut raw = None;
    archive::walk(archive_path, &PackageLimits::default(), |member, contents| {
        if member.kind == MemberKind::Metadata && member.path == Path::new(".PKGINFO") {
            let mut buffer = String::new();
            std::io::Read::read_to_string(contents, &mut buffer).ok();
            raw = Some(buffer);
        }
        Ok(())
    })
    .ok()?;
    let raw = raw?;
    let parsed = PackageInfo::from_str(&raw).ok()?;
    Some((parsed, raw))
}

/// Every section piko builds must match what pacman recorded, field for field.
#[test]
#[ignore = "requires a real pacman cache and local database"]
fn built_desc_matches_what_pacman_recorded() {
    let Some(packages) = installed_and_cached(120) else { return };
    if packages.is_empty() {
        eprintln!("skipping: no installed package is cached at its exact version");
        return;
    }

    let facts = InstallFacts {
        install_date: 0,
        reason: PackageInstallReason::Explicit,
        validation: vec![PackageValidation::None],
    };

    let mut checked = 0_usize;
    // Keyed by section so a systematic difference is obvious rather than drowned in
    // per-package noise.
    let mut differing: BTreeMap<String, (usize, String)> = BTreeMap::new();

    for (archive_path, pacman_desc) in &packages {
        let Some((info, raw)) = pkginfo(archive_path) else { continue };
        let built = record::desc(&info, &raw, &facts);
        let theirs = Record::parse(RecordKind::Desc, pacman_desc).unwrap();
        checked += 1;

        let mut keys: Vec<&str> = built.sections().iter().map(|s| s.keyword()).collect();
        keys.extend(theirs.sections().iter().map(|s| s.keyword()));
        keys.sort_unstable();
        keys.dedup();

        for key in keys {
            if TRANSACTIONAL.contains(&key) {
                continue;
            }
            let ours = built.get(key);
            let theirs = theirs.get(key);
            // 169 of this machine's 1157 entries have no `%XDATA%`, even though their
            // package's `.PKGINFO` does. Sampling twelve of them confirmed this. It is
            // historical drift in the database, not something piko should reproduce: a
            // current pacman writes the section, and 988 entries here have it. So the
            // section is compared where pacman recorded one, and skipped where it did not.
            if key == "XDATA" && theirs.is_none() {
                continue;
            }
            if ours != theirs {
                let entry = differing.entry(key.to_owned()).or_insert_with(|| {
                    (
                        0,
                        format!(
                            "{}: ours {:?} vs pacman {:?}",
                            archive_path.file_name().unwrap().to_string_lossy(),
                            ours.map(|v| v.first().cloned()),
                            theirs.map(|v| v.first().cloned())
                        ),
                    )
                });
                entry.0 += 1;
            }
        }
    }

    println!("{checked} packages compared");
    for (section, (count, example)) in &differing {
        println!("  %{section}%: {count} differ — e.g. {example}");
    }
    assert!(checked > 10, "expected a populated cache, compared {checked}");
    assert!(differing.is_empty(), "{} section(s) disagree with pacman", differing.len());
}
