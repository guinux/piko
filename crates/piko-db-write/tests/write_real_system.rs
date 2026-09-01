//! Tests the writer against the live local database of the machine running them.
//!
//! Every test here is `#[ignore]`d, because the machine may not be an ALPM based system and
//! the results depend on what is installed. Run them explicitly:
//!
//! ```text
//! cargo test -p piko-db --test write_real_system -- --ignored --nocapture
//! ```
//!
//! **Nothing here writes to the real database.** The system database is read; anything
//! written goes to a `tempfile::TempDir`.
//!
//! The claim under test is the one the whole `write` module rests on: piko writes back a
//! `desc` or `files` file that is byte-identical to what pacman wrote. Every installed
//! package is checked, not a sample, because the failures that matter here are rare. The
//! `(null)` backup hashes that motivated [`piko_db_write::Record`] occur on 2 of 1158
//! packages.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::path::{Path, PathBuf};

use piko_db::{EntryName, Limits, LocalDatabase};
use piko_db_write::{DbLock, LocalDbWriter, Record, RecordKind};

const LOCAL_DB: &str = "/var/lib/pacman/local";

/// Every entry directory in the system database, or `None` if this is not an ALPM system.
fn entry_dirs() -> Option<Vec<PathBuf>> {
    if !Path::new(LOCAL_DB).is_dir() {
        eprintln!("skipping: {LOCAL_DB} does not exist");
        return None;
    }
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(LOCAL_DB)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .map(|entry| entry.path())
        .collect();
    dirs.sort();
    Some(dirs)
}

/// Round-trips every entry's `file_name` through [`Record`] and reports the ones that differ.
fn assert_round_trips(kind: RecordKind, file_name: &str) {
    let Some(dirs) = entry_dirs() else { return };

    let mut checked = 0_usize;
    let mut absent = 0_usize;
    let mut failures = Vec::new();

    for dir in &dirs {
        let path = dir.join(file_name);
        let Ok(original) = std::fs::read_to_string(&path) else {
            absent += 1;
            continue;
        };
        checked += 1;

        let record = match Record::parse(kind, &original) {
            Ok(record) => record,
            Err(error) => {
                failures.push(format!("{}: parse failed: {error}", path.display()));
                continue;
            }
        };
        let rendered = record.render();
        if rendered != original {
            let line =
                original.lines().zip(rendered.lines()).position(|(a, b)| a != b).map_or_else(
                    || {
                        format!(
                            "length {} vs {}",
                            original.lines().count(),
                            rendered.lines().count()
                        )
                    },
                    |index| format!("first difference on line {}", index + 1),
                );
            failures.push(format!("{}: {line}", path.display()));
        }
    }

    println!("{file_name}: {checked} checked, {absent} absent, {} differed", failures.len());
    for failure in failures.iter().take(10) {
        println!("  {failure}");
    }
    assert!(failures.is_empty(), "{} entries did not round-trip", failures.len());
    assert!(checked > 100, "expected a populated database, checked {checked}");
}

/// The acceptance gate: rewriting an untouched `desc` must change nothing at all.
///
/// `alpm-db`'s own `Display` fails this on 125 of 1158 entries. See the table in
/// `write::record`'s module documentation.
#[test]
#[ignore = "requires a real ALPM local database"]
fn every_installed_desc_round_trips_byte_for_byte() {
    assert_round_trips(RecordKind::Desc, "desc");
}

/// As above for `files`. The failures `alpm-db` has include dropping `%BACKUP%` entries
/// whose hash pacman recorded as `(null)`.
#[test]
#[ignore = "requires a real ALPM local database"]
fn every_installed_files_round_trips_byte_for_byte() {
    assert_round_trips(RecordKind::Files, "files");
}

/// The whole database, copied through the writer into a temporary dbpath and compared byte
/// for byte against the original.
///
/// This is the acceptance gate for the `write` module. It exercises [`EntryName::new`],
/// [`LocalDbWriter::create_entry`], and [`LocalDbWriter::write_record`], and with them the
/// entire temp-file/fsync/rename path, at the scale and the messiness of a real system. It
/// then re-opens the result with piko's own scanner, to check the copy is a working database
/// and not merely a matching pile of bytes.
#[test]
#[ignore = "requires a real ALPM local database"]
fn the_whole_database_survives_a_copy_through_the_writer() {
    let Some(dirs) = entry_dirs() else { return };

    let target = tempfile::tempdir().unwrap();
    let lock = DbLock::acquire(target.path()).unwrap();
    let writer = LocalDbWriter::new(target.path(), &lock, Limits::default()).unwrap();

    let mut copied = 0_usize;
    let mut mismatches = Vec::new();

    for dir in &dirs {
        let raw = dir.file_name().unwrap().to_string_lossy().into_owned();
        let Ok(parsed) = EntryName::parse(&raw) else {
            // A directory the scanner itself would reject is not the writer's problem.
            continue;
        };

        // This rebuilds the name from the parsed halves, rather than reusing the string, to
        // check that the writer's own constructor agrees with the scanner.
        let entry = EntryName::new(parsed.name(), parsed.version()).unwrap();
        assert_eq!(entry.as_str(), raw, "EntryName::new did not reproduce the directory name");

        writer.create_entry(&entry).unwrap();
        for (kind, file_name) in [(RecordKind::Desc, "desc"), (RecordKind::Files, "files")] {
            let Ok(original) = std::fs::read_to_string(dir.join(file_name)) else { continue };
            let record = Record::parse(kind, &original).unwrap();
            writer.write_record(&entry, &record).unwrap();

            let written =
                std::fs::read_to_string(writer.entry_path(&entry).join(file_name)).unwrap();
            if written != original {
                mismatches.push(format!("{}/{file_name}", entry.as_str()));
            }
        }
        copied += 1;
    }

    println!("copied {copied} entries, {} mismatched", mismatches.len());
    for name in mismatches.iter().take(10) {
        println!("  {name}");
    }
    assert!(mismatches.is_empty(), "{} files differed from the original", mismatches.len());

    // The copy must be a database, not only matching bytes.
    let source = LocalDatabase::open(LOCAL_DB).unwrap();
    let copy = LocalDatabase::open(writer.root()).unwrap();
    assert_eq!(copy.len(), copied);
    assert_eq!(copy.len(), source.len());

    let mut source_names: Vec<String> =
        source.iter().map(|p| p.entry().as_str().to_owned()).collect();
    let mut copy_names: Vec<String> = copy.iter().map(|p| p.entry().as_str().to_owned()).collect();
    source_names.sort();
    copy_names.sort();
    assert_eq!(source_names, copy_names);

    lock.release().unwrap();
}

/// `pacman -D --asdeps` then `--asexplicit` on a real entry must leave it byte-identical.
///
/// A synthetic `desc` cannot cover this. The hazards are a `%URL%` that a URL parser would
/// normalize and a `%GROUPS%` section that must stay on the correct side of `%REASON%`.
/// Which entries have those is a property of the real database.
#[test]
#[ignore = "requires a real ALPM local database"]
fn flipping_the_install_reason_of_every_entry_is_reversible() {
    let Some(dirs) = entry_dirs() else { return };

    let target = tempfile::tempdir().unwrap();
    let lock = DbLock::acquire(target.path()).unwrap();
    let writer = LocalDbWriter::new(target.path(), &lock, Limits::default()).unwrap();

    let mut checked = 0_usize;
    let mut had_reason = 0_usize;
    let mut failures = Vec::new();

    for dir in &dirs {
        let raw = dir.file_name().unwrap().to_string_lossy().into_owned();
        let Ok(entry) = EntryName::parse(&raw) else { continue };
        let Ok(original) = std::fs::read_to_string(dir.join("desc")) else { continue };

        writer.create_entry(&entry).unwrap();
        writer.write_record(&entry, &Record::parse(RecordKind::Desc, &original).unwrap()).unwrap();
        checked += 1;

        let was_dependency = original.contains("%REASON%");
        if was_dependency {
            had_reason += 1;
        }
        let restore = if was_dependency {
            alpm_types::PackageInstallReason::Depend
        } else {
            alpm_types::PackageInstallReason::Explicit
        };
        let flip = if was_dependency {
            alpm_types::PackageInstallReason::Explicit
        } else {
            alpm_types::PackageInstallReason::Depend
        };

        writer.set_install_reason(&entry, flip).unwrap();
        writer.set_install_reason(&entry, restore).unwrap();

        let text = std::fs::read_to_string(writer.entry_path(&entry).join("desc")).unwrap();
        if text != original {
            failures.push(raw);
        }
    }

    println!(
        "{checked} entries flipped and restored ({had_reason} were dependencies), {} differed",
        failures.len()
    );
    for name in failures.iter().take(10) {
        println!("  {name}");
    }
    assert!(failures.is_empty(), "{} entries did not survive the flip", failures.len());
    assert!(had_reason > 0, "no entry had a %REASON%; the insertion path went untested");

    lock.release().unwrap();
}

/// The `(null)` backup hashes are the reason `Record` exists rather than being a wrapper
/// over `alpm-db`'s types. If a future system has none, the round-trip tests above still
/// pass but stop covering the case. This test reports that rather than losing the coverage
/// silently.
#[test]
#[ignore = "requires a real ALPM local database"]
fn reports_whether_this_system_still_exercises_null_backup_hashes() {
    let Some(dirs) = entry_dirs() else { return };

    let mut found = Vec::new();
    for dir in &dirs {
        let Ok(text) = std::fs::read_to_string(dir.join("files")) else { continue };
        let record = Record::parse(RecordKind::Files, &text).unwrap();
        let Some(backup) = record.get("BACKUP") else { continue };
        for entry in backup {
            if entry.ends_with("\t(null)") {
                found.push(format!("{}: {entry}", dir.file_name().unwrap().to_string_lossy()));
            }
        }
        // Whatever they contain, a rewrite must leave them untouched.
        assert_eq!(record.render(), text, "{}", dir.display());
    }

    if found.is_empty() {
        println!("note: no (null) backup hashes on this system; that case is untested here");
    } else {
        println!("{} backup entries with a (null) hash, all preserved:", found.len());
        for entry in &found {
            println!("  {entry}");
        }
    }
}
