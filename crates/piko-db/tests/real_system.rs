//! Tests against the live local database of the machine running them.
//!
//! Every test here is `#[ignore]`d, because the machine may not be an ALPM based system and
//! the results depend on what is installed. Run them explicitly:
//!
//! ```text
//! cargo test -p piko-db --test real_system -- --ignored --nocapture
//! ```
//!
//! Fixture-based tests prove piko does what piko intends. These prove those intentions match
//! a real, unsanitised database of over a thousand packages.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::path::Path;

use piko_db::{EntryName, LocalDatabase, LocalPackage};

const LOCAL_DB: &str = "/var/lib/pacman/local";

/// Opens the system database, or skips the test if this is not an ALPM based system.
fn open_system_db() -> Option<LocalDatabase> {
    if !Path::new(LOCAL_DB).is_dir() {
        eprintln!("skipping: {LOCAL_DB} does not exist");
        return None;
    }

    match LocalDatabase::open(LOCAL_DB) {
        Ok(db) => Some(db),
        Err(error) => panic!("failed to open {LOCAL_DB}: {error}"),
    }
}

#[test]
#[ignore = "requires a real ALPM local database"]
fn opens_the_system_database() {
    let Some(db) = open_system_db() else { return };

    assert!(db.len() > 100, "expected a populated database, found {} packages", db.len());
    println!("opened {} packages from {LOCAL_DB}", db.len());

    for diagnostic in db.diagnostics() {
        println!("diagnostic: {diagnostic}");
    }
    assert!(
        db.diagnostics().is_empty(),
        "a pristine system database should produce no diagnostics"
    );
}

/// The splitter is the one component with no upstream implementation to lean on. It is
/// checked against every entry name the system actually has.
#[test]
#[ignore = "requires a real ALPM local database"]
fn every_entry_name_round_trips() {
    let Some(db) = open_system_db() else { return };

    let mut with_epoch = 0_usize;
    let mut max_dashes = 0_usize;

    for package in &db {
        let entry = package.entry();
        let dir_name = entry.as_str();

        // The directory we would read from must be the directory we scanned.
        assert_eq!(
            package.path().file_name().and_then(|name| name.to_str()),
            Some(dir_name),
            "path does not match entry name for {dir_name}"
        );

        // Reparsing the rendered form must give the same answer.
        let reparsed = EntryName::parse(dir_name)
            .unwrap_or_else(|error| panic!("{dir_name} no longer parses: {error}"));
        assert_eq!(&reparsed, entry);

        assert_eq!(format!("{}-{}", package.name(), package.version()), dir_name);

        if package.version().epoch.is_some() {
            with_epoch += 1;
        }
        max_dashes = max_dashes.max(dir_name.matches('-').count());
    }

    println!("{} packages, {with_epoch} with an epoch, up to {max_dashes} dashes", db.len());
    assert!(with_epoch > 0, "expected at least one package with an epoch");
}

/// Opening must not read a single byte of package metadata — that is the whole design.
#[test]
#[ignore = "requires a real ALPM local database"]
fn opening_reads_no_package_metadata() {
    let Some(db) = open_system_db() else { return };

    let unloaded = db
        .iter()
        .filter(|package| {
            !package.is_desc_loaded() && !package.is_files_loaded() && !package.is_mtree_loaded()
        })
        .count();

    assert_eq!(unloaded, db.len(), "opening must leave every lazy slot untouched");
}

/// The strongest single check in the suite: every `desc`, `files` and `mtree` on a real
/// system must parse. It uses the limits and the unknown-section policy piko ships by default.
#[test]
#[ignore = "requires a real ALPM local database"]
fn every_package_loads_completely() {
    let Some(db) = open_system_db() else { return };

    let mut failures = Vec::new();
    let mut with_mtree = 0_usize;
    let mut total_files = 0_usize;

    for package in &db {
        if let Err(error) = package.load_all() {
            failures.push(format!("{}: {error:#}", package.name()));
            continue;
        }
        if package.mtree().is_ok_and(|mtree| mtree.is_some()) {
            with_mtree += 1;
        }
        total_files += package.file_list().map(<[_]>::len).unwrap_or(0);
    }

    println!("{} packages loaded, {with_mtree} with an mtree, {total_files} files total", db.len());
    assert!(
        failures.is_empty(),
        "{} packages failed to load:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// `%NAME%` and `%VERSION%` are advisory. On a healthy system they should still agree with
/// the directory name, and no `desc` should carry a section piko cannot interpret.
#[test]
#[ignore = "requires a real ALPM local database"]
fn no_package_is_inconsistent() {
    let Some(db) = open_system_db() else { return };

    let mut inconsistent = Vec::new();
    for package in &db {
        match package.check_consistency() {
            Ok(found) if found.is_empty() => {}
            Ok(found) => {
                for item in found {
                    inconsistent.push(format!("{}: {item}", package.name()));
                }
            }
            Err(error) => inconsistent.push(format!("{}: {error:#}", package.name())),
        }
    }

    assert!(inconsistent.is_empty(), "{}", inconsistent.join("\n"));
}

/// Both `desc` schema versions occur in the wild; the version-agnostic view must handle
/// whichever a given package uses.
#[test]
#[ignore = "requires a real ALPM local database"]
fn both_desc_schema_versions_are_present_and_readable() {
    let Some(db) = open_system_db() else { return };

    let mut v1 = 0_usize;
    let mut v2 = 0_usize;

    for package in &db {
        let desc = package.desc().unwrap_or_else(|error| {
            panic!("{}: {error:#}", package.name());
        });

        // Exercise the shared accessors regardless of schema.
        let _ = desc.description();
        let _ = desc.depends();
        let _ = desc.installed_size();

        if desc.is_v2() {
            assert!(desc.xdata().is_some(), "a v2 desc must expose %XDATA%");
            v2 += 1;
        } else {
            assert!(desc.xdata().is_none(), "a v1 desc has no %XDATA%");
            v1 += 1;
        }
    }

    println!("{v1} v1 desc files, {v2} v2 desc files");
    assert!(v1 > 0 && v2 > 0, "expected both schema versions on a real system");
}

/// The `Send + Sync` design exists so a whole database can be forced in parallel.
#[test]
#[ignore = "requires a real ALPM local database"]
fn the_whole_database_loads_from_several_threads() {
    let Some(db) = open_system_db() else { return };
    let db = &db;
    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get).min(8);

    std::thread::scope(|scope| {
        for offset in 0..threads {
            scope.spawn(move || {
                for package in db.iter().skip(offset).step_by(threads) {
                    package.load_all().unwrap_or_else(|error| {
                        panic!("{}: {error:#}", package.name());
                    });
                }
            });
        }
    });

    assert!(db.iter().all(LocalPackage::is_desc_loaded));
}

/// Lookup by name must find every package the scan reported.
#[test]
#[ignore = "requires a real ALPM local database"]
fn every_package_is_findable_by_name() {
    let Some(db) = open_system_db() else { return };

    for package in &db {
        let found = db.get(package.name()).unwrap_or_else(|| {
            panic!("{} is in the database but not findable", package.name());
        });
        assert_eq!(found.name(), package.name());
        assert_eq!(found.version(), package.version());
    }
}

/// `%URL%` is taken out of the text before the upstream parse, so the bytes it reports must be
/// the bytes on disk — the oracle here is the `desc` file itself, read without piko.
///
/// The normalized form is only counted, not asserted on. `url::Url` refuses nothing on this
/// machine today (0 of 1240), and pinning that would test Arch's packaging, not piko.
#[test]
#[ignore = "requires a real ALPM local database"]
fn every_url_is_reported_exactly_as_the_desc_holds_it() {
    let Some(db) = open_system_db() else { return };

    let mut normalized = 0_usize;
    let mut unparsable = 0_usize;
    let mut differs_from_raw = 0_usize;

    for package in &db {
        let entry = format!("{}-{}", package.name(), package.version());
        let text = std::fs::read_to_string(Path::new(LOCAL_DB).join(&entry).join("desc"))
            .unwrap_or_else(|error| panic!("{entry}: {error}"));
        let expected = text
            .split("%URL%\n")
            .nth(1)
            .and_then(|rest| rest.lines().next())
            .filter(|value| !value.is_empty());

        let desc = package.desc().unwrap_or_else(|error| panic!("{entry}: {error:#}"));
        assert_eq!(desc.url_raw(), expected, "{entry}");

        match desc.url() {
            Some(url) => {
                normalized += 1;
                if Some(url.to_string().as_str()) != expected {
                    differs_from_raw += 1;
                }
            }
            None if expected.is_some() => unparsable += 1,
            None => {}
        }
    }

    println!(
        "{} packages: {normalized} URLs normalize ({differs_from_raw} differ from the raw \
         bytes), {unparsable} do not parse at all",
        db.len()
    );
}
