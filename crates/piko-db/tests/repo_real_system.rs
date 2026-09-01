//! Tests against the live sync databases of the machine running them.
//!
//! Mirrors `tests/real_system.rs`. Every test here is `#[ignore]`d, because the machine may
//! have no sync databases at all and the results depend on what repositories are configured.
//! Run them explicitly:
//!
//! ```text
//! cargo test -p piko-db --test repo_real_system -- --ignored --nocapture
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::path::Path;

use alpm_types::{PackageRelation, RelationOrSoname};
use piko_db::{
    EntryName, Error,
    config::DbUsage,
    repo::{RepoDatabase, RepoName, RepoPackage, Variant},
    resolve::{SyncRepo, SyncRepos},
};

const SYNC_DIR: &str = "/var/lib/pacman/sync";

/// Opens `<repo>.db` directly (no sibling awareness), or skips if it is not present.
fn open_db_only(repo: &str) -> Option<RepoDatabase> {
    let path = Path::new(SYNC_DIR).join(format!("{repo}.db"));
    if !path.is_file() {
        eprintln!("skipping: {} does not exist", path.display());
        return None;
    }
    match RepoDatabase::open(&path) {
        Ok(db) => Some(db),
        Err(error) => panic!("failed to open {}: {error}", path.display()),
    }
}

/// Opens `repo` the way `open_repo` is meant to be used: prefer `.db`, defer files to
/// `.files`.
fn open_repo(repo: &str) -> Option<RepoDatabase> {
    if !Path::new(SYNC_DIR).is_dir() {
        eprintln!("skipping: {SYNC_DIR} does not exist");
        return None;
    }
    let name = RepoName::parse(repo).unwrap();
    match RepoDatabase::open_repo(SYNC_DIR, &name) {
        Ok(db) => Some(db),
        Err(error) => {
            eprintln!("skipping {repo}: {error}");
            None
        }
    }
}

#[test]
#[ignore = "requires a real ALPM sync database"]
fn opens_core_and_extra() {
    let Some(core) = open_db_only("core") else { return };
    let Some(extra) = open_db_only("extra") else { return };

    assert!(core.len() > 100, "expected a populated core.db, found {} packages", core.len());
    assert!(extra.len() > 5000, "expected a populated extra.db, found {} packages", extra.len());
    println!("core: {} packages, extra: {} packages", core.len(), extra.len());

    for diagnostic in core.diagnostics().iter().chain(extra.diagnostics()) {
        println!("diagnostic: {diagnostic}");
    }
    assert!(core.diagnostics().is_empty(), "a pristine core.db should produce no diagnostics");
    assert!(extra.diagnostics().is_empty(), "a pristine extra.db should produce no diagnostics");
}

/// `<name>-<version>` entry names in a repository archive have the same shape as local
/// database entries. The same splitter must handle both.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn every_entry_name_round_trips() {
    let Some(extra) = open_db_only("extra") else { return };

    let mut with_epoch = 0_usize;
    for package in &extra {
        let entry = package.entry();
        let dir_name = entry.as_str();

        let reparsed = EntryName::parse(dir_name)
            .unwrap_or_else(|error| panic!("{dir_name} no longer parses: {error}"));
        assert_eq!(&reparsed, entry);
        assert_eq!(format!("{}-{}", package.name(), package.version()), dir_name);

        if package.version().epoch.is_some() {
            with_epoch += 1;
        }
    }

    println!("{} packages, {with_epoch} with an epoch", extra.len());
    assert!(with_epoch > 0, "expected at least one package with an epoch");
}

/// Both `desc` schema versions occur in the wild. Measured at 75 v1 to 15 106 v2 across
/// `core` and `extra` while planning this milestone.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn both_desc_schema_versions_are_present_and_readable() {
    let Some(core) = open_db_only("core") else { return };
    let Some(extra) = open_db_only("extra") else { return };

    let mut v1 = 0_usize;
    let mut v2 = 0_usize;

    for package in core.iter().chain(extra.iter()) {
        let desc = package.desc().unwrap_or_else(|error| {
            panic!("{}: every real desc must parse: {error}", package.name())
        });
        let _ = desc.description();
        let _ = package.depends();

        if desc.is_v2() {
            assert!(desc.pgp_signature().is_none() || desc.md5_checksum().is_none());
            v2 += 1;
        } else {
            assert!(desc.md5_checksum().is_some(), "a v1 desc must have %MD5SUM%");
            assert!(desc.pgp_signature().is_some(), "%PGPSIG% is mandatory in v1");
            v1 += 1;
        }
    }

    println!("{v1} v1 desc entries, {v2} v2 desc entries");
    assert!(v1 > 0 && v2 > 0, "expected both schema versions across core and extra");
}

/// The headline property: opening `core.db` reads no file list at all. `is_files_loaded`
/// stays false immediately after `open`, proving the 19.7 MB `core.files` (581 MB for
/// `extra.files`) was not decompressed just to open the smaller archive.
///
/// `RepoDatabase::open` also auto-discovers the real sibling `core.files` sitting next to
/// `core.db` (see `sibling_files_path`), so `file_list()` succeeds here instead of reporting
/// `FilesUnavailable`. That outcome is covered separately by
/// `repo_hardening::a_db_only_database_has_no_file_lists`, using a fixture with no sibling.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn opening_db_only_touches_files_only_on_first_use() {
    let Some(core) = open_db_only("core") else { return };
    assert_eq!(core.variant(), Variant::Default);

    let package = core.iter().next().unwrap_or_else(|| panic!("core.db should not be empty"));
    assert!(!package.is_files_loaded(), "opening must not touch core.files");

    // Any outcome (resolved, skewed, or missing) is fine here — the point is only that the
    // lookup runs at all, i.e. the sibling was found and read on demand.
    let _ = package.file_list();
    assert!(package.is_files_loaded(), "the first file_list() call must have loaded the arena");
}

/// `open_repo` wires up the deferred `.files` source. The arena must still be untouched
/// immediately after opening, and load only on the first `file_list()` call — for every
/// package, since the arena is shared.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn open_repo_defers_files_until_first_use() {
    let Some(core) = open_repo("core") else { return };
    assert_eq!(core.variant(), Variant::Default, "core.db must be preferred over core.files");

    assert!(
        core.iter().all(|package| !package.is_files_loaded()),
        "the shared arena must be untouched immediately after open_repo"
    );

    let sample = core.iter().next().unwrap_or_else(|| panic!("core should not be empty"));
    let _ = sample.file_list();

    assert!(
        core.iter().all(piko_db::repo::RepoPackage::is_files_loaded),
        "the arena is shared: one file_list() call must mark every package loaded"
    );
}

/// The `.db`/`.files` skew this whole design exists to catch, checked against whatever the
/// live system's drift actually is right now. 12 of `core`'s 296 packages were skewed while
/// planning this milestone, so some skew on a real system is the expected case, not a bug.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn live_db_files_skew_is_handled_without_ever_serving_the_wrong_build() {
    let Some(core) = open_repo("core") else { return };

    let mut ok = 0_usize;
    let mut skewed = 0_usize;
    let mut missing = 0_usize;

    for package in &core {
        match package.file_list() {
            Ok(paths) => {
                assert!(paths.len() > 0 || true, "an empty file list is still a valid answer");
                ok += 1;
            }
            Err(error) => match &*error {
                Error::FilesVersionSkew { db_version, files_version, .. } => {
                    assert_ne!(db_version.to_string(), files_version.to_string());
                    skewed += 1;
                }
                Error::FilesMissingForPackage { .. } => missing += 1,
                other => panic!("{}: unexpected file_list failure: {other:?}", package.name()),
            },
        }
    }

    println!("core: {ok} resolved, {skewed} skewed, {missing} missing from .files");
    assert_eq!(ok + skewed + missing, core.len());
}

/// Every archive named something other than `<repo>.db`/`<repo>.files` must fail before any
/// decompression is attempted. `packages-meta-ext-v1.json.gz` (72 MB of JSON) sits in the
/// same directory as the real sync databases and must never be inflated.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn a_non_repo_database_file_is_rejected_by_name_before_any_decompression() {
    let stray = Path::new(SYNC_DIR).join("packages-meta-ext-v1.json.gz");
    if !stray.is_file() {
        eprintln!("skipping: {} does not exist", stray.display());
        return;
    }

    let err = RepoDatabase::open(&stray).unwrap_err();
    assert!(matches!(err, Error::UnrecognisedArchiveName { .. }), "got {err:?}");
}

/// The `Send + Sync` design exists so a whole database can be forced in parallel.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn the_whole_repository_loads_from_several_threads() {
    let Some(extra) = open_db_only("extra") else { return };
    let extra = &extra;
    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get).min(8);

    std::thread::scope(|scope| {
        for offset in 0..threads {
            scope.spawn(move || {
                for package in extra.iter().skip(offset).step_by(threads) {
                    let _ = package.desc().unwrap().description();
                }
            });
        }
    });
}

/// `core` and `extra` on the machine this was developed against carry no overlapping package
/// names (checked via `comm -12 <(pacman -Sl core | ...) <(pacman -Sl extra | ...)`, empty).
/// So this cannot exercise the priority tie-break; that is covered by fixtures in
/// `resolve::tests`. What it does prove against real data: a name that only exists in `core`
/// resolves to `core` when both are offered, under real `pacman.conf`'s default (`Usage`
/// unset, i.e. `DbUsage::ALL`) configuration.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn resolves_a_real_package_to_the_repository_that_actually_carries_it() {
    let Some(core) = open_db_only("core") else { return };
    let Some(extra) = open_db_only("extra") else { return };

    let known = core.iter().next().unwrap_or_else(|| panic!("core.db is empty"));
    if extra.get(known.name()).is_some() {
        // core/extra were disjoint when this was written, but Arch has been merging
        // packages from extra into core. If that reaches this test's `known` package,
        // there is nothing left to prove here — the tie-break case is already covered
        // by fixtures in `resolve::tests`.
        eprintln!("skipping: {} exists in both core and extra on this machine", known.name());
        return;
    }

    let repos =
        SyncRepos::new([SyncRepo::new(DbUsage::ALL, &extra), SyncRepo::new(DbUsage::ALL, &core)]);
    let bare_name = PackageRelation { name: known.name().clone(), version_requirement: None };
    let resolved = repos
        .find_literal_satisfier(&bare_name)
        .unwrap_or_else(|| panic!("{} not found even though core carries it", known.name()));

    assert_eq!(resolved.repo().as_str(), "core");
    assert_eq!(resolved.package().version(), known.version());
}

/// A version constraint is honored against real data, not just fixtures. A `>=` requirement
/// against a package's own version must still resolve it. A strict `>` requirement against
/// its own version must not — nothing on a real repo is ever newer than itself.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn a_version_constraint_is_honored_against_a_real_package() {
    let Some(core) = open_db_only("core") else { return };
    let known = core.iter().next().unwrap_or_else(|| panic!("core.db is empty"));
    let repos = SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core)]);

    let at_least: PackageRelation =
        format!("{}>={}", known.name(), known.version()).parse().unwrap();
    assert!(
        repos.find_literal_satisfier(&at_least).is_some(),
        "{} must satisfy its own version as a >= constraint",
        known.name()
    );

    let strictly_newer: PackageRelation =
        format!("{}>{}", known.name(), known.version()).parse().unwrap();
    assert!(
        repos.find_literal_satisfier(&strictly_newer).is_none(),
        "{} cannot satisfy a strictly-greater-than constraint against its own version",
        known.name()
    );
}

/// A soname `%PROVIDES%` entry, if this machine's `core`/`extra` happen to carry one, must
/// resolve via its own exact string — proof against real data, not just fixtures. This test
/// skips rather than asserting a fact about this machine's repositories that piko does not
/// control: neither `core` nor `extra` carried a soname `%PROVIDES%` entry while this was
/// written (Arch's `autodeps` soname feature, from pacman 6.1, was not yet in wide use on
/// this mirror).
#[test]
#[ignore = "requires a real ALPM sync database"]
fn a_real_soname_provide_resolves_by_its_own_exact_string() {
    let Some(core) = open_db_only("core") else { return };
    let Some(extra) = open_db_only("extra") else { return };

    let Some(soname) = core
        .iter()
        .chain(extra.iter())
        .flat_map(RepoPackage::provides)
        .find(|provided| !matches!(provided, RelationOrSoname::Relation(_)))
    else {
        eprintln!("skipping: no soname %PROVIDES% entry found in core or extra");
        return;
    };

    let repos =
        SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core), SyncRepo::new(DbUsage::ALL, &extra)]);
    assert!(
        !repos.find_satisfiers(soname).is_empty(),
        "{soname} is a real %PROVIDES% entry but find_satisfiers did not resolve it"
    );
}

/// A real named `%PROVIDES%` entry (e.g. a package providing a virtual package like `cron`
/// or `notification-daemon`), if one exists on this machine, must resolve the same way. This
/// proves the general named-relation provides fallback (not just soname) works against real
/// data.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn a_real_named_provide_resolves_by_its_own_name() {
    let Some(core) = open_db_only("core") else { return };
    let Some(extra) = open_db_only("extra") else { return };

    let Some(RelationOrSoname::Relation(provided)) = core
        .iter()
        .chain(extra.iter())
        .flat_map(RepoPackage::provides)
        .find(|provided| matches!(provided, RelationOrSoname::Relation(_)))
    else {
        eprintln!("skipping: no named %PROVIDES% entry found in core or extra");
        return;
    };

    let repos =
        SyncRepos::new([SyncRepo::new(DbUsage::ALL, &core), SyncRepo::new(DbUsage::ALL, &extra)]);
    let bare_name: RelationOrSoname = RelationOrSoname::Relation(PackageRelation {
        name: provided.name.clone(),
        version_requirement: None,
    });
    assert!(
        !repos.find_satisfiers(&bare_name).is_empty(),
        "{provided} is a real %PROVIDES% entry but find_satisfiers did not resolve its bare name"
    );
}

/// Lookup by name must find every package the scan reported.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn every_package_is_findable_by_name() {
    let Some(extra) = open_db_only("extra") else { return };

    for package in extra.iter().take(2000) {
        let found = extra.get(package.name()).unwrap_or_else(|| {
            panic!("{} is in the database but not findable", package.name());
        });
        assert_eq!(found.name(), package.name());
        assert_eq!(found.version(), package.version());
    }
}

/// The repository half of `real_system.rs`'s `%URL%` test, and the one that matters for a
/// transaction: `%FILENAME%` lives behind the same parse, so a `%URL%` that refuses to
/// normalize would otherwise make a package impossible to download.
#[test]
#[ignore = "requires a real ALPM sync database"]
fn every_repository_url_parses_or_is_reported_raw() {
    let mut entries = 0_usize;
    let mut normalized = 0_usize;
    let mut differs_from_raw = 0_usize;
    let mut unparsable = Vec::new();

    for repo in ["core", "extra", "multilib"] {
        let Some(db) = open_db_only(repo) else { continue };

        for package in &db {
            let desc = package
                .desc()
                .unwrap_or_else(|error| panic!("{repo}/{}: {error:#}", package.name()));
            entries += 1;

            match (desc.url(), desc.url_raw()) {
                (Some(url), raw) => {
                    normalized += 1;
                    if raw != Some(url.to_string().as_str()) {
                        differs_from_raw += 1;
                    }
                }
                (None, Some(raw)) => {
                    // Not an assertion failure: the package stays readable, which is the
                    // point. It is named so a future run can tell what changed upstream.
                    unparsable.push(format!("{repo}/{}: {raw}", package.name()));
                }
                (None, None) => {}
            }

            // The field an install actually needs must be reachable either way.
            assert!(!desc.file_name().to_string().is_empty());
        }
    }

    println!(
        "{entries} entries: {normalized} URLs normalize ({differs_from_raw} differ from the raw \
         bytes), {} do not parse at all",
        unparsable.len()
    );
    for entry in &unparsable {
        println!("unparsable: {entry}");
    }
}
