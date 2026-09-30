//! Checks the pending-file scan against `pacdiff` on a real system.
//!
//! `#[ignore]`d like every real-system test. Run explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test merge_real_system -- --ignored --nocapture
//! ```
//!
//! **Read-only.** Nothing is written anywhere. In particular, nothing here calls
//! `piko_txn::merge::apply` or `remove_if_identical`: both delete or overwrite a file the user
//! owns, and this machine's `/etc` is not a fixture.
//!
//! # Why `pacdiff` is the oracle
//!
//! A unit test proves the scan finds a `.pacnew` a fixture just put there. It cannot prove the
//! scan finds the ones a real system accumulated over years of upgrades, through packages that
//! declare `%BACKUP%` paths they no longer ship, directories nobody looks at, and files whose
//! names hold a dot. `pacdiff` walks the same `%BACKUP%` list from the other direction: it
//! finds the file and strips the suffix, where piko takes the entry and adds it. Two directions
//! agreeing on a real system is a much stronger claim than either alone.
//!
//! The comparison runs **both ways**. A one-way diff reports a real divergence as a match,
//! which is the failure mode a self-report in this repository has already had once.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};

use piko_db::LocalDatabase;
use piko_txn::{
    RootDir,
    merge::{self, BaseLimits, ScanLimits, Verdict},
};

const LOCAL_DB: &str = "/var/lib/pacman/local";
const ROOT: &str = "/";

/// The database and the root, or `None` where there is no real system to read.
fn system() -> Option<(LocalDatabase, RootDir)> {
    if !Path::new(LOCAL_DB).exists() {
        println!("skipping: {LOCAL_DB} is not there");
        return None;
    }
    let db = LocalDatabase::open(Path::new(LOCAL_DB))
        .unwrap_or_else(|error| panic!("{LOCAL_DB} exists but will not open: {error}"));
    let root = RootDir::open(Path::new(ROOT))
        .unwrap_or_else(|error| panic!("{ROOT} will not open: {error}"));
    Some((db, root))
}

/// What one external program printed, or `None` where it is not installed.
fn output_of(program: &str, arguments: &[&str]) -> Option<Vec<u8>> {
    match Command::new(program).args(arguments).output() {
        Ok(output) if output.status.success() => Some(output.stdout),
        Ok(output) => panic!("{program} failed: {}", String::from_utf8_lossy(&output.stderr)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("skipping: {program} is not installed");
            None
        }
        Err(error) => panic!("{program} could not be started: {error}"),
    }
}

/// Every pending file piko found, as an absolute path.
fn piko_pending(db: &LocalDatabase, root: &RootDir) -> (BTreeSet<PathBuf>, merge::Scan) {
    let scan = merge::scan(root, db, &ScanLimits::default());
    let paths = scan.pending().iter().map(|entry| Path::new(ROOT).join(&entry.pacfile)).collect();
    (paths, scan)
}

#[test]
#[ignore = "requires a real ALPM local database"]
fn piko_agrees_with_pacdiff_about_what_is_pending() {
    let Some((db, root)) = system() else { return };
    let Some(stdout) = output_of("pacdiff", &["--output"]) else { return };

    // `.pacorig` is subtracted deliberately, not by accident. Older versions of pacman wrote
    // them; nothing in the reference tree writes one any more, and piko does not create them.
    // `pacdiff` still scans for them, so leaving them in would fail this over a kind of file
    // neither tool produces.
    let theirs: BTreeSet<PathBuf> = String::from_utf8_lossy(&stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.ends_with(".pacorig"))
        .map(PathBuf::from)
        .collect();

    let (ours, scan) = piko_pending(&db, &root);
    for problem in scan.problems() {
        println!("problem: {problem}");
    }

    let missing: Vec<&PathBuf> = theirs.difference(&ours).collect();
    let extra: Vec<&PathBuf> = ours.difference(&theirs).collect();
    println!("pacdiff found {}, piko found {}", theirs.len(), ours.len());
    if theirs.is_empty() {
        println!("nothing is pending on this machine, so the agreement is over the empty set");
    }

    assert!(missing.is_empty(), "pacdiff found these and piko did not: {missing:?}");
    assert!(extra.is_empty(), "piko found these and pacdiff did not: {extra:?}");
}

#[test]
#[ignore = "requires a real ALPM local database"]
fn every_pending_file_has_a_base_candidate_or_a_reason() {
    let Some((db, root)) = system() else { return };
    let (_, scan) = piko_pending(&db, &root);

    let cache_dirs = vec![PathBuf::from("/var/cache/pacman/pkg")];
    let limits = BaseLimits::default();
    let (mut with_base, mut without_base) = (0_usize, 0_usize);

    // This machine's own keyring and default policy, so the split below is what `piko merge`
    // offers here. A keyring this user cannot use falls back to no check, and says so.
    let check = merge::BaseCheck::new(
        piko_db::config::SigLevel::default_global(),
        std::path::Path::new("/etc/pacman.d/gnupg"),
    )
    .unwrap_or_else(|error| {
        println!("checking no signature: {error}");
        merge::BaseCheck::Unchecked
    });

    for entry in scan.pending() {
        let found = merge::find_base(
            &cache_dirs,
            &entry.package,
            &entry.installed_version,
            &limits,
            &check,
        )
        .unwrap();
        for refused in &found.refused {
            println!("{}: passed over: {}", refused.path.display(), refused.reason);
        }
        match found.base {
            Some(candidate) => {
                with_base += 1;
                // The ancestor must sit strictly below the installed version. The installed
                // build is one side of the merge, never its base.
                assert!(
                    candidate.file_name.version() < &entry.installed_version,
                    "{} is not older than the installed {}",
                    candidate.file_name,
                    entry.installed_version
                );
                println!(
                    "{}: base {} (installed {})",
                    entry.pacfile.display(),
                    candidate.file_name,
                    entry.installed_version
                );
            }
            None => {
                without_base += 1;
                println!(
                    "{}: no cached build of {} below {}",
                    entry.pacfile.display(),
                    entry.package,
                    entry.installed_version
                );
            }
        }
    }

    // A cleaned cache is ordinary, so there is no assertion on the split itself.
    println!("{with_base} pending files have a base, {without_base} do not");
}

#[test]
#[ignore = "requires a real ALPM local database"]
fn a_base_extracted_from_the_cache_is_what_bsdtar_extracts() {
    let Some((db, root)) = system() else { return };
    let (_, scan) = piko_pending(&db, &root);

    let cache_dirs = vec![PathBuf::from("/var/cache/pacman/pkg")];
    let limits = BaseLimits::default();
    let mut compared = 0_usize;

    for entry in scan.pending() {
        // Extraction is what this compares, so no signature is asked for.
        let Some(candidate) = merge::find_base(
            &cache_dirs,
            &entry.package,
            &entry.installed_version,
            &limits,
            &merge::BaseCheck::Unchecked,
        )
        .unwrap()
        .base
        else {
            continue;
        };
        let ours = merge::extract_member(&candidate.path, &entry.target, &limits).unwrap();

        // `bsdtar` is what `pacdiff` itself reaches for, so it is an independent reader of the
        // same member. It spells the member without a leading separator.
        let member = entry.target.display().to_string();
        let Some(theirs) =
            output_of("bsdtar", &["-xqOf", &candidate.path.display().to_string(), &member])
        else {
            return;
        };

        match ours {
            Some(bytes) => assert_eq!(
                bytes,
                theirs,
                "{} differs from what bsdtar read out of {}",
                entry.target.display(),
                candidate.path.display()
            ),
            // A package that stopped shipping the file reads as empty on both sides.
            None => assert!(
                theirs.is_empty(),
                "piko found no {} in {} but bsdtar read {} bytes",
                entry.target.display(),
                candidate.path.display(),
                theirs.len()
            ),
        }
        compared += 1;
    }

    println!("{compared} bases matched bsdtar byte for byte");
}

#[test]
#[ignore = "requires a real ALPM local database"]
fn the_scan_reports_what_it_found_and_what_it_cost() {
    let Some((db, root)) = system() else { return };

    let started = std::time::Instant::now();
    let scan = merge::scan(&root, &db, &ScanLimits::default());
    let elapsed = started.elapsed();

    let backups: usize =
        db.iter().map(|package| package.backups().map(<[_]>::len).unwrap_or(0)).sum();
    let (mut identical, mut differs, mut missing, mut unreadable) = (0, 0, 0, 0);
    for entry in scan.pending() {
        match entry.verdict {
            Verdict::Identical => identical += 1,
            Verdict::Differs => differs += 1,
            Verdict::TargetMissing => missing += 1,
            Verdict::Unreadable => unreadable += 1,
        }
    }

    println!("{backups} %BACKUP% entries scanned in {elapsed:?}");
    println!(
        "{} pending: {differs} differ, {identical} identical, {missing} with no target, \
         {unreadable} unreadable",
        scan.pending().len()
    );
    println!("{} problems, {} withheld", scan.problems().len(), scan.problems_dropped());

    // Not a performance assertion, but a scan that read nothing would be a broken one.
    assert!(backups > 0, "a real system declares %BACKUP% entries");
}

/// A build pacman downloaded, with the `.sig` beside it, passes the check `piko merge` asks of a
/// base under this machine's keyring and default policy. Otherwise the check would turn every
/// three-way merge into a two-way view.
#[test]
#[ignore = "requires a real package cache and keyring"]
fn a_signed_cached_build_is_accepted_as_a_base() {
    let cache = PathBuf::from("/var/cache/pacman/pkg");
    let check = match merge::BaseCheck::new(
        piko_db::config::SigLevel::default_global(),
        std::path::Path::new("/etc/pacman.d/gnupg"),
    ) {
        Ok(check) => check,
        Err(error) => {
            eprintln!("skipping: {error}");
            return;
        }
    };
    let Ok(entries) = std::fs::read_dir(&cache) else { return };
    let signed = entries.filter_map(Result::ok).find_map(|entry| {
        let name = entry.file_name().to_str()?.to_owned();
        let file_name: alpm_types::PackageFileName = name.parse().ok()?;
        cache.join(format!("{name}.sig")).is_file().then_some(file_name)
    });
    let Some(file_name) = signed else {
        eprintln!("skipping: no cached package has a .sig");
        return;
    };

    // An installed version above every build, so the newest cached one is the candidate.
    let above: alpm_types::FullVersion = "999999:0-1".parse().unwrap();
    let search = merge::find_base(
        std::slice::from_ref(&cache),
        file_name.name(),
        &above,
        &BaseLimits::default(),
        &check,
    )
    .unwrap();
    assert!(search.refused.is_empty(), "{:?}", search.refused);
    assert!(search.base.is_some(), "no base found for {file_name}");
    println!("{file_name}: accepted as a base");
}
