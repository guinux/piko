//! Runs the disk-space estimate against this machine's real mount table and database.
//!
//! `#[ignore]`d like every real-system test. Run explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test space_real_system -- --ignored --nocapture
//! ```
//!
//! **Nothing here writes.** Every measurement is a `statvfs`, a `statat`, or a read of
//! `/proc/self/mounts` and the local database.
//!
//! # The oracle
//!
//! A hand-built table in a unit test proves the matching rule is transcribed correctly. It
//! cannot prove the rule *covers this machine*, because a unit test writes down both the
//! question and the answer. So the oracle here is coverage: every absolute path any installed
//! package owns must land on some mount point. A `MountPointUnknown` would mean that path's
//! bytes were charged to nobody, and an estimate that silently charges nothing is one that
//! silently passes.
//!
//! The numbers are checked against `stat -f`, which reads the same `statvfs` through a
//! different implementation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
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
use piko_txn::space::mounts::MountTable;

/// This machine's local database.
const LOCAL_DB: &str = "/var/lib/pacman/local";

fn table() -> MountTable {
    MountTable::load().expect("the mount table must be readable on a running system")
}

/// Every mount directory the kernel currently reports, read independently of `MountTable`.
fn kernel_mount_dirs() -> BTreeSet<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/mounts").unwrap();
    text.lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(|dir| PathBuf::from(dir.replace("\\040", " ")))
        .collect()
}

#[test]
#[ignore = "requires a real ALPM system"]
fn every_mount_the_kernel_reports_is_in_the_table() {
    let table = table();
    let parsed: BTreeSet<PathBuf> = table.dirs().map(Path::to_path_buf).collect();
    let kernel = kernel_mount_dirs();
    assert_eq!(parsed, kernel, "the parse dropped or invented a mount point");
    // Deduplication is the only reason the two counts can differ, and `kernel` is a set.
    assert_eq!(table.count(), kernel.len(), "a duplicate mount directory survived");
    println!("{} mount points", table.count());
}

#[test]
#[ignore = "requires a real ALPM system"]
fn a_duplicated_mount_directory_appears_once() {
    // This machine mounts `/boot` twice: an autofs placeholder, then the vfat filesystem that
    // shadows it. libalpm keeps both records and its stable sort makes the scan always answer
    // with the first, so the second is never checked; dropping it is the same answer.
    let raw = std::fs::read_to_string("/proc/self/mounts").unwrap();
    let mut seen: Vec<&str> =
        raw.lines().filter_map(|line| line.split_whitespace().nth(1)).collect();
    let total = seen.len();
    seen.sort_unstable();
    seen.dedup();
    if total == seen.len() {
        println!("no duplicated mount directory on this machine; nothing to prove");
        return;
    }
    println!("{} raw mount records, {} distinct directories", total, seen.len());
    assert_eq!(table().count(), seen.len());
}

#[test]
#[ignore = "requires a real ALPM system"]
fn the_root_and_every_mount_point_match_themselves() {
    let table = table();
    for dir in table.dirs() {
        let index = table
            .match_point(dir)
            .unwrap_or_else(|| panic!("{} matched no mount point", dir.display()));
        assert_eq!(
            table.dir(index).unwrap(),
            dir,
            "{} matched a different mount point than itself",
            dir.display()
        );
    }
    let root = table.match_point(Path::new("/")).expect("/ must match something");
    assert_eq!(table.dir(root).unwrap(), Path::new("/"));
}

#[test]
#[ignore = "requires a real ALPM system"]
fn every_file_every_installed_package_owns_lands_on_some_filesystem() {
    let database = LocalDatabase::open(Path::new(LOCAL_DB)).unwrap();
    let table = table();

    let mut checked = 0_u64;
    let mut unmatched: Vec<PathBuf> = Vec::new();
    let mut per_mount: std::collections::BTreeMap<PathBuf, u64> = std::collections::BTreeMap::new();
    for package in database.iter() {
        let Ok(files) = package.file_list() else { continue };
        for file in files {
            let absolute = Path::new("/").join(file);
            checked += 1;
            match table.match_point(&absolute) {
                Some(index) => {
                    *per_mount.entry(table.dir(index).unwrap().to_path_buf()).or_default() += 1;
                }
                None => unmatched.push(absolute),
            }
        }
    }

    println!("{checked} owned paths across {} packages", database.iter().count());
    for (dir, count) in &per_mount {
        println!("  {:<40} {count}", dir.display());
    }
    assert!(
        unmatched.is_empty(),
        "{} owned paths matched no mount point, e.g. {:?}",
        unmatched.len(),
        unmatched.first()
    );
    assert!(checked > 1000, "a real system owns far more than {checked} paths");
    // Whatever else this machine looks like, `/` must carry package files.
    assert!(per_mount.contains_key(Path::new("/")), "nothing was charged to the root");
}

#[test]
#[ignore = "requires a real ALPM system"]
fn the_free_space_read_per_mount_point_agrees_with_stat_f() {
    let table = table();
    let mut compared = 0_u32;
    for dir in table.dirs() {
        // `stat -f` reads the same `statvfs`. Pseudo-filesystems answer with zeros, which says
        // nothing either way, so they are skipped rather than asserted about.
        let Ok(output) = Command::new("stat").arg("-f").arg("-c").arg("%S %b %a").arg(dir).output()
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let mut fields = text.split_whitespace().map(str::parse::<u64>);
        let (Some(Ok(block_size)), Some(Ok(blocks)), Some(Ok(available))) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if blocks == 0 {
            continue;
        }
        let fs = rustix::fs::statvfs(dir).unwrap();
        assert_eq!(fs.f_bsize, block_size, "{} block size", dir.display());
        assert_eq!(fs.f_blocks, blocks, "{} capacity", dir.display());
        // Free space moves under a running system, so this is a sanity band rather than an
        // equality: the two readings are seconds apart.
        let drift = fs.f_bavail.abs_diff(available);
        assert!(
            drift * 100 <= blocks.max(1),
            "{}: {} vs {} available blocks is more than 1% of {blocks} apart",
            dir.display(),
            fs.f_bavail,
            available
        );
        compared += 1;
        println!(
            "  {:<40} {} MiB free of {} MiB",
            dir.display(),
            fs.f_bavail * block_size / (1024 * 1024),
            blocks * block_size / (1024 * 1024)
        );
    }
    assert!(compared > 0, "no mount point could be compared against stat -f");
}

#[test]
#[ignore = "requires a real ALPM system"]
fn a_download_of_every_cached_package_fits_in_the_cache() {
    // The strongest end-to-end assertion that costs nothing. The packages in the cache are
    // already on that filesystem. So this asks whether the check refuses something the machine
    // demonstrably holds. It must not.
    let cache = Path::new("/var/cache/pacman/pkg");
    if !cache.is_dir() {
        println!("no package cache on this machine; nothing to weigh");
        return;
    }
    let sizes: Vec<u64> = std::fs::read_dir(cache)
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .filter(std::fs::Metadata::is_file)
        .map(|metadata| metadata.len())
        .collect();
    let total: u64 = sizes.iter().sum();
    println!("{} cached files, {} MiB", sizes.len(), total / (1024 * 1024));

    // A single byte must always fit on a machine that can run this test at all.
    piko_txn::space::check_download(cache, [1_u64]).expect("one byte must fit");

    match piko_txn::space::check_download(cache, sizes) {
        Ok(()) => println!("the whole cache would fit again"),
        // Legitimate on a machine whose cache is larger than its remaining free space. The
        // refusal is the point; what matters is that it names the partition and both numbers.
        Err(piko_txn::Error::DiskSpace { too_full, read_only }) => {
            assert!(read_only.is_empty());
            let partition = too_full.first().expect("a refusal names a partition");
            assert!(partition.blocks_needed > partition.blocks_free);
            println!("refused, as expected on a full disk: {partition}");
        }
        Err(other) => panic!("unexpected error: {other}"),
    }
}
