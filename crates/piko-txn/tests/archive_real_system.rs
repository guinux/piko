//! Reads this machine's real cached packages with the extraction archive walker.
//!
//! This test is `#[ignore]`d, like every real-system test. Run it explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test archive_real_system -- --ignored --nocapture
//! ```
//!
//! By default, packages above [`SIZE_LIMIT`] are skipped. The development machine's cache is
//! 24 GB, and reaching the tar headers requires decompressing every byte. Set
//! `PIKO_FULL_CACHE=1` to walk all packages instead. That full run takes minutes rather than
//! seconds, and its result is the one quoted in commit messages.
//!
//! **Read-only.** The walker never writes. Extraction is a separate step.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::path::{Path, PathBuf};

use piko_txn::extract::{MemberKind, PackageLimits, archive, decision::EntryKind};

/// Packages larger than this are skipped unless `PIKO_FULL_CACHE` is set.
const SIZE_LIMIT: u64 = 8 * 1024 * 1024;

const CACHE: &str = "/var/cache/pacman/pkg";

/// Every package file in the cache, sorted smallest first so a partial run still covers many.
fn cached_packages() -> Option<Vec<(PathBuf, u64)>> {
    if !Path::new(CACHE).is_dir() {
        eprintln!("skipping: {CACHE} does not exist");
        return None;
    }
    let mut found: Vec<(PathBuf, u64)> = std::fs::read_dir(CACHE)
        .unwrap()
        .flatten()
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.contains(".pkg.tar") && !name.ends_with(".sig") && !name.ends_with(".part")
        })
        .filter_map(|entry| {
            let size = entry.metadata().ok()?.len();
            Some((entry.path(), size))
        })
        .collect();
    found.sort_by_key(|(path, size)| (*size, path.clone()));
    Some(found)
}

/// Every real package must be readable, and every member must be classifiable.
///
/// This is the acceptance gate for the walker. It also answers a question a fixture cannot:
/// whether refusing an unparseable numeric header field works in practice. `tar` returns an
/// error for a blank uid, gid, or mtime. The walker propagates that error instead of
/// defaulting to zero. If any real package had such a field, this test would show that choice
/// makes the package un-installable.
#[test]
#[ignore = "requires a real pacman cache"]
fn every_cached_package_can_be_read() {
    let Some(packages) = cached_packages() else { return };
    if packages.is_empty() {
        eprintln!("skipping: the cache holds no packages");
        return;
    }

    let full = std::env::var_os("PIKO_FULL_CACHE").is_some();
    let limits = PackageLimits::default();

    let (mut read, mut skipped, mut members, mut metadata, mut dirs, mut links) =
        (0_usize, 0_usize, 0_u64, 0_u64, 0_u64, 0_u64);
    let mut failures = Vec::new();

    for (path, size) in &packages {
        if !full && *size > SIZE_LIMIT {
            skipped += 1;
            continue;
        }

        let result = archive::walk(path, &limits, |member, _contents| {
            members += 1;
            match member.kind {
                MemberKind::Metadata => metadata += 1,
                MemberKind::Payload => {}
            }
            if member.entry == EntryKind::Directory {
                dirs += 1;
            }
            if member.is_symlink() {
                links += 1;
            }
            // Contents are not read here. This measures the walk only; `tar` must still skip
            // to the next member correctly.
            Ok(())
        });

        match result {
            Ok(()) => read += 1,
            Err(error) => {
                failures.push(format!("{}: {error}", path.display()));
            }
        }
    }

    println!(
        "read {read} packages ({skipped} skipped as larger than {} MiB{}), \
         {members} members: {metadata} metadata, {dirs} directories, {links} symlinks",
        SIZE_LIMIT / 1024 / 1024,
        if full { ", full run" } else { ", set PIKO_FULL_CACHE=1 for all" }
    );
    for failure in failures.iter().take(10) {
        println!("  {failure}");
    }
    assert!(failures.is_empty(), "{} packages could not be read", failures.len());
    assert!(read > 10, "expected a populated cache, read {read}");
    assert!(metadata > 0, "no metadata members seen; the classifier is not being exercised");
}

/// Reads member contents too, over a smaller sample.
///
/// The walk above never touches a member's body, so it cannot detect the stream
/// desynchronizing on its own. This test reads every byte of a few packages and checks that
/// the delivered size matches the size the header promised.
#[test]
#[ignore = "requires a real pacman cache"]
fn member_contents_match_their_declared_size() {
    let Some(packages) = cached_packages() else { return };
    let sample: Vec<_> = packages.iter().take(25).collect();
    if sample.is_empty() {
        eprintln!("skipping: the cache holds no packages");
        return;
    }

    let mut checked = 0_u64;
    let mut mismatches = Vec::new();

    for (path, _) in sample {
        archive::walk(path, &PackageLimits::default(), |member, contents| {
            let mut sink = Vec::new();
            std::io::Read::read_to_end(contents, &mut sink).unwrap();
            if sink.len() as u64 != member.size {
                mismatches.push(format!(
                    "{}: {} declared {} bytes, read {}",
                    path.display(),
                    member.path.display(),
                    member.size,
                    sink.len()
                ));
            }
            checked += 1;
            Ok(())
        })
        .unwrap();
    }

    println!("{checked} members read in full, {} size mismatches", mismatches.len());
    for entry in mismatches.iter().take(10) {
        println!("  {entry}");
    }
    assert!(mismatches.is_empty());
    assert!(checked > 0);
}
