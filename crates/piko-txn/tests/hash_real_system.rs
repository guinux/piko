//! Checks piko's MD5 against the hashes pacman recorded for real backup files.
//!
//! `#[ignore]`d like every real-system test. Run explicitly:
//!
//! ```text
//! cargo test -p piko-txn --test hash_real_system -- --ignored --nocapture
//! ```
//!
//! **Read-only.** Nothing is written anywhere.
//!
//! # Why this is the test that matters for hashing
//!
//! A unit test pinning `md5("abc")` proves piko computes *an* MD5. It does not prove piko
//! computes the same digest pacman did over the same file. Different buffering, a stray
//! newline, or hashing a path rather than its contents would all still pass it. The local
//! database holds hundreds of `%BACKUP%` entries whose hashes libalpm wrote by hashing the
//! very files that are still on disk. Agreeing with those is the real claim.
//!
//! A disagreement is not automatically a bug. A backup file the user edited *should* hash
//! differently — that is the entire point of recording it. So this test reports the split and
//! asserts on the matching majority, not on perfection.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::path::Path;

use piko_db::LocalDatabase;
use piko_txn::{
    RootDir,
    hash::{MAX_BACKUP_BYTES, file_md5_at},
};

const LOCAL_DB: &str = "/var/lib/pacman/local";

#[test]
#[ignore = "requires a real ALPM local database"]
fn piko_agrees_with_the_hashes_pacman_recorded() {
    if !Path::new(LOCAL_DB).is_dir() {
        eprintln!("skipping: {LOCAL_DB} does not exist");
        return;
    }
    let root = match RootDir::open(Path::new("/")) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("skipping: cannot open /: {error}");
            return;
        }
    };
    let db = LocalDatabase::open(LOCAL_DB).unwrap();

    let (mut matched, mut edited, mut unreadable, mut absent, mut null_hash) =
        (0_usize, 0_usize, 0_usize, 0_usize, 0_usize);
    let mut edited_examples = Vec::new();

    for package in db.iter() {
        let Ok(backups) = package.backups() else { continue };
        for entry in backups {
            let recorded = entry.md5.to_string();
            // pacman writes a literal `(null)` when it could not hash the file. Those are
            // the entries that motivated `piko_db_write::Record`. There is nothing to
            // compare against.
            if recorded == "(null)" {
                null_hash += 1;
                continue;
            }

            let path = entry.path.inner();
            let Ok(resolved) = root.resolve_parent(path) else {
                unreadable += 1;
                continue;
            };
            match file_md5_at(resolved.dir(), resolved.name(), MAX_BACKUP_BYTES) {
                Ok(Some(computed)) => {
                    if computed.to_string() == recorded {
                        matched += 1;
                    } else {
                        edited += 1;
                        if edited_examples.len() < 5 {
                            edited_examples.push(format!(
                                "{} ({})",
                                path.display(),
                                package.name()
                            ));
                        }
                    }
                }
                // The user deleted the config file.
                Ok(None) => absent += 1,
                // Almost always a permission denial: this test runs unprivileged and many
                // backup files under /etc are root-only.
                Err(_) => unreadable += 1,
            }
        }
    }

    println!(
        "backup files: {matched} match the recorded hash, {edited} differ (user-edited), \
         {absent} deleted, {unreadable} unreadable, {null_hash} recorded as (null)"
    );
    for example in &edited_examples {
        println!("  differs: {example}");
    }

    assert!(
        matched > 0,
        "not one backup file matched its recorded hash; the digest disagrees with pacman's"
    );
    // An edited config file is legitimate. But if *most* readable files disagreed, the
    // implementation would be wrong, not the user unusually thorough.
    assert!(
        matched >= edited,
        "{edited} of {} readable backup files disagreed; that is too many to be user edits",
        matched + edited
    );
}
