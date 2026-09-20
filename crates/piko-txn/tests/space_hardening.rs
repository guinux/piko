//! Exercises the disk-space estimate's refusals and its fail-open paths against a real
//! filesystem, in a temporary directory.
//!
//! These are not `#[ignore]`d. Everything here runs inside a `tempfile::TempDir`, reads the
//! real mount table, and never touches a system path. Only the `statvfs` numbers come from the
//! machine, and the assertions hold whatever those numbers are.
//!
//! The two directions both matter. A check that never refuses protects nothing. A check that
//! refuses a transaction which would have fitted is worse. It stops a correct install, and
//! teaches the user to turn `CheckSpace` off.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::path::{Path, PathBuf};

use piko_txn::{
    Error, RootDir,
    space::{Install, MemberFootprint, Problem, check_install, mounts::MountTable},
};

/// Nothing is `NoExtract` unless a test says so.
fn extracts_everything(_: &Path) -> bool {
    false
}

fn footprint(entries: &[(&str, u64)]) -> Vec<MemberFootprint> {
    entries
        .iter()
        .map(|(path, size)| MemberFootprint { path: PathBuf::from(path), size: *size })
        .collect()
}

#[test]
fn a_transaction_that_fits_is_allowed_and_reports_nothing() {
    let root = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(root.path()).unwrap();
    let rootfs = RootDir::open(root.path()).unwrap();

    let members = footprint(&[("usr/bin/tiny", 4096), ("usr/share/doc/tiny/README", 100)]);
    let problems = check_install(
        MountTable::load().unwrap(),
        &canonical,
        &rootfs,
        &[],
        &[Install { footprint: &members, replaced: None }],
        &extracts_everything,
    )
    .expect("4 KiB must fit on the filesystem running this test");
    assert!(problems.is_empty(), "{problems:?}");
}

#[test]
fn a_transaction_larger_than_the_filesystem_is_refused_and_names_both_numbers() {
    let root = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(root.path()).unwrap();
    let rootfs = RootDir::open(root.path()).unwrap();

    // An exabyte. No filesystem this test can run on holds it, and the arithmetic stays well
    // inside `i64` at 4 KiB blocks.
    let members = footprint(&[("usr/lib/enormous", 1 << 60)]);
    let error = check_install(
        MountTable::load().unwrap(),
        &canonical,
        &rootfs,
        &[],
        &[Install { footprint: &members, replaced: None }],
        &extracts_everything,
    )
    .unwrap_err();

    match error {
        Error::DiskSpace { too_full, read_only } => {
            assert!(read_only.is_empty(), "a writable tempdir is not read only");
            let partition = too_full.first().expect("the refusal names the partition");
            assert!(
                canonical.starts_with(&partition.mount_point),
                "{} is not under {}",
                canonical.display(),
                partition.mount_point.display()
            );
            assert!(partition.blocks_needed > partition.blocks_free);
            assert!(partition.bytes_needed() > partition.bytes_free());
        }
        other => panic!("got {other}"),
    }
}

#[test]
fn a_no_extract_member_is_not_charged_for() {
    let root = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(root.path()).unwrap();
    let rootfs = RootDir::open(root.path()).unwrap();
    let members = footprint(&[("usr/lib/enormous", 1 << 60)]);

    // The same transaction that the previous test proves is refused. piko does not count what
    // its own extraction will decline to write, so declaring the one member `NoExtract` empties
    // the estimate.
    let problems = check_install(
        MountTable::load().unwrap(),
        &canonical,
        &rootfs,
        &[],
        &[Install { footprint: &members, replaced: None }],
        &|path| path == Path::new("usr/lib/enormous"),
    )
    .expect("a member that is never written cannot fill a partition");
    assert!(problems.is_empty(), "{problems:?}");
}

#[test]
fn a_removal_credits_back_what_is_really_on_disk() {
    let root = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(root.path()).unwrap();
    std::fs::create_dir_all(root.path().join("usr/lib")).unwrap();
    // One megabyte on disk, replaced by four kilobytes. The net delta is negative, and a
    // negative requirement must not wrap into a huge unsigned one.
    std::fs::write(root.path().join("usr/lib/old"), vec![0_u8; 1024 * 1024]).unwrap();
    let rootfs = RootDir::open(root.path()).unwrap();

    let members = footprint(&[("usr/lib/new", 4096)]);
    let old = vec![PathBuf::from("usr/lib/old")];
    let problems = check_install(
        MountTable::load().unwrap(),
        &canonical,
        &rootfs,
        &[&old],
        &[Install { footprint: &members, replaced: None }],
        &extracts_everything,
    )
    .expect("a transaction that shrinks the system always fits");
    assert!(problems.is_empty(), "{problems:?}");
}

#[test]
fn a_file_that_cannot_be_stated_is_reported_and_the_estimate_continues() {
    let root = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(root.path()).unwrap();
    let rootfs = RootDir::open(root.path()).unwrap();

    // `%FILES%` names a path that is not there. libalpm skips it with a warning; piko returns
    // the warning instead of logging it, and still produces an estimate.
    let missing = vec![PathBuf::from("usr/lib/vanished")];
    let members = footprint(&[("usr/bin/tiny", 4096)]);
    let problems = check_install(
        MountTable::load().unwrap(),
        &canonical,
        &rootfs,
        &[&missing],
        &[Install { footprint: &members, replaced: None }],
        &extracts_everything,
    )
    .expect("a missing file is not a reason to refuse the transaction");
    assert_eq!(problems, vec![Problem::FileUnreadable { path: PathBuf::from("usr/lib/vanished") }]);
}

#[test]
fn a_removal_path_reached_through_a_symlinked_component_is_reported_not_followed() {
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret"), vec![0_u8; 4096]).unwrap();

    let root = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(root.path()).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
    let rootfs = RootDir::open(root.path()).unwrap();

    // libalpm resolves this with a plain `lstat` on a concatenated path, and would measure the
    // file outside the root. piko descends component by component with `O_NOFOLLOW`, so the
    // symlinked component refuses and the path is reported instead of measured.
    let doomed = vec![PathBuf::from("escape/secret")];
    let members = footprint(&[("usr/bin/tiny", 4096)]);
    let problems = check_install(
        MountTable::load().unwrap(),
        &canonical,
        &rootfs,
        &[&doomed],
        &[Install { footprint: &members, replaced: None }],
        &extracts_everything,
    )
    .unwrap();
    assert_eq!(problems, vec![Problem::FileUnreadable { path: PathBuf::from("escape/secret") }]);
}

#[test]
fn a_directory_in_a_file_list_counts_as_nothing() {
    let root = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(root.path()).unwrap();
    std::fs::create_dir_all(root.path().join("usr/lib")).unwrap();
    let rootfs = RootDir::open(root.path()).unwrap();

    // Both spellings. `%FILES%` writes a directory with a trailing slash. A list that omits
    // it must reach the same answer through the entry's mode.
    let doomed = vec![PathBuf::from("usr/lib/"), PathBuf::from("usr/lib")];
    let members = footprint(&[("usr/bin/tiny", 4096)]);
    let problems = check_install(
        MountTable::load().unwrap(),
        &canonical,
        &rootfs,
        &[&doomed],
        &[Install { footprint: &members, replaced: None }],
        &extracts_everything,
    )
    .unwrap();
    assert!(problems.is_empty(), "a directory is neither charged nor a problem: {problems:?}");
}

#[test]
fn a_root_no_mount_point_covers_is_refused_by_name() {
    let root = tempfile::tempdir().unwrap();
    let rootfs = RootDir::open(root.path()).unwrap();

    // A table that describes some other system. libalpm resolves the root's mount point
    // first and fails when it finds none, for exactly this reason. An estimate against a
    // table that does not describe this filesystem is not an estimate.
    let elsewhere = MountTable::parse(b"device /nowhere/at/all ext4 rw 0 0\n");
    let error =
        check_install(elsewhere, Path::new("/tmp"), &rootfs, &[], &[], &extracts_everything)
            .unwrap_err();
    assert!(matches!(error, Error::MountTableUnreadable { .. }), "got {error}");
}
