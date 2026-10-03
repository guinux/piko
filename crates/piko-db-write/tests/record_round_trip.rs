//! A `files` record piko writes is read back by piko's reader to the same paths and backups.
//!
//! The writer and the reader are two crates, so this test is the one place that holds them to
//! one format. A record the reader refused, or read differently, would make an installed
//! package unmanageable.

#![expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]

use std::collections::BTreeSet;

use piko_db_write::{Record, RecordKind};
use proptest::prelude::*;

/// A tree of paths as pacman lists it: every directory with a trailing `/`, and every parent
/// listed. Each item is a path of one to four segments, and a flag for a file at its end.
fn tree() -> impl Strategy<Value = (Vec<String>, Vec<String>)> {
    let segment = "[a-zA-Z0-9._+-]{1,8}".prop_filter("not . or ..", |s| s != "." && s != "..");
    let path = (prop::collection::vec(segment, 1..5), any::<bool>());
    prop::collection::vec(path, 0..24).prop_map(|items| {
        let mut directories = BTreeSet::new();
        let mut files = BTreeSet::new();
        for (segments, is_file) in items {
            let (last, parents) = segments.split_last().unwrap();
            let mut prefix = String::new();
            for parent in parents {
                prefix.push_str(parent);
                prefix.push('/');
                directories.insert(prefix.clone());
            }
            if is_file {
                files.insert(format!("{prefix}{last}"));
            } else {
                directories.insert(format!("{prefix}{last}/"));
            }
        }
        // A name used as both a file and a directory is one path twice. Keep the directory.
        files.retain(|file| !directories.contains(&format!("{file}/")));
        let backups = files.iter().take(3).cloned().collect();
        (directories.into_iter().chain(files).collect(), backups)
    })
}

proptest! {
    #[test]
    fn a_written_files_record_reads_back((paths, backups) in tree(), null in any::<bool>()) {
        let hash = if null { "(null)" } else { "d41d8cd98f00b204e9800998ecf8427e" };
        let mut record = Record::new(RecordKind::Files);
        record.set("FILES", paths.clone()).unwrap();
        record.set("BACKUP", backups.iter().map(|path| format!("{path}\t{hash}")).collect()).unwrap();

        let read = piko_db::meta::files::parse(&record.render()).unwrap();

        let read_paths: BTreeSet<String> =
            read.files().map(str::to_owned).collect();
        prop_assert_eq!(read_paths, paths.into_iter().collect::<BTreeSet<_>>());
        // The reader sorts by path component, the writer keeps the order it is given.
        let read_backups: BTreeSet<String> =
            read.backups().iter().map(|backup| backup.path.to_string()).collect();
        prop_assert_eq!(read_backups, backups.into_iter().collect::<BTreeSet<_>>());
        prop_assert!(read.backups().iter().all(|backup| backup.md5.is_none() == null));
    }
}
