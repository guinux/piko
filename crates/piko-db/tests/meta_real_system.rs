//! Differential tests of piko's metadata readers against the `alpm-*` parsers they replace.
//!
//! Every test here is `#[ignore]`d, because it reads this machine's databases. Run them
//! explicitly:
//!
//! ```text
//! cargo test -p piko-db --test meta_real_system -- --ignored --nocapture
//! ```
//!
//! Where the upstream parser accepts a file, piko must read the identical values. Where it
//! refuses one, piko must either read it or refuse it too, and the test prints which.

#![expect(
    clippy::panic,
    clippy::unwrap_used,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{path::Path, str::FromStr as _};

use alpm_common::MetadataFile as _;
use alpm_db::{desc::DbDescFile, files::DbFiles};
use piko_db::{LocalDatabase, meta::files};

const LOCAL_DB: &str = "/var/lib/pacman/local";

/// The text of every `<entry>/<name>` file in the local database.
fn local_texts(name: &str) -> Option<Vec<(String, String)>> {
    let root = Path::new(LOCAL_DB);
    if !root.is_dir() {
        eprintln!("skipping: {LOCAL_DB} does not exist");
        return None;
    }
    let mut texts = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().join(name);
        if path.is_file() {
            let text = std::fs::read_to_string(&path).unwrap();
            texts.push((entry.file_name().to_string_lossy().into_owned(), text));
        }
    }
    Some(texts)
}

/// Every local `files` file: piko reads the same paths and the same hashed backups as
/// `alpm-db`, plus the `(null)` entries `alpm-db` drops. A file `alpm-db` refuses for a path
/// listed twice or a missing parent, piko reads and names the defect.
#[test]
#[ignore = "requires a real ALPM local database"]
fn local_files_agree_with_alpm_db() {
    let Some(texts) = local_texts("files") else { return };
    let (mut agreed, mut nulls, mut upstream_refused) = (0_usize, 0_usize, 0_usize);

    for (entry, text) in &texts {
        let ours = files::parse(text).unwrap_or_else(|error| panic!("{entry}: {error}"));
        let Ok(theirs) = DbFiles::from_str(text) else {
            upstream_refused += 1;
            println!("{entry}: alpm-db refuses this file, piko reads it: {:?}", ours.defects());
            continue;
        };

        assert!(ours.defects().is_empty(), "{entry}: {:?}", ours.defects());
        let ours_paths: Vec<std::path::PathBuf> = ours.files().map(Into::into).collect();
        assert_eq!(ours_paths, AsRef::<[_]>::as_ref(&theirs), "{entry}: %FILES%");

        let hashed: Vec<_> = ours
            .backups()
            .iter()
            .filter_map(|backup| Some((backup.path.to_string(), backup.md5.as_ref()?.to_string())))
            .collect();
        let upstream: Vec<_> = theirs
            .backups()
            .iter()
            .map(|backup| (backup.path.to_string(), backup.md5.to_string()))
            .collect();
        assert_eq!(hashed, upstream, "{entry}: %BACKUP%");

        // Each path once, and a path with a hashed entry keeps that one.
        let null_paths: std::collections::BTreeSet<&str> = text
            .lines()
            .filter_map(|line| line.strip_suffix("\t(null)"))
            .filter(|path| !hashed.iter().any(|(hashed, _)| hashed == path))
            .collect();
        let null_entries = ours.backups().iter().filter(|backup| backup.md5.is_none()).count();
        assert_eq!(null_entries, null_paths.len(), "{entry}: every (null) path is kept once");
        nulls += null_entries;
        agreed += 1;
    }

    assert!(agreed > 100, "expected a populated database, found {agreed} entries");
    println!(
        "{agreed} files agree; {nulls} (null) backup entries kept; \
         {upstream_refused} refused by alpm-db only"
    );
}

/// `$body` with `$v` bound to either schema version of a `DbDescFile`.
macro_rules! either {
    ($desc:expr, |$v:ident| $body:expr) => {
        match $desc {
            DbDescFile::V1($v) => $body,
            DbDescFile::V2($v) => $body,
        }
    };
}

/// Renders each item, so two lists of different types compare.
fn strings<T: ToString>(items: &[T]) -> Vec<String> {
    items.iter().map(ToString::to_string).collect()
}

/// Every local `desc`: where `alpm-db` reads the file, piko reads every field to the same
/// value. Where `alpm-db` refuses it, piko reads it and names the fields it could not convert.
#[test]
#[ignore = "requires a real ALPM local database"]
fn local_desc_agrees_with_alpm_db() {
    let Some(texts) = local_texts("desc") else { return };
    let db = LocalDatabase::open(LOCAL_DB).unwrap();
    let (mut agreed, mut upstream_refused) = (0_usize, 0_usize);

    for (entry, text) in &texts {
        let package = db.iter().find(|package| package.entry().as_str() == entry).unwrap();
        let ours = package.desc().unwrap_or_else(|error| panic!("{entry}: {error}"));
        let Ok(theirs) = DbDescFile::from_str_with_schema(text, None) else {
            upstream_refused += 1;
            println!(
                "{entry}: alpm-db refuses this desc; piko reports {:?}",
                package
                    .check_consistency()
                    .unwrap()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
            continue;
        };

        either!(&theirs, |v| {
            assert_eq!(ours.name(), &v.name, "{entry}");
            assert_eq!(ours.version(), &v.version, "{entry}");
            assert_eq!(ours.base().unwrap(), &v.base, "{entry}");
            assert_eq!(ours.description(), v.description.as_ref(), "{entry}");
            assert_eq!(ours.architecture(), &v.arch, "{entry}");
            assert_eq!(ours.url(), v.url.as_ref(), "{entry}");
            assert_eq!(ours.packager(), Some(&v.packager), "{entry}");
            assert_eq!(ours.build_date().unwrap(), v.builddate, "{entry}");
            assert_eq!(ours.install_date().unwrap(), v.installdate, "{entry}");
            assert_eq!(ours.installed_size(), v.size, "{entry}");
            assert_eq!(ours.install_reason(), v.reason, "{entry}");
            assert_eq!(strings(ours.groups()), strings(&v.groups), "{entry}");
            assert_eq!(ours.licenses().unwrap(), v.license.as_slice(), "{entry}");
            assert_eq!(ours.validation().unwrap(), v.validation.as_slice(), "{entry}");
            assert_eq!(ours.replaces(), v.replaces.as_slice(), "{entry}");
            assert_eq!(ours.depends(), v.depends.as_slice(), "{entry}");
            assert_eq!(ours.optional_depends().unwrap(), v.optdepends.as_slice(), "{entry}");
            assert_eq!(ours.conflicts(), v.conflicts.as_slice(), "{entry}");
            assert_eq!(ours.provides(), v.provides.as_slice(), "{entry}");
        });
        match &theirs {
            DbDescFile::V1(_) => assert!(matches!(ours.xdata(), Ok(None)), "{entry}"),
            DbDescFile::V2(v) => assert_eq!(ours.xdata().unwrap(), Some(&v.xdata), "{entry}"),
        }
        assert!(package.check_consistency().unwrap().is_empty(), "{entry}");
        agreed += 1;
    }

    assert!(agreed > 100, "expected a populated database, found {agreed} entries");
    println!("{agreed} desc files agree; {upstream_refused} refused by alpm-db only");
}
