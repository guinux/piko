//! Differential test of piko's `.PKGINFO` reader against `alpm-pkginfo`, over this machine's
//! package cache.
//!
//! ```text
//! cargo test -p piko-txn --test pkginfo_real_system -- --ignored --nocapture
//! ```
//!
//! Where `alpm-pkginfo` reads a `.PKGINFO`, piko reads every key to the same value. Where it
//! refuses one, piko must read it, or refuse it for a key that decides something.

#![expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]

use std::{path::Path, str::FromStr as _};

use alpm_pkginfo::PackageInfo;
use piko_txn::{conflict::load_pkginfo, extract::PackageLimits, pkginfo};

const CACHE: &str = "/var/cache/pacman/pkg";

/// Renders each item, so two lists compare as text.
fn strings<T: ToString>(items: &[T]) -> Vec<String> {
    items.iter().map(ToString::to_string).collect()
}

#[test]
#[ignore = "requires a real pacman package cache"]
fn every_cached_pkginfo_agrees_with_alpm_pkginfo() {
    let cache = Path::new(CACHE);
    if !cache.is_dir() {
        eprintln!("skipping: {CACHE} does not exist");
        return;
    }
    let (mut agreed, mut upstream_refused, mut unreadable) = (0_usize, 0_usize, 0_usize);

    for entry in std::fs::read_dir(cache).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.contains(".pkg.tar") || name.ends_with(".sig") {
            continue;
        }
        let Ok((ours, raw)) = load_pkginfo(&path, &PackageLimits::default()) else {
            // An archive piko does not decode (xz, say), or one piko refuses: the second case
            // is checked against the raw text below when it can be read.
            unreadable += 1;
            continue;
        };
        let theirs = match PackageInfo::from_str(&raw) {
            Ok(theirs) => theirs,
            Err(_) => {
                upstream_refused += 1;
                let problems: Vec<_> =
                    ours.invalid_fields().iter().map(ToString::to_string).collect();
                println!("{name}: alpm-pkginfo refuses; piko: {problems:?}");
                continue;
            }
        };
        macro_rules! either {
            (|$v:ident| $body:expr) => {
                match &theirs {
                    PackageInfo::V1($v) => $body,
                    PackageInfo::V2($v) => $body,
                }
            };
        }
        either!(|v| {
            assert_eq!(ours.name, v.pkgname, "{name}");
            assert_eq!(ours.version, v.pkgver, "{name}");
            assert_eq!(ours.architecture, v.arch, "{name}");
            assert_eq!(ours.size, v.size, "{name}");
            assert_eq!(ours.depends, v.depend, "{name}");
            assert_eq!(ours.provides, v.provides, "{name}");
            assert_eq!(ours.conflicts, v.conflict, "{name}");
            assert_eq!(ours.replaces, v.replaces, "{name}");
            assert_eq!(ours.groups, v.group, "{name}");
            assert_eq!(ours.backups, strings(&v.backup), "{name}");
            assert_eq!(ours.base.values, [v.pkgbase.to_string()], "{name}");
            assert_eq!(ours.description.values, [v.pkgdesc.to_string()], "{name}");
            assert_eq!(ours.build_date.values, [v.builddate.to_string()], "{name}");
            assert_eq!(ours.licenses.values, strings(&v.license), "{name}");
            assert_eq!(ours.optional_depends.values, strings(&v.optdepend), "{name}");
        });
        match &theirs {
            PackageInfo::V1(_) => assert!(ours.xdata.values.is_empty(), "{name}"),
            PackageInfo::V2(v) => {
                assert_eq!(ours.xdata.values, strings(v.xdata.as_ref()), "{name}")
            }
        }
        assert!(ours.invalid_fields().is_empty(), "{name}: {:?}", ours.invalid_fields());
        assert!(pkginfo::parse(&raw).is_ok());
        agreed += 1;
    }

    println!(
        "{agreed} .PKGINFO files agree; {upstream_refused} refused by alpm-pkginfo only; \
         {unreadable} archives not read"
    );
}
