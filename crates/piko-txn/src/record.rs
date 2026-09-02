//! Builds a local database entry from an installed package.
//!
//! The `desc` a package gets in `<dbpath>/local` is almost entirely a transcription of its
//! `.PKGINFO`, with four fields the *transaction* supplies rather than the package:
//! `%INSTALLDATE%`, `%REASON%`, `%VALIDATION%`, and a `%SIZE%` that libalpm takes from the
//! installed size rather than the compressed one.
//!
//! Field order is [`RecordKind::Desc`]'s, which is `_alpm_local_db_write`'s
//! (`be_local.c:997`). Building through [`Record::set`] rather than by concatenation keeps it
//! that way: `set` inserts a section at its canonical position, so a field added here in the
//! wrong place still lands in the right one.

use alpm_pkginfo::PackageInfo;
use alpm_types::{PackageInstallReason, PackageValidation};
use piko_db_write::{Record, RecordKind};

use crate::install::Extraction;

/// What the transaction knows that the package does not.
#[derive(Clone, Debug)]
pub struct InstallFacts {
    /// Seconds since the epoch, recorded as `%INSTALLDATE%`.
    pub install_date: i64,
    /// Whether the user asked for this package or a dependency pulled it in.
    pub reason: PackageInstallReason,
    /// How the package file was verified.
    ///
    /// Empty means the section is omitted. piko does not yet verify anything, so a caller that
    /// has not checked a signature should pass [`PackageValidation::None`] rather than claim a
    /// stronger one. The field records what was actually done.
    pub validation: Vec<PackageValidation>,
}

/// Builds the `desc` record for a newly installed package.
///
/// `%SIZE%` is the package's installed size from `.PKGINFO`, not the size of the archive:
/// libalpm's comment at `be_local.c:1026` is explicit that "csize is irrelevant once
/// installed".
///
/// # Why the raw `.PKGINFO` is needed as well as the parsed one
///
/// `%URL%` is copied from `raw` rather than from `info`. `alpm-pkginfo` parses the field into
/// a `url::Url`, which *normalises* it: `https://archlinux.org` becomes
/// `https://archlinux.org/`. libalpm copies the string through untouched. Building from the
/// parsed value writes a `desc` that differs from pacman's, measured at 11 of 120 real
/// packages.
#[must_use]
pub fn desc(info: &PackageInfo, raw: &str, facts: &InstallFacts) -> Record {
    let mut record = Record::new(RecordKind::Desc);
    let mut one = |key: &str, value: String| record.set(key, vec![value]);

    match info {
        PackageInfo::V1(v1) => {
            one("NAME", v1.pkgname.to_string());
            one("VERSION", v1.pkgver.to_string());
            one("BASE", v1.pkgbase.to_string());
            one("DESC", v1.pkgdesc.to_string());
            one("URL", raw_field(raw, "url").unwrap_or_else(|| v1.url.to_string()));
            one("ARCH", v1.arch.to_string());
            one("BUILDDATE", v1.builddate.to_string());
            one("PACKAGER", v1.packager.to_string());
            if v1.size.to_string() != "0" {
                one("SIZE", v1.size.to_string());
            }
            record.set("GROUPS", strings(&v1.group));
            record.set("LICENSE", strings(&v1.license));
            record.set("REPLACES", strings(&v1.replaces));
            record.set("DEPENDS", strings(&v1.depend));
            record.set("OPTDEPENDS", strings(&v1.optdepend));
            record.set("CONFLICTS", strings(&v1.conflict));
            record.set("PROVIDES", strings(&v1.provides));
        }
        PackageInfo::V2(v2) => {
            one("NAME", v2.pkgname.to_string());
            one("VERSION", v2.pkgver.to_string());
            one("BASE", v2.pkgbase.to_string());
            one("DESC", v2.pkgdesc.to_string());
            one("URL", raw_field(raw, "url").unwrap_or_else(|| v2.url.to_string()));
            one("ARCH", v2.arch.to_string());
            one("BUILDDATE", v2.builddate.to_string());
            one("PACKAGER", v2.packager.to_string());
            if v2.size.to_string() != "0" {
                one("SIZE", v2.size.to_string());
            }
            record.set("GROUPS", strings(&v2.group));
            record.set("LICENSE", strings(&v2.license));
            record.set("REPLACES", strings(&v2.replaces));
            record.set("DEPENDS", strings(&v2.depend));
            record.set("OPTDEPENDS", strings(&v2.optdepend));
            record.set("CONFLICTS", strings(&v2.conflict));
            record.set("PROVIDES", strings(&v2.provides));
            record.set("XDATA", v2.xdata.clone().into_iter().map(|e| e.to_string()).collect());
        }
    }

    record.set("INSTALLDATE", vec![facts.install_date.to_string()]);
    // `%REASON%` is omitted for an explicit install.
    if facts.reason != PackageInstallReason::Explicit {
        record.set("REASON", vec![facts.reason.to_string()]);
    }
    record.set("VALIDATION", strings(&facts.validation));

    record
}

/// Builds the `files` record from what the installation actually laid down.
///
/// This is deliberately driven by [`Extraction::owned`] rather than by the archive's member
/// list. A `NoExtract` path is not on this system, and a `files` entry claiming it would make
/// the package appear to own a file that a later removal would then fail to find.
#[must_use]
pub fn files(extraction: &Extraction) -> Record {
    let mut record = Record::new(RecordKind::Files);

    let paths: Vec<String> =
        extraction.owned.iter().map(|path| path.to_string_lossy().into_owned()).collect();
    record.set("FILES", paths);

    // pacman writes `<path>\t<md5>`. `write::Record` keeps the line verbatim, tab included,
    // because that is what makes a `(null)` hash survive a rewrite.
    let backups: Vec<String> = extraction
        .backup_hashes
        .iter()
        .map(|(path, hash)| format!("{}\t{hash}", path.to_string_lossy()))
        .collect();
    record.set("BACKUP", backups);

    record
}

/// The verbatim value of a `key = value` line in a `.PKGINFO`.
///
/// `.PKGINFO` is `key = value` per line with `#` comments; the separator is exactly `" = "`.
/// Only fields that must round-trip byte-for-byte are read this way. Everything else goes
/// through `alpm-pkginfo`, per principle 1.
fn raw_field(raw: &str, key: &str) -> Option<String> {
    raw.lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| line.split_once(" = ").filter(|(name, _)| *name == key))
        .map(|(_, value)| value.to_owned())
}

/// Renders a list of values as the strings a section holds.
fn strings<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::{path::PathBuf, str::FromStr as _};

    use alpm_types::Md5Checksum;

    use super::*;
    use crate::install::Extraction;

    const PKGINFO: &str = "\
pkgname = foo
pkgbase = foo
pkgver = 1.0.0-1
pkgdesc = An example package
url = https://example.org/
builddate = 1733737242
packager = Foobar McFooface <foobar@mcfooface.org>
size = 123
arch = x86_64
license = MIT
depend = bar
";

    fn info() -> PackageInfo {
        PackageInfo::from_str(PKGINFO).unwrap()
    }

    fn facts() -> InstallFacts {
        InstallFacts {
            install_date: 1_733_737_243,
            reason: PackageInstallReason::Explicit,
            validation: vec![PackageValidation::None],
        }
    }

    /// The order is `be_local.c`'s, and it is the whole reason `Record::set` exists.
    #[test]
    fn desc_sections_are_in_pacmans_order() {
        let record = desc(&info(), PKGINFO, &facts());
        let order: Vec<&str> = record.sections().iter().map(|s| s.keyword()).collect();
        assert_eq!(
            order,
            [
                "NAME",
                "VERSION",
                "BASE",
                "DESC",
                "URL",
                "ARCH",
                "BUILDDATE",
                "INSTALLDATE",
                "PACKAGER",
                "SIZE",
                "LICENSE",
                "VALIDATION",
                "DEPENDS"
            ]
        );
    }

    #[test]
    fn desc_transcribes_the_pkginfo() {
        let record = desc(&info(), PKGINFO, &facts());
        assert_eq!(record.get("NAME").unwrap(), ["foo".to_owned()]);
        assert_eq!(record.get("VERSION").unwrap(), ["1.0.0-1".to_owned()]);
        assert_eq!(record.get("SIZE").unwrap(), ["123".to_owned()]);
        assert_eq!(record.get("DEPENDS").unwrap(), ["bar".to_owned()]);
        assert_eq!(record.get("INSTALLDATE").unwrap(), ["1733737243".to_owned()]);
    }

    /// An explicit install writes no `%REASON%`, matching a freshly installed package.
    #[test]
    fn an_explicit_install_omits_the_reason() {
        assert!(desc(&info(), PKGINFO, &facts()).get("REASON").is_none());

        let as_dependency = InstallFacts { reason: PackageInstallReason::Depend, ..facts() };
        let record = desc(&info(), PKGINFO, &as_dependency);
        assert_eq!(record.get("REASON").unwrap(), ["1".to_owned()]);
    }

    /// `%REASON%` must land between `%SIZE%` and `%GROUPS%`, not wherever it was set.
    #[test]
    fn the_reason_lands_in_its_canonical_position() {
        let as_dependency = InstallFacts { reason: PackageInstallReason::Depend, ..facts() };
        let record = desc(&info(), PKGINFO, &as_dependency);
        let order: Vec<&str> = record.sections().iter().map(|s| s.keyword()).collect();
        let size = order.iter().position(|k| *k == "SIZE").unwrap();
        let reason = order.iter().position(|k| *k == "REASON").unwrap();
        let license = order.iter().position(|k| *k == "LICENSE").unwrap();
        assert!(size < reason && reason < license, "{order:?}");
    }

    /// An empty section is not written at all; libalpm never emits one.
    #[test]
    fn empty_sections_are_omitted() {
        let record = desc(&info(), PKGINFO, &facts());
        assert!(record.get("GROUPS").is_none());
        assert!(record.get("CONFLICTS").is_none());
        assert!(record.get("REPLACES").is_none());
    }

    #[test]
    fn files_lists_what_was_installed() {
        let extraction = Extraction {
            owned: vec![
                PathBuf::from("usr/"),
                PathBuf::from("usr/bin/"),
                PathBuf::from("usr/bin/foo"),
            ],
            ..Extraction::default()
        };
        let record = files(&extraction);

        assert_eq!(
            record.get("FILES").unwrap(),
            ["usr/".to_owned(), "usr/bin/".to_owned(), "usr/bin/foo".to_owned()]
        );
        assert!(record.get("BACKUP").is_none(), "no backups, no section");
    }

    #[test]
    fn files_records_backup_hashes_tab_separated() {
        let mut extraction =
            Extraction { owned: vec![PathBuf::from("etc/foo.conf")], ..Extraction::default() };
        extraction
            .backup_hashes
            .insert(PathBuf::from("etc/foo.conf"), Md5Checksum::calculate_from(b"x"));
        let record = files(&extraction);

        let backup = record.get("BACKUP").unwrap().first().unwrap().clone();
        assert_eq!(backup, format!("etc/foo.conf\t{}", Md5Checksum::calculate_from(b"x")));
        assert!(backup.contains('\t'), "pacman separates path and hash with a tab");
    }

    /// A round-trip through the writer's own parser. What is built must be re-readable.
    #[test]
    fn the_built_records_round_trip() {
        let record = desc(&info(), PKGINFO, &facts());
        let text = record.render();
        assert_eq!(Record::parse(RecordKind::Desc, &text).unwrap().render(), text);

        let extraction =
            Extraction { owned: vec![PathBuf::from("usr/bin/foo")], ..Extraction::default() };
        let record = files(&extraction);
        let text = record.render();
        assert_eq!(Record::parse(RecordKind::Files, &text).unwrap().render(), text);
    }
}
