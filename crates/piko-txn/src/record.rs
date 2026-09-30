//! Builds a local database entry from an installed package.
//!
//! The `desc` a package gets in `<dbpath>/local` is almost entirely a transcription of its
//! `.PKGINFO`. Four fields come from the *transaction* rather than the package:
//! `%INSTALLDATE%`, `%REASON%`, `%VALIDATION%` and `%SIZE%`. libalpm takes that last one from
//! the installed size rather than the compressed one.
//!
//! Field order is [`RecordKind::Desc`]'s, which is `_alpm_local_db_write`'s
//! (`be_local.c:997`). Building through [`Record::set`] rather than by concatenation keeps it
//! that way. `set` inserts a section at its canonical position. A field added here in the
//! wrong place still lands in the right one.

use alpm_pkginfo::PackageInfo;
use alpm_types::{PackageInstallReason, PackageValidation};
use piko_db_write::{Record, RecordError, RecordKind};

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
    /// Empty means the section is omitted. piko does not yet verify anything here. A caller
    /// that has not checked a signature should pass [`PackageValidation::None`] rather than
    /// claim a stronger one. The field records what was actually done.
    pub validation: Vec<PackageValidation>,
}

/// Builds the `desc` record for a newly installed package.
///
/// `%SIZE%` is the package's installed size from `.PKGINFO`, not the size of the archive.
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
///
/// `%PACKAGER%` is copied the same way, for a second reason on top of that one.
/// [`crate::pkginfo::parse`] substitutes makepkg's default packager before the typed parse. So
/// `info` holds a value the package file never carried.
///
/// # Errors
///
/// [`RecordError`] if a value cannot be written as one value line: a group named `%REASON%`,
/// say. [`check`] asks the same question before anything is extracted.
pub fn desc(info: &PackageInfo, raw: &str, facts: &InstallFacts) -> Result<Record, RecordError> {
    let mut record = Record::new(RecordKind::Desc);
    let mut one = |key: &str, value: String| record.set(key, vec![value]);

    crate::pkginfo::either_version!(info, |v| {
        one("NAME", v.pkgname.to_string())?;
        one("VERSION", v.pkgver.to_string())?;
        one("BASE", v.pkgbase.to_string())?;
        one("DESC", v.pkgdesc.to_string())?;
        one("URL", raw_field(raw, "url").unwrap_or_else(|| v.url.to_string()))?;
        one("ARCH", v.arch.to_string())?;
        one("BUILDDATE", v.builddate.to_string())?;
        one("PACKAGER", raw_field(raw, "packager").unwrap_or_else(|| v.packager.to_string()))?;
        if v.size.to_string() != "0" {
            one("SIZE", v.size.to_string())?;
        }
        record.set("GROUPS", strings(&v.group))?;
        record.set("LICENSE", strings(&v.license))?;
        record.set("REPLACES", strings(&v.replaces))?;
        record.set("DEPENDS", strings(&v.depend))?;
        record.set("OPTDEPENDS", strings(&v.optdepend))?;
        record.set("CONFLICTS", strings(&v.conflict))?;
        record.set("PROVIDES", strings(&v.provides))?;
    });
    if let PackageInfo::V2(v2) = info {
        record.set("XDATA", v2.xdata.clone().into_iter().map(|e| e.to_string()).collect())?;
    }

    record.set("INSTALLDATE", vec![facts.install_date.to_string()])?;
    // `%REASON%` is omitted for an explicit install.
    if facts.reason != PackageInstallReason::Explicit {
        record.set("REASON", vec![facts.reason.to_string()])?;
    }
    record.set("VALIDATION", strings(&facts.validation))?;

    Ok(record)
}

/// Builds the `files` record from what the installation actually laid down.
///
/// This is deliberately driven by [`Extraction::owned`] rather than by the archive's member
/// list. A `NoExtract` path is not on this system. A `files` entry claiming it would make the
/// package appear to own a file a later removal then fails to find.
///
/// # Errors
///
/// [`RecordError`] if a path cannot be written as one value line: a member name holding a
/// newline, say. [`check`] asks the same question before anything is extracted.
pub fn files(extraction: &Extraction) -> Result<Record, RecordError> {
    let paths = extraction.owned.iter().map(|path| path.to_string_lossy().into_owned());
    // pacman writes `<path>\t<md5>`. `write::Record` keeps the line verbatim, tab included,
    // because that is what makes a `(null)` hash survive a rewrite.
    let backups = extraction
        .backup_hashes
        .iter()
        .map(|(path, hash)| format!("{}\t{hash}", path.to_string_lossy()));
    files_record(paths.collect(), backups.collect())
}

/// The `files` record for `paths` and `backups`, each backup already spelled
/// `<path>\t<hash>`.
fn files_record(paths: Vec<String>, backups: Vec<String>) -> Result<Record, RecordError> {
    let mut record = Record::new(RecordKind::Files);
    record.set("FILES", paths)?;
    record.set("BACKUP", backups)?;
    Ok(record)
}

/// Refuses a package whose entry cannot be written, before anything of it is extracted.
///
/// The format has no escaping, so a value holding a line break, or reading as a `%KEYWORD%`
/// header, would change what the rest of the entry says. A package could then choose its own
/// install reason, or claim a file it never shipped, which a later removal deletes. `desc` and
/// `files` refuse such a value, but `install_step` builds them after the extraction. This asks
/// the same question at `verify`, from what the archive read already gave: the `.PKGINFO`,
/// every member path, and every declared backup.
///
/// The transaction's own facts and the backup hashes are left out: a number, a
/// [`PackageInstallReason`] and a hash always fit. So placeholders stand in for them, and the
/// member list stands in for the paths the extraction will lay down, which it contains.
///
/// # Errors
///
/// [`RecordError`] naming the first value that does not fit.
pub fn check<'a>(
    info: &PackageInfo,
    raw: &str,
    paths: impl Iterator<Item = &'a str>,
    backups: impl Iterator<Item = &'a str>,
) -> Result<(), RecordError> {
    let facts = InstallFacts {
        install_date: 0,
        reason: PackageInstallReason::Depend,
        validation: vec![PackageValidation::None],
    };
    desc(info, raw, &facts)?;
    let backups = backups.map(|path| format!("{path}\t(null)")).collect();
    files_record(paths.map(str::to_owned).collect(), backups)?;
    Ok(())
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
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
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
        let record = desc(&info(), PKGINFO, &facts()).unwrap();
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
        let record = desc(&info(), PKGINFO, &facts()).unwrap();
        assert_eq!(record.get("NAME").unwrap(), ["foo".to_owned()]);
        assert_eq!(record.get("VERSION").unwrap(), ["1.0.0-1".to_owned()]);
        assert_eq!(record.get("SIZE").unwrap(), ["123".to_owned()]);
        assert_eq!(record.get("DEPENDS").unwrap(), ["bar".to_owned()]);
        assert_eq!(record.get("INSTALLDATE").unwrap(), ["1733737243".to_owned()]);
    }

    /// The substitute [`crate::pkginfo::parse`] makes must never reach the database. pacman
    /// writes what the package file says, and so does this.
    #[test]
    fn the_packager_written_is_the_one_the_package_file_carries() {
        let raw = PKGINFO.replace(
            "Foobar McFooface <foobar@mcfooface.org>",
            piko_db::desc_compat::UNKNOWN_PACKAGER,
        );
        let record = desc(&crate::pkginfo::parse(&raw).unwrap(), &raw, &facts()).unwrap();

        assert_eq!(
            record.get("PACKAGER").unwrap(),
            [piko_db::desc_compat::UNKNOWN_PACKAGER.to_owned()]
        );
    }

    /// An explicit install writes no `%REASON%`, matching a freshly installed package.
    #[test]
    fn an_explicit_install_omits_the_reason() {
        assert!(desc(&info(), PKGINFO, &facts()).unwrap().get("REASON").is_none());

        let as_dependency = InstallFacts { reason: PackageInstallReason::Depend, ..facts() };
        let record = desc(&info(), PKGINFO, &as_dependency).unwrap();
        assert_eq!(record.get("REASON").unwrap(), ["1".to_owned()]);
    }

    /// `%REASON%` must land between `%SIZE%` and `%GROUPS%`, not wherever it was set.
    #[test]
    fn the_reason_lands_in_its_canonical_position() {
        let as_dependency = InstallFacts { reason: PackageInstallReason::Depend, ..facts() };
        let record = desc(&info(), PKGINFO, &as_dependency).unwrap();
        let order: Vec<&str> = record.sections().iter().map(|s| s.keyword()).collect();
        let size = order.iter().position(|k| *k == "SIZE").unwrap();
        let reason = order.iter().position(|k| *k == "REASON").unwrap();
        let license = order.iter().position(|k| *k == "LICENSE").unwrap();
        assert!(size < reason && reason < license, "{order:?}");
    }

    /// An empty section is not written at all; libalpm never emits one.
    #[test]
    fn empty_sections_are_omitted() {
        let record = desc(&info(), PKGINFO, &facts()).unwrap();
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
        let record = files(&extraction).unwrap();

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
        let record = files(&extraction).unwrap();

        let backup = record.get("BACKUP").unwrap().first().unwrap().clone();
        assert_eq!(backup, format!("etc/foo.conf\t{}", Md5Checksum::calculate_from(b"x")));
        assert!(backup.contains('\t'), "pacman separates path and hash with a tab");
    }

    /// A round-trip through the writer's own parser. What is built must be re-readable.
    #[test]
    fn the_built_records_round_trip() {
        let record = desc(&info(), PKGINFO, &facts()).unwrap();
        let text = record.render();
        assert_eq!(Record::parse(RecordKind::Desc, &text).unwrap().render(), text);

        let extraction =
            Extraction { owned: vec![PathBuf::from("usr/bin/foo")], ..Extraction::default() };
        let record = files(&extraction).unwrap();
        let text = record.render();
        assert_eq!(Record::parse(RecordKind::Files, &text).unwrap().render(), text);
    }
}
