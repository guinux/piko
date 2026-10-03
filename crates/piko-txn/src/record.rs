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

use alpm_types::{PackageInstallReason, PackageValidation};
use piko_db_write::{Record, RecordError, RecordKind};

use crate::{
    install::Extraction,
    pkginfo::{PkgInfo, Shown},
};

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
/// A shown field is written from its [`Shown::values`](crate::pkginfo::Shown::values): the typed rendering when it converts,
/// the value as written otherwise, as libalpm writes every field. `%URL%` and `%PACKAGER%` are
/// always written as the package file holds them. `url::Url` would normalize the first,
/// `https://archlinux.org` becoming `https://archlinux.org/`, measured at 11 of 120 real
/// packages. A shown field the package does not carry is not written.
///
/// An empty value is not a defect: makepkg writes `url = ` for a `PKGBUILD` with no `url`. An
/// empty scalar is written as a section with no value line ([`Record::set_empty`]), which
/// libalpm and `piko_db` read back as an empty value. An empty value in a shown list is left
/// out: libalpm writes it as an empty line, which ends the section and reads back as no value.
///
/// # Errors
///
/// [`RecordError`] if a value cannot be written as one value line: a group named `%REASON%`,
/// say. [`check`] asks the same question before anything is extracted.
pub fn desc(info: &PkgInfo, facts: &InstallFacts) -> Result<Record, RecordError> {
    let mut record = Record::new(RecordKind::Desc);
    let mut one = |key: &str, value: Option<&str>| match value {
        Some("") => record.set_empty(key),
        Some(value) => record.set(key, vec![value.to_owned()]),
        None => Ok(()),
    };

    one("NAME", Some(info.name.as_ref()))?;
    one("VERSION", Some(&info.version.to_string()))?;
    one("BASE", info.base.first())?;
    one("DESC", info.description.first())?;
    one("URL", info.url.first())?;
    one("ARCH", Some(&info.architecture.to_string()))?;
    one("BUILDDATE", info.build_date.first())?;
    one("PACKAGER", info.packager.first())?;
    if info.size != 0 {
        one("SIZE", Some(&info.size.to_string()))?;
    }
    record.set("GROUPS", strings(&info.groups))?;
    record.set("LICENSE", not_empty(&info.licenses))?;
    record.set("REPLACES", strings(&info.replaces))?;
    record.set("DEPENDS", strings(&info.depends))?;
    record.set("OPTDEPENDS", not_empty(&info.optional_depends))?;
    record.set("CONFLICTS", strings(&info.conflicts))?;
    record.set("PROVIDES", strings(&info.provides))?;
    record.set("XDATA", not_empty(&info.xdata))?;

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
    info: &PkgInfo,
    paths: impl Iterator<Item = &'a str>,
    backups: impl Iterator<Item = &'a str>,
) -> Result<(), RecordError> {
    let facts = InstallFacts {
        install_date: 0,
        reason: PackageInstallReason::Depend,
        validation: vec![PackageValidation::None],
    };
    desc(info, &facts)?;
    let backups = backups.map(|path| format!("{path}\t(null)")).collect();
    files_record(paths.map(str::to_owned).collect(), backups)?;
    Ok(())
}

/// The values of a shown list, without the empty ones.
fn not_empty(shown: &Shown) -> Vec<String> {
    shown.values.iter().filter(|value| !value.is_empty()).cloned().collect()
}

/// Renders a list of values as the strings a section holds.
fn strings<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use std::path::PathBuf;

    use alpm_types::Md5Checksum;

    use super::*;

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

    fn info() -> PkgInfo {
        crate::pkginfo::parse(PKGINFO).unwrap()
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
        let record = desc(&info(), &facts()).unwrap();
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
        let record = desc(&info(), &facts()).unwrap();
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
        let record = desc(&crate::pkginfo::parse(&raw).unwrap(), &facts()).unwrap();

        assert_eq!(
            record.get("PACKAGER").unwrap(),
            [piko_db::desc_compat::UNKNOWN_PACKAGER.to_owned()]
        );
    }

    /// An explicit install writes no `%REASON%`, matching a freshly installed package.
    #[test]
    fn an_explicit_install_omits_the_reason() {
        assert!(desc(&info(), &facts()).unwrap().get("REASON").is_none());

        let as_dependency = InstallFacts { reason: PackageInstallReason::Depend, ..facts() };
        let record = desc(&info(), &as_dependency).unwrap();
        assert_eq!(record.get("REASON").unwrap(), ["1".to_owned()]);
    }

    /// `%REASON%` must land between `%SIZE%` and `%GROUPS%`, not wherever it was set.
    #[test]
    fn the_reason_lands_in_its_canonical_position() {
        let as_dependency = InstallFacts { reason: PackageInstallReason::Depend, ..facts() };
        let record = desc(&info(), &as_dependency).unwrap();
        let order: Vec<&str> = record.sections().iter().map(|s| s.keyword()).collect();
        let size = order.iter().position(|k| *k == "SIZE").unwrap();
        let reason = order.iter().position(|k| *k == "REASON").unwrap();
        let license = order.iter().position(|k| *k == "LICENSE").unwrap();
        assert!(size < reason && reason < license, "{order:?}");
    }

    /// An empty section is not written at all; libalpm never emits one.
    #[test]
    fn empty_sections_are_omitted() {
        let record = desc(&info(), &facts()).unwrap();
        assert!(record.get("GROUPS").is_none());
        assert!(record.get("CONFLICTS").is_none());
        assert!(record.get("REPLACES").is_none());
    }

    /// makepkg writes `url = ` and `pkgdesc = ` for a `PKGBUILD` without them. The package is
    /// installable, and its entry reads back with an empty value, as pacman's does.
    #[test]
    fn an_empty_shown_value_is_written_as_an_empty_section() {
        let raw = PKGINFO
            .replace("pkgdesc = An example package", "pkgdesc = ")
            .replace("url = https://example.org/", "url = ")
            .replace("license = MIT", "license = \nlicense = MIT");
        let info = crate::pkginfo::parse(&raw).unwrap();
        check(&info, std::iter::empty(), std::iter::empty()).unwrap();
        let rendered = desc(&info, &facts()).unwrap().render();

        assert!(rendered.contains("%DESC%\n\n%URL%\n\n%ARCH%\n"), "{rendered}");
        assert!(rendered.contains("%LICENSE%\nMIT\n\n"), "{rendered}");

        let db = piko_db::fixture::DbFixture::new();
        db.package("foo-1.0.0-1").desc(&rendered).files(piko_db::fixture::MINIMAL_FILES).build();
        let local = piko_db::LocalDatabase::open(db.path()).unwrap();
        let package = local.get_str("foo").unwrap();
        let read = package.desc().unwrap();
        assert_eq!(read.description(), "");
        assert!(read.url().is_none());
        assert_eq!(read.licenses().unwrap().len(), 1);
    }

    /// A shown key the package does not carry is named at install exactly when the entry
    /// written without it reads back with a defect. This ties `PkgInfo::problems` to the local
    /// `desc` reader: a key added to or removed from either side alone fails here.
    #[test]
    fn a_missing_key_is_named_when_the_entry_reads_back_incomplete() {
        for key in ["pkgbase", "pkgdesc", "url", "builddate", "packager", "license"] {
            let raw: String = PKGINFO
                .lines()
                .filter(|line| !line.starts_with(&format!("{key} = ")))
                .map(|line| format!("{line}\n"))
                .collect();
            assert_ne!(raw, PKGINFO, "{key} is in the fixture");
            let info = crate::pkginfo::parse(&raw).unwrap();
            let named = info
                .problems()
                .iter()
                .any(|problem| matches!(problem, crate::pkginfo::Problem::MissingKey { key: found } if *found == key));

            let rendered = desc(&info, &facts()).unwrap().render();
            let db = piko_db::fixture::DbFixture::new();
            db.package("foo-1.0.0-1")
                .desc(&rendered)
                .files(piko_db::fixture::MINIMAL_FILES)
                .build();
            let local = piko_db::LocalDatabase::open(db.path()).unwrap();
            let package = local.get_str("foo").unwrap();
            let defects = package.desc().unwrap().invalid_fields();

            assert_eq!(named, !defects.is_empty(), "{key}: {defects:?}");
        }
    }

    /// An empty value in a key that decides something still refuses the package.
    #[test]
    fn an_empty_group_is_refused() {
        let info = crate::pkginfo::parse(&format!("{PKGINFO}group = \n")).unwrap();
        assert!(check(&info, std::iter::empty(), std::iter::empty()).is_err());
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
        let record = desc(&info(), &facts()).unwrap();
        let text = record.render();
        assert_eq!(Record::parse(RecordKind::Desc, &text).unwrap().render(), text);

        let extraction =
            Extraction { owned: vec![PathBuf::from("usr/bin/foo")], ..Extraction::default() };
        let record = files(&extraction).unwrap();
        let text = record.render();
        assert_eq!(Record::parse(RecordKind::Files, &text).unwrap().render(), text);
    }
}
