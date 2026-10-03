//! A repository `desc` entry, read one field at a time.
//!
//! The relation sections, `%CSIZE%` and `%ISIZE%` come from the eager tier
//! (`super::eager`), which reads them for every package at open. This module reads the rest,
//! when something asks for [`super::RepoPackage::desc`].
//!
//! Six sections decide something, and refuse the entry when they are missing or invalid:
//! `%FILENAME%`, `%NAME%`, `%VERSION%`, `%ARCH%`, `%SHA256SUM%`, and `%PGPSIG%` when present.
//! An install downloads, checks and verifies a package by these. Every other section is shown
//! only. Each gets its own [`Result`], and an invalid value costs that field alone.

use alpm_types::{
    Architecture, Base64OpenPGPSignature, BuildDate, CompressedSize, FullVersion, Group,
    InstalledSize, License, Md5Checksum, Name, OptionalDependency, PackageBaseName,
    PackageDescription, PackageFileName, PackageRelation, Packager, RelationOrSoname,
    Sha256Checksum, Url,
};

use super::eager::EagerFields;
use crate::{
    desc_compat::UnknownSection,
    eager::DescFieldError,
    meta::{
        desc::{Index, PackagerField, UrlField, number, typed},
        section::Sections,
    },
};

/// Every section of the repository `desc` format, from the `alpm-repo-descv1` and
/// `alpm-repo-descv2` specifications.
pub(crate) const KNOWN_SECTIONS: &[&str] = &[
    "FILENAME",
    "NAME",
    "BASE",
    "VERSION",
    "DESC",
    "GROUPS",
    "CSIZE",
    "ISIZE",
    "MD5SUM",
    "SHA256SUM",
    "PGPSIG",
    "URL",
    "LICENSE",
    "ARCH",
    "BUILDDATE",
    "PACKAGER",
    "REPLACES",
    "CONFLICTS",
    "PROVIDES",
    "DEPENDS",
    "OPTDEPENDS",
    "MAKEDEPENDS",
    "CHECKDEPENDS",
];

/// The fields of a repository `desc` that the eager tier does not read.
#[derive(Debug)]
pub(crate) struct RepoDesc {
    file_name: PackageFileName,
    name: Name,
    version: FullVersion,
    architecture: Architecture,
    sha256: Sha256Checksum,
    pgp_signature: Option<Base64OpenPGPSignature>,
    base: Result<PackageBaseName, DescFieldError>,
    description: Result<PackageDescription, DescFieldError>,
    url: UrlField,
    packager: PackagerField,
    build_date: Result<BuildDate, DescFieldError>,
    licenses: Result<Box<[License]>, DescFieldError>,
    optional_depends: Result<Box<[OptionalDependency]>, DescFieldError>,
    make_depends: Result<Box<[PackageRelation]>, DescFieldError>,
    check_depends: Result<Box<[PackageRelation]>, DescFieldError>,
    md5: Result<Option<Md5Checksum>, DescFieldError>,
}

impl RepoDesc {
    /// Reads `text`, returning the fields and the sections this build does not know.
    ///
    /// # Errors
    ///
    /// A [`DescFieldError`] when a section that decides something is missing or invalid. No
    /// other section can refuse the entry.
    pub(crate) fn parse(text: &str) -> Result<(Self, Vec<UnknownSection>), DescFieldError> {
        let index = Index::new(text, KNOWN_SECTIONS);
        let pgp_signature = match index.scalar("PGPSIG")? {
            Some(value) => Some(typed("PGPSIG")(value)?),
            None => None,
        };
        let md5 = match index.scalar("MD5SUM") {
            Ok(Some(value)) => typed("MD5SUM")(value).map(Some),
            Ok(None) => Ok(None),
            Err(error) => Err(error),
        };

        let desc = Self {
            file_name: index.required("FILENAME", typed("FILENAME"))?,
            name: index.required("NAME", typed("NAME"))?,
            version: index.required("VERSION", typed("VERSION"))?,
            architecture: index.required("ARCH", typed("ARCH"))?,
            sha256: index.required("SHA256SUM", typed("SHA256SUM"))?,
            pgp_signature,
            base: index.required("BASE", typed("BASE")),
            description: index.required("DESC", |value| Ok(PackageDescription::from(value))),
            url: UrlField::read(&index),
            packager: PackagerField::read(&index),
            build_date: index.required("BUILDDATE", number("BUILDDATE")),
            licenses: index.list("LICENSE", typed("LICENSE")),
            optional_depends: index.list("OPTDEPENDS", typed("OPTDEPENDS")),
            make_depends: index.list("MAKEDEPENDS", typed("MAKEDEPENDS")),
            check_depends: index.list("CHECKDEPENDS", typed("CHECKDEPENDS")),
            md5,
        };
        Ok((desc, index.unknown))
    }

    /// Every field that did not convert, as a sentence naming the section.
    pub(crate) fn invalid_fields(&self) -> Vec<String> {
        let errors = [
            self.base.as_ref().err(),
            self.description.as_ref().err(),
            self.url.error(),
            self.packager.error(),
            self.build_date.as_ref().err(),
            self.licenses.as_ref().err(),
            self.optional_depends.as_ref().err(),
            self.make_depends.as_ref().err(),
            self.check_depends.as_ref().err(),
            self.md5.as_ref().err(),
        ];
        errors.into_iter().flatten().map(ToString::to_string).collect()
    }
}

/// Read-only access to a repository `desc` entry.
///
/// Obtained from [`crate::repo::RepoPackage::desc`].
#[derive(Clone, Copy, Debug)]
pub struct RepoDescView<'a> {
    desc: &'a RepoDesc,
    eager: &'a EagerFields,
    depends: &'a [RelationOrSoname],
    text: &'a str,
}

impl<'a> RepoDescView<'a> {
    /// Wraps the parsed fields, the eager tier and the converted `%DEPENDS%` of one entry.
    pub(crate) const fn new(
        desc: &'a RepoDesc,
        eager: &'a EagerFields,
        depends: &'a [RelationOrSoname],
        text: &'a str,
    ) -> Self {
        Self { desc, eager, depends, text }
    }

    /// Whether this `desc` uses the v2 schema, which drops `%MD5SUM%`.
    #[must_use]
    pub const fn is_v2(&self) -> bool {
        matches!(self.desc.md5, Ok(None))
    }

    /// `%FILENAME%`, the package file's name on the repository server.
    #[must_use]
    pub const fn file_name(&self) -> &'a PackageFileName {
        &self.desc.file_name
    }

    /// `%NAME%`.
    #[must_use]
    pub const fn name(&self) -> &'a Name {
        &self.desc.name
    }

    /// `%VERSION%`.
    #[must_use]
    pub const fn version(&self) -> &'a FullVersion {
        &self.desc.version
    }

    /// `%ARCH%`, the architecture the package was built for.
    #[must_use]
    pub const fn architecture(&self) -> &'a Architecture {
        &self.desc.architecture
    }

    /// `%SHA256SUM%`.
    #[must_use]
    pub const fn sha256_checksum(&self) -> &'a Sha256Checksum {
        &self.desc.sha256
    }

    /// `%PGPSIG%`, the package file's detached OpenPGP signature, or `None` when the entry
    /// publishes none.
    #[must_use]
    pub const fn pgp_signature(&self) -> Option<&'a Base64OpenPGPSignature> {
        self.desc.pgp_signature.as_ref()
    }

    /// `%BASE%`, the name of the package base this package was built from.
    ///
    /// # Errors
    ///
    /// If the section is missing, repeated, or holds an invalid name.
    pub const fn base(&self) -> Result<&'a PackageBaseName, &'a DescFieldError> {
        self.desc.base.as_ref()
    }

    /// `%DESC%`, the one-line package description, empty when the section is unusable.
    #[must_use]
    pub fn description(&self) -> &'a str {
        self.desc.description.as_ref().map_or("", AsRef::as_ref)
    }

    /// `%URL%`, the upstream project URL, normalized by `url::Url`.
    ///
    /// `None` when the section is absent, empty, or holds a value `url::Url` refuses.
    /// [`RepoDescView::url_raw`] still has such a value.
    #[must_use]
    pub const fn url(&self) -> Option<&'a Url> {
        self.desc.url.parsed()
    }

    /// `%URL%` exactly as the `desc` holds it, which is what libalpm reports.
    #[must_use]
    pub fn url_raw(&self) -> Option<&'a str> {
        self.desc.url.raw()
    }

    /// `%PACKAGER%`, the identity that built the package.
    ///
    /// `None` when the value is not a valid packager, as makepkg's
    /// [`UNKNOWN_PACKAGER`](crate::desc_compat::UNKNOWN_PACKAGER) default is not: it carries no
    /// email address. [`RepoDescView::packager_raw`] still has such a value.
    #[must_use]
    pub const fn packager(&self) -> Option<&'a Packager> {
        self.desc.packager.parsed()
    }

    /// `%PACKAGER%` exactly as the `desc` holds it, which is what libalpm reports.
    #[must_use]
    pub fn packager_raw(&self) -> Option<&'a str> {
        self.desc.packager.raw()
    }

    /// `%BUILDDATE%`, as a Unix timestamp.
    ///
    /// # Errors
    ///
    /// If the section is missing, repeated, or not a decimal integer.
    pub const fn build_date(&self) -> Result<BuildDate, &'a DescFieldError> {
        match &self.desc.build_date {
            Ok(date) => Ok(*date),
            Err(error) => Err(error),
        }
    }

    /// `%LICENSE%`.
    ///
    /// # Errors
    ///
    /// If an entry is not a valid license expression.
    pub fn licenses(&self) -> Result<&'a [License], &'a DescFieldError> {
        self.desc.licenses.as_deref()
    }

    /// `%OPTDEPENDS%`.
    ///
    /// # Errors
    ///
    /// If an entry is not a valid optional dependency.
    pub fn optional_depends(&self) -> Result<&'a [OptionalDependency], &'a DescFieldError> {
        self.desc.optional_depends.as_deref()
    }

    /// `%MAKEDEPENDS%`.
    ///
    /// # Errors
    ///
    /// If an entry is not a valid package relation.
    pub fn make_depends(&self) -> Result<&'a [PackageRelation], &'a DescFieldError> {
        self.desc.make_depends.as_deref()
    }

    /// `%CHECKDEPENDS%`.
    ///
    /// # Errors
    ///
    /// If an entry is not a valid package relation.
    pub fn check_depends(&self) -> Result<&'a [PackageRelation], &'a DescFieldError> {
        self.desc.check_depends.as_deref()
    }

    /// `%MD5SUM%`. `Ok(None)` for a v2 `desc`, which drops this section.
    ///
    /// # Errors
    ///
    /// If the section is repeated or not an MD5 hash.
    pub const fn md5_checksum(&self) -> Result<Option<&'a Md5Checksum>, &'a DescFieldError> {
        match &self.desc.md5 {
            Ok(md5) => Ok(md5.as_ref()),
            Err(error) => Err(error),
        }
    }

    /// Every shown field whose value did not convert, as a sentence naming the section.
    ///
    /// The repository counterpart of `LocalPackage::check_consistency`'s
    /// `Inconsistency::InvalidField`. makepkg's `Unknown Packager` is not one.
    #[must_use]
    pub fn invalid_fields(&self) -> Vec<String> {
        self.desc.invalid_fields()
    }

    /// The value lines of every section named `keyword`, exactly as the `desc` holds them.
    ///
    /// This is what libalpm reports for a field. A frontend shows it when the typed form of a
    /// field is an error.
    #[must_use]
    pub fn section_values(&self, keyword: &str) -> Vec<&'a str> {
        Sections::new(self.text)
            .filter(|section| section.keyword == keyword)
            .flat_map(|section| section.values())
            .collect()
    }

    /// `%GROUPS%`.
    #[must_use]
    pub fn groups(&self) -> &'a [Group] {
        self.eager.groups()
    }

    /// `%DEPENDS%`, the run-time dependencies.
    #[must_use]
    pub const fn depends(&self) -> &'a [RelationOrSoname] {
        self.depends
    }

    /// `%PROVIDES%`.
    #[must_use]
    pub fn provides(&self) -> &'a [RelationOrSoname] {
        self.eager.provides()
    }

    /// `%CONFLICTS%`.
    #[must_use]
    pub fn conflicts(&self) -> &'a [PackageRelation] {
        self.eager.conflicts()
    }

    /// `%REPLACES%`.
    #[must_use]
    pub fn replaces(&self) -> &'a [PackageRelation] {
        self.eager.replaces()
    }

    /// `%CSIZE%`, the compressed package file's size in bytes.
    #[must_use]
    pub const fn compressed_size(&self) -> CompressedSize {
        self.eager.compressed_size
    }

    /// `%ISIZE%`, the installed size in bytes.
    #[must_use]
    pub const fn installed_size(&self) -> InstalledSize {
        self.eager.installed_size
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;
    use crate::desc_compat::UNKNOWN_PACKAGER;

    /// The `%PACKAGER%` [`DESC_V1`] carries.
    const FOOFACE: &str = "Foobar McFooface <foobar@mcfooface.org>";

    /// A real-shaped v1 `desc`, close to the `acl` entry of `core.db`. It has every mandatory
    /// v1 field, `%MD5SUM%` included.
    const DESC_V1: &str = "\
%FILENAME%
foo-1.0.0-1-x86_64.pkg.tar.zst

%NAME%
foo

%BASE%
foo

%VERSION%
1.0.0-1

%DESC%
An example package

%CSIZE%
1234

%ISIZE%
5678

%MD5SUM%
d41d8cd98f00b204e9800998ecf8427e

%SHA256SUM%
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

%PGPSIG%
iHUEABYKAB0WIQQEKYl95fO9rFN6MGltQr3RFuAGjwUCakJwmAAKCRBtQr3RFuAGj1vHAP0bsAdCvP2Xjp37sEjXaYxsWZ6GDZp1T76l5QRlrymcVAEAoQXhPlmjPC/ZJMVtJWbaKU4URbvliSVsc6A3n32JcgY=

%URL%
https://example.org/

%LICENSE%
MIT

%ARCH%
x86_64

%BUILDDATE%
1733737242

%PACKAGER%
Foobar McFooface <foobar@mcfooface.org>

";

    fn parse(text: &str) -> RepoDesc {
        RepoDesc::parse(text).unwrap().0
    }

    #[test]
    fn reads_every_field_of_a_v1_desc() {
        let desc = parse(DESC_V1);

        assert_eq!(desc.file_name.to_string(), "foo-1.0.0-1-x86_64.pkg.tar.zst");
        assert_eq!(desc.name.as_ref(), "foo");
        assert_eq!(desc.version.to_string(), "1.0.0-1");
        assert_eq!(desc.architecture.to_string(), "x86_64");
        assert!(desc.pgp_signature.is_some());
        assert!(matches!(desc.md5, Ok(Some(_))), "a v1 desc has %MD5SUM%");
        assert_eq!(desc.base.as_ref().unwrap().as_ref(), "foo");
        assert_eq!(*desc.build_date.as_ref().unwrap(), 1_733_737_242);
        assert_eq!(desc.packager.raw(), Some(FOOFACE));
        assert!(desc.invalid_fields().is_empty(), "{:?}", desc.invalid_fields());
    }

    /// A v2 `desc` drops `%MD5SUM%`, and may drop `%PGPSIG%`.
    #[test]
    fn reads_a_v2_desc() {
        let text = DESC_V1
            .replace("%MD5SUM%\nd41d8cd98f00b204e9800998ecf8427e\n\n", "")
            .lines()
            .filter(|line| !line.starts_with("%PGPSIG%") && !line.starts_with("iHUE"))
            .collect::<Vec<_>>()
            .join("\n");
        let desc = parse(&text);

        assert!(matches!(desc.md5, Ok(None)));
        assert!(desc.pgp_signature.is_none());
    }

    #[test]
    fn makepkgs_default_packager_keeps_its_bytes_and_is_not_reported() {
        let desc = parse(&DESC_V1.replace(FOOFACE, UNKNOWN_PACKAGER));
        assert!(desc.packager.parsed().is_none());
        assert_eq!(desc.packager.raw(), Some(UNKNOWN_PACKAGER));
        assert!(desc.invalid_fields().is_empty());
    }

    /// An invalid shown field costs that field alone. The entry still names the file an
    /// install downloads.
    #[test]
    fn an_invalid_shown_field_costs_only_itself() {
        let text = DESC_V1
            .replace("%BUILDDATE%\n1733737242", "%BUILDDATE%\nyesterday")
            .replace("https://example.org/", "www.example.org");
        let desc = parse(&text);

        assert!(desc.build_date.is_err());
        assert!(desc.url.parsed().is_none());
        assert_eq!(desc.url.raw(), Some("www.example.org"));
        assert_eq!(desc.file_name.to_string(), "foo-1.0.0-1-x86_64.pkg.tar.zst");
        assert_eq!(desc.invalid_fields().len(), 1, "{:?}", desc.invalid_fields());
    }

    /// The sections an install downloads, checks and verifies by refuse the entry.
    #[test]
    fn a_missing_or_invalid_deciding_field_refuses_the_entry() {
        let checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        for (from, to) in [
            ("%FILENAME%\nfoo-1.0.0-1-x86_64.pkg.tar.zst", "%FILENAME%\nfoo"),
            (checksum, "not-a-checksum"),
            ("%PGPSIG%\niHUE", "%PGPSIG%\n!!!"),
            ("%ARCH%\nx86_64", "%ARCH%\nx86_64\n\n%ARCH%\nany"),
            ("%NAME%\nfoo", "%NAME%\n-bad-"),
        ] {
            let text = DESC_V1.replace(from, to);
            assert!(RepoDesc::parse(&text).is_err(), "{to:?}");
        }
    }

    /// Every `desc` of every `.db` archive on this machine: where `alpm-repo-db` reads the
    /// entry, piko reads every field to the same value. The archive reader is private to this
    /// crate, so this test lives here rather than in `tests/meta_real_system.rs`.
    #[test]
    #[ignore = "requires this machine's real /var/lib/pacman/sync"]
    fn every_real_desc_agrees_with_alpm_repo_db() {
        use std::{path::Path, str::FromStr as _};

        use alpm_repo_db::desc::RepoDescFile;

        use crate::repo::archive::{self, ArchiveItem};

        macro_rules! either {
            ($desc:expr, |$v:ident| $body:expr) => {
                match $desc {
                    RepoDescFile::V1($v) => $body,
                    RepoDescFile::V2($v) => $body,
                }
            };
        }

        let sync = Path::new("/var/lib/pacman/sync");
        if !sync.is_dir() {
            println!("skipping: {} not present", sync.display());
            return;
        }
        let (mut agreed, mut upstream_refused) = (0_usize, 0_usize);

        for entry in std::fs::read_dir(sync).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|ext| ext != "db") {
                continue;
            }
            archive::walk(
                &path,
                &crate::limits::Limits::default(),
                |item| {
                    let ArchiveItem::Desc { entry, text } = item else { return Ok(()) };
                    let name = entry.as_str();
                    let (ours, unknown) = RepoDesc::parse(&text).unwrap();
                    assert!(unknown.is_empty(), "{name}: {unknown:?}");
                    let Ok(theirs) = RepoDescFile::from_str(&text) else {
                        upstream_refused += 1;
                        println!("{name}: alpm-repo-db refuses; piko: {:?}", ours.invalid_fields());
                        return Ok(());
                    };
                    either!(&theirs, |v| {
                        assert_eq!(ours.file_name, v.file_name, "{name}");
                        assert_eq!(ours.name, v.name, "{name}");
                        assert_eq!(ours.version, v.version, "{name}");
                        assert_eq!(ours.architecture, v.arch, "{name}");
                        assert_eq!(ours.sha256, v.sha256_checksum, "{name}");
                        assert_eq!(ours.base.as_ref().unwrap(), &v.base, "{name}");
                        assert_eq!(ours.description.as_ref().unwrap(), &v.description, "{name}");
                        assert_eq!(ours.url.parsed(), v.url.as_ref(), "{name}");
                        assert_eq!(ours.packager.parsed(), Some(&v.packager), "{name}");
                        assert_eq!(*ours.build_date.as_ref().unwrap(), v.build_date, "{name}");
                        assert_eq!(ours.licenses.as_deref().unwrap(), v.license, "{name}");
                        let optional = ours.optional_depends.as_deref().unwrap();
                        assert_eq!(optional, v.optional_dependencies, "{name}");
                        let make = ours.make_depends.as_deref().unwrap();
                        assert_eq!(make, v.make_dependencies, "{name}");
                        let check = ours.check_depends.as_deref().unwrap();
                        assert_eq!(check, v.check_dependencies, "{name}");
                    });
                    match &theirs {
                        RepoDescFile::V1(v) => {
                            assert_eq!(ours.md5.as_ref().unwrap().as_ref(), Some(&v.md5_checksum));
                            assert_eq!(ours.pgp_signature.as_ref(), Some(&v.pgp_signature));
                        }
                        RepoDescFile::V2(v) => {
                            assert!(matches!(ours.md5, Ok(None)), "{name}");
                            assert_eq!(ours.pgp_signature, v.pgp_signature, "{name}");
                        }
                    }
                    assert!(ours.invalid_fields().is_empty(), "{name}");
                    agreed += 1;
                    Ok(())
                },
                |_skipped| {},
            )
            .unwrap();
        }

        assert!(agreed > 100, "expected populated repositories, found {agreed} entries");
        println!("{agreed} desc entries agree; {upstream_refused} refused by alpm-repo-db only");
    }
}
