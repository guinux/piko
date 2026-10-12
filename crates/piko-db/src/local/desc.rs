//! The local database's `desc` file, read one field at a time.
//!
//! The relation sections, `%SIZE%` and `%REASON%` come from the eager tier
//! ([`super::EagerView`]), which reads them for every installed package. This module reads the
//! rest, when something asks for [`super::LocalPackage::desc`].
//!
//! Three sections decide something, and refuse the file when they are missing or invalid:
//! `%NAME%`, `%VERSION%` and `%ARCH%`. Every other section is shown only. Each gets its own
//! [`Result`], and an invalid value is reported through
//! [`super::LocalPackage::check_consistency`], never by the loss of the file.

use alpm_types::{
    Architecture, BuildDate, ExtraData, ExtraDataEntry, FullVersion, Group, InstalledSize, License,
    Name, OptionalDependency, PackageBaseName, PackageDescription, PackageInstallReason,
    PackageRelation, PackageValidation, Packager, RelationOrSoname, Url,
};

use super::EagerView;
use crate::{
    desc_compat::UnknownSection,
    eager::DescFieldError,
    meta::{
        desc::{Index, PackagerField, UrlField, named, non_empty, number, typed, typed_comparable},
        section::Sections,
    },
};

/// Every section of the local `desc` format, from the `alpm-db-descv1` and `alpm-db-descv2`
/// specifications.
pub(crate) const KNOWN_SECTIONS: &[&str] = &[
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
    "GROUPS",
    "REASON",
    "LICENSE",
    "VALIDATION",
    "REPLACES",
    "DEPENDS",
    "OPTDEPENDS",
    "CONFLICTS",
    "PROVIDES",
    "XDATA",
];

/// The fields of a local `desc` that the eager tier does not read.
#[derive(Debug)]
pub(crate) struct LocalDesc {
    name: Name,
    version: FullVersion,
    architecture: Architecture,
    base: Result<PackageBaseName, DescFieldError>,
    description: Result<PackageDescription, DescFieldError>,
    url: UrlField,
    packager: PackagerField,
    build_date: Result<BuildDate, DescFieldError>,
    install_date: Result<BuildDate, DescFieldError>,
    licenses: Result<Box<[License]>, DescFieldError>,
    validation: Result<Box<[PackageValidation]>, DescFieldError>,
    optional_depends: Result<Box<[OptionalDependency]>, DescFieldError>,
    xdata: Result<Option<ExtraData>, DescFieldError>,
}

impl LocalDesc {
    /// Reads `text`, returning the fields and the sections this build does not know.
    ///
    /// # Errors
    ///
    /// A [`DescFieldError`] when `%NAME%`, `%VERSION%` or `%ARCH%` is missing or invalid. No
    /// other section can refuse the file.
    pub(crate) fn parse(text: &str) -> Result<(Self, Vec<UnknownSection>), DescFieldError> {
        let index = Index::new(text, KNOWN_SECTIONS);

        let desc = Self {
            name: index.required("NAME", typed("NAME"))?,
            version: index.required("VERSION", typed_comparable("VERSION"))?,
            architecture: index.required("ARCH", typed("ARCH"))?,
            base: index.required("BASE", typed("BASE")),
            description: index.required("DESC", |value| Ok(PackageDescription::from(value))),
            url: UrlField::read(&index),
            packager: PackagerField::read(&index),
            build_date: index.required("BUILDDATE", number("BUILDDATE")),
            install_date: index.required("INSTALLDATE", number("INSTALLDATE")),
            licenses: index.list("LICENSE", typed("LICENSE")),
            validation: index
                .list("VALIDATION", named("VALIDATION"))
                .and_then(|list| non_empty(list, "VALIDATION")),
            optional_depends: index.list("OPTDEPENDS", typed_comparable("OPTDEPENDS")),
            xdata: xdata(&index),
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
            self.install_date.as_ref().err(),
            self.licenses.as_ref().err(),
            self.validation.as_ref().err(),
            self.optional_depends.as_ref().err(),
            self.xdata.as_ref().err(),
        ];
        errors.into_iter().flatten().map(ToString::to_string).collect()
    }

    /// `%NAME%`.
    pub(crate) const fn name(&self) -> &Name {
        &self.name
    }

    /// `%VERSION%`.
    pub(crate) const fn version(&self) -> &FullVersion {
        &self.version
    }
}

/// `%XDATA%`, which only a v2 `desc` has.
fn xdata(index: &Index<'_>) -> Result<Option<ExtraData>, DescFieldError> {
    if !index.has("XDATA") {
        return Ok(None);
    }
    let entries = index.list("XDATA", typed::<ExtraDataEntry>("XDATA"))?;
    ExtraData::try_from(entries.into_vec()).map(Some).map_err(|source| {
        DescFieldError::InvalidEntry { section: "XDATA", value: String::new(), source }
    })
}

/// Read-only access to a local `desc` file.
///
/// Obtained from [`LocalPackage::desc`](crate::local::LocalPackage::desc).
#[derive(Clone, Copy, Debug)]
pub struct DescView<'a> {
    desc: &'a LocalDesc,
    eager: EagerView<'a>,
}

impl<'a> DescView<'a> {
    /// Wraps the parsed fields and the eager tier of one entry.
    pub(crate) const fn new(desc: &'a LocalDesc, eager: EagerView<'a>) -> Self {
        Self { desc, eager }
    }

    /// Whether this `desc` uses the v2 schema, which carries `%XDATA%`.
    #[must_use]
    pub fn is_v2(&self) -> bool {
        matches!(self.desc.xdata, Ok(Some(_)))
    }

    /// `%NAME%`.
    ///
    /// Advisory only. The authoritative package name comes from the entry directory name —
    /// see [`LocalPackage::name`](crate::local::LocalPackage::name).
    #[must_use]
    pub const fn name(&self) -> &'a Name {
        &self.desc.name
    }

    /// `%VERSION%`.
    ///
    /// Advisory only, for the same reason as [`DescView::name`].
    #[must_use]
    pub const fn version(&self) -> &'a FullVersion {
        &self.desc.version
    }

    /// `%ARCH%`, the architecture the package was built for.
    #[must_use]
    pub const fn architecture(&self) -> &'a Architecture {
        &self.desc.architecture
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
    /// [`DescView::url_raw`] still has such a value.
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
    /// email address. [`DescView::packager_raw`] still has such a value.
    #[must_use]
    pub fn packager(&self) -> Option<&'a Packager> {
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

    /// `%INSTALLDATE%`, as a Unix timestamp.
    ///
    /// # Errors
    ///
    /// If the section is missing, repeated, or not a decimal integer.
    pub const fn install_date(&self) -> Result<BuildDate, &'a DescFieldError> {
        match &self.desc.install_date {
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

    /// `%VALIDATION%`, how the package's integrity was checked at install time.
    ///
    /// # Errors
    ///
    /// If the section is missing or empty, or an entry is not a known method.
    pub fn validation(&self) -> Result<&'a [PackageValidation], &'a DescFieldError> {
        self.desc.validation.as_deref()
    }

    /// `%OPTDEPENDS%`.
    ///
    /// # Errors
    ///
    /// If an entry is not a valid optional dependency.
    pub fn optional_depends(&self) -> Result<&'a [OptionalDependency], &'a DescFieldError> {
        self.desc.optional_depends.as_deref()
    }

    /// `%OPTDEPENDS%`, one entry at a time: an invalid line is an error of its own, and the
    /// lines around it still read.
    ///
    /// libalpm reads each optional dependency on its own. A caller that matches the entries,
    /// rather than showing the list, reads them here, so one invalid line does not hide the
    /// others.
    pub fn optional_depends_each(
        &self,
    ) -> impl Iterator<Item = Result<OptionalDependency, DescFieldError>> + 'a {
        self.section_values("OPTDEPENDS").into_iter().map(typed_comparable("OPTDEPENDS"))
    }

    /// `%XDATA%`, the extra data section. `Ok(None)` for a v1 `desc`, which has no such section.
    ///
    /// # Errors
    ///
    /// If an entry is invalid, or no entry names the `pkgtype`.
    pub fn xdata(&self) -> Result<Option<&'a ExtraData>, &'a DescFieldError> {
        self.desc.xdata.as_ref().map(Option::as_ref)
    }

    /// Every shown field whose value did not convert, as a sentence naming the section.
    ///
    /// The same list `LocalPackage::check_consistency` reports as
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
        Sections::new(self.eager.text())
            .filter(|section| section.keyword == keyword)
            .flat_map(|section| section.values())
            .collect()
    }

    /// `%GROUPS%`.
    #[must_use]
    pub const fn groups(&self) -> &'a [Group] {
        self.eager.groups()
    }

    /// `%DEPENDS%`, the run-time dependencies.
    #[must_use]
    pub const fn depends(&self) -> &'a [RelationOrSoname] {
        self.eager.depends()
    }

    /// `%PROVIDES%`.
    #[must_use]
    pub const fn provides(&self) -> &'a [RelationOrSoname] {
        self.eager.provides()
    }

    /// `%CONFLICTS%`.
    #[must_use]
    pub const fn conflicts(&self) -> &'a [PackageRelation] {
        self.eager.conflicts()
    }

    /// `%REPLACES%`.
    #[must_use]
    pub const fn replaces(&self) -> &'a [PackageRelation] {
        self.eager.replaces()
    }

    /// `%SIZE%`, the installed size in bytes.
    #[must_use]
    pub const fn installed_size(&self) -> InstalledSize {
        self.eager.installed_size()
    }

    /// `%REASON%`: whether the package was installed explicitly or as a dependency.
    #[must_use]
    pub const fn install_reason(&self) -> PackageInstallReason {
        self.eager.install_reason()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;
    use crate::{desc_compat::UNKNOWN_PACKAGER, fixture::MINIMAL_DESC_V1};

    /// The `%PACKAGER%` [`MINIMAL_DESC_V1`] carries.
    const FOOFACE: &str = "Foobar McFooface <foobar@mcfooface.org>";

    fn parse(text: &str) -> LocalDesc {
        LocalDesc::parse(text).unwrap().0
    }

    #[test]
    fn reads_every_field_of_a_v1_desc() {
        let desc = parse(MINIMAL_DESC_V1);

        assert_eq!(desc.name.as_ref(), "foo");
        assert_eq!(desc.version.to_string(), "1.0.0-1");
        assert_eq!(desc.base.as_ref().unwrap().as_ref(), "foo");
        assert_eq!(desc.description.as_ref().unwrap().as_ref(), "An example package");
        assert_eq!(desc.architecture.to_string(), "x86_64");
        assert_eq!(*desc.build_date.as_ref().unwrap(), 1_733_737_242);
        assert_eq!(*desc.install_date.as_ref().unwrap(), 1_733_737_243);
        assert_eq!(desc.url.raw(), Some("https://example.org/"));
        assert!(desc.url.parsed().is_some());
        assert_eq!(desc.validation.as_deref().unwrap(), [PackageValidation::Pgp]);
        assert!(matches!(desc.xdata, Ok(None)), "a v1 desc has no %XDATA%");
        assert!(desc.invalid_fields().is_empty());
    }

    #[test]
    fn reads_xdata_of_a_v2_desc() {
        let desc = parse(&format!("{MINIMAL_DESC_V1}%XDATA%\npkgtype=pkg\n\n"));
        assert!(matches!(desc.xdata, Ok(Some(_))));
    }

    #[test]
    fn packager_is_both_typed_and_raw() {
        let desc = parse(MINIMAL_DESC_V1);
        assert_eq!(desc.packager.parsed().unwrap().to_string(), FOOFACE);
        assert!(desc.packager.error().is_none());
        assert_eq!(desc.packager.raw(), Some(FOOFACE));
    }

    /// makepkg's default has no email address, so no `Packager` can hold it. The bytes stay,
    /// and the value is not reported: it is a documented default, not a defect.
    #[test]
    fn makepkgs_default_packager_keeps_its_bytes_and_is_not_reported() {
        let desc = parse(&MINIMAL_DESC_V1.replace(FOOFACE, UNKNOWN_PACKAGER));
        assert!(desc.packager.parsed().is_none());
        assert_eq!(desc.packager.raw(), Some(UNKNOWN_PACKAGER));
        assert!(desc.invalid_fields().is_empty());
    }

    /// The point of reading one field at a time: an invalid value costs that field, is
    /// reported, and every other field stays readable.
    #[test]
    fn an_invalid_shown_field_costs_only_itself() {
        let text = MINIMAL_DESC_V1
            .replace(FOOFACE, "Jane Doe")
            .replace("%BUILDDATE%\n1733737242", "%BUILDDATE%\nyesterday")
            .replace("https://example.org/", "www.example.org");
        let desc = parse(&text);

        assert!(desc.packager.parsed().is_none());
        assert!(desc.build_date.is_err());
        assert!(desc.url.parsed().is_none());
        assert_eq!(desc.url.raw(), Some("www.example.org"));
        assert_eq!(desc.name.as_ref(), "foo");
        assert_eq!(desc.invalid_fields().len(), 2, "{:?}", desc.invalid_fields());
    }

    #[test]
    fn an_empty_url_has_no_raw_value_either() {
        let desc = parse(&MINIMAL_DESC_V1.replace("https://example.org/", ""));
        assert!(desc.url.parsed().is_none());
        assert_eq!(desc.url.raw(), None);
    }

    /// The three sections that decide something refuse the file.
    #[test]
    fn a_missing_or_invalid_deciding_field_refuses_the_file() {
        for (from, to) in [
            ("%NAME%\nfoo", "%NAME%\n-bad-"),
            ("%VERSION%\n1.0.0-1", "%VERSION%\n"),
            ("%ARCH%\nx86_64", "%ARCH%\nx86_64\n\n%ARCH%\nany"),
        ] {
            let text = MINIMAL_DESC_V1.replace(from, to);
            assert!(LocalDesc::parse(&text).is_err(), "{to:?}");
        }
    }

    #[test]
    fn an_unknown_section_is_returned_with_its_line() {
        let (_, unknown) = LocalDesc::parse(&format!("{MINIMAL_DESC_V1}%FUTURE%\nx\n")).unwrap();
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown.first().map(|section| section.keyword.as_str()), Some("FUTURE"));
    }
}
