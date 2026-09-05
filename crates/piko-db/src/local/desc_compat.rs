//! Version-agnostic access to a local `desc` file.
//!
//! `alpm-db` models `desc` as an enum over `alpm-db-descv1` and `alpm-db-descv2`, which
//! differ only in v2's `%XDATA%` section. Both are common on a real system — roughly 993 v2
//! to 173 v1 entries on the machine this was developed against. Without [`DescView`], every
//! caller would have to match on the variant itself.
//!
//! The repository equivalent is [`crate::repo::desc_compat`]. What the two have in common —
//! the unknown-section filter and its policy — lives in [`crate::desc_compat`].

use alpm_db::desc::DbDescFile;
use alpm_types::{
    Architecture, BuildDate, ExtraData, FullVersion, Group, InstalledSize, License, Name,
    OptionalDependency, PackageBaseName, PackageDescription, PackageInstallReason, PackageRelation,
    PackageValidation, Packager, RelationOrSoname, Url,
};

use crate::desc_compat::TakenFields;

/// Read-only access to a `desc` file, independent of its schema version.
///
/// Obtained from [`LocalPackage::desc`](crate::LocalPackage::desc).
#[derive(Clone, Copy, Debug)]
pub struct DescView<'a> {
    inner: &'a DbDescFile,
    taken: &'a TakenFields,
}

/// Generates accessors that read the same field from either schema version.
macro_rules! shared_field {
    ($( $(#[$meta:meta])* $method:ident: $field:ident -> $ty:ty ),* $(,)?) => {
        $(
            $(#[$meta])*
            #[must_use]
            pub fn $method(&self) -> $ty {
                match self.inner {
                    DbDescFile::V1(desc) => &desc.$field,
                    DbDescFile::V2(desc) => &desc.$field,
                }
            }
        )*
    };
}

/// Generates accessors for fields that are cheap to copy.
macro_rules! shared_copy_field {
    ($( $(#[$meta:meta])* $method:ident: $field:ident -> $ty:ty ),* $(,)?) => {
        $(
            $(#[$meta])*
            #[must_use]
            pub fn $method(&self) -> $ty {
                match self.inner {
                    DbDescFile::V1(desc) => desc.$field,
                    DbDescFile::V2(desc) => desc.$field,
                }
            }
        )*
    };
}

impl<'a> DescView<'a> {
    /// Wraps a parsed `desc` and the fields taken out of it before parsing.
    pub(crate) const fn new(inner: &'a DbDescFile, taken: &'a TakenFields) -> Self {
        Self { inner, taken }
    }

    /// The underlying schema-tagged value, for callers that need the distinction.
    ///
    /// Its `url` field is always `None`: `%URL%` is blanked before the upstream parser sees
    /// the text, so [`DescView::url`] and [`DescView::url_raw`] are the only sources for it.
    /// Its `packager` field can likewise hold a substitute — read [`DescView::packager`] and
    /// [`DescView::packager_raw`] rather than it.
    #[must_use]
    pub const fn as_inner(&self) -> &'a DbDescFile {
        self.inner
    }

    /// Whether this `desc` uses the v2 schema, which carries `%XDATA%`.
    #[must_use]
    pub const fn is_v2(&self) -> bool {
        matches!(self.inner, DbDescFile::V2(_))
    }

    shared_field! {
        /// `%NAME%`.
        ///
        /// Advisory only. The authoritative package name comes from the entry directory
        /// name — see [`LocalPackage::name`](crate::LocalPackage::name).
        name: name -> &'a Name,
        /// `%VERSION%`.
        ///
        /// Advisory only, for the same reason as [`DescView::name`].
        version: version -> &'a FullVersion,
        /// `%BASE%`, the name of the package base this package was built from.
        base: base -> &'a PackageBaseName,
        /// `%DESC%`, the one-line package description.
        description: description -> &'a PackageDescription,
        /// `%ARCH%`, the architecture the package was built for.
        architecture: arch -> &'a Architecture,
        /// `%GROUPS%`.
        groups: groups -> &'a [Group],
        /// `%LICENSE%`.
        licenses: license -> &'a [License],
        /// `%VALIDATION%`, how the package's integrity was checked at install time.
        validation: validation -> &'a [PackageValidation],
        /// `%REPLACES%`.
        replaces: replaces -> &'a [PackageRelation],
        /// `%DEPENDS%`, the run-time dependencies.
        depends: depends -> &'a [RelationOrSoname],
        /// `%OPTDEPENDS%`.
        optional_depends: optdepends -> &'a [OptionalDependency],
        /// `%CONFLICTS%`.
        conflicts: conflicts -> &'a [PackageRelation],
        /// `%PROVIDES%`.
        provides: provides -> &'a [RelationOrSoname],
    }

    shared_copy_field! {
        /// `%BUILDDATE%`, as a Unix timestamp.
        build_date: builddate -> BuildDate,
        /// `%INSTALLDATE%`, as a Unix timestamp.
        install_date: installdate -> BuildDate,
        /// `%SIZE%`, the installed size in bytes.
        installed_size: size -> InstalledSize,
        /// `%REASON%`: whether the package was installed explicitly or as a dependency.
        install_reason: reason -> PackageInstallReason,
    }

    /// `%PACKAGER%`, the identity that built the package.
    ///
    /// `None` when the value is makepkg's
    /// [`UNKNOWN_PACKAGER`](crate::desc_compat::UNKNOWN_PACKAGER) default, which carries no
    /// email address and so cannot become an `alpm_types::Packager`.
    /// [`DescView::packager_raw`] still has it.
    #[must_use]
    pub fn packager(&self) -> Option<&'a Packager> {
        if self.taken.packager.is_unknown() {
            return None;
        }
        Some(match self.inner {
            DbDescFile::V1(desc) => &desc.packager,
            DbDescFile::V2(desc) => &desc.packager,
        })
    }

    /// `%PACKAGER%` exactly as the `desc` holds it, which is what libalpm reports.
    #[must_use]
    pub fn packager_raw(&self) -> Option<&'a str> {
        self.taken.packager.raw()
    }

    /// `%URL%`, the upstream project URL, normalized by `url::Url`.
    ///
    /// The section is mandatory but its value may be empty, which is `None` here. So is a
    /// value `url::Url` refuses — it does not make the `desc` unreadable, and
    /// [`DescView::url_raw`] still has it.
    #[must_use]
    pub const fn url(&self) -> Option<&'a Url> {
        self.taken.url.parsed()
    }

    /// `%URL%` exactly as the `desc` holds it, which is what libalpm reports.
    #[must_use]
    pub fn url_raw(&self) -> Option<&'a str> {
        self.taken.url.raw()
    }

    /// `%XDATA%`, the extra data section.
    ///
    /// `None` for a v1 `desc`, which has no such section.
    #[must_use]
    pub const fn xdata(&self) -> Option<&'a ExtraData> {
        match self.inner {
            DbDescFile::V1(_) => None,
            DbDescFile::V2(desc) => Some(&desc.xdata),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use alpm_common::MetadataFile as _;
    use alpm_types::{PackageInstallReason, PackageValidation};

    use super::*;
    use crate::{desc_compat::UNKNOWN_PACKAGER, fixture::MINIMAL_DESC_V1};

    /// The `%PACKAGER%` [`MINIMAL_DESC_V1`] carries.
    const FOOFACE: &str = "Foobar McFooface <foobar@mcfooface.org>";

    /// Parses a `desc` the way [`crate::LocalPackage`] does: the taken fields removed first.
    fn parse(text: &str) -> (DbDescFile, TakenFields) {
        let (text, taken) = crate::desc_compat::take_fields(text);
        (DbDescFile::from_str_with_schema(&text, None).unwrap(), taken)
    }

    #[test]
    fn view_exposes_every_field_of_a_v1_desc() {
        let (desc, taken) = parse(MINIMAL_DESC_V1);
        let view = DescView::new(&desc, &taken);

        assert_eq!(view.name().as_ref(), "foo");
        assert_eq!(view.version().to_string(), "1.0.0-1");
        assert_eq!(view.base().as_ref(), "foo");
        assert_eq!(view.description().to_string(), "An example package");
        assert_eq!(view.architecture().to_string(), "x86_64");
        assert_eq!(view.build_date(), 1_733_737_242);
        assert_eq!(view.install_date(), 1_733_737_243);
        assert_eq!(view.installed_size(), 123);
        assert_eq!(view.install_reason(), PackageInstallReason::Explicit);
        assert!(view.url().is_some());
        assert_eq!(view.url_raw(), Some("https://example.org/"));
        assert!(view.groups().is_empty());
        assert!(view.depends().is_empty());
        assert_eq!(view.validation(), [PackageValidation::Pgp]);
        assert!(!view.is_v2());
        assert!(view.xdata().is_none(), "a v1 desc has no %XDATA%");
    }

    #[test]
    fn packager_is_both_typed_and_raw() {
        let (desc, taken) = parse(MINIMAL_DESC_V1);
        let view = DescView::new(&desc, &taken);

        assert_eq!(view.packager().map(ToString::to_string).as_deref(), Some(FOOFACE));
        assert_eq!(view.packager_raw(), Some(FOOFACE));
    }

    /// makepkg's default has no email address, so no `Packager` can hold it. The bytes stay
    /// reachable, which is what libalpm reports and what `piko info` prints.
    #[test]
    fn makepkgs_default_packager_has_no_typed_form_but_keeps_its_bytes() {
        let (desc, taken) = parse(&MINIMAL_DESC_V1.replace(FOOFACE, UNKNOWN_PACKAGER));
        let view = DescView::new(&desc, &taken);

        assert!(view.packager().is_none());
        assert_eq!(view.packager_raw(), Some(UNKNOWN_PACKAGER));
        assert_eq!(view.name().as_ref(), "foo", "every other section still reads");
    }

    #[test]
    fn view_exposes_xdata_for_a_v2_desc() {
        let text = format!("{MINIMAL_DESC_V1}%XDATA%\npkgtype=pkg\n\n");
        let (desc, taken) = parse(&text);
        let view = DescView::new(&desc, &taken);

        assert!(view.is_v2());
        assert!(view.xdata().is_some());
        assert_eq!(view.name().as_ref(), "foo", "shared fields work across versions");
    }

    /// The point of the `%URL%` split: a `%URL%` `url::Url` refuses costs the URL its
    /// normalized form, and nothing else. libalpm prints such a value verbatim, so the bytes
    /// must survive.
    #[test]
    fn an_unparsable_url_leaves_every_other_field_readable() {
        let text = MINIMAL_DESC_V1.replace("https://example.org/", "www.example.org");
        let (desc, taken) = parse(&text);
        let view = DescView::new(&desc, &taken);

        assert_eq!(view.url(), None, "the value does not normalize");
        assert_eq!(view.url_raw(), Some("www.example.org"), "but the bytes are kept");
        assert_eq!(view.name().as_ref(), "foo");
        assert_eq!(view.description().to_string(), "An example package");
    }

    /// An empty `%URL%` is how a package with no URL is recorded, and must stay distinct from
    /// a value that failed to normalize: both are `None`, but only one has bytes.
    #[test]
    fn an_empty_url_has_no_raw_value_either() {
        let text = MINIMAL_DESC_V1.replace("https://example.org/", "");
        let (desc, taken) = parse(&text);
        let view = DescView::new(&desc, &taken);

        assert_eq!(view.url(), None);
        assert_eq!(view.url_raw(), None);
    }
}
