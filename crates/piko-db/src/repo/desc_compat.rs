//! Version-agnostic access to a repository `desc` entry, mirroring [`crate::desc_compat`].
//!
//! The same two problems solved for the local database's `desc` format recur here.
//! `alpm-repo-db` models `desc` as an enum over `alpm-repo-descv1` and `alpm-repo-descv2`
//! (75 v1 to 15 106 v2 entries measured across the real `core` and `extra` repositories). It
//! also derives `#[serde(deny_unknown_fields)]`, so one future `%KEY%` would make an entire
//! repository unreadable rather than just one package. [`RepoDescView`] flattens the schema
//! split. [`crate::desc_compat::filter_unknown_sections`] (reused, not duplicated — see its doc
//! comment) handles the second problem the same way milestone 1 does.

use alpm_repo_db::desc::{RepoDescFile, SectionKeyword};
use alpm_types::{
    Architecture, Base64OpenPGPSignature, BuildDate, CompressedSize, FullVersion, Group,
    InstalledSize, License, Md5Checksum, Name, OptionalDependency, PackageBaseName,
    PackageDescription, PackageFileName, PackageRelation, Packager, RelationOrSoname, Url,
};

use crate::desc_compat::TakenFields;

/// Whether `keyword` is a section this build recognises in a repository `desc`.
pub(crate) fn is_known_section(keyword: &str) -> bool {
    use std::str::FromStr as _;
    SectionKeyword::from_str(keyword).is_ok()
}

/// Read-only access to a repository `desc` entry, independent of its schema version.
///
/// Obtained from [`crate::repo::RepoPackage::desc`].
#[derive(Clone, Copy, Debug)]
pub struct RepoDescView<'a> {
    inner: &'a RepoDescFile,
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
                    RepoDescFile::V1(desc) => &desc.$field,
                    RepoDescFile::V2(desc) => &desc.$field,
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
                    RepoDescFile::V1(desc) => desc.$field,
                    RepoDescFile::V2(desc) => desc.$field,
                }
            }
        )*
    };
}

impl<'a> RepoDescView<'a> {
    /// Wraps a parsed repository `desc` and the fields taken out of it before parsing.
    pub(crate) const fn new(inner: &'a RepoDescFile, taken: &'a TakenFields) -> Self {
        Self { inner, taken }
    }

    /// The underlying schema-tagged value, for callers that need the distinction.
    ///
    /// Its `url` field is always `None`: `%URL%` is blanked before the upstream parser sees
    /// the text, so [`RepoDescView::url`] and [`RepoDescView::url_raw`] are the only sources
    /// for it. Its `packager` field can likewise hold a substitute — read
    /// [`RepoDescView::packager`] and [`RepoDescView::packager_raw`] rather than it.
    #[must_use]
    pub const fn as_inner(&self) -> &'a RepoDescFile {
        self.inner
    }

    /// Whether this `desc` uses the v2 schema.
    #[must_use]
    pub const fn is_v2(&self) -> bool {
        matches!(self.inner, RepoDescFile::V2(_))
    }

    shared_field! {
        /// `%FILENAME%`, the package file's name on the repository server.
        file_name: file_name -> &'a PackageFileName,
        /// `%NAME%`.
        name: name -> &'a Name,
        /// `%BASE%`, the name of the package base this package was built from.
        base: base -> &'a PackageBaseName,
        /// `%VERSION%`.
        version: version -> &'a FullVersion,
        /// `%DESC%`, the one-line package description.
        description: description -> &'a PackageDescription,
        /// `%GROUPS%`.
        groups: groups -> &'a [Group],
        /// `%LICENSE%`.
        licenses: license -> &'a [License],
        /// `%ARCH%`, the architecture the package was built for.
        architecture: arch -> &'a Architecture,
        /// `%REPLACES%`.
        replaces: replaces -> &'a [PackageRelation],
        /// `%CONFLICTS%`.
        conflicts: conflicts -> &'a [PackageRelation],
        /// `%PROVIDES%`.
        provides: provides -> &'a [RelationOrSoname],
        /// `%DEPENDS%`, the run-time dependencies.
        depends: dependencies -> &'a [RelationOrSoname],
        /// `%OPTDEPENDS%`.
        optional_depends: optional_dependencies -> &'a [OptionalDependency],
        /// `%MAKEDEPENDS%`.
        make_depends: make_dependencies -> &'a [PackageRelation],
        /// `%CHECKDEPENDS%`.
        check_depends: check_dependencies -> &'a [PackageRelation],
    }

    shared_copy_field! {
        /// `%CSIZE%`, the compressed package file's size in bytes.
        compressed_size: compressed_size -> CompressedSize,
        /// `%ISIZE%`, the installed size in bytes.
        installed_size: installed_size -> InstalledSize,
        /// `%BUILDDATE%`, as a Unix timestamp.
        build_date: build_date -> BuildDate,
    }

    /// `%PACKAGER%`, the identity that built the package.
    ///
    /// `None` when the value is makepkg's
    /// [`UNKNOWN_PACKAGER`](crate::desc_compat::UNKNOWN_PACKAGER) default, which carries no
    /// email address and so cannot become an `alpm_types::Packager`.
    /// [`RepoDescView::packager_raw`] still has it.
    #[must_use]
    pub fn packager(&self) -> Option<&'a Packager> {
        if self.taken.packager.is_unknown() {
            return None;
        }
        Some(match self.inner {
            RepoDescFile::V1(desc) => &desc.packager,
            RepoDescFile::V2(desc) => &desc.packager,
        })
    }

    /// `%PACKAGER%` exactly as the `desc` holds it, which is what libalpm reports.
    #[must_use]
    pub fn packager_raw(&self) -> Option<&'a str> {
        self.taken.packager.raw()
    }

    /// `%URL%`, the upstream project URL, normalized by `url::Url`.
    ///
    /// `None` when the section is absent, empty, or holds a value `url::Url` refuses. That
    /// last case does not make the entry unreadable, and [`RepoDescView::url_raw`] still has it.
    #[must_use]
    pub const fn url(&self) -> Option<&'a Url> {
        self.taken.url.parsed()
    }

    /// `%URL%` exactly as the `desc` holds it, which is what libalpm reports.
    #[must_use]
    pub fn url_raw(&self) -> Option<&'a str> {
        self.taken.url.raw()
    }

    /// `%MD5SUM%`.
    ///
    /// `None` for a v2 `desc`, which drops this section. `alpm-repo-db` itself uses the
    /// presence of `%MD5SUM%` to distinguish the two schemas.
    #[must_use]
    pub const fn md5_checksum(&self) -> Option<&'a Md5Checksum> {
        match self.inner {
            RepoDescFile::V1(desc) => Some(&desc.md5_checksum),
            RepoDescFile::V2(_) => None,
        }
    }

    /// `%SHA256SUM%`.
    #[must_use]
    pub const fn sha256_checksum(&self) -> &'a alpm_types::Sha256Checksum {
        match self.inner {
            RepoDescFile::V1(desc) => &desc.sha256_checksum,
            RepoDescFile::V2(desc) => &desc.sha256_checksum,
        }
    }

    /// `%PGPSIG%`, the package file's detached OpenPGP signature.
    ///
    /// Mandatory in v1; optional in v2. `None` only for a v2 `desc` that omits it.
    #[must_use]
    pub const fn pgp_signature(&self) -> Option<&'a Base64OpenPGPSignature> {
        match self.inner {
            RepoDescFile::V1(desc) => Some(&desc.pgp_signature),
            RepoDescFile::V2(desc) => desc.pgp_signature.as_ref(),
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
    use std::str::FromStr as _;

    use super::*;
    use crate::desc_compat::UNKNOWN_PACKAGER;

    /// The `%PACKAGER%` [`MINIMAL_DESC_V1`] carries.
    const FOOFACE: &str = "Foobar McFooface <foobar@mcfooface.org>";

    /// A real-shaped v1 `desc`, close to the `acl` entry read from `core.db` while planning
    /// this module. It has every mandatory v1 field, `%MD5SUM%` included.
    const MINIMAL_DESC_V1: &str = "\
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

    fn parse(text: &str) -> RepoDescFile {
        RepoDescFile::from_str(text).unwrap()
    }

    /// Parses an entry the way [`crate::repo::RepoPackage`] does: taken fields removed first.
    fn parse_with_taken(text: &str) -> (RepoDescFile, TakenFields) {
        let (text, taken) = crate::desc_compat::take_fields(text);
        (parse(&text), taken)
    }

    #[test]
    fn view_exposes_every_field_of_a_v1_desc() {
        let (desc, taken) = parse_with_taken(MINIMAL_DESC_V1);
        let view = RepoDescView::new(&desc, &taken);

        assert_eq!(view.name().as_ref(), "foo");
        assert_eq!(view.version().to_string(), "1.0.0-1");
        assert_eq!(view.base().as_ref(), "foo");
        assert_eq!(view.description().to_string(), "An example package");
        assert_eq!(view.architecture().to_string(), "x86_64");
        assert_eq!(view.build_date(), 1_733_737_242);
        assert!(view.url().is_some());
        assert!(view.groups().is_empty());
        assert!(view.depends().is_empty());
        assert!(!view.is_v2());
        assert!(view.md5_checksum().is_some(), "a v1 desc always has %MD5SUM%");
        assert!(view.pgp_signature().is_some(), "%PGPSIG% is mandatory in v1");
    }

    /// The same package as [`MINIMAL_DESC_V1`], minus `%MD5SUM%`. The presence or absence of
    /// that section is exactly what `alpm-repo-db`'s schema heuristic keys on.
    const MINIMAL_DESC_V2: &str = "\
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

%SHA256SUM%
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

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

    #[test]
    fn packager_is_both_typed_and_raw() {
        let (desc, taken) = parse_with_taken(MINIMAL_DESC_V1);
        let view = RepoDescView::new(&desc, &taken);

        assert_eq!(view.packager().map(ToString::to_string).as_deref(), Some(FOOFACE));
        assert_eq!(view.packager_raw(), Some(FOOFACE));
    }

    /// A locally built package added to a repository with `repo-add` carries makepkg's
    /// default. It must not cost the entry every other section.
    #[test]
    fn makepkgs_default_packager_has_no_typed_form_but_keeps_its_bytes() {
        let (desc, taken) = parse_with_taken(&MINIMAL_DESC_V1.replace(FOOFACE, UNKNOWN_PACKAGER));
        let view = RepoDescView::new(&desc, &taken);

        assert!(view.packager().is_none());
        assert_eq!(view.packager_raw(), Some(UNKNOWN_PACKAGER));
        assert_eq!(view.name().as_ref(), "foo", "every other section still reads");
    }

    #[test]
    fn view_flattens_a_v2_desc_which_has_no_md5sum() {
        let (desc, taken) = parse_with_taken(MINIMAL_DESC_V2);
        let view = RepoDescView::new(&desc, &taken);

        assert!(view.is_v2());
        assert!(view.md5_checksum().is_none(), "a v2 desc has no %MD5SUM%");
        assert_eq!(view.name().as_ref(), "foo", "shared fields still work across versions");
    }

    #[test]
    fn is_known_section_recognises_every_real_key() {
        for key in [
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
        ] {
            assert!(is_known_section(key), "{key} should be recognised");
        }
        assert!(!is_known_section("SOMETHING_FROM_THE_FUTURE"));
    }

    /// Exercises the forward-compatibility guarantee, through the shared filter this module
    /// reuses rather than reimplements.
    #[test]
    fn drops_an_unknown_section_and_still_parses() {
        let text = format!("{MINIMAL_DESC_V1}%FUTURE_THING%\nsomething\n\n");
        let (filtered, unknown) =
            crate::desc_compat::filter_unknown_sections(&text, is_known_section);

        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown.first().map(|s| s.keyword.as_str()), Some("FUTURE_THING"));

        let desc = parse(&filtered);
        assert_eq!(RepoDescView::new(&desc, &TakenFields::default()).name().as_ref(), "foo");
    }

    /// The repository side of the `%URL%` split: a `%URL%` `url::Url` refuses must not cost
    /// the entry its `%FILENAME%`, which is what an install downloads.
    #[test]
    fn an_unparsable_url_leaves_the_file_name_readable() {
        let text = MINIMAL_DESC_V1.replace("https://example.org/", "www.example.org");
        let (desc, taken) = parse_with_taken(&text);
        let view = RepoDescView::new(&desc, &taken);

        assert_eq!(view.url(), None);
        assert_eq!(view.url_raw(), Some("www.example.org"));
        assert_eq!(view.file_name().to_string(), "foo-1.0.0-1-x86_64.pkg.tar.zst");
    }
}
