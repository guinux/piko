//! The `desc` fields read eagerly for every repository package.
//!
//! The scan and the relation parsing live in [`crate::eager`], shared with the local
//! database. This module holds only what is specific to the repository format: the two
//! mandatory size sections, and the [`EagerFields`] shape [`super::RepoPackage`] stores.

use alpm_types::{CompressedSize, Group, InstalledSize, PackageRelation, RelationOrSoname};

use crate::eager::{self, DescFieldError};

/// The `desc` sections parsed for every package at open time.
///
/// Field-for-field a subset of [`super::RepoDescView`], which remains the way to read
/// everything else.
#[derive(Debug)]
pub(crate) struct EagerFields {
    /// The relation sections, shared with the local database's eager tier.
    pub(crate) relations: eager::Relations,
    /// `%CSIZE%`, the compressed package file's size in bytes.
    pub(crate) compressed_size: CompressedSize,
    /// `%ISIZE%`, the installed size in bytes.
    pub(crate) installed_size: InstalledSize,
}

impl EagerFields {
    /// Where `%DEPENDS%` sits in the entry's text, for the deferred conversion.
    pub(crate) const fn depends_text(&self) -> Option<(usize, usize)> {
        self.relations.depends_text
    }

    /// `%PROVIDES%`.
    pub(crate) fn provides(&self) -> &[RelationOrSoname] {
        &self.relations.provides
    }

    /// `%CONFLICTS%`.
    pub(crate) fn conflicts(&self) -> &[PackageRelation] {
        &self.relations.conflicts
    }

    /// `%REPLACES%`.
    pub(crate) fn replaces(&self) -> &[PackageRelation] {
        &self.relations.replaces
    }

    /// `%GROUPS%`.
    pub(crate) fn groups(&self) -> &[Group] {
        &self.relations.groups
    }
}

/// Parses the eager subset out of one repository `desc` entry's text.
///
/// `text` is the *filtered* text: unknown sections are already removed by
/// [`crate::desc_compat::filter_unknown_sections`]. So an unrecognised `%KEYWORD%` here is
/// simply one this module does not read, not one this build does not know.
///
/// # Errors
///
/// [`DescFieldError`] if `%CSIZE%` or `%ISIZE%` is absent or malformed, or if any entry of a
/// relation section fails to parse. The caller drops the package and reports the diagnostic.
pub(crate) fn parse(text: &str) -> Result<EagerFields, DescFieldError> {
    let mut compressed_size = None;
    let mut installed_size = None;

    let relations = eager::scan(text, eager::Depends::Deferred, |keyword, line| {
        match keyword.as_bytes() {
            b"CSIZE" => compressed_size = Some(eager::scalar(line, "CSIZE")?),
            b"ISIZE" => installed_size = Some(eager::scalar(line, "ISIZE")?),
            _ => {}
        }
        Ok(())
    })?;

    Ok(EagerFields {
        relations,
        compressed_size: compressed_size
            .ok_or(DescFieldError::MissingSection { section: "CSIZE" })?,
        installed_size: installed_size
            .ok_or(DescFieldError::MissingSection { section: "ISIZE" })?,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// Every real `desc` shape this module reads, in one entry.
    const DESC: &str = "\
%FILENAME%
foo-1.0.0-1-x86_64.pkg.tar.zst

%NAME%
foo

%CSIZE%
1234

%ISIZE%
5678

%GROUPS%
base
base-devel

%DEPENDS%
glibc
bash>=5.0
libexample.so=1-64

%PROVIDES%
foo-alias
lib:libthing.so.2

%CONFLICTS%
oldfoo

%REPLACES%
ancientfoo
";

    #[test]
    fn reads_every_eager_section() {
        let fields = parse(DESC).unwrap();

        assert_eq!(fields.compressed_size, 1234);
        assert_eq!(fields.installed_size, 5678);
        assert_eq!(fields.groups(), ["base".to_owned(), "base-devel".to_owned()]);
        assert_eq!(fields.provides().len(), 2);
        assert_eq!(fields.conflicts().len(), 1);
        assert_eq!(fields.replaces().len(), 1);

        // `%DEPENDS%` is the one section this parse only *locates*.
        let depends = crate::eager::parse_depends(DESC, fields.depends_text()).unwrap();
        assert_eq!(depends.len(), 3);
    }

    /// The deferred section must be located exactly, not approximately. A range that ran on
    /// into `%PROVIDES%` would silently give a package its provides as dependencies.
    #[test]
    fn the_deferred_depends_range_stops_at_the_next_section() {
        let fields = parse(DESC).unwrap();
        let depends = crate::eager::parse_depends(DESC, fields.depends_text()).unwrap();
        let rendered: Vec<String> = depends.iter().map(ToString::to_string).collect();
        assert_eq!(rendered, ["glibc", "bash>=5.0", "libexample.so=1-64"]);
    }

    /// A `desc` with no `%DEPENDS%` at all must yield no dependencies rather than the whole
    /// entry re-read as one.
    #[test]
    fn an_absent_depends_section_defers_to_nothing() {
        let text = DESC.replace("%DEPENDS%\nglibc\nbash>=5.0\nlibexample.so=1-64\n", "");
        let fields = parse(&text).unwrap();
        assert_eq!(fields.depends_text(), None);
        assert!(crate::eager::parse_depends(&text, fields.depends_text()).unwrap().is_empty());
    }

    #[test]
    fn a_missing_size_section_is_an_error_not_a_default() {
        let text = DESC.replace("%CSIZE%\n1234\n", "");
        let error = parse(&text).unwrap_err();
        assert!(
            matches!(error, DescFieldError::MissingSection { section: "CSIZE" }),
            "got {error:?}"
        );
    }

    #[test]
    fn a_malformed_size_is_an_error_not_a_zero() {
        let text = DESC.replace("1234", "twelve");
        let error = parse(&text).unwrap_err();
        assert!(
            matches!(error, DescFieldError::InvalidSize { section: "CSIZE", .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn a_malformed_relation_names_its_section() {
        let text = DESC.replace("%CONFLICTS%\noldfoo", "%CONFLICTS%\noldfoo>=");
        let error = parse(&text).unwrap_err();
        assert!(
            matches!(&error, DescFieldError::InvalidEntry { section: "CONFLICTS", .. }),
            "got {error:?}"
        );
    }

    /// States the behaviour change deferring `%DEPENDS%` buys, as a test: the open no longer
    /// rejects the entry, and the same error arrives from the same parser when the section is
    /// actually read.
    #[test]
    fn a_malformed_depends_is_reported_when_read_rather_than_at_open() {
        let text = DESC.replace("bash>=5.0", "bash>=");
        let Ok(fields) = parse(&text) else {
            panic!("a malformed %DEPENDS% must not fail the open")
        };

        let error = crate::eager::parse_depends(&text, fields.depends_text()).unwrap_err();
        assert!(
            matches!(&error, DescFieldError::InvalidEntry { section: "DEPENDS", .. }),
            "got {error:?}"
        );
    }

    /// Sections this module does not read must cost nothing and must not be mistaken for one
    /// it does, including a `%DESC%` whose free text could look like anything.
    #[test]
    fn deferred_sections_are_ignored_entirely() {
        let text = format!("{DESC}\n%DESC%\nglibc\nbash>=5.0\n\n%URL%\nnot a url at all\n");
        let fields = parse(&text).unwrap();
        let depends = crate::eager::parse_depends(&text, fields.depends_text()).unwrap();
        assert_eq!(depends.len(), 3, "%DESC% text must not land in %DEPENDS%");
    }

    #[test]
    fn an_entry_with_no_relations_at_all_is_valid() {
        let text = "%CSIZE%\n1\n\n%ISIZE%\n2\n";
        let fields = parse(text).unwrap();
        assert!(crate::eager::parse_depends(text, fields.depends_text()).unwrap().is_empty());
        assert!(fields.provides().is_empty());
        assert!(fields.groups().is_empty());
    }
}
