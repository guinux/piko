//! The `desc` fields read eagerly for every repository package.
//!
//! The scan and the relation parsing live in [`crate::eager`], shared with the local
//! database. This module holds only what is specific to the repository format: the two
//! mandatory size sections, and the [`EagerFields`] shape [`super::RepoPackage`] stores.

use alpm_types::{CompressedSize, Group, InstalledSize, PackageRelation, RelationOrSoname};

use crate::eager::{self, DescFieldError, RelationBudget, ScanError};

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
    pub(crate) fn depends_text(&self) -> &[(usize, usize)] {
        &self.relations.depends_text
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
/// `budget` is the archive's, shared by every `desc` it holds.
///
/// # Errors
///
/// - [`ScanError::Field`] if `%CSIZE%` or `%ISIZE%` is absent or malformed, or if any entry of
///   a relation section fails to parse. The caller drops the package and reports the
///   diagnostic.
/// - [`ScanError::Budget`] if `budget` runs out. The caller fails the open.
pub(crate) fn parse(text: &str, budget: &mut RelationBudget) -> Result<EagerFields, ScanError> {
    let mut compressed_size = None;
    let mut installed_size = None;

    let relations = eager::scan(text, eager::Depends::Deferred, Some(budget), |keyword, line| {
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
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// [`super::parse`] with a budget that cannot run out, for the tests about `desc` content.
    fn parse(text: &str) -> Result<EagerFields, ScanError> {
        super::parse(text, &mut RelationBudget::new(usize::MAX))
    }

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
        assert!(fields.depends_text().is_empty());
        assert!(crate::eager::parse_depends(&text, fields.depends_text()).unwrap().is_empty());
    }

    #[test]
    fn a_missing_size_section_is_an_error_not_a_default() {
        let text = DESC.replace("%CSIZE%\n1234\n", "");
        let error = parse(&text).unwrap_err();
        assert!(
            matches!(error, ScanError::Field(DescFieldError::MissingSection { section: "CSIZE" })),
            "got {error:?}"
        );
    }

    #[test]
    fn a_malformed_size_is_an_error_not_a_zero() {
        let text = DESC.replace("1234", "twelve");
        let error = parse(&text).unwrap_err();
        assert!(
            matches!(error, ScanError::Field(DescFieldError::InvalidSize { section: "CSIZE", .. })),
            "got {error:?}"
        );
    }

    #[test]
    fn a_malformed_relation_names_its_section() {
        let text = DESC.replace("%CONFLICTS%\noldfoo", "%CONFLICTS%\noldfoo>=");
        let error = parse(&text).unwrap_err();
        assert!(
            matches!(
                &error,
                ScanError::Field(DescFieldError::InvalidEntry { section: "CONFLICTS", .. })
            ),
            "got {error:?}"
        );
    }

    /// Pins what deferring `%DEPENDS%` buys. The open accepts the entry. The same error then
    /// arrives from the same parser when the section is read.
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

    /// Sections this module does not read must cost nothing. They must not be mistaken for
    /// one it does, including a `%DESC%` whose free text could look like anything.
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

    /// [`DESC`] holds nine relation entries: two groups, three dependencies, two provides, one
    /// conflict and one replacement. The deferred `%DEPENDS%` counts, although nothing parses it
    /// here. Otherwise a flood of dependencies would pass the open and be built later, by the
    /// planner, with no bound at all.
    #[test]
    fn every_relation_entry_is_charged_including_the_deferred_dependencies() {
        let mut budget = RelationBudget::new(9);
        super::parse(DESC, &mut budget).unwrap();

        let error = super::parse(DESC, &mut RelationBudget::new(8)).unwrap_err();
        assert!(matches!(error, ScanError::Budget { max: 8 }), "got {error:?}");
    }

    /// The budget is the archive's, not one `desc`'s: a second package spends what the first
    /// left.
    #[test]
    fn the_budget_is_shared_by_every_desc_that_spends_it() {
        let mut budget = RelationBudget::new(12);
        super::parse(DESC, &mut budget).unwrap();

        let error = super::parse(DESC, &mut budget).unwrap_err();
        assert!(matches!(error, ScanError::Budget { max: 12 }), "got {error:?}");
    }

    /// Only relation sections are charged. `%CSIZE%`, `%ISIZE%` and every other section build
    /// no value that grows with its line count.
    #[test]
    fn other_sections_cost_nothing() {
        let text = format!("{}\n%DESC%\n{}", "%CSIZE%\n1\n\n%ISIZE%\n2\n", "text\n".repeat(100));
        super::parse(&text, &mut RelationBudget::new(0)).unwrap();
    }
}
