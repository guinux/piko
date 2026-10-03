//! Typed reading of `desc` sections, one field at a time.
//!
//! A `desc` holds two kinds of field. A field that decides something, such as `%NAME%` or a
//! relation section, must be valid, or the entry cannot be used. A field that is only shown,
//! such as `%LICENSE%` or `%PACKAGER%`, gets its own [`Result`]. One invalid value then costs
//! that field, and the caller reports it, but every other field stays readable.
//!
//! [`Index`] finds each known section once. Its methods convert one field each, with the
//! value parser of `alpm-types`.

use std::str::FromStr;

use alpm_types::{Packager, Url};

use crate::{
    desc_compat::{UNKNOWN_PACKAGER, UnknownSection},
    eager::DescFieldError,
    meta::section::{Section, Sections},
};

/// The known sections of one `desc`, in text order, and the unknown ones.
#[derive(Debug)]
pub(crate) struct Index<'a> {
    sections: Vec<Section<'a>>,
    /// The sections whose keyword is not in the known list, in text order.
    pub(crate) unknown: Vec<UnknownSection>,
}

impl<'a> Index<'a> {
    /// Reads the sections of `text`, and sorts them into known and unknown by `known`.
    pub(crate) fn new(text: &'a str, known: &[&str]) -> Self {
        let mut sections = Vec::new();
        let mut unknown = Vec::new();
        for section in Sections::new(text) {
            if known.contains(&section.keyword) {
                sections.push(section);
            } else {
                unknown.push(UnknownSection {
                    keyword: section.keyword.to_owned(),
                    line: section.line,
                });
            }
        }
        Self { sections, unknown }
    }

    /// Every section named `keyword`, in text order.
    fn all(&self, keyword: &str) -> impl Iterator<Item = &Section<'a>> {
        self.sections.iter().filter(move |section| section.keyword == keyword)
    }

    /// The one value line of a scalar section, or `None` when the section is absent.
    ///
    /// A section with no value line reads as an empty value, as libalpm reads it.
    ///
    /// # Errors
    ///
    /// - [`DescFieldError::DuplicateSection`] if the section appears twice. A scalar has one
    ///   value, so a second section is not something to add to the first.
    /// - [`DescFieldError::TooManyValues`] if the section holds more than one value line.
    pub(crate) fn scalar(&self, keyword: &'static str) -> Result<Option<&'a str>, DescFieldError> {
        let mut found = self.all(keyword);
        let Some(section) = found.next() else { return Ok(None) };
        if found.next().is_some() {
            return Err(DescFieldError::DuplicateSection { section: keyword });
        }
        let mut values = section.values();
        let value = values.next().unwrap_or_default();
        if values.next().is_some() {
            return Err(DescFieldError::TooManyValues { section: keyword });
        }
        Ok(Some(value))
    }

    /// A scalar section that must be present, converted by `parse`.
    ///
    /// # Errors
    ///
    /// [`DescFieldError::MissingSection`] if the section is absent, or what [`Self::scalar`]
    /// and `parse` return.
    pub(crate) fn required<T>(
        &self,
        keyword: &'static str,
        parse: impl FnOnce(&str) -> Result<T, DescFieldError>,
    ) -> Result<T, DescFieldError> {
        let value =
            self.scalar(keyword)?.ok_or(DescFieldError::MissingSection { section: keyword })?;
        parse(value)
    }

    /// Every value line of every section named `keyword`, converted by `parse`.
    ///
    /// A repeated section adds to the first, as `alpm_list_add` does.
    ///
    /// # Errors
    ///
    /// The first error `parse` returns.
    pub(crate) fn list<T>(
        &self,
        keyword: &'static str,
        mut parse: impl FnMut(&str) -> Result<T, DescFieldError>,
    ) -> Result<Box<[T]>, DescFieldError> {
        self.all(keyword).flat_map(Section::values).map(&mut parse).collect()
    }

    /// Whether a section named `keyword` is present.
    pub(crate) fn has(&self, keyword: &str) -> bool {
        self.all(keyword).next().is_some()
    }
}

/// `%URL%`, kept as written and normalized separately.
///
/// libalpm copies the value through untouched (`be_local.c:1010`, `be_sync.c`). The normalized
/// form is what a caller that inspects a scheme or a host needs. A value `url::Url` refuses is
/// not normalized, and costs nothing else.
#[derive(Debug)]
pub(crate) struct UrlField {
    raw: Result<Option<Box<str>>, DescFieldError>,
    parsed: Option<Url>,
}

impl UrlField {
    /// Reads `%URL%`. An absent or empty section has no value.
    pub(crate) fn read(index: &Index<'_>) -> Self {
        let raw =
            index.scalar("URL").map(|value| value.filter(|value| !value.is_empty()).map(Box::from));
        let parsed = raw
            .as_ref()
            .ok()
            .and_then(Option::as_deref)
            .and_then(|value| Url::from_str(value).ok());
        Self { raw, parsed }
    }

    /// The value exactly as the `desc` holds it.
    pub(crate) fn raw(&self) -> Option<&str> {
        self.raw.as_ref().ok().and_then(Option::as_deref)
    }

    /// The normalized form, or `None` when the value is absent, empty or not a URL.
    pub(crate) const fn parsed(&self) -> Option<&Url> {
        self.parsed.as_ref()
    }

    /// Why the section could not be read: it appears twice, or holds two values.
    pub(crate) fn error(&self) -> Option<&DescFieldError> {
        self.raw.as_ref().err()
    }
}

/// `%PACKAGER%`, kept as written and parsed separately.
///
/// libalpm copies the value through untouched (`be_local.c:786`, `be_sync.c:637`).
#[derive(Debug)]
pub(crate) struct PackagerField {
    raw: Result<Option<Box<str>>, DescFieldError>,
    parsed: Option<Packager>,
    /// Why the value has no typed form, when the reason is a defect. makepkg's
    /// [`UNKNOWN_PACKAGER`] default is not one: it is what a locally built package carries when
    /// its builder set no `PACKAGER`.
    defect: Option<DescFieldError>,
}

impl PackagerField {
    /// Reads `%PACKAGER%`.
    pub(crate) fn read(index: &Index<'_>) -> Self {
        let raw = index.scalar("PACKAGER").map(|value| value.map(Box::from));
        let (parsed, defect) = match &raw {
            Ok(Some(value)) => match typed::<Packager>("PACKAGER")(value) {
                Ok(parsed) => (Some(parsed), None),
                Err(_) if &**value == UNKNOWN_PACKAGER => (None, None),
                Err(error) => (None, Some(error)),
            },
            Ok(None) => (None, Some(DescFieldError::MissingSection { section: "PACKAGER" })),
            // The raw value carries the error, and is reported once.
            Err(_) => (None, None),
        };
        Self { raw, parsed, defect }
    }

    /// The value exactly as the `desc` holds it.
    pub(crate) fn raw(&self) -> Option<&str> {
        self.raw.as_ref().ok().and_then(Option::as_deref)
    }

    /// The typed form, or `None` when the value is absent or not a valid packager.
    pub(crate) const fn parsed(&self) -> Option<&Packager> {
        self.parsed.as_ref()
    }

    /// Why the section is a defect, if it is one.
    pub(crate) fn error(&self) -> Option<&DescFieldError> {
        self.raw.as_ref().err().or(self.defect.as_ref())
    }
}

/// `list`, unless it is empty.
///
/// # Errors
///
/// [`DescFieldError::MissingSection`] for an empty list.
pub(crate) fn non_empty<T>(
    list: Box<[T]>,
    section: &'static str,
) -> Result<Box<[T]>, DescFieldError> {
    if list.is_empty() { Err(DescFieldError::MissingSection { section }) } else { Ok(list) }
}

/// Converts `value` with the `alpm-types` parser of `T`.
///
/// # Errors
///
/// [`DescFieldError::InvalidEntry`], naming `section` and the value.
pub(crate) fn typed<T>(section: &'static str) -> impl Fn(&str) -> Result<T, DescFieldError>
where
    T: FromStr<Err = alpm_types::Error>,
{
    move |value| {
        T::from_str(value).map_err(|source| DescFieldError::InvalidEntry {
            section,
            value: value.to_owned(),
            source,
        })
    }
}

/// Converts `value` with a parser whose error is not an `alpm-types` one, such as a keyword
/// list.
///
/// # Errors
///
/// [`DescFieldError::InvalidValue`], naming `section` and the value.
pub(crate) fn named<T: FromStr>(
    section: &'static str,
) -> impl Fn(&str) -> Result<T, DescFieldError> {
    move |value| {
        T::from_str(value)
            .map_err(|_| DescFieldError::InvalidValue { section, value: value.to_owned() })
    }
}

/// Converts `value` as a decimal integer.
///
/// # Errors
///
/// [`DescFieldError::InvalidSize`], naming `section` and the value.
pub(crate) fn number<T: FromStr>(
    section: &'static str,
) -> impl Fn(&str) -> Result<T, DescFieldError> {
    move |value| crate::eager::scalar(value, section)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use alpm_types::{License, Name};

    use super::*;

    const KNOWN: &[&str] = &["NAME", "LICENSE", "SIZE"];

    #[test]
    fn a_scalar_reads_its_one_value() {
        let index = Index::new("%NAME%\nfoo\n\n%SIZE%\n12\n", KNOWN);
        let name: Name = index.required("NAME", typed("NAME")).unwrap();
        assert_eq!(name.as_ref(), "foo");
        assert_eq!(index.required("SIZE", number::<u64>("SIZE")).unwrap(), 12);
    }

    #[test]
    fn a_scalar_with_no_value_reads_as_empty() {
        let index = Index::new("%NAME%\n\n", KNOWN);
        assert_eq!(index.scalar("NAME").unwrap(), Some(""));
    }

    #[test]
    fn a_scalar_refuses_two_sections_and_two_values() {
        let twice = Index::new("%NAME%\nfoo\n\n%NAME%\nbar\n", KNOWN);
        assert!(matches!(twice.scalar("NAME"), Err(DescFieldError::DuplicateSection { .. })));

        let two_values = Index::new("%NAME%\nfoo\nbar\n", KNOWN);
        assert!(matches!(two_values.scalar("NAME"), Err(DescFieldError::TooManyValues { .. })));
    }

    #[test]
    fn a_missing_required_section_is_named() {
        let index = Index::new("%SIZE%\n1\n", KNOWN);
        let missing = index.required("NAME", typed::<Name>("NAME"));
        assert!(matches!(missing, Err(DescFieldError::MissingSection { section: "NAME" })));
    }

    #[test]
    fn a_list_adds_a_repeated_section_to_the_first() {
        let index = Index::new("%LICENSE%\nMIT\n\n%NAME%\nfoo\n\n%LICENSE%\nGPL-3.0-only\n", KNOWN);
        let licenses: Box<[License]> = index.list("LICENSE", typed("LICENSE")).unwrap();
        let licenses: Vec<_> = licenses.iter().map(ToString::to_string).collect();
        assert_eq!(licenses, ["MIT", "GPL-3.0-only"]);
    }

    #[test]
    fn an_unknown_section_is_set_aside_with_its_line() {
        let index = Index::new("%NAME%\nfoo\n\n%FUTURE%\nx\n", KNOWN);
        assert_eq!(index.unknown, [UnknownSection { keyword: "FUTURE".to_owned(), line: 4 }]);
        assert!(!index.has("FUTURE"));
    }
}
