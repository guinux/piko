//! Forward compatibility for `%SECTION%`-shaped metadata, shared by both databases.
//!
//! `alpm-db` rejects a `desc` containing a `%KEY%` it does not know. libalpm instead warns
//! and skips the block. This is precisely what lets pacman keep reading a database after a
//! newer pacman has written a section it has never heard of. A package manager that refuses
//! to read its own database after a partial upgrade is not robust. piko follows libalpm by
//! default — see [`UnknownSectionPolicy`].
//!
//! This module holds only the part both databases share. The local `desc` view lives in
//! [`crate::local::desc_compat`], and the repository one in [`crate::repo::desc_compat`].
//! [`filter_unknown_sections`] is deliberately reused by both rather than duplicated: the two
//! formats have different keyword sets, but the identical section grammar.
//!
//! [`take_url`] and [`DescUrl`] are here for the same reason: `%URL%` is the one section both
//! formats hand to a parser that can refuse a value libalpm prints verbatim, and both parsers
//! convert every section or none.

use std::{borrow::Cow, str::FromStr as _};

use alpm_types::Url;

/// What to do about a `%SECTION%` this build does not recognise.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UnknownSectionPolicy {
    /// Drop the section and record a diagnostic, as libalpm does.
    ///
    /// This is the default. It keeps a database written by a newer pacman readable, at the
    /// cost of ignoring data piko does not understand.
    #[default]
    Warn,

    /// Refuse to parse the file.
    ///
    /// Appropriate when a database is being audited rather than used, and any surprise
    /// should stop the process.
    Reject,
}

/// A `%SECTION%` that was dropped because this build does not recognise it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownSection {
    /// The section keyword, without the surrounding `%`.
    pub keyword: String,
    /// The 1-based line number the section header appeared on.
    pub line: usize,
}

/// Removes sections `alpm-db` would reject, returning the filtered text.
///
/// A section is a `%KEYWORD%` header line followed by value lines, terminated by a blank
/// line or end of input — the same shape libalpm's reader assumes. `is_known` decides
/// whether a `%KEYWORD%` is recognised. It is a parameter rather than a hardcoded lookup, so
/// this same pre-pass serves both the local `desc` format and the repository `desc` format.
/// The two have different (though overlapping) keyword sets — see
/// [`crate::repo::desc_compat`].
///
/// Returns the text to parse and the sections that were dropped.
pub(crate) fn filter_unknown_sections(
    text: &str,
    is_known: impl Fn(&str) -> bool,
) -> (String, Vec<UnknownSection>) {
    let mut kept = String::with_capacity(text.len());
    let mut unknown = Vec::new();
    let mut skipping = false;

    for (index, line) in text.lines().enumerate() {
        if let Some(keyword) = section_keyword(line) {
            skipping = !is_known(keyword);
            if skipping {
                // `index` is bounded by the line count, so this cannot overflow.
                unknown.push(UnknownSection {
                    keyword: keyword.to_owned(),
                    line: index.saturating_add(1),
                });
                continue;
            }
        } else if line.trim().is_empty() {
            // A blank line ends the current block, whether or not it was being skipped.
            skipping = false;
        } else if skipping {
            continue;
        }

        kept.push_str(line);
        kept.push('\n');
    }

    (kept, unknown)
}

/// Splits `%URL%` out of a `desc`: the text to hand to the upstream parser, and the raw value.
///
/// `alpm-db` and `alpm-repo-db` convert `%URL%` with `alpm_types::Url`, which is
/// `url::Url::parse` and rejects anything without an absolute scheme. Both parsers convert
/// every section or none, so a `%URL%` libalpm would print verbatim otherwise takes the whole
/// `desc` down with it — and with it the package's name, its dependencies, and the file name
/// an install needs.
///
/// The value lines are blanked, the header is not removed: `alpm-db` requires `%URL%` to be
/// present, and accepts it empty. Only the first `%URL%` is touched, so a duplicated section
/// still reaches the upstream parser and is still reported as one.
///
/// Returns [`Cow::Borrowed`] when there is nothing to blank — an absent or already-empty
/// section, which is every `desc` that has no URL to lose.
pub(crate) fn take_url(text: &str) -> (Cow<'_, str>, Option<&str>) {
    let Some(value) = first_url_value(text) else {
        return (Cow::Borrowed(text), None);
    };

    let mut kept = String::with_capacity(text.len());
    let mut in_url = false;
    let mut passed = false;

    for line in text.lines() {
        if let Some(keyword) = section_keyword(line) {
            in_url = !passed && keyword == "URL";
            passed |= in_url;
        } else if line.trim().is_empty() {
            in_url = false;
        } else if in_url {
            // A scalar section holds one line, but drop the whole block rather than assume
            // it: libalpm ignores the extra lines too, since they match no `%KEYWORD%`.
            continue;
        }

        kept.push_str(line);
        kept.push('\n');
    }

    (Cow::Owned(kept), Some(value))
}

/// The first value line of the first `%URL%` section, if it has one.
fn first_url_value(text: &str) -> Option<&str> {
    let mut in_url = false;

    for line in text.lines() {
        if let Some(keyword) = section_keyword(line) {
            if in_url {
                // The section ended at the next header, with no value line.
                return None;
            }
            in_url = keyword == "URL";
        } else if line.trim().is_empty() {
            if in_url {
                return None;
            }
        } else if in_url {
            return Some(line);
        }
    }

    None
}

/// A `desc`'s `%URL%`, kept as written and normalized separately.
///
/// The raw value is the one libalpm has: `be_local.c:1010` copies the string through
/// untouched. The normalized one is what `piko info` prints, and what a caller wanting to
/// inspect a scheme or a host needs. A value that does not parse is simply not normalized —
/// [`DescUrl::parsed`] is `None` and [`DescUrl::raw`] still has the bytes.
#[derive(Debug, Default)]
pub(crate) struct DescUrl {
    raw: Option<Box<str>>,
    parsed: Option<Url>,
}

impl DescUrl {
    /// Normalizes `raw`, keeping the bytes either way.
    pub(crate) fn new(raw: Option<&str>) -> Self {
        Self { raw: raw.map(Box::from), parsed: raw.and_then(|value| Url::from_str(value).ok()) }
    }

    /// The normalized form, or `None` when the section was absent, empty, or unparsable.
    pub(crate) const fn parsed(&self) -> Option<&Url> {
        self.parsed.as_ref()
    }

    /// The value exactly as the `desc` holds it.
    pub(crate) fn raw(&self) -> Option<&str> {
        self.raw.as_deref()
    }
}

/// Extracts `KEYWORD` from a `%KEYWORD%` header line, if the line is one.
fn section_keyword(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('%')?.strip_suffix('%')?;
    (!inner.is_empty() && !inner.contains('%')).then_some(inner)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use alpm_common::MetadataFile as _;
    use alpm_db::desc::DbDescFile;

    use super::*;
    use crate::fixture::MINIMAL_DESC_V1;
    use crate::local::desc_compat::DescView;

    fn parse(text: &str) -> DbDescFile {
        DbDescFile::from_str_with_schema(text, None).unwrap()
    }

    fn known(keyword: &str) -> bool {
        alpm_db::desc::SectionKeyword::from_str(keyword).is_ok()
    }

    fn filter(text: &str) -> (String, Vec<UnknownSection>) {
        filter_unknown_sections(text, known)
    }

    #[test]
    fn a_well_formed_desc_is_passed_through_unchanged_in_meaning() {
        let (filtered, unknown) = filter(MINIMAL_DESC_V1);
        assert!(unknown.is_empty(), "{unknown:?}");
        assert!(parse(&filtered).eq(&parse(MINIMAL_DESC_V1)));
    }

    /// The forward-compatibility guarantee: a `desc` written by a newer pacman must still
    /// load, minus the parts we cannot interpret.
    #[test]
    fn drops_an_unknown_section_and_still_parses() {
        let text = format!("{MINIMAL_DESC_V1}%FUTURE_THING%\nsomething\nsomething else\n\n");
        let (filtered, unknown) = filter(&text);

        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown.first().map(|s| s.keyword.as_str()), Some("FUTURE_THING"));
        assert!(!filtered.contains("something"), "the block body must be dropped too");

        let desc = parse(&filtered);
        assert_eq!(DescView::new(&desc, &DescUrl::default()).name().as_ref(), "foo");
    }

    /// `%MAKEDEPENDS%` and `%CHECKDEPENDS%` are read by libalpm but not modelled by
    /// `alpm-db`. They are the concrete case this filter exists for.
    #[test]
    fn drops_sections_libalpm_reads_but_alpm_db_does_not_model() {
        let text = format!(
            "{MINIMAL_DESC_V1}%MAKEDEPENDS%\ncmake\nninja\n\n%CHECKDEPENDS%\npython-pytest\n\n"
        );
        let (filtered, unknown) = filter(&text);

        let keywords: Vec<_> = unknown.iter().map(|s| s.keyword.as_str()).collect();
        assert_eq!(keywords, ["MAKEDEPENDS", "CHECKDEPENDS"]);
        assert!(!filtered.contains("cmake"));
        assert!(!filtered.contains("python-pytest"));
        assert_eq!(DescView::new(&parse(&filtered), &DescUrl::default()).name().as_ref(), "foo");
    }

    /// A dropped block must not swallow the section that follows it.
    #[test]
    fn a_known_section_after_an_unknown_one_survives() {
        let text = "%FUTURE%\nignored\n\n%NAME%\nfoo\n\n";
        let (filtered, unknown) = filter(text);

        assert_eq!(unknown.len(), 1);
        assert!(filtered.contains("%NAME%\nfoo"), "{filtered:?}");
        assert!(!filtered.contains("ignored"));
    }

    #[test]
    fn take_url_returns_the_value_and_blanks_the_section() {
        let (text, url) = take_url(MINIMAL_DESC_V1);

        assert_eq!(url, Some("https://example.org/"));
        assert!(text.contains("%URL%\n\n"), "the header stays, the value goes: {text:?}");
        assert!(!text.contains("example.org"));
        assert!(parse(&text).eq(&parse(&text)), "the blanked text still parses");
    }

    /// The section is mandatory for `alpm-db`, so blanking it must not remove it. This is the
    /// measurement that decided the shape of `take_url`: an absent `%URL%` is `MissingSection`,
    /// an empty one is `None`.
    #[test]
    fn a_desc_with_its_url_blanked_still_parses() {
        let (text, _) = take_url(MINIMAL_DESC_V1);
        assert_eq!(DescView::new(&parse(&text), &DescUrl::default()).name().as_ref(), "foo");
    }

    #[test]
    fn take_url_borrows_when_there_is_nothing_to_blank() {
        let absent = "%NAME%\nfoo\n\n";
        let (text, url) = take_url(absent);
        assert!(matches!(text, Cow::Borrowed(_)), "no copy for a desc with no %URL%");
        assert_eq!(url, None);

        let empty = "%NAME%\nfoo\n\n%URL%\n\n";
        let (text, url) = take_url(empty);
        assert!(matches!(text, Cow::Borrowed(_)), "no copy for an empty %URL%");
        assert_eq!(url, None);
    }

    /// A `%URL%` at the very end of the file, with no blank line after it.
    #[test]
    fn take_url_reads_a_value_that_ends_the_file() {
        let (text, url) = take_url("%NAME%\nfoo\n\n%URL%\nhttps://example.org/\n");
        assert_eq!(url, Some("https://example.org/"));
        assert!(!text.contains("example.org"));
    }

    /// Only the first `%URL%` is blanked, so `alpm-db` still sees — and still reports — the
    /// duplicate. Swallowing the second one would turn a malformed file into a silent one.
    #[test]
    fn take_url_leaves_a_second_url_section_alone() {
        let text = "%URL%\nhttps://example.org/\n\n%URL%\nhttps://other.example/\n\n";
        let (text, url) = take_url(text);

        assert_eq!(url, Some("https://example.org/"));
        assert!(text.contains("https://other.example/"), "{text:?}");
    }

    /// Without a blank line between them, the header itself must still end the skip.
    #[test]
    fn an_unknown_section_not_terminated_by_a_blank_line_still_ends_at_the_next_header() {
        let text = "%FUTURE%\nignored\n%NAME%\nfoo\n";
        let (filtered, unknown) = filter(text);

        assert_eq!(unknown.len(), 1);
        assert!(filtered.contains("%NAME%\nfoo"), "{filtered:?}");
        assert!(!filtered.contains("ignored"));
    }

    #[test]
    fn reports_the_line_number_of_an_unknown_section() {
        let text = "%NAME%\nfoo\n\n%FUTURE%\nx\n";
        let (_, unknown) = filter(text);
        assert_eq!(unknown.first().map(|s| s.line), Some(4));
    }

    #[test]
    fn recognises_only_well_formed_headers() {
        assert_eq!(section_keyword("%NAME%"), Some("NAME"));
        assert_eq!(section_keyword("NAME"), None);
        assert_eq!(section_keyword("%NAME"), None);
        assert_eq!(section_keyword("%%"), None);
        assert_eq!(section_keyword("%A%B%"), None, "a value containing '%' is not a header");
        assert_eq!(section_keyword("100% done"), None);
    }

    /// A value line that merely starts with '%' must not be mistaken for a header and
    /// silently dropped.
    #[test]
    fn a_value_line_starting_with_a_percent_sign_is_kept() {
        let text = "%DESC%\n100% pure\n\n";
        let (filtered, unknown) = filter(text);
        assert!(unknown.is_empty(), "{unknown:?}");
        assert!(filtered.contains("100% pure"));
    }

    #[test]
    fn an_empty_input_produces_no_sections() {
        let (filtered, unknown) = filter("");
        assert!(filtered.is_empty());
        assert!(unknown.is_empty());
    }
}
