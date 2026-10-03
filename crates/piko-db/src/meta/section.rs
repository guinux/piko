//! The `%KEYWORD%` section grammar, shared by every `desc` and `files` reader and writer check.
//!
//! A section is a `%KEYWORD%` header line, then value lines up to the first empty line. That is
//! libalpm's reader (`be_local.c`, `be_sync.c:595`): `READ_AND_STORE_ALL` stops at the first
//! line of length zero. A line after that empty line and before the next header belongs to no
//! section, and is skipped. A header line also ends the section before it, with no empty line
//! between them.
//!
//! [`Sections`] yields each section in text order, a repeated keyword included. Whether a
//! repeat adds to the first occurrence or is refused is the caller's decision, because it
//! depends on the field.
//!
//! # Why this reader needs no bound of its own
//!
//! The reader builds nothing. A [`Section`] is three borrowed values, and [`Section::values`]
//! is an iterator over the text. So what the reader costs is bounded by the text, which the
//! caller has already read against a byte bound. What a caller *builds* from the values still
//! needs a count bound, as the relation budget of `crate::eager` shows.

use std::{iter::Peekable, ops::Range, str::Lines};

/// Extracts `KEYWORD` from a `%KEYWORD%` header line, if the line is one.
///
/// A header is `%`, then a non-empty keyword holding no further `%`, then `%`. This is the one
/// header grammar. [`Sections`], the text filters of [`crate::desc_compat`] and
/// `piko-db-write`'s record check all read a line through it, so a line never reads as a header
/// in one and as a value in another.
#[must_use]
pub fn section_keyword(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('%')?.strip_suffix('%')?;
    (!inner.is_empty() && !inner.contains('%')).then_some(inner)
}

/// One `%KEYWORD%` section of a text, borrowed from it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Section<'a> {
    /// The keyword, without the surrounding `%`.
    pub keyword: &'a str,
    /// The 1-based number of the header line.
    pub line: usize,
    /// The value lines, from the start of the first one to the end of the last one.
    ///
    /// Empty for a section with no value. Never holds an empty line.
    body: &'a str,
    /// Where `body` starts in the text, in bytes.
    start: usize,
}

impl<'a> Section<'a> {
    /// The value lines, in order. None of them is empty.
    pub fn values(&self) -> Lines<'a> {
        self.body.lines()
    }

    /// Where the value lines are in the text, as a byte range.
    ///
    /// For a section with no value, the range is empty and starts at the end of the header.
    #[must_use]
    pub const fn body_range(&self) -> Range<usize> {
        self.start..self.start.saturating_add(self.body.len())
    }
}

/// Every `%KEYWORD%` section of a text, in order.
#[derive(Debug)]
pub struct Sections<'a> {
    text: &'a str,
    lines: Peekable<Lines<'a>>,
    /// The number of lines already consumed.
    consumed: usize,
    /// The 1-based number of the first line that belongs to no section, if one was read.
    first_stray: Option<usize>,
}

impl<'a> Sections<'a> {
    /// Reads the sections of `text`.
    #[must_use]
    pub fn new(text: &'a str) -> Self {
        Self { text, lines: text.lines().peekable(), consumed: 0, first_stray: None }
    }

    /// The byte offset of `line` in the text.
    ///
    /// `str::lines` yields subslices of the text, so the offset is the distance between the
    /// two pointers.
    fn offset_of(&self, line: &str) -> usize {
        (line.as_ptr() as usize).saturating_sub(self.text.as_ptr() as usize)
    }

    /// The first non-empty line read so far that belongs to no section.
    ///
    /// Such a line comes before the first header, or after the empty line that ends a section.
    /// libalpm skips it, and so does this reader. A caller that must account for every line,
    /// such as the `files` reader, refuses the text instead.
    #[must_use]
    pub const fn first_stray_line(&self) -> Option<usize> {
        self.first_stray
    }

    /// The next line, counted.
    fn take_line(&mut self) -> Option<&'a str> {
        let line = self.lines.next()?;
        // The line count is bounded by the text length, so this cannot overflow.
        self.consumed = self.consumed.saturating_add(1);
        Some(line)
    }
}

impl<'a> Iterator for Sections<'a> {
    type Item = Section<'a>;

    fn next(&mut self) -> Option<Section<'a>> {
        // Skip to the next header. A line before it belongs to no section.
        let (keyword, header) = loop {
            let line = self.take_line()?;
            if let Some(keyword) = section_keyword(line) {
                break (keyword, line);
            }
            if !line.is_empty() && self.first_stray.is_none() {
                self.first_stray = Some(self.consumed);
            }
        };
        let line = self.consumed;
        let header_end = self.offset_of(header).saturating_add(header.len());
        let mut first = None;
        let mut last = header_end;

        while let Some(next) = self.lines.peek() {
            if next.is_empty() {
                // The empty line ends the section. It is consumed, and so is not read again.
                self.take_line();
                break;
            }
            if section_keyword(next).is_some() {
                // A header ends the section too. It is left for the next call.
                break;
            }
            let Some(value) = self.take_line() else { break };
            let offset = self.offset_of(value);
            first.get_or_insert(offset);
            last = offset.saturating_add(value.len());
        }

        let start = first.unwrap_or(header_end);
        let body = first.and_then(|first| self.text.get(first..last)).unwrap_or_default();
        Some(Section { keyword, line, body, start })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(keyword, values)` of every section of `text`.
    fn read(text: &str) -> Vec<(&str, Vec<&str>)> {
        Sections::new(text).map(|section| (section.keyword, section.values().collect())).collect()
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

    #[test]
    fn reads_every_section_in_order() {
        let text = "%NAME%\nfoo\n\n%DEPENDS%\nbar\nbaz\n\n";
        assert_eq!(read(text), [("NAME", vec!["foo"]), ("DEPENDS", vec!["bar", "baz"])]);
    }

    /// A section's values run to the first empty line, as `READ_AND_STORE_ALL` reads them. A
    /// line after it and before the next header belongs to no section.
    #[test]
    fn an_empty_line_ends_a_section() {
        let text = "%DEPENDS%\nfoo\n\nbar\n\n%PROVIDES%\nbaz\n";
        assert_eq!(read(text), [("DEPENDS", vec!["foo"]), ("PROVIDES", vec!["baz"])]);
    }

    #[test]
    fn a_header_ends_the_section_before_it() {
        let text = "%FUTURE%\nignored\n%NAME%\nfoo\n";
        assert_eq!(read(text), [("FUTURE", vec!["ignored"]), ("NAME", vec!["foo"])]);
    }

    #[test]
    fn a_repeated_section_is_yielded_twice() {
        let text = "%DEPENDS%\nfoo\n\n%PROVIDES%\nbaz\n\n%DEPENDS%\nbar\n";
        assert_eq!(
            read(text),
            [("DEPENDS", vec!["foo"]), ("PROVIDES", vec!["baz"]), ("DEPENDS", vec!["bar"])]
        );
    }

    /// `%A%B%` is not a header, so it is a value, and it does not end the section before it.
    #[test]
    fn a_value_shaped_like_a_bad_header_is_a_value() {
        assert_eq!(read("%GROUPS%\nbase\n%A%B%\n"), [("GROUPS", vec!["base", "%A%B%"])]);
    }

    #[test]
    fn a_value_line_starting_with_a_percent_sign_is_kept() {
        assert_eq!(read("%DESC%\n100% pure\n\n"), [("DESC", vec!["100% pure"])]);
    }

    #[test]
    fn a_section_with_no_value_is_still_yielded() {
        let text = "%URL%\n\n%NAME%\nfoo\n";
        assert_eq!(read(text), [("URL", vec![]), ("NAME", vec!["foo"])]);
    }

    #[test]
    fn lines_before_the_first_header_belong_to_no_section() {
        assert_eq!(read("stray\n\n%NAME%\nfoo\n"), [("NAME", vec!["foo"])]);
    }

    #[test]
    fn a_stray_line_is_skipped_and_reported() {
        let mut sections = Sections::new("%FILES%\na\n\nb\n\nc\n");
        assert_eq!(sections.by_ref().count(), 1);
        assert_eq!(sections.first_stray_line(), Some(4));

        let mut clean = Sections::new("%FILES%\na\n\n\n%BACKUP%\n");
        assert_eq!(clean.by_ref().count(), 2);
        assert_eq!(clean.first_stray_line(), None, "an empty line is not a stray line");
    }

    #[test]
    fn an_empty_text_has_no_section() {
        assert!(read("").is_empty());
        assert!(read("\n\n").is_empty());
    }

    #[test]
    fn reports_the_line_number_of_each_header() {
        let lines: Vec<_> = Sections::new("%NAME%\nfoo\n\n%FUTURE%\nx\n").map(|s| s.line).collect();
        assert_eq!(lines, [1, 4]);
    }

    /// The body range is what a deferred section is read back from, so it must cover exactly
    /// the value lines.
    #[test]
    fn the_body_range_covers_the_value_lines() {
        let text = "%NAME%\nfoo\n\n%DEPENDS%\nbar\nbaz\n\n%URL%\n\n";
        let ranges: Vec<_> =
            Sections::new(text).map(|s| text.get(s.body_range()).map(str::to_owned)).collect();
        assert_eq!(
            ranges,
            [Some("foo".to_owned()), Some("bar\nbaz".to_owned()), Some(String::new())]
        );
    }

    /// A carriage return before the line feed is not part of the value, as `str::lines`
    /// reads it.
    #[test]
    fn a_crlf_line_ending_is_not_part_of_the_value() {
        assert_eq!(
            read("%NAME%\r\nfoo\r\n\r\n%ARCH%\r\nany\r\n"),
            [("NAME", vec!["foo"]), ("ARCH", vec!["any"])]
        );
    }
}
