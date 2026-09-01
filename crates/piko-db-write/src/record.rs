//! A `desc` or `files` file as an ordered list of raw sections.
//!
//! # Why not `alpm-db`'s types
//!
//! Principle 1 says to reuse the official crates for parsing, and the reader does exactly
//! that. The writer cannot. The reason is measured, not assumed. Rendering all 1158 entries
//! of the real local database through `alpm-db`'s `Display`, then comparing byte for byte
//! against what pacman wrote, gives this result:
//!
//! | | `desc` | `files` |
//! |---|---|---|
//! | byte-identical | 1033 | 839 |
//! | `%URL%` gained a trailing `/` | 105 | — |
//! | `%REASON%`/`%GROUPS%` emitted in the opposite order | 20 | — |
//! | list reordered (component-wise vs byte-wise sort) | — | 269 |
//! | missing blank line after the last section | — | 48 |
//! | **`%BACKUP%` entries dropped** | — | 2 (3 entries) |
//!
//! Only the middle rows are cosmetic. The last row is data loss. pacman records a backup
//! entry with the literal hash `(null)` when it could not hash the file. `alpm-db` discards
//! those entries at parse time. A package whose `etc/gdm/PostSession/Default` silently
//! carried `%BACKUP%` gets overwritten on its next upgrade with no `.pacsave`. The loss
//! happens in the *parser*, so no amount of fixing the emitter recovers it.
//!
//! The writer therefore keeps its own representation. It is deliberately dumb: a section
//! keyword and its value lines, both preserved as written. Every bit of interpretation is a
//! bit that can be lost, so interpretation stays on the reading side, where losing it is
//! harmless.
//!
//! # The format
//!
//! Every section in both files has the same shape. This is what makes this module work:
//!
//! ```text
//! %KEYWORD%
//! value
//! value
//! <blank>
//! ```
//!
//! `_alpm_local_db_write` (`be_local.c:972`) emits `desc` this way for single-valued fields
//! (`fprintf("%%NAME%%\n%s\n\n")`) and for lists (`write_deps`) alike, and emits `files` the
//! same way for `%FILES%` and `%BACKUP%`. A file is a concatenation of such sections and
//! nothing else, so it ends with a blank line whenever it is not empty.

use std::fmt::Write as _;

/// Which file a [`Record`] represents.
///
/// The only thing this decides is where [`Record::set`] inserts a section that is not
/// already present — see [`RecordKind::order`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    /// An entry's `desc` file.
    Desc,
    /// An entry's `files` file.
    Files,
}

/// `desc` section keywords in the order `_alpm_local_db_write` emits them
/// (`be_local.c:997-1075`).
///
/// `%REASON%` comes before `%GROUPS%` here. `alpm-db`'s `Display` has these the other way
/// round, which accounts for 20 of the 1158 real entries.
const DESC_ORDER: &[&str] = &[
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
    "REASON",
    "GROUPS",
    "LICENSE",
    "VALIDATION",
    "REPLACES",
    "DEPENDS",
    "OPTDEPENDS",
    "CONFLICTS",
    "PROVIDES",
    "XDATA",
];

/// `files` section keywords in the order `_alpm_local_db_write` emits them
/// (`be_local.c:1084-1106`).
const FILES_ORDER: &[&str] = &["FILES", "BACKUP"];

impl RecordKind {
    /// The canonical section order for this file.
    #[must_use]
    pub const fn order(self) -> &'static [&'static str] {
        match self {
            Self::Desc => DESC_ORDER,
            Self::Files => FILES_ORDER,
        }
    }
}

/// One `%KEYWORD%` block and its value lines, exactly as they appear on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Section {
    keyword: String,
    values: Vec<String>,
}

impl Section {
    /// Builds a section from a keyword (without the surrounding `%`) and its values.
    #[must_use]
    pub fn new(keyword: impl Into<String>, values: Vec<String>) -> Self {
        Self { keyword: keyword.into(), values }
    }

    /// The section keyword, without the surrounding `%`.
    #[must_use]
    pub fn keyword(&self) -> &str {
        &self.keyword
    }

    /// The value lines, as written.
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.values
    }
}

/// Why a `desc` or `files` file could not be represented for rewriting.
///
/// Both variants mean the file is not in the shape `_alpm_local_db_write` produces. The
/// writer refuses rather than guessing. The alternative would write back a file that
/// silently dropped whatever it did not understand, which is the exact failure this module
/// exists to avoid.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecordError {
    /// A value line appeared before any `%KEYWORD%` header.
    #[error("line {line} has no section: {content:?}")]
    ValueOutsideSection {
        /// The 1-based line number.
        line: usize,
        /// The offending line, truncated for display.
        content: String,
    },

    /// The same `%KEYWORD%` appeared twice.
    ///
    /// A rewrite would have to choose which one to keep. Either choice loses data.
    #[error("section %{keyword}% appears more than once, first again at line {line}")]
    DuplicateSection {
        /// The repeated keyword.
        keyword: String,
        /// The 1-based line number of the repeat.
        line: usize,
    },
}

/// A `desc` or `files` file, preserved well enough to write back unchanged.
///
/// [`Record::parse`] followed by [`Record::render`] is the identity on every file
/// `_alpm_local_db_write` can produce. This is verified byte for byte against all 1158
/// entries of the real local database, for both file kinds.
#[derive(Clone, Debug)]
pub struct Record {
    kind: RecordKind,
    sections: Vec<Section>,
}

impl Record {
    /// An empty record.
    #[must_use]
    pub const fn new(kind: RecordKind) -> Self {
        Self { kind, sections: Vec::new() }
    }

    /// Parses `text` into its sections, keeping every value line verbatim.
    ///
    /// A blank line ends the current section. This matches the reader in `local_db_read`
    /// (`be_local.c:770`), which also treats a blank line as a terminator, not as a value.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError`] if the text is not a plain concatenation of sections.
    pub fn parse(kind: RecordKind, text: &str) -> Result<Self, RecordError> {
        let mut sections: Vec<Section> = Vec::new();
        let mut current: Option<Section> = None;

        for (index, line) in text.lines().enumerate() {
            // The line count bounds `index`, so this cannot overflow.
            let line_number = index.saturating_add(1);

            if let Some(keyword) = section_keyword(line) {
                if let Some(section) = current.take() {
                    sections.push(section);
                }
                if sections.iter().any(|section| section.keyword == keyword) {
                    return Err(RecordError::DuplicateSection {
                        keyword: keyword.to_owned(),
                        line: line_number,
                    });
                }
                current = Some(Section::new(keyword, Vec::new()));
                continue;
            }

            if line.is_empty() {
                if let Some(section) = current.take() {
                    sections.push(section);
                }
                continue;
            }

            match current.as_mut() {
                Some(section) => section.values.push(line.to_owned()),
                None => {
                    return Err(RecordError::ValueOutsideSection {
                        line: line_number,
                        content: truncate(line),
                    });
                }
            }
        }

        // A file that ends without a blank line still closes its last section.
        if let Some(section) = current.take() {
            sections.push(section);
        }

        Ok(Self { kind, sections })
    }

    /// Renders the record back to the on-disk form.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for section in &self.sections {
            // Writing to a `String` is infallible, so this `Result` carries no information.
            let _ = writeln!(out, "%{}%", section.keyword);
            for value in &section.values {
                out.push_str(value);
                out.push('\n');
            }
            out.push('\n');
        }
        out
    }

    /// Which file this record represents.
    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        self.kind
    }

    /// The sections, in the order they will be rendered.
    #[must_use]
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// The value lines of `keyword`, if the section is present.
    #[must_use]
    pub fn get(&self, keyword: &str) -> Option<&[String]> {
        self.sections.iter().find(|section| section.keyword == keyword).map(Section::values)
    }

    /// Sets `keyword` to `values`, replacing the section in place if it already exists.
    ///
    /// An empty `values` removes the section rather than writing an empty one. libalpm never
    /// emits an empty section: every writer of a list guards on the list being non-empty
    /// (`write_deps` returns early on `NULL`), and every writer of a scalar guards on the
    /// value being present.
    ///
    /// A section not already present is inserted at its position in [`RecordKind::order`],
    /// not appended. The point of this type is that a rewritten file is indistinguishable
    /// from one pacman wrote. A keyword absent from that table — a section from a newer
    /// pacman, which the reader deliberately tolerates — goes last, since there is nothing
    /// better to infer.
    pub fn set(&mut self, keyword: &str, values: Vec<String>) {
        if values.is_empty() {
            self.remove(keyword);
            return;
        }

        if let Some(section) = self.sections.iter_mut().find(|s| s.keyword == keyword) {
            section.values = values;
            return;
        }

        let section = Section::new(keyword, values);
        match self.insertion_point(keyword) {
            Some(index) => self.sections.insert(index, section),
            None => self.sections.push(section),
        }
    }

    /// Removes `keyword`, reporting whether it was there.
    pub fn remove(&mut self, keyword: &str) -> bool {
        let before = self.sections.len();
        self.sections.retain(|section| section.keyword != keyword);
        self.sections.len() != before
    }

    /// The index `keyword` belongs at, or `None` to append.
    ///
    /// A section this build does not recognize ranks *last*, so inserting a known section
    /// steps over it rather than landing behind it. Without that rule, a single unrecognized
    /// section at the end of a file would capture every later insertion. The reader
    /// deliberately tolerates such sections (see [`piko_db::desc_compat`]), so they are not
    /// hypothetical.
    fn insertion_point(&self, keyword: &str) -> Option<usize> {
        let order = self.kind.order();
        let rank = |name: &str| order.iter().position(|entry| *entry == name);
        // An unknown keyword has no place in the canonical order, so this appends it.
        let target = rank(keyword)?;
        self.sections
            .iter()
            .position(|section| rank(&section.keyword).unwrap_or(usize::MAX) > target)
    }
}

/// Extracts `KEYWORD` from a `%KEYWORD%` header line, if the line is one.
///
/// This deliberately follows the same rule as [`piko_db::desc_compat`]'s reader-side
/// splitter: a header is `%`, then a non-empty keyword containing no further `%`, then `%`.
fn section_keyword(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('%')?.strip_suffix('%')?;
    (!inner.is_empty() && !inner.contains('%')).then_some(inner)
}

/// Shortens untrusted content so a hostile file cannot flood an error message.
fn truncate(content: &str) -> String {
    const MAX: usize = 32;
    match content.char_indices().nth(MAX) {
        Some((index, _)) => {
            let head = content.get(..index).unwrap_or_default();
            format!("{head}…")
        }
        None => content.to_owned(),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    const DESC: &str = "%NAME%\nfoo\n\n%VERSION%\n1.0.0-1\n\n%DEPENDS%\nbar\nbaz>=2\n\n";

    #[test]
    fn round_trips_a_desc() {
        let record = Record::parse(RecordKind::Desc, DESC).unwrap();
        assert_eq!(record.render(), DESC);
    }

    #[test]
    fn keeps_values_verbatim() {
        let record = Record::parse(RecordKind::Desc, DESC).unwrap();
        assert_eq!(record.get("DEPENDS").unwrap(), ["bar".to_owned(), "baz>=2".to_owned()]);
        assert_eq!(record.get("MISSING"), None);
    }

    /// This is the measured reason this module exists. A `(null)` backup hash is a value
    /// like any other here, while `alpm-db`'s typed parse discards the whole entry.
    #[test]
    fn preserves_a_null_backup_hash() {
        let files = "%BACKUP%\netc/gdm/PostSession/Default\t(null)\n\n";
        let record = Record::parse(RecordKind::Files, files).unwrap();
        assert_eq!(record.render(), files);
    }

    /// This is the other measured reason. A URL must survive untouched, not be normalized by
    /// a URL parser with opinions about trailing slashes.
    #[test]
    fn preserves_a_url_without_a_trailing_slash() {
        let desc = "%URL%\nhttps://archlinux.org\n\n";
        assert_eq!(Record::parse(RecordKind::Desc, desc).unwrap().render(), desc);
    }

    #[test]
    fn an_empty_file_round_trips() {
        // On a real system, seven packages ship a zero-byte `files`.
        let record = Record::parse(RecordKind::Files, "").unwrap();
        assert!(record.sections().is_empty());
        assert_eq!(record.render(), "");
    }

    /// A file truncated before its final blank line still parses. Rendering repairs the
    /// missing terminator rather than propagating it.
    #[test]
    fn closes_a_section_at_end_of_input() {
        let record = Record::parse(RecordKind::Desc, "%NAME%\nfoo\n").unwrap();
        assert_eq!(record.get("NAME").unwrap(), ["foo".to_owned()]);
        assert_eq!(record.render(), "%NAME%\nfoo\n\n");
    }

    #[test]
    fn set_replaces_in_place_without_moving_the_section() {
        let mut record = Record::parse(RecordKind::Desc, DESC).unwrap();
        record.set("VERSION", vec!["2.0.0-1".to_owned()]);
        assert_eq!(
            record.render(),
            "%NAME%\nfoo\n\n%VERSION%\n2.0.0-1\n\n%DEPENDS%\nbar\nbaz>=2\n\n"
        );
    }

    /// This is the `pacman -D --asdeps` path. A `%REASON%` section that was not there must
    /// land where libalpm would have put it, between `%SIZE%` and `%GROUPS%`.
    #[test]
    fn set_inserts_at_the_canonical_position() {
        let text = "%NAME%\nfoo\n\n%SIZE%\n10\n\n%GROUPS%\ng\n\n%DEPENDS%\nbar\n\n";
        let mut record = Record::parse(RecordKind::Desc, text).unwrap();
        record.set("REASON", vec!["1".to_owned()]);
        assert_eq!(
            record.render(),
            "%NAME%\nfoo\n\n%SIZE%\n10\n\n%REASON%\n1\n\n%GROUPS%\ng\n\n%DEPENDS%\nbar\n\n"
        );
    }

    #[test]
    fn set_inserts_before_every_later_section_even_when_the_neighbour_is_absent() {
        let mut record =
            Record::parse(RecordKind::Desc, "%NAME%\nfoo\n\n%PROVIDES%\np\n\n").unwrap();
        record.set("DEPENDS", vec!["bar".to_owned()]);
        assert_eq!(record.render(), "%NAME%\nfoo\n\n%DEPENDS%\nbar\n\n%PROVIDES%\np\n\n");
    }

    /// A section keyword this build does not know still round-trips. It has no canonical
    /// position, so it is appended.
    #[test]
    fn an_unknown_section_is_preserved_and_appended() {
        let text = "%NAME%\nfoo\n\n%FROM_THE_FUTURE%\nx\n\n";
        let mut record = Record::parse(RecordKind::Desc, text).unwrap();
        assert_eq!(record.render(), text);
        record.set("VERSION", vec!["1-1".to_owned()]);
        assert_eq!(record.render(), "%NAME%\nfoo\n\n%VERSION%\n1-1\n\n%FROM_THE_FUTURE%\nx\n\n");
    }

    /// libalpm never writes an empty section. Setting one to nothing must therefore remove
    /// it rather than emit a bare header.
    #[test]
    fn setting_no_values_removes_the_section() {
        let mut record = Record::parse(RecordKind::Desc, DESC).unwrap();
        record.set("DEPENDS", Vec::new());
        assert_eq!(record.render(), "%NAME%\nfoo\n\n%VERSION%\n1.0.0-1\n\n");
    }

    #[test]
    fn remove_reports_whether_it_did_anything() {
        let mut record = Record::parse(RecordKind::Desc, DESC).unwrap();
        assert!(record.remove("DEPENDS"));
        assert!(!record.remove("DEPENDS"));
    }

    #[test]
    fn refuses_a_value_before_any_section() {
        let err = Record::parse(RecordKind::Desc, "stray\n%NAME%\nfoo\n\n").unwrap_err();
        assert!(matches!(err, RecordError::ValueOutsideSection { line: 1, .. }), "got {err:?}");
    }

    /// Keeping one of the two would be a silent choice about which data to lose.
    #[test]
    fn refuses_a_duplicated_section() {
        let err = Record::parse(RecordKind::Desc, "%NAME%\nfoo\n\n%NAME%\nbar\n\n").unwrap_err();
        assert!(matches!(err, RecordError::DuplicateSection { line: 4, .. }), "got {err:?}");
    }

    /// A duplicate separated by no blank line is still a duplicate.
    #[test]
    fn refuses_a_duplicated_section_without_a_separator() {
        let err = Record::parse(RecordKind::Desc, "%NAME%\nfoo\n%NAME%\nbar\n").unwrap_err();
        assert!(matches!(err, RecordError::DuplicateSection { .. }), "got {err:?}");
    }

    #[test]
    fn error_messages_do_not_echo_a_whole_hostile_line() {
        let text = format!("{}\n%NAME%\nfoo\n\n", "x".repeat(10_000));
        let err = Record::parse(RecordKind::Desc, &text).unwrap_err();
        assert!(err.to_string().len() < 200, "error message was not truncated");
    }

    /// Repeated blank lines are separators, not values, so they collapse on render. This is
    /// the one shape where round-tripping is deliberately not the identity. It is also a
    /// shape libalpm cannot produce.
    #[test]
    fn extra_blank_lines_are_separators() {
        let record =
            Record::parse(RecordKind::Desc, "%NAME%\nfoo\n\n\n\n%VERSION%\n1-1\n\n").unwrap();
        assert_eq!(record.render(), "%NAME%\nfoo\n\n%VERSION%\n1-1\n\n");
    }
}
