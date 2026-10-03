//! Property tests of the metadata readers: any text, however malformed, is read or refused,
//! and never makes a reader panic or read outside the text.
//!
//! Two generators feed them. An arbitrary string finds what a hand-written case does not
//! think of. A section-shaped one, of `%KEYWORD%` headers, values and empty lines, reaches
//! the paths past the first header that an arbitrary string rarely does.

use proptest::prelude::*;

use super::{files, kv::Pairs, section::Sections};
use crate::{
    eager::{self, RelationBudget},
    local::desc::LocalDesc,
    repo::desc::RepoDesc,
};

/// A text of `%KEYWORD%` headers, values and empty lines.
fn section_shaped() -> impl Strategy<Value = String> {
    let line = prop_oneof![
        prop_oneof![
            Just("%NAME%"),
            Just("%VERSION%"),
            Just("%ARCH%"),
            Just("%DEPENDS%"),
            Just("%FILES%"),
            Just("%BACKUP%"),
            Just("%FILENAME%"),
            Just("%SHA256SUM%"),
        ]
        .prop_map(str::to_owned),
        "%[A-Z]{1,8}%",
        "[a-z0-9 ./=<>:%\t-]{0,16}",
        Just(String::new()),
    ];
    prop::collection::vec(line, 0..48).prop_map(|lines| lines.join("\n"))
}

/// Either generator.
fn text() -> impl Strategy<Value = String> {
    prop_oneof![any::<String>(), section_shaped()]
}

proptest! {
    /// Every section borrows a range of the text, and every value is a non-empty line.
    #[test]
    fn sections_stay_inside_the_text(text in text()) {
        for section in Sections::new(&text) {
            let range = section.body_range();
            prop_assert!(range.end <= text.len());
            let body = text.get(range);
            prop_assert!(body.is_some(), "the range falls on character boundaries");
            for value in section.values() {
                prop_assert!(!value.is_empty());
                prop_assert!(!value.contains('\n'));
            }
        }
    }

    /// Every pair has a key without a space or `=`.
    #[test]
    fn pairs_have_well_formed_keys(text in text()) {
        for pair in Pairs::new(&text) {
            prop_assert!(!pair.key.is_empty());
            prop_assert!(!pair.key.contains([' ', '=']));
        }
    }

    /// A `files` text is read or refused, and a read one lists every path once, relative.
    #[test]
    fn files_are_read_or_refused(text in text()) {
        if let Ok(read) = files::parse(&text) {
            let mut seen = std::collections::HashSet::new();
            for path in read.files().map(std::path::Path::new) {
                prop_assert!(path.is_relative());
                prop_assert!(seen.insert(path), "listed once");
            }
        }
        let _ = files::parse_repo(&text);
    }

    /// A `desc` is read or refused by either database's reader.
    #[test]
    fn desc_is_read_or_refused(text in text()) {
        let _ = LocalDesc::parse(&text);
        let _ = RepoDesc::parse(&text);
    }

    /// The eager scan never charges more entries than the text has lines, and a deferred
    /// `%DEPENDS%` converts from the range it recorded.
    #[test]
    fn the_eager_scan_counts_within_the_text(text in text()) {
        let lines = text.lines().count();
        let mut budget = RelationBudget::new(lines);
        if let Ok(relations) = eager::scan(&text, eager::Depends::Deferred, Some(&mut budget), |_| Ok(())) {
            let _ = eager::parse_depends(&text, &relations.depends_text);
        }
    }
}
