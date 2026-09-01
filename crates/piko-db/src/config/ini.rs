//! Line-level tokenizer for `pacman.conf`-style INI files.
//!
//! Mirrors `ini.c`'s `parse_ini` grammar exactly — this module only tokenizes; the directive
//! semantics (which key means what, `Include` handling, defaults) live in
//! [`crate::config`].
//!
//! Public because `pacman.conf` is not the only file with this grammar. An alpm **hook** file
//! is parsed by the same `parse_ini` in libalpm (`hook.c:605`). `piko-txn` tokenizes hooks
//! through this module instead of duplicating it. This keeps three subtle rules consistent
//! between the two: a `#` starts a comment only at the beginning of a line, a bare key is
//! distinct from a key with an empty value, and splitting on the *first* `=` preserves a
//! hook's second `=` (e.g. `Exec = … Markers=needs-restart`).

/// One tokenized line of a config file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Line<'a> {
    /// A `[name]` section header.
    Section {
        /// The text between `[` and `]`, trimmed.
        name: &'a str,
    },
    /// A `key` or `key = value` directive.
    Directive {
        /// The directive name, trimmed.
        key: &'a str,
        /// `None` for a bare directive with no `=` at all (e.g. `CheckSpace`). `Some("")` for
        /// `key =` with nothing after the `=`. These two are distinct. Which directives
        /// accept which shape is decided in [`crate::config`], not here.
        value: Option<&'a str>,
    },
}

/// A tokenized line paired with its 1-based line number, matching `linenum` in `ini.c`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Token<'a> {
    /// The 1-based physical line this token came from.
    pub line: usize,
    /// What the line said.
    pub content: Line<'a>,
}

/// Tokenizes `text`, skipping blank lines and comments.
///
/// A comment is a line whose first non-whitespace character is `#`. This is checked only at
/// the start of the (trimmed) line, matching `ini.c`'s `line[0] == '#'`. A `#` later in a
/// directive line belongs to the value, not to a comment:
/// `Server = https://host/$repo # note` keeps `# note` in the value. This looks like a bug at
/// first. It is deliberate behavior inherited from `ini.c`.
pub fn tokenize(text: &str) -> impl Iterator<Item = Token<'_>> {
    text.lines().enumerate().filter_map(|(index, raw_line)| {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        let line = index.saturating_add(1);

        if let Some(name) = trimmed.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
            return Some(Token { line, content: Line::Section { name } });
        }

        Some(Token { line, content: parse_directive(trimmed) })
    })
}

/// Splits a directive line on its first `=`, matching `ini.c`'s use of `strsep(&value, "=")`.
fn parse_directive(trimmed: &str) -> Line<'_> {
    match trimmed.split_once('=') {
        Some((key, value)) => Line::Directive { key: key.trim(), value: Some(value.trim()) },
        None => Line::Directive { key: trimmed.trim(), value: None },
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

    fn tokens(text: &str) -> Vec<Token<'_>> {
        tokenize(text).collect()
    }

    #[test]
    fn recognises_a_section_header() {
        let got = tokens("[core]");
        assert_eq!(got, [Token { line: 1, content: Line::Section { name: "core" } }]);
    }

    #[test]
    fn recognises_a_bare_directive_with_no_value() {
        let got = tokens("CheckSpace");
        assert_eq!(
            got,
            [Token { line: 1, content: Line::Directive { key: "CheckSpace", value: None } }]
        );
    }

    /// `Key =` (nothing after the `=`) is `Some("")`. A bare `Key` is `None`.
    /// `_parse_options` in `conf.c` keys off exactly this distinction.
    #[test]
    fn distinguishes_an_empty_value_from_no_value() {
        let got = tokens("LogFile =");
        assert_eq!(
            got,
            [Token { line: 1, content: Line::Directive { key: "LogFile", value: Some("") } }]
        );
    }

    #[test]
    fn parses_a_key_value_directive() {
        let got = tokens("DBPath = /var/lib/pacman/");
        assert_eq!(
            got,
            [Token {
                line: 1,
                content: Line::Directive { key: "DBPath", value: Some("/var/lib/pacman/") }
            }]
        );
    }

    /// A comment starts only at the beginning of the (trimmed) line. A later `#` is part of
    /// the value. This test pins that behavior, so it does not get "fixed" into stripping
    /// inline comments.
    #[test]
    fn keeps_a_trailing_hash_as_part_of_the_value() {
        let got = tokens("Server = https://host/$repo # note");
        assert_eq!(
            got,
            [Token {
                line: 1,
                content: Line::Directive {
                    key: "Server",
                    value: Some("https://host/$repo # note")
                }
            }]
        );
    }

    #[test]
    fn skips_blank_lines_and_full_line_comments() {
        let got = tokens("\n# a comment\n   \nCheckSpace\n");
        assert_eq!(
            got,
            [Token { line: 4, content: Line::Directive { key: "CheckSpace", value: None } }]
        );
    }

    #[test]
    fn line_numbers_are_one_based_and_count_every_physical_line() {
        let got = tokens("[options]\nCheckSpace\n\n[core]\n");
        assert_eq!(
            got,
            [
                Token { line: 1, content: Line::Section { name: "options" } },
                Token { line: 2, content: Line::Directive { key: "CheckSpace", value: None } },
                Token { line: 4, content: Line::Section { name: "core" } },
            ]
        );
    }

    #[test]
    fn trims_surrounding_whitespace_on_keys_and_values() {
        let got = tokens("  DBPath   =   /var/lib/pacman/  ");
        assert_eq!(
            got,
            [Token {
                line: 1,
                content: Line::Directive { key: "DBPath", value: Some("/var/lib/pacman/") }
            }]
        );
    }

    /// A malformed section-like line (no closing `]`) falls through to directive parsing,
    /// matching `ini.c`. Its `line[0]=='[' && line[len-1]==']'` check simply fails, and the
    /// whole line goes to the key/value branch instead.
    #[test]
    fn an_unclosed_bracket_is_not_a_section_header() {
        let got = tokens("[core");
        assert_eq!(
            got,
            [Token { line: 1, content: Line::Directive { key: "[core", value: None } }]
        );
    }
}
