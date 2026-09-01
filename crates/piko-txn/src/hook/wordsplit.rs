//! Splits a hook's `Exec` line into a program and its arguments.
//!
//! `alpm-hooks(5)` says only: "Command arguments are split on whitespace. Values containing
//! whitespace should be enclosed in quotes." The implementation behind that sentence is
//! `wordsplit` in pacman's `src/common/util-common.c`, the *frontend* tree. That is why it is
//! not in the `../libalpm` reference copy alongside `hook.c`. This module transcribes its
//! algorithm, plus the rules that are not obvious from the one-line summary:
//!
//! - **Quotes are word-internal, not word-forming.** `a"b c"d` is the single word `ab cd`, not
//!   three words. The scan looks for the next unquoted whitespace. A quoted run is stepped
//!   over as part of whatever word it sits in.
//! - **Both `'` and `"` quote, identically.** There is no shell-style "single quotes are
//!   literal, double quotes expand" distinction, because nothing is expanded at all: no
//!   variables, no globs, no tilde. A hook that wants any of those runs a shell — every
//!   `Exec = /bin/sh -c '…'` on a real system does exactly that.
//! - **Inside a quoted run, `\` escapes only that run's quote character.** Everywhere else a
//!   backslash is an ordinary character. `C:\path` needs no doubling.
//! - **An unbalanced quote is an error**, not a word running to the end of the line.
//!
//! This is validated against every `.hook` installed on a real Arch system — see
//! `crates/piko-txn/tests/real_hooks.rs`.

use std::ffi::OsString;

/// An `Exec` value that could not be split.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SplitError {
    /// A quoted run was never closed.
    #[error("the quote opened at character {position} is never closed")]
    UnbalancedQuote {
        /// 0-based character offset of the opening quote.
        position: usize,
    },
    /// The value held no words at all.
    #[error("it is empty")]
    Empty,
}

/// Splits `value` into a program and its arguments.
///
/// # Errors
///
/// [`SplitError`] if a quote is left open, or if the value contains no word. libalpm treats a
/// missing `Exec` and an unusable one the same way: it refuses the hook file rather than
/// running something it had to guess at.
pub fn split(value: &str) -> Result<Vec<OsString>, SplitError> {
    let characters: Vec<char> = value.chars().collect();
    let mut words: Vec<OsString> = Vec::new();
    let mut index = skip_whitespace(&characters, 0);

    while index < characters.len() {
        let (word, next) = read_word(&characters, index)?;
        words.push(OsString::from(word));
        index = skip_whitespace(&characters, next);
    }

    if words.is_empty() {
        return Err(SplitError::Empty);
    }
    Ok(words)
}

/// The index of the first non-whitespace character at or after `from`.
fn skip_whitespace(characters: &[char], from: usize) -> usize {
    let mut index = from;
    while characters.get(index).is_some_and(|c| c.is_whitespace()) {
        index = index.saturating_add(1);
    }
    index
}

/// Reads one word starting at `from`, returning it and the index just past it.
///
/// A word ends at the first whitespace that is not inside a quoted run.
fn read_word(characters: &[char], from: usize) -> Result<(String, usize), SplitError> {
    let mut word = String::new();
    let mut index = from;

    while let Some(&current) = characters.get(index) {
        if current.is_whitespace() {
            break;
        }
        if current == '\'' || current == '"' {
            index = read_quoted(characters, index, current, &mut word)?;
        } else {
            word.push(current);
            index = index.saturating_add(1);
        }
    }

    Ok((word, index))
}

/// Reads a run quoted by `quote`, starting at the opening quote, appending its contents.
///
/// Returns the index just past the closing quote.
fn read_quoted(
    characters: &[char],
    opening: usize,
    quote: char,
    into: &mut String,
) -> Result<usize, SplitError> {
    let mut index = opening.saturating_add(1);

    while let Some(&current) = characters.get(index) {
        if current == quote {
            return Ok(index.saturating_add(1));
        }
        // A backslash escapes *this run's* quote and nothing else. In every other case it is
        // an ordinary character, and it is kept as one.
        if current == '\\' && characters.get(index.saturating_add(1)) == Some(&quote) {
            into.push(quote);
            index = index.saturating_add(2);
            continue;
        }
        into.push(current);
        index = index.saturating_add(1);
    }

    Err(SplitError::UnbalancedQuote { position: opening })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn words(value: &str) -> Vec<String> {
        split(value).unwrap().into_iter().map(|word| word.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn a_plain_command_splits_on_whitespace() {
        assert_eq!(words("/usr/bin/ldconfig -r ."), ["/usr/bin/ldconfig", "-r", "."]);
    }

    #[test]
    fn leading_and_trailing_whitespace_is_ignored() {
        assert_eq!(words("   /bin/true   "), ["/bin/true"]);
        assert_eq!(words("/bin/echo \t a  \t b "), ["/bin/echo", "a", "b"]);
    }

    /// The shape every real `Exec = /bin/sh -c '…'` on an Arch system has.
    #[test]
    fn a_quoted_argument_keeps_its_spaces() {
        assert_eq!(
            words("/bin/sh -c 'pkill --exact gvfsd || true'"),
            ["/bin/sh", "-c", "pkill --exact gvfsd || true"]
        );
    }

    #[test]
    fn double_quotes_work_the_same_as_single_quotes() {
        assert_eq!(words(r#"/bin/echo "a b" c"#), ["/bin/echo", "a b", "c"]);
    }

    /// A first reading of "values containing whitespace should be enclosed in quotes" gets
    /// this wrong: a quote does not start a word. It only suspends splitting inside one.
    #[test]
    fn quotes_are_word_internal() {
        assert_eq!(words(r#"a"b c"d"#), ["ab cd"]);
        assert_eq!(words("x'y z'"), ["xy z"]);
    }

    /// Nothing is expanded, so the other quote character is just a character.
    #[test]
    fn the_other_quote_is_literal_inside_a_quoted_run() {
        assert_eq!(words(r#"/bin/echo "it's fine""#), ["/bin/echo", "it's fine"]);
    }

    #[test]
    fn a_backslash_escapes_the_enclosing_quote() {
        assert_eq!(words(r#"/bin/echo "say \"hi\"""#), ["/bin/echo", r#"say "hi""#]);
    }

    /// A backslash is an ordinary character outside a quoted run, and inside one before
    /// anything but the closing quote. A Windows-style path needs no doubling.
    #[test]
    fn a_backslash_is_otherwise_literal() {
        assert_eq!(words(r"/bin/echo a\b"), ["/bin/echo", r"a\b"]);
        assert_eq!(words(r#"/bin/echo "a\b""#), ["/bin/echo", r"a\b"]);
    }

    /// This is refused rather than silently reinterpreted as a word running to end of line. A
    /// hook whose command was guessed at is worse than a hook that does not load.
    #[test]
    fn an_unbalanced_quote_is_refused() {
        assert_eq!(
            split("/bin/sh -c 'never closed"),
            Err(SplitError::UnbalancedQuote { position: 11 })
        );
        assert!(matches!(split(r#"a "b"#), Err(SplitError::UnbalancedQuote { .. })));
    }

    #[test]
    fn an_empty_value_is_refused() {
        assert_eq!(split(""), Err(SplitError::Empty));
        assert_eq!(split("   \t "), Err(SplitError::Empty));
    }

    /// An empty quoted run is a real, empty argument. A program may well want one.
    #[test]
    fn an_empty_quoted_run_is_an_empty_argument() {
        assert_eq!(words("/bin/echo '' x"), ["/bin/echo", "", "x"]);
    }

    /// The ini tokenizer splits on the first `=` only, so a value with more of them arrives
    /// here intact. Pinned together because the pair is what makes a real hook work.
    #[test]
    fn a_value_carrying_more_equals_signs_survives() {
        assert_eq!(
            words("/usr/bin/systemctl --runtime set-property sshd.service Markers=needs-restart"),
            [
                "/usr/bin/systemctl",
                "--runtime",
                "set-property",
                "sshd.service",
                "Markers=needs-restart"
            ]
        );
    }
}
