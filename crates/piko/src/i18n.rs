//! The messages of the command line, and the one catalog every message is rendered with.
//!
//! The catalog holds the library messages (`piko_i18n`) and the messages of
//! `locales/*/cli.ftl`, in the language the environment selects ([`Language::from_env`]).
//! `LC_ALL=C` selects English, so a script that reads piko's output can pin it.
//!
//! A call site names a message with [`tr!`], and the diagnostic macros [`print_error!`],
//! [`print_warning!`] and [`print_note!`] add the keyword at the head of the line. Each value is
//! escaped by the caller, as before: a template is piko's own text, and a value can come from a
//! package or a mirror.
//!
//! Indentation and the `:: ` prefix of a question are layout, not language, so the code writes
//! them. Fluent removes the spaces at the start and at the end of a value.

use std::sync::OnceLock;

use piko_i18n::{Catalog, Language, Localize, Message, Placeables};

/// The messages of this crate, in every language.
const SOURCES: &[(Language, &str)] = &[
    (Language::English, include_str!("../locales/en/cli.ftl")),
    (Language::French, include_str!("../locales/fr/cli.ftl")),
];

/// The `--help` text, in every language. See `crate::help`.
pub const HELP: &[(Language, &str)] = &[
    (Language::English, include_str!("../locales/en/help.ftl")),
    (Language::French, include_str!("../locales/fr/help.ftl")),
];

/// The catalog of this process, built on first use.
static CATALOG: OnceLock<Catalog> = OnceLock::new();

/// A catalog in `language`: the library messages, then this crate's.
fn build(language: Language) -> Catalog {
    SOURCES
        .iter()
        .chain(HELP)
        .fold(Catalog::new(language, Placeables::Plain), |catalog, (each, source)| {
            catalog.with(*each, source)
        })
}

/// The language of this process.
///
/// A unit test compares output with English text, whatever the locale of the machine that runs
/// it. An integration test sets `LC_ALL=C` on the process it starts.
pub fn language() -> Language {
    if cfg!(test) { Language::English } else { Language::from_env() }
}

/// `message`, in the language of this process.
pub fn render(message: &Message) -> String {
    CATALOG.get_or_init(|| build(language())).format(message)
}

/// `bytes` in a binary unit, in the language of this process: `5.04 MiB` in English.
pub fn size(bytes: u64) -> String {
    CATALOG.get_or_init(|| build(language())).size(bytes)
}

/// The message of `value`, in the language of this process.
pub fn localized(value: &impl Localize) -> String {
    render(&value.message())
}

/// Renders the message `id` of `locales/*/cli.ftl`, with a value for each of its variables.
///
/// A value is anything `piko_i18n::Arg` converts from: a `&str` or a `String` is quoted as it
/// is, and a `usize` or a `u64` is a count, which selects a plural form.
///
/// ```text
/// tr!("cli-pattern-matched", pattern = expansion.pattern.as_str(), packages = names.len())
/// ```
///
/// The unit tests read every call in this crate and check that the identifier exists and that
/// the call names exactly the variables the English message uses.
macro_rules! tr {
    ($id:literal $(, $name:ident = $value:expr)* $(,)?) => {
        $crate::i18n::render(&::piko_i18n::Message::new($id) $(.arg(stringify!($name), $value))*)
    };
}

/// Prints [`tr!`]'s message on stderr, after the `Error:` keyword.
macro_rules! print_error {
    ($($message:tt)+) => {
        eprintln!("{}", $crate::i18n::error(&$crate::i18n::tr!($($message)+)))
    };
}

/// Prints [`tr!`]'s message on stderr, after the `Warning:` keyword.
macro_rules! print_warning {
    ($($message:tt)+) => {
        eprintln!("{}", $crate::i18n::warning(&$crate::i18n::tr!($($message)+)))
    };
}

/// Prints [`tr!`]'s message on stderr, after the `Note:` keyword.
macro_rules! print_note {
    ($($message:tt)+) => {
        eprintln!("{}", $crate::i18n::note(&$crate::i18n::tr!($($message)+)))
    };
}

pub(crate) use {print_error, print_note, print_warning, tr};

/// `Error: <text>`.
pub fn error(text: &str) -> String {
    tr!("cli-error", text = text)
}

/// `Warning: <text>`.
pub fn warning(text: &str) -> String {
    tr!("cli-warning", text = text)
}

/// `Note: <text>`.
pub fn note(text: &str) -> String {
    tr!("cli-note", text = text)
}

/// `Caused by: <text>`.
pub fn caused_by(text: &str) -> String {
    tr!("cli-caused-by", text = text)
}

/// `Try: <text>`.
pub fn try_this(text: &str) -> String {
    tr!("cli-try", text = text)
}

/// Whether `answer` accepts a yes/no question.
///
/// The English words are accepted in every language, so a script that answers `y` works
/// whatever the locale. pacman accepts the translated words too (`YESEXPR`).
pub fn is_yes(answer: &str) -> bool {
    let words = tr!("cli-yes-answers");
    ["y", "yes"]
        .into_iter()
        .chain(words.split_whitespace())
        .any(|word| answer.eq_ignore_ascii_case(word))
}

#[cfg(test)]
#[expect(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly, and the scan indexes the \
              source it read"
)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use super::*;

    fn english() -> &'static str {
        let english = SOURCES.iter().find(|(each, _)| *each == Language::English);
        let Some((_, english)) = english else { panic!("no English source") };
        english
    }

    #[test]
    fn every_translation_agrees_with_english() {
        for sources in [SOURCES, HELP] {
            let english = sources.iter().find(|(each, _)| *each == Language::English);
            let Some((_, english)) = english else { panic!("no English source") };
            assert_eq!(piko_i18n::audit::check(english), []);
            for (language, source) in sources.iter().filter(|(each, _)| *each != Language::English)
            {
                assert_eq!(piko_i18n::audit::compare(english, source), [], "{language:?}");
            }
        }
    }

    /// The `tr!`, `print_error!`, `print_warning!` and `print_note!` calls of `source`: the
    /// message identifier of each, and the variables it names.
    fn calls(source: &str) -> Vec<(String, BTreeSet<String>)> {
        let mut found = Vec::new();
        for opening in ["tr!(", "print_error!(", "print_warning!(", "print_note!("] {
            let mut rest = source;
            while let Some(at) = rest.find(opening) {
                // `include_str!(` ends with `tr!(` too.
                let joined = rest[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|before| before.is_alphanumeric() || before == '_');
                rest = &rest[at + opening.len()..];
                if joined {
                    continue;
                }
                let Some(literal) = rest.trim_start().strip_prefix('"') else { continue };
                let Some(end) = literal.find('"') else { continue };
                let id = literal[..end].to_owned();
                found.push((id, names(&literal[end + 1..])));
            }
        }
        found
    }

    /// The `name =` arguments of a call, read up to its closing parenthesis.
    fn names(arguments: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let mut depth = 0usize;
        let mut chars = arguments.char_indices().peekable();
        let mut after_comma = false;
        while let Some((index, character)) = chars.next() {
            match character {
                '"' => {
                    // Skip a string literal, and its escapes.
                    while let Some((_, inner)) = chars.next() {
                        match inner {
                            '\\' => {
                                chars.next();
                            }
                            '"' => break,
                            _ => {}
                        }
                    }
                }
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth == 0 => break,
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => after_comma = true,
                _ if after_comma && !character.is_whitespace() => {
                    after_comma = false;
                    let word: String = arguments[index..]
                        .chars()
                        .take_while(|each| each.is_alphanumeric() || *each == '_')
                        .collect();
                    let tail = arguments[index + word.len()..].trim_start();
                    if !word.is_empty() && tail.starts_with('=') && !tail.starts_with("==") {
                        names.insert(word);
                    }
                }
                _ => {}
            }
        }
        names
    }

    fn sources(dir: &Path, found: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                sources(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                // The calls a test module makes, this one's scan included, are not the
                // messages the program prints.
                let text = std::fs::read_to_string(&path).unwrap();
                let code = text.split("#[cfg(test)]").next().unwrap_or_default();
                found.push(code.to_owned());
            }
        }
    }

    /// Every message call of this crate, by identifier.
    fn every_call() -> BTreeMap<String, Vec<BTreeSet<String>>> {
        let mut files = Vec::new();
        sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
        let mut by_id: BTreeMap<String, Vec<BTreeSet<String>>> = BTreeMap::new();
        for file in &files {
            for (id, names) in calls(file) {
                by_id.entry(id).or_default().push(names);
            }
        }
        by_id
    }

    #[test]
    fn every_call_names_a_message_and_its_variables() {
        let messages = piko_i18n::audit::variables(english());
        let calls = every_call();
        assert!(calls.len() > 100, "the scan found only {} messages", calls.len());
        for (id, uses) in &calls {
            let Some(expected) = messages.get(id) else { panic!("{id} is not in cli.ftl") };
            for names in uses {
                assert_eq!(names, expected, "a call of {id} names other variables");
            }
        }
        for id in messages.keys() {
            assert!(calls.contains_key(id), "{id} is in cli.ftl, and nothing uses it");
        }
    }

    #[test]
    fn the_scan_reads_a_call_as_written() {
        let found = calls(
            r#"tr!("a", name = f("x, y = z"), count = list.len()) print_error!("b") tr!(id) include_str!("c")"#,
        );
        assert_eq!(found[0].0, "a");
        assert_eq!(found[0].1, BTreeSet::from(["name".to_owned(), "count".to_owned()]));
        assert_eq!(found[1], ("b".to_owned(), BTreeSet::new()));
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn a_count_selects_the_plural_form() {
        let english = build(Language::English);
        let message = |groups: usize, packages: usize| {
            Message::new("cli-pattern-matched-groups")
                .arg("pattern", "x*")
                .arg("groups", groups)
                .arg("packages", packages)
        };
        assert_eq!(english.format(&message(1, 2)), "x* matched 1 group and 2 packages");
        let french = build(Language::French);
        assert_eq!(french.format(&message(1, 2)), "x* correspond à 1 groupe et 2 paquets");
        assert_eq!(french.format(&Message::new("cli-error").arg("text", "e")), "Erreur\u{a0}: e");
    }

    #[test]
    fn english_answers_are_accepted_in_every_language() {
        assert!(is_yes("y"));
        assert!(is_yes("YES"));
        assert!(!is_yes("n"));
        assert!(!is_yes(""));
    }
}
