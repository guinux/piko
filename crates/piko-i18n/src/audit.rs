//! Whether a translation file is safe to print and agrees with its English source.
//!
//! A translation is text piko writes to a terminal, so it must not hold a control character
//! or a bidirectional override. That includes a character a Fluent string literal spells as
//! an escape, such as `{"\u001B"}`. A translation must also have the messages of its English
//! source, and each message must use the same variables. A message that drops `$package` says
//! nothing wrong in Fluent's eyes, and leaves out the package the user needs to read.
//!
//! The library crates and each frontend run [`check`] and [`compare`] over their sources in
//! their tests.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fluent_syntax::ast::{
    CallArguments, Entry, Expression, InlineExpression, Pattern, PatternElement,
};
use fluent_syntax::unicode::unescape_unicode_to_string;

use crate::Language;

/// One problem in a translation file.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Discrepancy {
    /// The file does not parse.
    Syntax {
        /// What the parser reported.
        detail: String,
    },
    /// The text of a message holds a character piko never prints from a translation.
    UnsafeCharacter {
        /// The message.
        id: String,
        /// The character.
        character: char,
    },
    /// Two messages have the same identifier.
    Duplicate {
        /// The identifier.
        id: String,
    },
    /// The English source has a message the translation does not.
    Missing {
        /// The identifier.
        id: String,
    },
    /// The translation has a message the English source does not.
    Extra {
        /// The identifier.
        id: String,
    },
    /// A message uses other variables than its English source.
    Variables {
        /// The identifier.
        id: String,
        /// The variables of the English message.
        english: Vec<String>,
        /// The variables of the translated message.
        translation: Vec<String>,
    },
}

impl fmt::Display for Discrepancy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { detail } => write!(f, "syntax error: {detail}"),
            Self::UnsafeCharacter { id, character } => {
                write!(f, "{id} holds the character U+{:04X}", u32::from(*character))
            }
            Self::Duplicate { id } => write!(f, "{id} is defined twice"),
            Self::Missing { id } => write!(f, "{id} is not translated"),
            Self::Extra { id } => write!(f, "{id} is not in the English source"),
            Self::Variables { id, english, translation } => write!(
                f,
                "{id} uses {} where English uses {}",
                translation.join(", "),
                english.join(", ")
            ),
        }
    }
}

/// The problems of one file, on its own: syntax, unsafe characters, duplicate identifiers.
#[must_use]
pub fn check(source: &str) -> Vec<Discrepancy> {
    read(source).1
}

/// The problems of a translation against its English source, [`check`]'s included.
#[must_use]
pub fn compare(english: &str, translation: &str) -> Vec<Discrepancy> {
    let (source, _) = read(english);
    let (translated, mut problems) = read(translation);
    for (id, variables) in &source {
        match translated.get(id) {
            None => problems.push(Discrepancy::Missing { id: id.clone() }),
            Some(other) if other != variables => problems.push(Discrepancy::Variables {
                id: id.clone(),
                english: variables.iter().cloned().collect(),
                translation: other.iter().cloned().collect(),
            }),
            Some(_) => {}
        }
    }
    for id in translated.keys() {
        if !source.contains_key(id) {
            problems.push(Discrepancy::Extra { id: id.clone() });
        }
    }
    problems
}

/// The messages of `source`, each with the names of the variables it uses.
///
/// A frontend compares this with the messages its code builds, so a call that passes a
/// variable the message does not use, or forgets one, fails a test rather than a translation.
#[must_use]
pub fn variables(source: &str) -> BTreeMap<String, BTreeSet<String>> {
    read(source).0
}

/// [`compare`] over the library messages: every translation against English.
#[must_use]
pub fn library() -> Vec<(Language, Discrepancy)> {
    let english: String = crate::catalog::library_sources(Language::English).collect();
    let mut problems: Vec<_> =
        check(&english).into_iter().map(|each| (Language::English, each)).collect();
    for language in Language::ALL.iter().filter(|each| **each != Language::English) {
        let translation: String = crate::catalog::library_sources(*language).collect();
        problems.extend(compare(&english, &translation).into_iter().map(|each| (*language, each)));
    }
    problems
}

/// The messages of `source`, each with the variables it uses, and the problems found on the
/// way.
fn read(source: &str) -> (BTreeMap<String, BTreeSet<String>>, Vec<Discrepancy>) {
    let mut problems = Vec::new();
    let resource = fluent_syntax::parser::parse(source).unwrap_or_else(|(partial, errors)| {
        problems
            .extend(errors.iter().map(|error| Discrepancy::Syntax { detail: error.to_string() }));
        partial
    });
    let mut messages = BTreeMap::new();
    for entry in &resource.body {
        let Entry::Message(message) = entry else { continue };
        let id = message.id.name.to_owned();
        let mut walk = Walk::default();
        if let Some(value) = &message.value {
            walk.pattern(value);
        }
        for attribute in &message.attributes {
            walk.pattern(&attribute.value);
        }
        problems.extend(
            walk.unsafe_characters
                .into_iter()
                .map(|character| Discrepancy::UnsafeCharacter { id: id.clone(), character }),
        );
        if messages.insert(id.clone(), walk.variables).is_some() {
            problems.push(Discrepancy::Duplicate { id });
        }
    }
    (messages, problems)
}

/// Whether piko refuses `character` in a translation.
///
/// A control character other than a line feed can move the cursor or change the colors of a
/// terminal. A bidirectional override or isolate can make the text read in another order than
/// its bytes (CVE-2021-42574). The catalog adds isolates around a value itself when a
/// frontend asks for them; a translation never needs to.
fn is_unsafe(character: char) -> bool {
    (character.is_control() && character != '\n')
        || matches!(character, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// What a walk over one message collects.
#[derive(Default)]
struct Walk {
    variables: BTreeSet<String>,
    unsafe_characters: BTreeSet<char>,
}

impl Walk {
    fn pattern(&mut self, pattern: &Pattern<&str>) {
        for element in &pattern.elements {
            match element {
                PatternElement::TextElement { value } => self.text(value),
                PatternElement::Placeable { expression } => self.expression(expression),
            }
        }
    }

    fn expression(&mut self, expression: &Expression<&str>) {
        match expression {
            Expression::Select { selector, variants } => {
                self.inline(selector);
                for variant in variants {
                    self.pattern(&variant.value);
                }
            }
            Expression::Inline(inline) => self.inline(inline),
        }
    }

    fn inline(&mut self, inline: &InlineExpression<&str>) {
        match inline {
            InlineExpression::StringLiteral { value } => {
                self.text(&unescape_unicode_to_string(value));
            }
            InlineExpression::VariableReference { id } => {
                self.variables.insert(id.name.to_owned());
            }
            InlineExpression::FunctionReference { arguments, .. } => self.arguments(arguments),
            InlineExpression::TermReference { arguments, .. } => {
                if let Some(arguments) = arguments {
                    self.arguments(arguments);
                }
            }
            InlineExpression::Placeable { expression } => self.expression(expression),
            InlineExpression::NumberLiteral { .. } | InlineExpression::MessageReference { .. } => {}
        }
    }

    fn arguments(&mut self, arguments: &CallArguments<&str>) {
        for each in &arguments.positional {
            self.inline(each);
        }
        for each in &arguments.named {
            self.inline(&each.value);
        }
    }

    fn text(&mut self, text: &str) {
        self.unsafe_characters.extend(text.chars().filter(|each| is_unsafe(*each)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_library_messages_agree_in_every_language() {
        let problems = library();
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn a_control_character_is_refused_even_spelled_as_an_escape() {
        let problems = check("a = red {\"\\u001B\"}[31m text\nb = tab\there\n");
        assert_eq!(
            problems,
            [
                Discrepancy::UnsafeCharacter { id: "a".to_owned(), character: '\u{1B}' },
                Discrepancy::UnsafeCharacter { id: "b".to_owned(), character: '\t' },
            ]
        );
    }

    #[test]
    fn a_bidirectional_override_is_refused() {
        let problems = check("a = abc\u{202E}def\n");
        assert_eq!(
            problems,
            [Discrepancy::UnsafeCharacter { id: "a".to_owned(), character: '\u{202E}' }]
        );
    }

    #[test]
    fn a_no_break_space_is_accepted() {
        assert!(check("a = Erreur{\"\\u00A0\"}: { $text }\n").is_empty());
    }

    #[test]
    fn a_dropped_variable_is_reported() {
        let problems = compare(
            "a = { $package } requires { $relation }\n",
            "a = quelque chose requiert { $relation }\n",
        );
        assert_eq!(
            problems,
            [Discrepancy::Variables {
                id: "a".to_owned(),
                english: vec!["package".to_owned(), "relation".to_owned()],
                translation: vec!["relation".to_owned()],
            }]
        );
    }

    #[test]
    fn a_variable_used_only_in_a_selector_counts() {
        let english =
            "a = { $count ->\n    [one] one package\n   *[other] { $count } packages\n}\n";
        let french = "a = { $count ->\n    [one] un paquet\n   *[other] { $count } paquets\n}\n";
        assert!(compare(english, french).is_empty());
    }

    #[test]
    fn missing_extra_and_duplicate_messages_are_reported() {
        let problems = compare("a = A\nb = B\n", "a = A\nc = C\nc = C\n");
        assert_eq!(
            problems,
            [
                Discrepancy::Duplicate { id: "c".to_owned() },
                Discrepancy::Missing { id: "b".to_owned() },
                Discrepancy::Extra { id: "c".to_owned() },
            ]
        );
    }

    #[test]
    fn a_syntax_error_is_reported() {
        assert!(matches!(check("a = { $\n").as_slice(), [Discrepancy::Syntax { .. }, ..]));
    }
}
