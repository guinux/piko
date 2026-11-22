//! The catalog: the translations of one language, and English behind them.

use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource, FluentValue};

use crate::{Arg, Language, Message};

/// A Fluent bundle that can be shared between threads.
type Bundle = FluentBundle<FluentResource>;

/// The messages of the library crates, in every language.
///
/// A frontend adds its own messages with [`Catalog::with`].
/// The message of each binary unit, from the byte up. A `u64` reaches the exbibyte.
const UNITS: [&str; 7] =
    ["size-bytes", "size-kib", "size-mib", "size-gib", "size-tib", "size-pib", "size-eib"];

const LIBRARY: &[(Language, &str)] = &[
    (Language::English, include_str!("../locales/en/solve.ftl")),
    (Language::English, include_str!("../locales/en/db.ftl")),
    (Language::English, include_str!("../locales/en/txn.ftl")),
    (Language::English, include_str!("../locales/en/net.ftl")),
    (Language::English, include_str!("../locales/en/dbwrite.ftl")),
    (Language::English, include_str!("../locales/en/sig.ftl")),
    (Language::English, include_str!("../locales/en/size.ftl")),
    (Language::French, include_str!("../locales/fr/solve.ftl")),
    (Language::French, include_str!("../locales/fr/db.ftl")),
    (Language::French, include_str!("../locales/fr/txn.ftl")),
    (Language::French, include_str!("../locales/fr/net.ftl")),
    (Language::French, include_str!("../locales/fr/dbwrite.ftl")),
    (Language::French, include_str!("../locales/fr/sig.ftl")),
    (Language::French, include_str!("../locales/fr/size.ftl")),
];

/// The library messages of `language`, as the audit reads them.
pub(crate) fn library_sources(language: Language) -> impl Iterator<Item = &'static str> {
    LIBRARY.iter().filter(move |(each, _)| *each == language).map(|(_, source)| *source)
}

/// How a rendered message marks the values it quotes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Placeables {
    /// The values are inserted as they are. For a terminal: an isolation mark is an invisible
    /// character there, and it changes the bytes a script compares.
    Plain,
    /// Each value is wrapped in the Unicode marks FSI and PDI (U+2068, U+2069). For a graphical
    /// frontend: a right-to-left value then cannot reorder the sentence around it.
    Isolated,
}

/// Renders [`Message`]s in one language, with English as the fallback.
///
/// A message the language does not translate, or translates with an error, renders in English.
/// A message English does not have renders as its identifier, so the gap is visible and the
/// call never fails. [`Catalog::try_format`] reports both cases instead.
pub struct Catalog {
    language: Language,
    primary: Bundle,
    fallback: Option<Bundle>,
}

impl std::fmt::Debug for Catalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Catalog").field("language", &self.language).finish_non_exhaustive()
    }
}

impl Catalog {
    /// A catalog of the library messages, in `language`.
    #[must_use]
    pub fn new(language: Language, placeables: Placeables) -> Self {
        let fallback =
            (language != Language::English).then(|| empty_bundle(Language::English, placeables));
        let mut catalog = Self { language, primary: empty_bundle(language, placeables), fallback };
        for (each, source) in LIBRARY {
            catalog.add(*each, source);
        }
        catalog
    }

    /// Adds the messages of a frontend, written in `language`.
    ///
    /// A source in a language that is neither the catalog's nor English is not used. A message
    /// whose identifier the catalog already has keeps its first text.
    #[must_use]
    pub fn with(mut self, language: Language, source: &str) -> Self {
        self.add(language, source);
        self
    }

    /// The language the catalog renders.
    #[must_use]
    pub const fn language(&self) -> Language {
        self.language
    }

    /// Renders `message`. This never fails: see [`Catalog`] for what replaces a gap.
    #[must_use]
    pub fn format(&self, message: &Message) -> String {
        if let Ok(text) = self.render(&self.primary, message) {
            return text;
        }
        if let Some(fallback) = &self.fallback
            && let Ok(text) = self.render(fallback, message)
        {
            return text;
        }
        message.id().to_owned()
    }

    /// `bytes` in the largest binary unit it reaches, in the language of the catalog.
    ///
    /// A count of bytes is written whole. A larger unit has two decimals, rounded, after the
    /// decimal mark of the language: `15 B`, `1.46 KiB` and `1.43 MiB` in English. The rule
    /// is `indicatif`'s `BinaryBytes`, so a size in a sentence and a size in a progress bar
    /// agree.
    #[must_use]
    pub fn size(&self, bytes: u64) -> String {
        // A `u64` past 2^53 loses its last digits as an `f64`. That is past 8 PiB, and the
        // two decimals shown are far coarser.
        let mut value = bytes as f64;
        let mut unit = 0;
        while value >= 1024.0 && unit < UNITS.len().saturating_sub(1) {
            value /= 1024.0;
            unit = unit.saturating_add(1);
        }
        let number = if unit == 0 {
            bytes.to_string()
        } else {
            let mark = self.format(&Message::new("size-decimal-mark"));
            format!("{value:.2}").replace('.', &mark)
        };
        let id = UNITS.get(unit).copied().unwrap_or("size-bytes");
        self.format(&Message::new(id).arg("value", number))
    }

    /// Renders `message` in the language of the catalog only, with no fallback.
    ///
    /// # Errors
    ///
    /// [`FormatError::Missing`] when the language has no such message, and
    /// [`FormatError::Invalid`] when the message does not render with these arguments: a
    /// variable it uses has no value, for example.
    pub fn try_format(&self, message: &Message) -> Result<String, FormatError> {
        self.render(&self.primary, message)
    }

    /// Renders `message` with `bundle`, or says why it cannot.
    ///
    /// A nested message is rendered by [`Catalog::format`], with its own fallback, so a gap in
    /// a reason does not cost the sentence around it.
    fn render(&self, bundle: &Bundle, message: &Message) -> Result<String, FormatError> {
        let missing = || FormatError::Missing { id: message.id().to_owned() };
        let pattern =
            bundle.get_message(message.id()).ok_or_else(missing)?.value().ok_or_else(missing)?;
        let mut args = FluentArgs::new();
        for (name, value) in message.args() {
            let value = match value {
                Arg::Text(text) => FluentValue::from(text.as_str()),
                // Fluent holds a number as an `f64`. A count past 2^53 loses its last digits,
                // which no count piko prints comes near.
                Arg::Count(count) => FluentValue::from(*count),
                Arg::Message(nested) => FluentValue::from(self.format(nested)),
                Arg::Size(bytes) => FluentValue::from(self.size(*bytes)),
            };
            args.set(name.as_ref(), value);
        }
        let mut errors = Vec::new();
        let text = bundle.format_pattern(pattern, Some(&args), &mut errors);
        if errors.is_empty() {
            Ok(text.into_owned())
        } else {
            Err(FormatError::Invalid {
                id: message.id().to_owned(),
                errors: errors.iter().map(ToString::to_string).collect(),
            })
        }
    }

    /// Adds `source` to the bundle of `language`, if the catalog has one.
    ///
    /// A syntax error costs only the entry it is in. [`crate::audit::check`] reports it, and
    /// each crate's tests run the audit over its sources.
    fn add(&mut self, language: Language, source: &str) {
        let bundle = if language == self.language {
            &mut self.primary
        } else if language == Language::English
            && let Some(fallback) = &mut self.fallback
        {
            fallback
        } else {
            return;
        };
        let resource =
            FluentResource::try_new(source.to_owned()).unwrap_or_else(|(partial, _)| partial);
        // A duplicate identifier is the one failure here, and the first text stays.
        let _ = bundle.add_resource(resource);
    }
}

/// A bundle for `language`, with no message yet.
fn empty_bundle(language: Language, placeables: Placeables) -> Bundle {
    // Every tag parses: `Language`'s tests check it. The default identifier is `und`, whose
    // plural rules only the English ones would differ from.
    let tag = language.tag().parse().unwrap_or_default();
    let mut bundle = Bundle::new_concurrent(vec![tag]);
    bundle.set_use_isolating(placeables == Placeables::Isolated);
    bundle
}

/// Why a message did not render in the language of a catalog.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum FormatError {
    /// The language has no message with this identifier.
    #[error("the catalog has no message {id}")]
    Missing {
        /// The identifier.
        id: String,
    },
    /// The message exists and did not render with the arguments given.
    #[error("message {id} does not render: {}", errors.join("; "))]
    Invalid {
        /// The identifier.
        id: String,
        /// What Fluent reported, one entry per problem.
        errors: Vec<String>,
    },
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    const EN: &str = "\
greeting = Hello, { $name }
packages = { $count ->
    [one] 1 package
   *[other] { $count } packages
}
only-english = Only in English
";

    const FR: &str = "\
greeting = Bonjour, { $name }
packages = { $count ->
    [one] { $count } paquet
   *[other] { $count } paquets
}
";

    fn catalog(language: Language, placeables: Placeables) -> Catalog {
        Catalog::new(language, placeables).with(Language::English, EN).with(Language::French, FR)
    }

    #[test]
    fn a_message_renders_in_the_language_of_the_catalog() {
        let message = Message::new("greeting").arg("name", "piko");
        assert_eq!(catalog(Language::English, Placeables::Plain).format(&message), "Hello, piko");
        assert_eq!(catalog(Language::French, Placeables::Plain).format(&message), "Bonjour, piko");
    }

    #[test]
    fn a_count_selects_the_plural_form_of_the_language() {
        let en = catalog(Language::English, Placeables::Plain);
        let fr = catalog(Language::French, Placeables::Plain);
        let packages = |count: usize| Message::new("packages").arg("count", count);
        assert_eq!(en.format(&packages(0)), "0 packages");
        assert_eq!(en.format(&packages(1)), "1 package");
        assert_eq!(en.format(&packages(2)), "2 packages");
        // French puts zero in the singular form.
        assert_eq!(fr.format(&packages(0)), "0 paquet");
        assert_eq!(fr.format(&packages(1)), "1 paquet");
        assert_eq!(fr.format(&packages(2)), "2 paquets");
    }

    #[test]
    fn an_untranslated_message_falls_back_to_english() {
        let fr = catalog(Language::French, Placeables::Plain);
        let message = Message::new("only-english");
        assert_eq!(fr.format(&message), "Only in English");
        assert_eq!(
            fr.try_format(&message),
            Err(FormatError::Missing { id: "only-english".to_owned() })
        );
    }

    #[test]
    fn a_message_no_language_has_renders_as_its_identifier() {
        let fr = catalog(Language::French, Placeables::Plain);
        assert_eq!(fr.format(&Message::new("no-such-message")), "no-such-message");
    }

    #[test]
    fn a_missing_argument_is_an_error_and_falls_back() {
        let fr = catalog(Language::French, Placeables::Plain);
        let message = Message::new("greeting");
        assert!(matches!(fr.try_format(&message), Err(FormatError::Invalid { .. })));
        // English has the same error, so the identifier is all that is left.
        assert_eq!(fr.format(&message), "greeting");
    }

    #[test]
    fn a_nested_message_renders_in_the_language_and_falls_back_on_its_own() {
        let fr = catalog(Language::French, Placeables::Plain);
        let nested = |id: &'static str| Message::new("greeting").arg("name", Message::new(id));
        assert_eq!(fr.format(&nested("only-english")), "Bonjour, Only in English");
        let packages = Message::new("packages").arg("count", 2usize);
        let message = Message::new("greeting").arg("name", packages);
        assert_eq!(fr.format(&message), "Bonjour, 2 paquets");
    }

    #[test]
    fn isolation_marks_wrap_a_value_only_when_asked() {
        let message = Message::new("greeting").arg("name", "piko");
        let isolated = catalog(Language::English, Placeables::Isolated).format(&message);
        assert_eq!(isolated, "Hello, \u{2068}piko\u{2069}");
        let plain = catalog(Language::English, Placeables::Plain).format(&message);
        assert_eq!(plain, "Hello, piko");
    }

    #[test]
    fn a_source_in_a_third_language_is_not_used() {
        let fr = Catalog::new(Language::French, Placeables::Plain)
            .with(Language::English, "a = English\n");
        assert_eq!(fr.format(&Message::new("a")), "English");
        let en = Catalog::new(Language::English, Placeables::Plain)
            .with(Language::French, "a = Français\n");
        assert!(en.try_format(&Message::new("a")).is_err());
    }

    #[test]
    fn a_syntax_error_costs_only_its_entry() {
        let en = Catalog::new(Language::English, Placeables::Plain)
            .with(Language::English, "good = Good\nbad = { $\nlater = Later\n");
        assert_eq!(en.try_format(&Message::new("good")).unwrap(), "Good");
        assert_eq!(en.try_format(&Message::new("later")).unwrap(), "Later");
    }

    /// English writes a size as `indicatif`'s `BinaryBytes` does: its own examples.
    #[test]
    fn a_size_takes_the_largest_unit_it_reaches() {
        let english = catalog(Language::English, Placeables::Plain);
        let sizes = [
            (0, "0 B"),
            (15, "15 B"),
            (1023, "1023 B"),
            (1024, "1.00 KiB"),
            (1_500, "1.46 KiB"),
            (1_500_000, "1.43 MiB"),
            (1_500_000_000, "1.40 GiB"),
            (1_500_000_000_000, "1.36 TiB"),
            (1_500_000_000_000_000, "1.33 PiB"),
            (u64::MAX, "16.00 EiB"),
        ];
        for (bytes, text) in sizes {
            assert_eq!(english.size(bytes), text, "{bytes}");
        }
    }

    #[test]
    fn a_size_has_the_decimal_mark_and_the_units_of_the_language() {
        let french = catalog(Language::French, Placeables::Plain);
        assert_eq!(french.size(15), "15\u{a0}o");
        assert_eq!(french.size(1_500_000), "1,43\u{a0}Mio");
        let message = Message::new("size-mib").arg("value", "2");
        assert_eq!(french.format(&message), "2\u{a0}Mio");
        let french = french.with(Language::French, "test-size = { $size } libres");
        let sized = Message::new("test-size").arg("size", Arg::Size(1_500));
        assert_eq!(french.format(&sized), "1,46\u{a0}Kio libres");
    }

    #[test]
    fn a_catalog_can_be_shared_between_threads() {
        fn shareable<T: Send + Sync>() {}
        shareable::<Catalog>();
    }
}
