//! The languages piko has a translation for, and how the environment selects one.

/// A language piko has a translation for.
///
/// English is the source language. Every other language falls back to it, message by message.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Language {
    /// English, the source language.
    English,
    /// French.
    French,
}

impl Language {
    /// Every language, the source language first.
    pub const ALL: &'static [Self] = &[Self::English, Self::French];

    /// The BCP 47 tag of the language, which selects its plural rules.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::French => "fr",
        }
    }

    /// The language a POSIX locale name selects, or `None` when piko has no translation for it.
    ///
    /// The name has the form `language[_territory][.codeset][@modifier]`, as in `fr_FR.UTF-8`.
    /// Only the language part counts. `C` and `POSIX` select English.
    #[must_use]
    pub fn from_locale(name: &str) -> Option<Self> {
        let language = name.split(['_', '-', '.', '@']).next().unwrap_or_default();
        match language {
            "C" | "POSIX" | "en" => Some(Self::English),
            "fr" => Some(Self::French),
            _ => None,
        }
    }

    /// The language the environment of this process selects, as gettext selects it.
    ///
    /// The first of `LC_ALL`, `LC_MESSAGES` and `LANG` that is set and not empty names the
    /// locale. When that locale is not `C` or `POSIX`, the colon-separated list in `LANGUAGE`
    /// comes first, and the first entry piko has a translation for wins. Anything else selects
    /// English.
    ///
    /// This is a convenience for a frontend that follows the environment. A frontend with its
    /// own setting passes its own [`Language`] to [`crate::Catalog::new`] instead.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_variables(|name| std::env::var(name).ok())
    }

    /// [`Language::from_env`], over a lookup the tests control.
    fn from_variables(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let set = |name: &str| lookup(name).filter(|value| !value.is_empty());
        let Some(locale) = set("LC_ALL").or_else(|| set("LC_MESSAGES")).or_else(|| set("LANG"))
        else {
            return Self::English;
        };
        // gettext ignores `LANGUAGE` in the `C` locale, so a script that sets `LC_ALL=C` gets
        // the untranslated text whatever else is set.
        if matches!(locale.split(['.', '@']).next(), Some("C" | "POSIX")) {
            return Self::English;
        }
        if let Some(list) = set("LANGUAGE")
            && let Some(language) = list.split(':').find_map(Self::from_locale)
        {
            return language;
        }
        Self::from_locale(&locale).unwrap_or(Self::English)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn negotiate(variables: &[(&str, &str)]) -> Language {
        Language::from_variables(|name| {
            variables.iter().find(|(key, _)| *key == name).map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn a_locale_name_selects_its_language_part() {
        assert_eq!(Language::from_locale("fr_FR.UTF-8"), Some(Language::French));
        assert_eq!(Language::from_locale("fr_CA@euro"), Some(Language::French));
        assert_eq!(Language::from_locale("fr"), Some(Language::French));
        assert_eq!(Language::from_locale("en_GB.UTF-8"), Some(Language::English));
        assert_eq!(Language::from_locale("C.UTF-8"), Some(Language::English));
        assert_eq!(Language::from_locale("POSIX"), Some(Language::English));
        assert_eq!(Language::from_locale("de_DE.UTF-8"), None);
        assert_eq!(Language::from_locale("français"), None);
    }

    #[test]
    fn lc_all_comes_before_lc_messages_and_lang() {
        assert_eq!(negotiate(&[("LANG", "fr_FR.UTF-8")]), Language::French);
        assert_eq!(negotiate(&[("LANG", "fr_FR.UTF-8"), ("LC_ALL", "C")]), Language::English);
        assert_eq!(
            negotiate(&[("LANG", "en_US.UTF-8"), ("LC_MESSAGES", "fr_FR.UTF-8")]),
            Language::French
        );
    }

    #[test]
    fn an_empty_variable_counts_as_unset() {
        assert_eq!(negotiate(&[("LC_ALL", ""), ("LANG", "fr_FR.UTF-8")]), Language::French);
    }

    #[test]
    fn language_is_ignored_in_the_c_locale() {
        assert_eq!(negotiate(&[("LC_ALL", "C"), ("LANGUAGE", "fr")]), Language::English);
        assert_eq!(negotiate(&[("LANGUAGE", "fr")]), Language::English);
    }

    #[test]
    fn language_takes_its_first_entry_with_a_translation() {
        assert_eq!(
            negotiate(&[("LANG", "en_US.UTF-8"), ("LANGUAGE", "de:fr:en")]),
            Language::French
        );
        assert_eq!(negotiate(&[("LANG", "fr_FR.UTF-8"), ("LANGUAGE", "de:nl")]), Language::French);
    }

    #[test]
    fn a_language_without_a_translation_selects_english() {
        assert_eq!(negotiate(&[("LANG", "de_DE.UTF-8")]), Language::English);
        assert_eq!(negotiate(&[]), Language::English);
    }

    #[test]
    fn every_tag_parses() {
        for language in Language::ALL {
            assert!(language.tag().parse::<unic_langid::LanguageIdentifier>().is_ok());
        }
    }
}
