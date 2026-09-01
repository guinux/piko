//! Parsing of repository names.
//!
//! Per [alpm-repo-name], a repository name is a UTF-8 string, at least one character long,
//! that must not contain `/`, `?`, `!` or a newline, and must not start with `-`.
//!
//! `alpm-types` has no type for this, confirmed by inspection of its `src/`. This is the
//! second reimplementation this crate carries, alongside [`crate::EntryName`]. The spec is
//! short enough to encode exactly.
//!
//! [alpm-repo-name]: https://alpm.archlinux.page/specifications/alpm-repo-name.7.html

use std::fmt;

/// Why a string is not a valid repository name.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RepoNameError {
    /// The name has no characters at all.
    #[error("a repository name must be at least one character long")]
    Empty,

    /// The name contains `/`, `?`, `!` or a newline.
    #[error("repository name {name:?} contains the disallowed character {found:?}")]
    DisallowedCharacter {
        /// The rejected name.
        name: String,
        /// The character that made it invalid.
        found: char,
    },

    /// The name starts with `-`, which would be ambiguous with a command-line flag.
    #[error("repository name {name:?} must not start with '-'")]
    LeadingDash {
        /// The rejected name.
        name: String,
    },
}

/// A validated repository name, e.g. `core` or `extra`.
///
/// ```
/// use piko_db::repo::RepoName;
///
/// let repo = RepoName::parse("core")?;
/// assert_eq!(repo.as_str(), "core");
///
/// assert!(RepoName::parse("").is_err());
/// assert!(RepoName::parse("-core").is_err());
/// assert!(RepoName::parse("co/re").is_err());
/// # Ok::<(), piko_db::repo::RepoNameError>(())
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepoName(Box<str>);

impl RepoName {
    /// Parses a repository name.
    ///
    /// # Errors
    ///
    /// Returns [`RepoNameError`] if `s` violates the [alpm-repo-name] format.
    ///
    /// [alpm-repo-name]: https://alpm.archlinux.page/specifications/alpm-repo-name.7.html
    pub fn parse(s: &str) -> Result<Self, RepoNameError> {
        if s.is_empty() {
            return Err(RepoNameError::Empty);
        }
        if let Some(found) = s.chars().find(|&c| matches!(c, '/' | '?' | '!' | '\n')) {
            return Err(RepoNameError::DisallowedCharacter { name: s.to_owned(), found });
        }
        if s.starts_with('-') {
            return Err(RepoNameError::LeadingDash { name: s.to_owned() });
        }
        Ok(Self(s.into()))
    }

    /// The repository name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RepoName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RepoName {
    fn as_ref(&self) -> &str {
        &self.0
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

    #[test]
    fn accepts_real_repository_names() {
        for name in ["core", "extra", "multilib", "core-testing"] {
            let repo = RepoName::parse(name).unwrap_or_else(|e| panic!("{name:?}: {e}"));
            assert_eq!(repo.as_str(), name);
            assert_eq!(repo.to_string(), name);
        }
    }

    #[test]
    fn rejects_an_empty_name() {
        assert!(matches!(RepoName::parse(""), Err(RepoNameError::Empty)));
    }

    #[test]
    fn rejects_disallowed_characters() {
        for name in ["co/re", "co?re", "co!re", "co\nre"] {
            assert!(
                matches!(RepoName::parse(name), Err(RepoNameError::DisallowedCharacter { .. })),
                "{name:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_leading_dash() {
        assert!(matches!(RepoName::parse("-core"), Err(RepoNameError::LeadingDash { .. })));
    }

    /// A dash elsewhere in the name is fine; only a *leading* one is ambiguous with a flag.
    #[test]
    fn accepts_a_dash_that_is_not_leading() {
        assert!(RepoName::parse("core-testing").is_ok());
    }
}
