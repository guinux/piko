//! Shell-style glob matching, in the one place every caller reads it from.
//!
//! Three pattern rules exist across piko, and only the first is here.
//!
//! 1. **Does this one pattern match this one string?** [`matches()`], and [`Glob`] for the same
//!    question asked in a loop. Forward, anchored to the whole string, and with no `!`
//!    inversion.
//! 2. **Does this *list* of patterns select this string?** [`crate::resolve::matches_any`],
//!    which is libalpm's `_alpm_fnmatch_patterns` (`util.c:1528`): a backwards scan where a
//!    leading `!` de-selects.
//! 3. **Does `HoldPkg` name this package?** `cmd::removal::is_held`, in the `piko` crate,
//!    which is pacman's bare `fnmatch` inside a forward `alpm_list_find` (`remove.c:33`), with
//!    no inversion at all.
//!
//! Rules 2 and 3 disagree, on purpose, and both call rule 1 for their innermost test. The scan
//! direction and the `!` sigil are a property of a *list*; whether one pattern covers one
//! string is not. Keeping the innermost test here means the two list rules can differ in
//! exactly the way they are meant to, and in no other way.

/// The three characters that make a string a glob pattern rather than a name.
///
/// `]` is absent on purpose: it closes a class rather than opening one, and `glob::Pattern`
/// reads an unmatched one as a literal.
const METACHARACTERS: [char; 3] = ['*', '?', '['];

/// Whether `target` carries a glob metacharacter, and so names a pattern rather than a package.
///
/// # Reading a metacharacter as a pattern takes no working spelling away
///
/// A package name admits `[A-Za-z0-9_@+.-]`, with `-` and `.` barred from the first position
/// (`alpm_types::Name`). So none of `*`, `?` and `[` can appear in a package name or in a group
/// name, which are the two things a target is expanded against.
///
/// Two `RelationOrSoname` spellings do admit one, both in a **version** position: a version
/// comparison such as `foo>=1*`, and a `SonameV2`'s soname version such as `lib:libfoo.so.*`.
/// Neither can resolve to a package, because no package declares a version or a soname carrying
/// a glob character. So no target that would have resolved is taken over by this reading. The
/// version comparison is refused outright rather than expanded, since its two readings really
/// are ambiguous; the soname simply matches no name.
///
/// Unit tests pin both halves. This is what makes the reading safe rather than merely
/// convenient, so an `alpm-types` release that widened the name grammar has to break here.
#[must_use]
pub fn is_pattern(target: &str) -> bool {
    target.contains(METACHARACTERS)
}

/// Whether `pattern` matches the whole of `text`.
///
/// The rule, written once. A leading `!` is an ordinary character here: inversion belongs to a
/// list of patterns, and the two callers that read a list apply it themselves.
///
/// A malformed pattern — an unbalanced `[`, say — falls back to an exact string comparison
/// rather than matching everything or being reported as a parse error. `fnmatch` has no notion
/// of an invalid pattern to propagate, and a pattern that is really a plain name is by far the
/// common case in `pacman.conf`.
#[must_use]
pub fn matches(pattern: &str, text: &str) -> bool {
    glob::Pattern::new(pattern).map_or(pattern == text, |compiled| compiled.matches(text))
}

/// [`matches()`], with the compile hoisted out of a loop.
///
/// `Glob::new(p).matches(t)` and `matches(p, t)` always agree; a unit test pins that too. This
/// form exists because a target pattern is compared against every package name a
/// [`crate::solve::Universe`] holds, and a search term against every package in a repository —
/// about 15 000 on a real `extra`. Compiling per comparison would build the same
/// `glob::Pattern` once per package.
///
/// Matching is case-sensitive. A caller that wants otherwise lowercases both the pattern and
/// the text before it gets here, which is what [`crate::search`] does.
#[derive(Clone, Debug)]
pub struct Glob {
    pattern: String,
    /// `None` for a malformed pattern, which [`Glob::matches`] then compares literally.
    compiled: Option<glob::Pattern>,
}

impl Glob {
    /// Compiles `pattern`.
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        Self { pattern: pattern.to_owned(), compiled: glob::Pattern::new(pattern).ok() }
    }

    /// Whether this pattern matches the whole of `text`.
    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        self.compiled.as_ref().map_or(self.pattern == text, |compiled| compiled.matches(text))
    }

    /// The pattern as it was given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.pattern
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    #[test]
    fn a_metacharacter_makes_a_target_a_pattern() {
        for target in ["foo*", "f?o", "f[ab]o", "*", "linux-*-headers"] {
            assert!(is_pattern(target), "{target} carries a metacharacter");
        }
    }

    #[test]
    fn a_spelling_a_package_name_could_take_is_never_a_pattern() {
        for target in ["foo", "foo>=1.0", "lib:libfoo.so.1", "gcc-libs", "foo]", "!foo"] {
            assert!(!is_pattern(target), "{target} is a name, a relation or a soname");
        }
    }

    /// The claim [`is_pattern`] rests on: a metacharacter can never appear in the name a
    /// target is expanded against.
    #[test]
    fn a_glob_metacharacter_is_never_a_package_name() {
        for target in ["foo*", "f?o", "f[ab]o", "*", "lib:libfoo.so.*", "foo>=1*"] {
            assert!(target.parse::<alpm_types::Name>().is_err(), "{target} parsed as a Name");
        }
    }

    /// The two spellings that *do* admit a metacharacter, both in a version position. They
    /// parse, so this records where the name-grammar argument stops. Neither resolves to a
    /// package, which is why reading them as patterns steals nothing: a version comparison is
    /// refused when it carries a metacharacter, and a soname matches no package name.
    #[test]
    fn a_metacharacter_survives_only_in_a_version_position() {
        for target in ["foo>=1*", "foo=1.*", "lib:libfoo.so.*"] {
            assert!(
                target.parse::<alpm_types::RelationOrSoname>().is_ok(),
                "{target} no longer parses; the pattern rule can be widened"
            );
        }
        for target in ["foo*", "f?o", "f[ab]o", "*", "python-*"] {
            assert!(
                target.parse::<alpm_types::RelationOrSoname>().is_err(),
                "{target} parsed as a RelationOrSoname"
            );
        }
    }

    #[test]
    fn a_pattern_is_anchored_to_the_whole_string() {
        assert!(matches("lin*", "linux"));
        assert!(!matches("lin*", "xlinux"));
        assert!(!matches("*nux", "linuxx"));
        assert!(matches("*nux", "linux"));
    }

    #[test]
    fn a_malformed_pattern_matches_itself_and_nothing_else() {
        assert!(matches("foo[", "foo["));
        assert!(!matches("foo[", "fooa"));
        assert!(!matches("foo[", "foo"));
    }

    /// Rule 1 has no inversion. `crate::resolve::matching_pattern` strips the sigil before it
    /// gets here, and `cmd::removal::is_held` never strips one at all.
    #[test]
    fn a_leading_bang_is_an_ordinary_character() {
        assert!(!matches("!foo", "foo"));
        assert!(matches("!foo", "!foo"));
    }

    #[test]
    fn matching_is_case_sensitive() {
        assert!(!matches("PYTHON-*", "python-foo"));
        assert!(matches("python-*", "python-foo"));
    }

    /// The compiled form is a cache, so it may never answer differently from the rule it
    /// caches.
    #[test]
    fn the_compiled_form_agrees_with_the_free_function() {
        let cases = [
            ("lin*", "linux"),
            ("lin*", "xlinux"),
            ("foo[", "foo["),
            ("foo[", "fooa"),
            ("!foo", "foo"),
            ("!foo", "!foo"),
            ("f?o", "foo"),
            ("f?o", "fooo"),
            ("f[ab]o", "fao"),
            ("f[ab]o", "fco"),
            ("*", ""),
            ("plain", "plain"),
            ("plain", "other"),
        ];
        for (pattern, text) in cases {
            assert_eq!(
                Glob::new(pattern).matches(text),
                matches(pattern, text),
                "{pattern} against {text}"
            );
        }
    }

    #[test]
    fn a_glob_reports_the_pattern_it_was_built_from() {
        assert_eq!(Glob::new("linux-*").as_str(), "linux-*");
        assert_eq!(Glob::new("foo[").as_str(), "foo[");
    }
}
