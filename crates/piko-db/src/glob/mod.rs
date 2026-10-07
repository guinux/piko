//! Shell-style glob matching, in the one place every caller reads it from.
//!
//! Three pattern rules exist across piko, and only the first is here.
//!
//! 1. **Does this one pattern match this one string?** [`matches()`], and [`Glob`] for the same
//!    question asked in a loop. Forward, anchored to the whole string, and with no `!`
//!    inversion.
//! 2. **Does this *list* of patterns select this string?** [`crate::resolve::PatternList`],
//!    which is libalpm's `_alpm_fnmatch_patterns` (`util.c:1528`): a backwards scan where a
//!    leading `!` de-selects.
//! 3. **Does `HoldPkg` name this package?** `cmd::removal::is_held`, in the `piko` crate. It
//!    is pacman's bare `fnmatch` inside a forward `alpm_list_find` (`remove.c:33`), with no
//!    inversion at all.
//!
//! Rules 2 and 3 disagree, on purpose, and both call rule 1 for their innermost test. The scan
//! direction and the `!` sigil are a property of a *list*. Whether one pattern covers one
//! string is not. Keeping the innermost test here lets the two list rules differ in exactly
//! the way they are meant to. They can differ in no other way.
//!
//! Rule 1 is glibc's `fnmatch(pattern, string, 0)`, which libalpm calls for every pattern it
//! reads. The `fnmatch` submodule transcribes it, because no crate reads the same grammar.
//!
//! [`expand()`] is glibc's `glob`, which lists the paths a pattern names on the filesystem. It
//! is what `pacman.conf`'s `Include` reads, and it matches each name with the same `fnmatch`.

mod expand;
mod fnmatch;

pub use expand::expand;

/// The three characters that make a string a glob pattern rather than a name.
///
/// `]` is absent on purpose: it closes a bracket expression rather than opening one, and
/// `fnmatch` reads a `]` outside one as an ordinary character.
const METACHARACTERS: [char; 3] = ['*', '?', '['];

/// Whether `target` carries a glob metacharacter, and so names a pattern rather than a package.
///
/// # Reading a metacharacter as a pattern takes no working spelling away
///
/// A package name admits `[A-Za-z0-9_@+.-]`, with `-` and `.` barred from the first position
/// (`alpm_types::Name`). So none of `*`, `?` and `[` can appear in a package name or a group
/// name. Those are the two things a target is expanded against.
///
/// Two `RelationOrSoname` spellings do admit one, both in a **version** position. They are a
/// version comparison such as `foo>=1*`, and a `SonameV2`'s soname version such as
/// `lib:libfoo.so.*`.
/// Neither can resolve to a package, because no package declares a version or a soname carrying
/// a glob character. So no target that would have resolved is taken over by this reading. The
/// version comparison is refused outright rather than expanded, since its two readings really
/// are ambiguous; the soname simply matches no name.
///
/// Unit tests pin both halves. That is what makes the reading safe rather than merely
/// convenient. An `alpm-types` release widening the name grammar has to break here.
#[must_use]
pub fn is_pattern(target: &str) -> bool {
    target.contains(METACHARACTERS)
}

/// Whether `pattern` matches the whole of `text`.
///
/// The rule, written once. A leading `!` is an ordinary character here. Inversion belongs to a
/// list of patterns, and the two callers that read a list apply it themselves.
///
/// The grammar is `fnmatch`'s, so no pattern is malformed. A `\` escapes the next character,
/// `[!…]` and `[^…]` both negate, and a `[` with no closing `]` is an ordinary character. A
/// pattern that ends in a lone `\` matches nothing.
#[must_use]
pub fn matches(pattern: &str, text: &str) -> bool {
    fnmatch::Compiled::new(pattern).matches(text)
}

/// [`matches()`], with the compile hoisted out of a loop.
///
/// `Glob::new(p).matches(t)` and `matches(p, t)` always agree, and a unit test pins that too.
/// This form exists because a target pattern is compared against every package name a
/// [`crate::solve::Universe`] holds. A search term is compared against every package in a
/// repository, about 15 000 on a real `extra`. Compiling per comparison would decode the same
/// pattern once per package.
///
/// Matching is case-sensitive. A caller that wants otherwise lowercases both the pattern and
/// the text before it gets here, which is what [`crate::search`] does.
#[derive(Clone, Debug)]
pub struct Glob {
    pattern: String,
    compiled: fnmatch::Compiled,
}

impl Glob {
    /// Compiles `pattern`.
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        Self { pattern: pattern.to_owned(), compiled: fnmatch::Compiled::new(pattern) }
    }

    /// Whether this pattern matches the whole of `text`.
    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        self.compiled.matches(text)
    }

    /// The pattern as it was given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.pattern
    }
}

#[cfg(test)]
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
    /// package, which is why reading them as patterns steals nothing. A version comparison is
    /// refused when it carries a metacharacter. A soname matches no package name.
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

    /// A `[` with no closing `]` is an ordinary character.
    #[test]
    fn an_unclosed_bracket_is_an_ordinary_character() {
        assert!(matches("foo[", "foo["));
        assert!(!matches("foo[", "fooa"));
        assert!(!matches("foo[", "foo"));
    }

    /// The grammar is glibc's `fnmatch`, not the `glob` crate's. Each answer was measured with
    /// glibc 2.44's `fnmatch(pattern, text, 0)` in `C.UTF-8`. `tests/glob_real_system.rs` diffs
    /// the rule against the C library over several million pairs.
    #[test]
    fn the_grammar_is_fnmatch() {
        let cases = [
            // `^` negates, as `!` does.
            ("[^a]b", "xb", true),
            ("[^a]b", "ab", false),
            ("[!a]b", "xb", true),
            // `\` escapes the next character. A lone `\` at the end matches nothing.
            (r"etc/foo\*", "etc/foo*", true),
            (r"etc/foo\*", "etc/foobar", false),
            (r"foo\\", r"foo\", true),
            (r"foo\", r"foo\", false),
            (r"foo\", "foo", false),
            (r"[\]", "]", false),
            (r"[\]]", "]", true),
            // An unclosed `[` is an ordinary character, and the rest is still a pattern.
            ("a[*", "a[xyz", true),
            ("a[*", "ab", false),
            ("foo[bar", "foo[bar", true),
            ("foo[bar", "foob", false),
            // Any run of `*` is one `*`, and it matches `/` and a leading `.`.
            ("***", "abc", true),
            ("a**b", "axyb", true),
            ("*.conf", ".x.conf", true),
            ("usr/*", "usr/a/b", true),
            // A first `]` is a member, and so is a `-` that ends the set.
            ("[]a]", "]", true),
            ("[!]a]", "b", true),
            ("[!]a]", "]", false),
            ("[a-]", "-", true),
            ("[z-a]", "m", false),
            // Classes, equivalence classes and collating symbols.
            ("[[:alpha:]]", "é", true),
            ("[[:digit:]]", "\u{663}", false),
            ("[[:foo:]]", "f", false),
            ("[![:foo:]]", "f", false),
            ("[[=a=]]", "a", true),
            ("[[.a.]]", "a", true),
            ("[[.ab.]]", "a", false),
            // A range compares collation sequence values, which `C.UTF-8` gives to the
            // characters below U+0100 only. A character past that is in no range, and a range
            // that ends past it holds its first character only.
            ("[à-ê]", "é", true),
            ("[Ā-ʒ]", "ɐ", false),
            ("[!Ā-ʒ]", "ɐ", true),
            ("[ʒ-ʒ]", "ʒ", false),
            ("[é-ʒ]", "ö", false),
            ("[é-ʒ]", "é", true),
            ("[a-[.ʒ.]]", "b", false),
            // For a character with no value, glibc reads on past the `-` before it reads the
            // range's end. The `]` of a `[.z.]` end then closes the expression.
            ("[!a-[.z.]]", "ɐ", false),
            ("[!a-[.z.]]", "ɐ]", true),
            ("[!a-[.z.]]", "é", true),
            // A text glibc's wide reading refuses is read again byte by byte.
            ("?", "é", true),
            ("??", "é", true),
            ("", "", true),
        ];
        for (pattern, text, expected) in cases {
            assert_eq!(matches(pattern, text), expected, "{pattern:?} against {text:?}");
            assert_eq!(Glob::new(pattern).matches(text), expected, "{pattern:?} against {text:?}");
        }
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
