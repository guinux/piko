//! `fnmatch(pattern, string, 0)`, transcribed from glibc 2.44 (`posix/fnmatch.c` and
//! `posix/fnmatch_loop.c`).
//!
//! libalpm matches a pattern with exactly this call (`_alpm_fnmatch`, `util.c:1557`), and
//! pacman's `HoldPkg` check calls `fnmatch` directly (`remove.c:33`). The `glob` crate reads a
//! different grammar: it has no `\` escape, reads `[^…]` as a set that holds `^`, and refuses an
//! unclosed `[` or a `**` next to another character. So this module is a transcription, not a
//! translation into the crate's grammar. `crates/piko-db/tests/glob_real_system.rs` diffs it
//! against the C library's `fnmatch`.
//!
//! # What the transcription keeps
//!
//! - `\` escapes the next character, also inside a bracket expression. A pattern that ends in
//!   a lone `\` matches nothing.
//! - `[!…]` and `[^…]` both negate. glibc reads `^` as a literal only when `POSIXLY_CORRECT` is
//!   set, and this module never reads the environment.
//! - A `]` right after `[`, `[!` or `[^` is a member of the set. A `-` first or last is a
//!   member too.
//! - A `[` with no closing `]` is an ordinary character, and the rest of the pattern is read
//!   from the character after it.
//! - `[:class:]`, `[=c=]` and `[.c.]` inside a bracket expression, with each malformed spelling
//!   handled the way glibc handles it, including its quirks. A class name glibc cannot read
//!   refuses the match. An equivalence class or a collating symbol names one character only.
//! - `*` and `?` match `/` and a leading `.`: the flags are 0.
//! - The text is read twice when the first read finds no match. glibc converts both strings to
//!   wide characters in a multibyte locale. When that version finds no match, `fnmatch` runs the
//!   byte version too. So under pacman's UTF-8 locale `??` matches `é`, which is two bytes.
//!
//! # The locale is fixed to `C.UTF-8`
//!
//! pacman calls `setlocale(LC_ALL, "")`, so its answer depends on the user's locale. In
//! `en_US.UTF-8`, `[a-z]` matches `é`, and `[a-Z]` is a valid range. A pattern in `pacman.conf` or
//! in a hook decides what a transaction does, and the same configuration must decide the same
//! thing for every user. This module answers as glibc answers in `C.UTF-8`. A range compares
//! collation sequence values, and `C.UTF-8` gives one only to the characters below U+0100, equal
//! to the code point. A character past that is in no range, and a range that ends past it holds
//! its first character only (see `range_tail`). A byte always has a value, equal to the byte.
//! A character class follows the character's Unicode properties, which glibc's
//! `C.UTF-8` tables are generated from. For ASCII the classes are exact. The `combining` class,
//! which only `C.UTF-8` and the locales built on it define, is not known here, so a pattern that
//! names it matches nothing.

/// The end of the pattern or of the text. Both are C strings in glibc, so a NUL ends them.
const NUL: u32 = 0;
const STAR: u32 = '*' as u32;
const QUESTION: u32 = '?' as u32;
const BACKSLASH: u32 = '\\' as u32;
const OPEN: u32 = '[' as u32;
const CLOSE: u32 = ']' as u32;
const BANG: u32 = '!' as u32;
const CARET: u32 = '^' as u32;
const COLON: u32 = ':' as u32;
const EQUALS: u32 = '=' as u32;
const DOT: u32 = '.' as u32;
const DASH: u32 = '-' as u32;
const LOWER_A: u32 = 'a' as u32;
const LOWER_Z: u32 = 'z' as u32;

/// glibc's `CHAR_CLASS_MAX_LENGTH`, which is `CHARCLASS_NAME_MAX` (`bits/posix2_lim.h`).
const CHAR_CLASS_MAX_LENGTH: usize = 2048;

/// A pattern, ready to match: its characters and its bytes, each up to the first NUL.
#[derive(Clone, Debug)]
pub(super) struct Compiled {
    /// The characters, for glibc's wide version.
    wide: Box<[u32]>,
    /// The bytes, for glibc's byte version.
    narrow: Box<[u32]>,
    /// Whether the pattern is ASCII, so that both versions read the same units.
    ascii: bool,
    /// The pattern, when it holds no `*`, `?`, `[` or `\`. It then matches only itself.
    literal: Option<Box<str>>,
}

impl Compiled {
    /// Prepares `pattern`.
    pub(super) fn new(pattern: &str) -> Self {
        let pattern = until_nul(pattern);
        Self {
            wide: pattern.chars().map(u32::from).collect(),
            narrow: pattern.bytes().map(u32::from).collect(),
            ascii: pattern.is_ascii(),
            literal: (!pattern.contains(['*', '?', '[', '\\'])).then(|| pattern.into()),
        }
    }

    /// `fnmatch(pattern, text, 0) == 0`.
    pub(super) fn matches(&self, text: &str) -> bool {
        self.matches_text(text, false)
    }

    /// `fnmatch(pattern, name, FNM_PERIOD) == 0`, for a directory entry's name: a `.` that
    /// starts the name matches only a `.` in the pattern, never a wildcard or a bracket
    /// expression.
    ///
    /// A name that is not UTF-8 cannot be read as characters. glibc's conversion fails, and it
    /// runs the byte version alone.
    pub(super) fn matches_name(&self, name: &[u8]) -> bool {
        match std::str::from_utf8(name) {
            Ok(name) => self.matches_text(name, true),
            Err(_) => fct(&self.narrow, &Narrow(name), 0, 0, true, None),
        }
    }

    /// `fnmatch`, with `FNM_PERIOD` when `period` is set.
    fn matches_text(&self, text: &str, period: bool) -> bool {
        if let Some(literal) = &self.literal {
            return text
                .strip_prefix(&**literal)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('\0'));
        }
        let text = until_nul(text);
        // With both strings in ASCII, the two versions read the same units and answer the same.
        // The byte version is the cheaper one to run.
        if self.ascii && text.is_ascii() {
            return fct(&self.narrow, &Narrow(text.as_bytes()), 0, 0, period, None);
        }
        fct(&self.wide, &Wide(text), 0, 0, period, None)
            || fct(&self.narrow, &Narrow(text.as_bytes()), 0, 0, period, None)
    }
}

/// `text` up to its first NUL, where the C string ends.
fn until_nul(text: &str) -> &str {
    text.find('\0').and_then(|at| text.get(..at)).unwrap_or(text)
}

/// The text, read by one version of the matcher.
trait Text {
    /// The unit at `n`, or `None` at the end of the text.
    fn at(&self, n: usize) -> Option<u32>;
    /// Where the unit after the one at `n` starts.
    fn after(&self, n: usize) -> usize;
    /// Where the text ends.
    fn end(&self) -> usize;
    /// Whether `unit` belongs to `class`: `iswctype` or `_ISCTYPE`.
    fn in_class(class: Class, unit: u32) -> bool;
    /// The collation sequence value of `unit`, which a range compares, or `None` when the locale
    /// gives it none: `__collseq_table_lookup` in the wide version, `collseq[]` in the byte one.
    fn collation_sequence(unit: u32) -> Option<u32>;
}

/// The text by character, as glibc's wide version reads it. A position is a byte offset.
struct Wide<'a>(&'a str);

impl Text for Wide<'_> {
    fn at(&self, n: usize) -> Option<u32> {
        self.0.get(n..)?.chars().next().map(u32::from)
    }

    fn after(&self, n: usize) -> usize {
        let width = self.0.get(n..).and_then(|rest| rest.chars().next()).map_or(1, char::len_utf8);
        n.saturating_add(width)
    }

    fn end(&self) -> usize {
        self.0.len()
    }

    fn in_class(class: Class, unit: u32) -> bool {
        char::from_u32(unit).is_some_and(|c| class.contains(c))
    }

    /// `C.UTF-8`'s wide table holds the characters below U+0100 only, each valued at its code
    /// point. Measured with glibc 2.44 over every code point.
    fn collation_sequence(unit: u32) -> Option<u32> {
        (unit < 0x100).then_some(unit)
    }
}

/// The text by byte, as glibc's byte version reads it in a UTF-8 locale.
struct Narrow<'a>(&'a [u8]);

impl Text for Narrow<'_> {
    fn at(&self, n: usize) -> Option<u32> {
        self.0.get(n).copied().map(u32::from)
    }

    fn after(&self, n: usize) -> usize {
        n.saturating_add(1)
    }

    fn end(&self) -> usize {
        self.0.len()
    }

    /// A byte past ASCII is part of a multibyte character in a UTF-8 locale, and belongs to no
    /// class.
    fn in_class(class: Class, unit: u32) -> bool {
        u8::try_from(unit).is_ok_and(|byte| byte.is_ascii() && class.contains(char::from(byte)))
    }

    /// `C.UTF-8`'s byte table values every byte at the byte itself.
    fn collation_sequence(unit: u32) -> Option<u32> {
        Some(unit)
    }
}

/// A `[:name:]` class glibc's `wctype` knows in every locale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Class {
    Alnum,
    Alpha,
    Blank,
    Cntrl,
    Digit,
    Graph,
    Lower,
    Print,
    Punct,
    Space,
    Upper,
    Xdigit,
}

impl Class {
    /// The class `name` names, as `wctype` reads it.
    fn named(name: &[u32]) -> Option<Self> {
        let name: String = name.iter().filter_map(|unit| char::from_u32(*unit)).collect();
        Some(match name.as_str() {
            "alnum" => Self::Alnum,
            "alpha" => Self::Alpha,
            "blank" => Self::Blank,
            "cntrl" => Self::Cntrl,
            "digit" => Self::Digit,
            "graph" => Self::Graph,
            "lower" => Self::Lower,
            "print" => Self::Print,
            "punct" => Self::Punct,
            "space" => Self::Space,
            "upper" => Self::Upper,
            "xdigit" => Self::Xdigit,
            _ => return None,
        })
    }

    /// Whether `c` belongs to this class.
    ///
    /// For ASCII, this is the `C` locale's table. Past ASCII, it is the Unicode property glibc's
    /// `C.UTF-8` table is generated from (`localedata/unicode-gen/unicode_utils.py`). A digit is
    /// `0` to `9` only, and another script's decimal digit is alphabetic.
    fn contains(self, c: char) -> bool {
        match self {
            Self::Alnum => is_alpha(c) || c.is_ascii_digit(),
            Self::Alpha => is_alpha(c),
            Self::Blank => c == '\t' || (is_space(c) && !is_line_break(c)),
            Self::Cntrl => c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'),
            Self::Digit => c.is_ascii_digit(),
            Self::Graph => is_print(c) && !is_space(c),
            Self::Lower => c.is_lowercase(),
            Self::Print => is_print(c),
            Self::Punct => is_print(c) && !is_space(c) && !is_alpha(c) && !c.is_ascii_digit(),
            Self::Space => is_space(c),
            Self::Upper => c.is_uppercase(),
            Self::Xdigit => c.is_ascii_hexdigit(),
        }
    }
}

/// glibc's `is_alpha`: alphabetic, or a decimal digit of a script other than ASCII.
fn is_alpha(c: char) -> bool {
    c.is_alphabetic() || (!c.is_ascii() && c.is_numeric())
}

/// glibc's `is_space`: white space, except a no-break space and a control character other
/// than the five ASCII ones.
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
        || (c.is_whitespace()
            && !c.is_control()
            && !matches!(c, '\u{a0}' | '\u{2007}' | '\u{202f}'))
}

/// Whether `c` ends a line, so that it is space but not blank.
fn is_line_break(c: char) -> bool {
    matches!(c, '\n' | '\u{b}' | '\u{c}' | '\r' | '\u{2028}' | '\u{2029}')
}

/// glibc's `is_print`: not a control character, nor a line or paragraph separator.
fn is_print(c: char) -> bool {
    !c.is_control() && !matches!(c, '\u{2028}' | '\u{2029}')
}

/// Where a `*` stopped a nested match: glibc's `struct STRUCT`.
#[derive(Clone, Copy, Debug)]
struct Ends {
    /// The `*` in the pattern.
    pattern: usize,
    /// The position in the text.
    string: usize,
    /// Whether a `.` at that position must be matched by a `.`.
    no_leading_period: bool,
}

/// The unit at `i` in `pattern`, or [`NUL`] past its end.
fn unit(pattern: &[u32], i: usize) -> u32 {
    pattern.get(i).copied().unwrap_or(NUL)
}

/// glibc's `FCT`: matches `pattern` from `p` against `text` from `n`.
///
/// With `no_leading_period`, a `.` at `n` is matched by a `.` only: glibc's `FNM_PERIOD`, which
/// applies to the first unit of the text alone.
///
/// With `ends`, the match stops at the next `*`, records where in `ends`, and succeeds. The
/// caller then goes on from there. That is how glibc matches the part between two `*` at the
/// first place it fits, and never tries a later one.
fn fct<T: Text>(
    pattern: &[u32],
    text: &T,
    mut p: usize,
    mut n: usize,
    mut no_leading_period: bool,
    mut ends: Option<&mut Option<Ends>>,
) -> bool {
    loop {
        let mut c = unit(pattern, p);
        if c == NUL {
            break;
        }
        p = p.saturating_add(1);

        match c {
            QUESTION => {
                let Some(current) = text.at(n) else { return false };
                if current == DOT && no_leading_period {
                    return false;
                }
            }
            BACKSLASH => {
                c = unit(pattern, p);
                p = p.saturating_add(1);
                // A trailing `\` loses.
                if c == NUL || text.at(n) != Some(c) {
                    return false;
                }
            }
            STAR => {
                if let Some(slot) = ends.as_mut() {
                    **slot =
                        Some(Ends { pattern: p.saturating_sub(1), string: n, no_leading_period });
                    return true;
                }
                if no_leading_period && text.at(n) == Some(DOT) {
                    return false;
                }

                // Every `?` among the `*` consumes one unit, and the `*` merge into one.
                c = unit(pattern, p);
                p = p.saturating_add(1);
                while c == QUESTION || c == STAR {
                    if c == QUESTION {
                        if text.at(n).is_none() {
                            return false;
                        }
                        n = text.after(n);
                    }
                    c = unit(pattern, p);
                    p = p.saturating_add(1);
                }
                if c == NUL {
                    return true;
                }

                let mut end: Option<Ends> = None;
                let mut found = false;
                // A literal unit lets the loop skip every position that cannot start the rest.
                let first = match c {
                    OPEN => None,
                    BACKSLASH => Some(unit(pattern, p)),
                    _ => Some(c),
                };
                p = p.saturating_sub(1);
                while n < text.end() {
                    if first.is_none_or(|first| text.at(n) == Some(first))
                        && fct(pattern, text, p, n, no_leading_period, Some(&mut end))
                    {
                        found = true;
                        break;
                    }
                    n = text.after(n);
                    no_leading_period = false;
                }
                match (found, end) {
                    (true, None) => return true,
                    (true, Some(at)) => {
                        p = at.pattern;
                        n = at.string;
                        no_leading_period = at.no_leading_period;
                        continue;
                    }
                    (false, _) => return false,
                }
            }
            OPEN => {
                let Some(current) = text.at(n) else { return false };
                if current == DOT && no_leading_period {
                    return false;
                }
                match bracket::<T>(pattern, p, current) {
                    Bracket::Fail => return false,
                    Bracket::Consumed(after) => p = after,
                    // An unclosed `[` is an ordinary character, and the pattern goes on from
                    // the unit after it.
                    Bracket::Literal => {
                        if current != OPEN {
                            return false;
                        }
                    }
                }
            }
            _ => {
                if text.at(n) != Some(c) {
                    return false;
                }
            }
        }
        n = text.after(n);
        no_leading_period = false;
    }
    n == text.end()
}

/// What a bracket expression decided for one unit of the text.
enum Bracket {
    /// The unit does not match, or the expression is malformed in a way glibc refuses.
    Fail,
    /// The unit matches. The pattern goes on at this position.
    Consumed(usize),
    /// The `[` has no closing `]`, and is an ordinary character.
    Literal,
}

/// What one member of a bracket expression decided.
enum Member {
    /// The unit is a member. The rest of the expression starts at this position.
    Matched(usize),
    /// The unit is not this member: `c` is the next unit of the pattern, and `p` follows it.
    Next { c: u32, p: usize },
    /// glibc returns `FNM_NOMATCH` from inside the expression.
    Fail,
}

/// Matches `current` against the bracket expression whose `[` ends just before `p`.
fn bracket<T: Text>(pattern: &[u32], mut p: usize, current: u32) -> Bracket {
    let not = matches!(unit(pattern, p), BANG | CARET);
    if not {
        p = p.saturating_add(1);
    }
    let mut c = unit(pattern, p);
    p = p.saturating_add(1);

    loop {
        let member = if c == BACKSLASH {
            if unit(pattern, p) == NUL {
                return Bracket::Fail;
            }
            normal_member::<T>(pattern, unit(pattern, p), p.saturating_add(1), current)
        } else if c == OPEN && unit(pattern, p) == COLON {
            class_member::<T>(pattern, p, current)
        } else if c == OPEN && unit(pattern, p) == EQUALS {
            equivalence_member::<T>(pattern, p, current)
        } else if c == NUL {
            return Bracket::Literal;
        } else if c == OPEN && unit(pattern, p) == DOT {
            collating_member::<T>(pattern, p, current)
        } else {
            normal_member::<T>(pattern, c, p, current)
        };

        match member {
            Member::Matched(after) => return skip_matched(pattern, after, not),
            Member::Fail => return Bracket::Fail,
            Member::Next { c: next, p: after } => {
                c = next;
                p = after;
            }
        }
        if c == CLOSE {
            return if not { Bracket::Consumed(p) } else { Bracket::Fail };
        }
    }
}

/// `[:name:]`, with `p` on the `:`.
///
/// A name holds the letters `a` to `y` only: glibc tests `c >= 'z'`, so a `z` ends it too. Any
/// other character means this is no class, and the `[` is an ordinary member.
fn class_member<T: Text>(pattern: &[u32], open: usize, current: u32) -> Member {
    let mut p = open;
    let mut name: Vec<u32> = Vec::new();
    loop {
        if name.len() == CHAR_CLASS_MAX_LENGTH {
            return Member::Fail;
        }
        p = p.saturating_add(1);
        let c = unit(pattern, p);
        if c == COLON && unit(pattern, p.saturating_add(1)) == CLOSE {
            p = p.saturating_add(2);
            break;
        }
        if !(LOWER_A..LOWER_Z).contains(&c) {
            return normal_member::<T>(pattern, OPEN, open, current);
        }
        name.push(c);
    }
    let Some(class) = Class::named(&name) else { return Member::Fail };
    if T::in_class(class, current) {
        return Member::Matched(p);
    }
    Member::Next { c: unit(pattern, p), p: p.saturating_add(1) }
}

/// `[=c=]`, with `p` on the first `=`. In a locale with no collation rules, it names `c`.
fn equivalence_member<T: Text>(pattern: &[u32], open: usize, current: u32) -> Member {
    let named = unit(pattern, open.saturating_add(1));
    if named == NUL
        || unit(pattern, open.saturating_add(2)) != EQUALS
        || unit(pattern, open.saturating_add(3)) != CLOSE
    {
        return normal_member::<T>(pattern, OPEN, open, current);
    }
    let p = open.saturating_add(4);
    if current == named {
        return Member::Matched(p);
    }
    Member::Next { c: unit(pattern, p), p: p.saturating_add(1) }
}

/// `[.c.]`, with `p` on the first `.`. In a locale with no collation rules, only a symbol of
/// one character exists. It can start a range.
fn collating_member<T: Text>(pattern: &[u32], open: usize, current: u32) -> Member {
    let Some((symbol, mut p)) = collating_symbol(pattern, open) else { return Member::Fail };
    let is_range = unit(pattern, p) == DASH && unit(pattern, p.saturating_add(1)) != NUL;
    if !is_range && current == symbol {
        return Member::Matched(p);
    }
    let c = unit(pattern, p);
    p = p.saturating_add(1);
    range_tail::<T>(pattern, symbol, c, p, current)
}

/// Reads `[.c.]` with `open` on the first `.`: the one character it names, and the position
/// after its `]`. `None` for an unclosed symbol, or one that is not one character long.
fn collating_symbol(pattern: &[u32], open: usize) -> Option<(u32, usize)> {
    let mut p = open;
    let mut length: usize = 0;
    loop {
        p = p.saturating_add(1);
        let c = unit(pattern, p);
        if c == DOT && unit(pattern, p.saturating_add(1)) == CLOSE {
            break;
        }
        if c == NUL {
            return None;
        }
        length = length.saturating_add(1);
    }
    (length == 1).then(|| (unit(pattern, open.saturating_add(1)), p.saturating_add(2)))
}

/// glibc's `normal_bracket`: the member `c`, read just before `p`, which can start a range.
fn normal_member<T: Text>(pattern: &[u32], c: u32, p: usize, current: u32) -> Member {
    let after = unit(pattern, p.saturating_add(1));
    let is_range = unit(pattern, p) == DASH && after != NUL && after != CLOSE;
    if !is_range && c == current {
        return Member::Matched(p);
    }
    let next = unit(pattern, p);
    range_tail::<T>(pattern, c, next, p.saturating_add(1), current)
}

/// Reads a range from `cold` when `c` is a `-` that does not end the expression. `p` follows
/// `c`.
///
/// glibc compares collation sequence values, not characters, in three steps:
///
/// 1. It looks up `current` before it reads the end of the range. A unit with no value is in no
///    range, and glibc goes on from the unit after the one that follows the `-`. So a `[.c.]` end
///    is not read as one: its `.`, `c` and `.` become members, and its `]` closes the expression.
///    A `\` end escapes nothing either.
/// 2. A range whose start has no value holds nothing.
/// 3. A range whose end has no value holds its start only.
///
/// When the `-` is the last unit of the pattern and `current` has no value, glibc reads past the
/// end of the pattern. This refuses the match instead, as glibc does for a unit that has one.
fn range_tail<T: Text>(pattern: &[u32], cold: u32, c: u32, mut p: usize, current: u32) -> Member {
    if c != DASH || unit(pattern, p) == CLOSE {
        return Member::Next { c, p };
    }
    let mut cend = unit(pattern, p);
    p = p.saturating_add(1);
    let Some(fcollseq) = T::collation_sequence(current) else {
        if cend == NUL {
            return Member::Fail;
        }
        return Member::Next { c: unit(pattern, p), p: p.saturating_add(1) };
    };
    if cend == OPEN && unit(pattern, p) == DOT {
        let Some((symbol, after)) = collating_symbol(pattern, p) else { return Member::Fail };
        cend = symbol;
        p = after;
    } else {
        if cend == BACKSLASH {
            cend = unit(pattern, p);
            p = p.saturating_add(1);
        }
        if cend == NUL {
            return Member::Fail;
        }
    }
    let matched = match (T::collation_sequence(cold), T::collation_sequence(cend)) {
        (None, _) => false,
        (Some(lcollseq), None) => lcollseq == fcollseq,
        (Some(lcollseq), Some(hcollseq)) => lcollseq <= fcollseq && fcollseq <= hcollseq,
    };
    if matched {
        return Member::Matched(p);
    }
    Member::Next { c: unit(pattern, p), p: p.saturating_add(1) }
}

/// glibc's `matched:` loop: skips the rest of an expression that already matched.
///
/// It reads the rest with rules of its own, which are not the scan's: a class name ends at the
/// first character outside `a` to `y`, and a malformed `[=` or `[.` refuses the match. An
/// expression with no closing `]` makes the `[` an ordinary character here too.
fn skip_matched(pattern: &[u32], mut p: usize, not: bool) -> Bracket {
    loop {
        let c = unit(pattern, p);
        p = p.saturating_add(1);
        if c == CLOSE {
            break;
        }
        if c == NUL {
            return Bracket::Literal;
        }
        if c == BACKSLASH {
            if unit(pattern, p) == NUL {
                return Bracket::Fail;
            }
            p = p.saturating_add(1);
        } else if c == OPEN && unit(pattern, p) == COLON {
            let start = p;
            let mut length: usize = 0;
            loop {
                p = p.saturating_add(1);
                let c = unit(pattern, p);
                length = length.saturating_add(1);
                if length == CHAR_CLASS_MAX_LENGTH {
                    return Bracket::Fail;
                }
                if c == COLON && unit(pattern, p.saturating_add(1)) == CLOSE {
                    break;
                }
                if !(LOWER_A..LOWER_Z).contains(&c) {
                    // Back to the `:`, after the `+= 2` below, as glibc's `startp - 2` does.
                    p = start.saturating_sub(2);
                    break;
                }
            }
            p = p.saturating_add(2);
        } else if c == OPEN && unit(pattern, p) == EQUALS {
            if unit(pattern, p.saturating_add(1)) == NUL {
                return Bracket::Fail;
            }
            p = p.saturating_add(2);
            if unit(pattern, p) != EQUALS || unit(pattern, p.saturating_add(1)) != CLOSE {
                return Bracket::Fail;
            }
            p = p.saturating_add(2);
        } else if c == OPEN && unit(pattern, p) == DOT {
            loop {
                p = p.saturating_add(1);
                let c = unit(pattern, p);
                if c == NUL {
                    return Bracket::Fail;
                }
                if c == DOT && unit(pattern, p.saturating_add(1)) == CLOSE {
                    break;
                }
            }
            p = p.saturating_add(2);
        }
    }
    if not { Bracket::Fail } else { Bracket::Consumed(p) }
}
