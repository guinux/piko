//! Which program a front end starts for a merge, and in which order its arguments go.
//!
//! The order is the algorithm, so it lives here. `diff3 -m` takes the caller's file, then the
//! common ancestor, then the other side. Swapping the first and the last produces a merge that
//! keeps the wrong side, and the result still looks like a merge. A second front end must get
//! that order without re-deriving it.
//!
//! Starting the program is not here. That needs a terminal, and it is a front end's job. See
//! [`Invocation`].
//!
//! # No shell runs
//!
//! `pacdiff` leaves `$diffprog` unquoted and lets the shell split it, which also expands globs
//! and depends on `IFS`. This module splits with the rule piko already owns for a hook's
//! `Exec`: whitespace separates words, `'` and `"` quote a run inside a word, and nothing is
//! expanded. An unbalanced quote is refused rather than guessed at. So `DIFFPROG='meld --diff'`
//! works, and a value that needs a shell has to name one.

use std::{ffi::OsString, path::Path};

use crate::hook::wordsplit::{self, SplitError};

/// The program a difference is shown with, when nothing else is configured.
///
/// `pacdiff` defaults to `vim -d`. piko defaults to `diff -u`, which prints the difference and
/// returns. So the default answers "what changed" without taking over the terminal, and the
/// question is asked again straight after. An editor is one `DIFFPROG` away for anyone who
/// wants to edit there.
///
/// A three-way view (`-3`) hands the program three paths. `diff` takes two, so that flag needs
/// a `DIFFPROG` that reads three, such as `vim -d`.
pub const DEFAULT_DIFFPROG: &str = "diff -u";
/// The program three files are merged with, when nothing else is configured.
///
/// `pacdiff`'s own default. It writes the merged file to its standard output, and exits
/// non-zero when it wrote conflict markers.
pub const DEFAULT_MERGEPROG: &str = "diff3 -m";

/// A program to start, split into the program and its arguments.
///
/// The configured arguments come first, then the file paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    /// The program to start.
    pub program: OsString,
    /// Its arguments.
    pub arguments: Vec<OsString>,
}

/// Splits a `DIFFPROG` or `MERGEPROG` value into words.
///
/// # Errors
///
/// [`SplitError`] if a quote is left open, or if the value holds no word.
pub fn parse_program(value: &str) -> Result<Vec<OsString>, SplitError> {
    wordsplit::split(value)
}

/// `$DIFFPROG <pacfile> <target>`, the two-way view.
///
/// `None` when `diffprog` is empty, which [`parse_program`] already refuses.
#[must_use]
pub fn two_way_diff(diffprog: &[OsString], pacfile: &Path, target: &Path) -> Option<Invocation> {
    self::build(diffprog, &[pacfile, target])
}

/// `$DIFFPROG <pacfile> <base> <target>`, the three-way view `pacdiff --threeway` shows.
///
/// `None` when `diffprog` is empty.
#[must_use]
pub fn three_way_diff(
    diffprog: &[OsString],
    pacfile: &Path,
    base: &Path,
    target: &Path,
) -> Option<Invocation> {
    self::build(diffprog, &[pacfile, base, target])
}

/// `$MERGEPROG <mine> <base> <theirs>`, whose standard output is the merged file.
///
/// `mine` is the installed file, `base` the common ancestor, `theirs` the pending file. That
/// order is what `diff3 -m` reads, and reversing it keeps the wrong side.
///
/// `None` when `mergeprog` is empty.
#[must_use]
pub fn three_way_merge(
    mergeprog: &[OsString],
    mine: &Path,
    base: &Path,
    theirs: &Path,
) -> Option<Invocation> {
    self::build(mergeprog, &[mine, base, theirs])
}

/// `$DIFFPROG <target> <merged>`, the review shown before a merge is kept.
///
/// `None` when `diffprog` is empty.
#[must_use]
pub fn review_diff(diffprog: &[OsString], target: &Path, merged: &Path) -> Option<Invocation> {
    self::build(diffprog, &[target, merged])
}

/// Splits `words` into a program and its arguments, then appends `paths`.
fn build(words: &[OsString], paths: &[&Path]) -> Option<Invocation> {
    let (program, configured) = words.split_first()?;
    let mut arguments: Vec<OsString> = configured.to_vec();
    arguments.extend(paths.iter().map(|path| path.as_os_str().to_os_string()));
    Some(Invocation { program: program.clone(), arguments })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn words(value: &str) -> Vec<OsString> {
        parse_program(value).unwrap()
    }

    fn rendered(invocation: &Invocation) -> Vec<String> {
        std::iter::once(invocation.program.to_string_lossy().into_owned())
            .chain(invocation.arguments.iter().map(|a| a.to_string_lossy().into_owned()))
            .collect()
    }

    #[test]
    fn splits_a_program_and_its_flags() {
        assert_eq!(words(DEFAULT_DIFFPROG), vec![OsString::from("diff"), OsString::from("-u")]);
        assert_eq!(words(DEFAULT_MERGEPROG), vec![OsString::from("diff3"), OsString::from("-m")]);
        // A value the user may set, rather than one piko ships.
        assert_eq!(words("vim -d"), vec![OsString::from("vim"), OsString::from("-d")]);
    }

    #[test]
    fn a_quoted_run_stays_one_word() {
        assert_eq!(
            words("meld '--diff mode'"),
            vec![OsString::from("meld"), OsString::from("--diff mode")]
        );
    }

    /// An unbalanced quote is refused rather than guessed at. No shell runs, so there is
    /// nothing to fall back on.
    #[test]
    fn refuses_an_unbalanced_quote() {
        assert!(parse_program("vim '-d").is_err());
        assert!(parse_program("   ").is_err());
    }

    #[test]
    fn the_two_way_view_shows_the_pending_file_first() {
        let invocation =
            two_way_diff(&words("vim -d"), Path::new("/etc/f.pacnew"), Path::new("/etc/f"))
                .unwrap();
        assert_eq!(rendered(&invocation), ["vim", "-d", "/etc/f.pacnew", "/etc/f"]);
    }

    #[test]
    fn the_three_way_view_puts_the_base_in_the_middle() {
        let invocation = three_way_diff(
            &words("vim -d"),
            Path::new("/etc/f.pacnew"),
            Path::new("/tmp/base"),
            Path::new("/etc/f"),
        )
        .unwrap();
        assert_eq!(rendered(&invocation), ["vim", "-d", "/etc/f.pacnew", "/tmp/base", "/etc/f"]);
    }

    /// `diff3 -m` reads mine, then the ancestor, then theirs. Reversing the first and the last
    /// keeps the wrong side, and the result still looks like a merge.
    #[test]
    fn the_merge_takes_mine_then_base_then_theirs() {
        let invocation = three_way_merge(
            &words(DEFAULT_MERGEPROG),
            Path::new("/etc/f"),
            Path::new("/tmp/base"),
            Path::new("/etc/f.pacnew"),
        )
        .unwrap();
        assert_eq!(rendered(&invocation), ["diff3", "-m", "/etc/f", "/tmp/base", "/etc/f.pacnew"]);
    }

    #[test]
    fn the_review_shows_the_installed_file_first() {
        let invocation =
            review_diff(&words("vim -d"), Path::new("/etc/f"), Path::new("/tmp/merged")).unwrap();
        assert_eq!(rendered(&invocation), ["vim", "-d", "/etc/f", "/tmp/merged"]);
    }

    #[test]
    fn an_empty_word_list_builds_nothing() {
        assert!(two_way_diff(&[], Path::new("a"), Path::new("b")).is_none());
    }
}
