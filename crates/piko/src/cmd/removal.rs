//! `HoldPkg`, the one part of removal planning that stays CLI-only.
//!
//! The planning algorithm itself is implemented in [`piko_db::solve`]
//! (`RemovalOptions`/`RemovalFailure`/`plan_removal`/`removal_names`), so any frontend gets the
//! same plan `piko plan -R` is diffed against, not just this CLI. What is left here is
//! genuinely frontend-only.

use piko_db::solve::RemovalFailure;

/// Whether `name` is designated by one of `pacman.conf`'s `HoldPkg` patterns.
///
/// # Not [`piko_db::resolve::matches_any`], deliberately
///
/// The two implement different functions. `matches_any` is libalpm's `_alpm_fnmatch_patterns`
/// (`util.c:1528`). It scans backwards, and a leading `!` inverts the match. pacman's
/// `HoldPkg` check is `alpm_list_find(config->holdpkg, name, fnmatch_cmp)` (`remove.c:137`),
/// and `fnmatch_cmp` is a bare `fnmatch(pattern, string, 0)` (`remove.c:33`): a forward scan
/// with no sigil handling at all.
///
/// The difference is reachable. `HoldPkg = !foo` holds a package literally named `!foo` under
/// pacman's rule, and holds nothing under libalpm's. That is an odd thing to write, but the
/// direction it fails in is the dangerous one: `matches_any` would decide a held package is
/// not held. This repo has already shipped one bug from assuming those two rules were
/// interchangeable.
///
/// A malformed glob falls back to an exact-string comparison, as `matches_any` does and for
/// the same reason: real `fnmatch` has no "invalid pattern" to report, and `HoldPkg` entries
/// are almost always plain names.
fn is_held(name: &str, hold_pkg: &[String]) -> bool {
    hold_pkg.iter().any(|pattern| {
        glob::Pattern::new(pattern).map_or(pattern == name, |compiled| compiled.matches(name))
    })
}

/// pacman's `HoldPkg` guard: whether a removal of `names` may go ahead.
///
/// Transcribed from `pacman_remove` (`remove.c:133-145`), which warns once per held package
/// and then asks a single `noyes` question, a prompt whose default is no.
///
/// 1. It is a prompt, not a hard error. A held package can be removed; the user just has to
///    say so. Making it an error would put piko on the wrong side of a decision pacman leaves
///    to the person running it.
/// 2. `noconfirm` refuses rather than accepts. pacman's `question` returns the preset when
///    `config->noconfirm` is set (`util.c:1737`), and `noyes`'s preset is 0. The flag that
///    means "assume yes" everywhere else means "assume no" here, so an unattended `piko remove
///    --noconfirm` does not take away a held package. piko prints why, instead of echoing
///    pacman's prompt with no answer after it: exiting non-zero without explaining is worse
///    than a line of output.
/// 3. It runs before the plan is displayed, so the warnings are not buried under a step list
///    the user is about to be told they cannot have.
///
/// piko keeps the per-package warnings that pacman's `--print` path drops. That is not a
/// behavioral divergence: pacman loses them to `config->logmask &= ~ALPM_LOG_WARNING`
/// (`pacman.c:1300`), a blanket mute of every warning under `--print`, not a decision about
/// this one. Naming the held package is what makes the refusal actionable.
///
/// Returns `true` to continue. A refusal is [`ExitCode::FAILURE`] at every call site, unlike an
/// ordinary declined prompt, which piko exits `0` for. The `noconfirm` path reaches this
/// refusal with nobody having declined anything, and reporting success for a removal that did
/// not happen is how a script concludes the package is gone. pacman returns 1 for both.
///
/// [`ExitCode::FAILURE`]: std::process::ExitCode::FAILURE
pub fn hold_pkg_allows(
    names: &[String],
    hold_pkg: &[String],
    noconfirm: bool,
    out: &mut impl std::io::Write,
) -> bool {
    let held: Vec<&String> = names.iter().filter(|name| is_held(name, hold_pkg)).collect();
    if held.is_empty() {
        return true;
    }

    for name in held {
        eprintln!("warning: {name} is designated as a HoldPkg");
    }
    if noconfirm {
        // Deliberately does not name a flag. `piko remove` arrives here from `--noconfirm`;
        // `piko plan -R` arrives here always (see the call site for why `--print` forces it).
        eprintln!("error: HoldPkg was found in the target list, and this run cannot ask");
        eprintln!("note: this question defaults to no, so it has to be answered in person");
        return false;
    }
    crate::output::confirm(
        out,
        "HoldPkg was found in target list. Do you want to continue? [y/N] ",
        false,
    )
}

/// Prints a [`RemovalFailure`] to stderr, with the hint that fits it.
pub fn report(failure: &RemovalFailure) {
    match failure {
        RemovalFailure::NotInstalled(name) => {
            eprintln!("error: no installed package or group named {name}");
        }
        RemovalFailure::WouldBreakSystem(facts) => {
            eprintln!("error: removing this would leave the system unsatisfied");
            for fact in facts {
                eprintln!("  {fact}");
            }
            eprintln!("note: pass -c to remove the dependents too");
        }
        RemovalFailure::Planner(error) => crate::output::report(error.as_ref()),
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
    use super::{hold_pkg_allows, is_held};

    fn patterns(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_owned()).collect()
    }

    /// The overwhelmingly common shape: `HoldPkg = pacman glibc`, plain names.
    #[test]
    fn a_plain_name_is_matched_exactly() {
        let held = patterns(&["pacman", "glibc"]);
        assert!(is_held("pacman", &held));
        assert!(is_held("glibc", &held));
        assert!(!is_held("pacman-contrib", &held), "a prefix is not a match");
        assert!(!is_held("libglibc", &held), "a suffix is not a match");
        assert!(!is_held("pacman", &[]), "an empty list holds nothing");
    }

    /// `pacman.conf(5)` documents `HoldPkg` as taking shell globs, and `fnmatch_cmp`
    /// (`remove.c:33`) is what implements it.
    #[test]
    fn a_glob_pattern_is_matched_as_a_glob() {
        let held = patterns(&["linux*"]);
        assert!(is_held("linux", &held));
        assert!(is_held("linux-firmware", &held));
        assert!(!is_held("util-linux", &held));
    }

    /// The whole reason [`is_held`] exists instead of a call to
    /// `piko_db::resolve::matches_any`: pacman's `HoldPkg` check is a bare `fnmatch`, with no
    /// `!` inversion. `matches_any` would read this entry as "everything except `foo`" and
    /// answer `false`, deciding a held package is not held. That is the dangerous direction.
    #[test]
    fn a_leading_bang_is_a_literal_character_not_an_inversion() {
        let held = patterns(&["!foo"]);
        assert!(is_held("!foo", &held), "pacman's fnmatch matches it literally");
        assert!(!is_held("foo", &held), "and it does not hold `foo` itself");
        assert!(
            !piko_db::resolve::matches_any(&held, "!foo"),
            "the libalpm rule really does disagree here; if this ever starts passing, \
             `is_held` may be collapsible into `matches_any`"
        );
    }

    /// Two entries where the later one would override the earlier under libalpm's
    /// backwards-with-inversion scan. pacman's forward `alpm_list_find` has no such rule, so
    /// both still hold.
    #[test]
    fn a_later_entry_does_not_override_an_earlier_one() {
        let held = patterns(&["glibc", "pacman"]);
        assert!(is_held("glibc", &held));
        assert!(is_held("pacman", &held));
    }

    /// Same fallback `matches_any` takes, and for the same reason: `fnmatch` has no invalid
    /// pattern to report, so an unbalanced bracket must not swallow every name.
    #[test]
    fn a_malformed_pattern_falls_back_to_an_exact_comparison() {
        let held = patterns(&["foo[bar"]);
        assert!(is_held("foo[bar", &held));
        assert!(!is_held("foob", &held));
        assert!(!is_held("anything-else", &held));
    }

    /// A removal that touches nothing held must not prompt at all, so `out` stays empty. This
    /// is the case every ordinary `piko remove` takes.
    #[test]
    fn nothing_held_means_no_prompt_and_no_output() {
        let mut out = Vec::new();
        assert!(hold_pkg_allows(
            &patterns(&["foo", "bar"]),
            &patterns(&["pacman"]),
            false,
            &mut out
        ));
        assert!(out.is_empty(), "a prompt was written when nothing was held");
    }

    /// `noconfirm` is the one flag whose meaning inverts here: pacman's `noyes` returns its
    /// preset of 0. A held package must therefore stop an unattended run, and must do so
    /// without writing a question nobody can answer.
    #[test]
    fn noconfirm_refuses_rather_than_accepting() {
        let mut out = Vec::new();
        assert!(!hold_pkg_allows(
            &patterns(&["foo", "pacman"]),
            &patterns(&["pacman"]),
            true,
            &mut out
        ));
        assert!(out.is_empty(), "a question was asked despite there being nobody to answer it");
    }
}
