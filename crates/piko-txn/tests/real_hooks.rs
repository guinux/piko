//! The hook parser against every `.hook` installed on this machine.
//!
//! ```text
//! cargo test -p piko-txn --test real_hooks -- --ignored
//! ```
//!
//! `#[ignore]`d and skipped gracefully, in the established style. These tests read
//! `/usr/share/libalpm/hooks` and `/etc/pacman.d/hooks`, which only exist on a real ALPM system.
//!
//! # What makes this an oracle
//!
//! Every one of these files was installed by a package and is parsed by pacman on every
//! transaction. So pacman's *silence* is the check. If piko refuses one, or splits its `Exec`
//! into a program that is not on this system, piko is wrong: pacman has been running them for
//! months. This is the same shape of oracle file-conflict detection uses (see
//! `docs/libalpm-compat.md` §56). It is also the only oracle available, since there is no
//! `pacman --print-hooks`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::path::{Path, PathBuf};

use piko_txn::hook::{Hooks, When, parse, trigger::Summary};

const SYSTEM_HOOKS: &str = "/usr/share/libalpm/hooks";
const CUSTOM_HOOKS: &str = "/etc/pacman.d/hooks";

/// The configured directories, in pacman's own priority order, or `None` on a non-ALPM system.
fn hook_dirs() -> Option<Vec<PathBuf>> {
    if !Path::new(SYSTEM_HOOKS).is_dir() {
        eprintln!("skipping: {SYSTEM_HOOKS} is not present");
        return None;
    }
    Some(vec![PathBuf::from(SYSTEM_HOOKS), PathBuf::from(CUSTOM_HOOKS)])
}

/// Nothing installed on a working system may fail to parse.
#[test]
#[ignore = "requires a real ALPM system"]
fn every_installed_hook_parses() {
    let Some(dirs) = hook_dirs() else { return };
    let (hooks, problems) = Hooks::collect(&dirs);

    assert!(problems.is_empty(), "real hooks were refused: {problems:#?}");
    assert!(hooks.all().len() > 10, "only {} hooks found", hooks.all().len());
    eprintln!("parsed {} hooks with no problems", hooks.all().len());
}

/// Every `Exec` must name a program that is actually on this system.
///
/// A word-splitting bug shows up here as a path with a quote or half an argument stuck to it.
#[test]
#[ignore = "requires a real ALPM system"]
fn every_exec_names_a_program_that_exists() {
    let Some(dirs) = hook_dirs() else { return };
    let (hooks, _) = Hooks::collect(&dirs);

    let mut checked = 0_usize;
    for hook in hooks.all() {
        let Some(program) = hook.exec.first() else { continue };
        let path = Path::new(program);
        assert!(
            path.is_absolute(),
            "{}: Exec program {program:?} is not an absolute path",
            hook.name
        );
        assert!(path.exists(), "{}: Exec program {} does not exist", hook.name, path.display());
        checked = checked.saturating_add(1);
    }
    assert!(checked > 10, "only {checked} hooks had an Exec");
    eprintln!("checked {checked} Exec programs");
}

/// The `/bin/sh -c '…'` shape must come back as exactly three words, with the script intact.
///
/// Getting the quoting wrong turns one argument into several. The hook then misbehaves,
/// silently.
#[test]
#[ignore = "requires a real ALPM system"]
fn quoted_shell_hooks_split_into_exactly_three_words() {
    let Some(dirs) = hook_dirs() else { return };
    let (hooks, _) = Hooks::collect(&dirs);

    let mut seen = 0_usize;
    for hook in hooks.all() {
        let words: Vec<String> =
            hook.exec.iter().map(|w| w.to_string_lossy().into_owned()).collect();
        if words.get(1).map(String::as_str) != Some("-c") {
            continue;
        }
        assert_eq!(words.len(), 3, "{}: {words:?}", hook.name);
        let script = words.get(2).unwrap();
        assert!(
            !script.starts_with('\'') && !script.ends_with('\''),
            "{}: the quotes were kept in the script: {script}",
            hook.name
        );
        assert!(script.contains(' '), "{}: the script lost its spaces: {script}", hook.name);
        seen = seen.saturating_add(1);
    }
    assert!(seen >= 3, "only {seen} `sh -c` hooks found; expected several on Arch");
}

/// Ordering must be by file name with the suffix removed, across both directories at once.
#[test]
#[ignore = "requires a real ALPM system"]
fn hooks_come_back_in_name_order() {
    let Some(dirs) = hook_dirs() else { return };
    let (hooks, _) = Hooks::collect(&dirs);

    let stems: Vec<&str> = hooks
        .all()
        .iter()
        .map(|hook| hook.name.strip_suffix(".hook").unwrap_or(&hook.name))
        .collect();
    let mut sorted = stems.clone();
    sorted.sort_unstable();
    assert_eq!(stems, sorted, "hooks are not in name order");
}

/// The two real hooks built on an inverted `Target` must exclude what they say they exclude.
///
/// This is the check that would have caught `matches_any` ignoring `!`. Before the fix, both
/// of these hooks reported the files *below* the directory as matched targets. So
/// `gtk-update-icon-cache` would have run against paths its author explicitly excluded.
#[test]
#[ignore = "requires a real ALPM system"]
fn inverted_targets_in_real_hooks_exclude_what_they_name() {
    let Some(dirs) = hook_dirs() else { return };
    let (hooks, _) = Hooks::collect(&dirs);

    let inverted: Vec<_> = hooks
        .all()
        .iter()
        .filter(|hook| {
            hook.triggers.iter().any(|trigger| trigger.targets.iter().any(|t| t.starts_with('!')))
        })
        .collect();
    assert!(!inverted.is_empty(), "no hook on this system uses an inverted Target");

    let mut asserted = 0_usize;
    for hook in inverted {
        let trigger = hook
            .triggers
            .iter()
            .find(|trigger| trigger.targets.iter().any(|t| t.starts_with('!')))
            .unwrap();
        assert!(
            hook.needs_targets,
            "{}: this test can only read a hook's matches through NeedsTargets",
            hook.name
        );

        // Both probes must match the **positive** pattern, or the inverted one is never
        // consulted and the test proves nothing. Two earlier versions of this test got that
        // wrong. One built both probes from the inverted pattern: neither matched, so the hook
        // never fired and every assertion was skipped. The other dropped the trailing slash the
        // real patterns end with, so the deeper probe matched nothing either. Both versions
        // passed against a deliberately reintroduced bug — that is how the errors were found.
        //
        // `usr/lib/modules/*/` uses `fnmatch`'s `*`, which crosses `/` and matches any depth.
        // So the included probe is one segment deep, and the excluded probe is the same path
        // with a further segment. That is exactly the pair `!usr/lib/modules/*/?*` exists to
        // separate.
        let positive = trigger.targets.iter().find(|t| !t.starts_with('!')).unwrap();
        let included = positive.replace("?*", "leaf").replace('*', "branch");
        assert!(
            included.ends_with('/'),
            "{}: this test assumes a directory pattern, got {positive}",
            hook.name
        );
        let excluded = format!("{included}deeper/");

        let summary = Summary {
            added: vec![piko_txn::hook::trigger::Added {
                name: "probe".to_owned(),
                files: vec![included.clone(), excluded.clone()],
                old_files: Vec::new(),
                replaces_installed: false,
            }],
            ..Summary::default()
        };

        let when = hook.when.unwrap_or(When::PostTransaction);
        let fired = hooks.triggered(when, &summary);
        let (_, targets) = fired
            .iter()
            .find(|(fired, _)| fired.name == hook.name)
            .unwrap_or_else(|| panic!("{}: did not fire for {included}", hook.name));

        assert!(
            targets.contains(&included),
            "{}: the included path {included} was not reported; got {targets:?}",
            hook.name
        );
        assert!(
            !targets.contains(&excluded),
            "{}: the excluded path {excluded} was reported as a target — the leading ! was \
             ignored, or the pattern list was scanned forwards",
            hook.name
        );
        asserted = asserted.saturating_add(1);
    }

    assert!(asserted >= 2, "only {asserted} inverted hooks were actually checked");
}

/// Every parsed hook must round-trip its own file: what piko read is what is on disk.
#[test]
#[ignore = "requires a real ALPM system"]
fn every_hook_matches_what_its_file_says() {
    let Some(dirs) = hook_dirs() else { return };
    let (hooks, _) = Hooks::collect(&dirs);

    for hook in hooks.all() {
        // Find which directory it came from. The later one wins.
        let path =
            dirs.iter().rev().map(|dir| dir.join(&hook.name)).find(|path| path.exists()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let reparsed = parse::parse(&hook.name, &text).unwrap();

        assert_eq!(reparsed.when, hook.when, "{}", hook.name);
        assert_eq!(reparsed.exec, hook.exec, "{}", hook.name);
        assert_eq!(reparsed.triggers.len(), hook.triggers.len(), "{}", hook.name);
        assert_eq!(reparsed.depends, hook.depends, "{}", hook.name);

        // Every `Depends` must also be a dependency string piko can parse. Otherwise the hook
        // would be skipped on a system where it is in fact satisfied.
        for entry in &hook.depends {
            assert!(
                entry.parse::<alpm_types::PackageRelation>().is_ok(),
                "{}: unparseable Depends {entry:?}",
                hook.name
            );
        }
    }
}
