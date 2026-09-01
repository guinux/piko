//! Whether a transaction sets a hook off, and with which targets.
//!
//! This is a pure function over a [`Summary`] of what the transaction will do — no filesystem,
//! no database, no process. That is what makes `_alpm_hook_trigger_match_pkg` and
//! `_alpm_hook_trigger_match_file` (`hook.c:359` and `:254`) reviewable side by side. It is the
//! same split `extract::decision` and `conflict::decision` already use.
//!
//! # "Upgrade" is not "a newer version"
//!
//! `alpm-hooks(5)` is explicit and easy to misread: "Installations are considered an upgrade if
//! the package or file is already present on the system **regardless of whether the new package
//! version is actually greater** than the currently installed version. For Path triggers, this
//! is true even if the file changes ownership from one package to another."
//!
//! So for a `Package` trigger, upgrade means "something was installed under this name before".
//! For a `Path` trigger it means "this path is in both the set being written and the set being
//! taken away". It is computed as a set intersection, with no reference to versions or to which
//! package owned it.

use std::collections::BTreeSet;

use piko_db::resolve::matches_any;

use super::parse::{Hook, Operations, Trigger, TriggerKind};

/// One package the transaction adds.
#[derive(Clone, Debug, Default)]
pub struct Added {
    /// Its name.
    pub name: String,
    /// The paths it will own, without a leading `/`.
    pub files: Vec<String>,
    /// The paths the version it replaces owns, empty for a fresh install.
    ///
    /// This is non-empty, or [`Self::replaces_installed`] is set — the two go together. The
    /// flag exists because a package can replace an installed version that owns no files.
    pub old_files: Vec<String>,
    /// Whether a version of this package was already installed.
    pub replaces_installed: bool,
}

/// One package the transaction takes away outright.
#[derive(Clone, Debug, Default)]
pub struct Removed {
    /// Its name.
    pub name: String,
    /// The paths it owns, without a leading `/`.
    pub files: Vec<String>,
}

/// Everything a hook needs to know about a transaction.
#[derive(Clone, Debug, Default)]
pub struct Summary {
    /// Packages being installed or upgraded — libalpm's `trans->add`.
    pub added: Vec<Added>,
    /// Packages being removed — libalpm's `trans->remove`.
    pub removed: Vec<Removed>,
    /// `NoExtract` patterns: a path matching them is never written, so it triggers nothing.
    pub no_extract: Vec<String>,
}

/// What a trigger matched, if anything.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Matches {
    /// Names or paths appearing where there were none.
    pub install: BTreeSet<String>,
    /// Names or paths replacing existing ones.
    pub upgrade: BTreeSet<String>,
    /// Names or paths going away.
    pub remove: BTreeSet<String>,
}

impl Matches {
    /// Whether `operations` selects at least one of the three sets.
    fn fires(&self, operations: Operations) -> bool {
        (operations.contains(Operations::INSTALL) && !self.install.is_empty())
            || (operations.contains(Operations::UPGRADE) && !self.upgrade.is_empty())
            || (operations.contains(Operations::REMOVE) && !self.remove.is_empty())
    }

    /// The subset `operations` asked for. This is what `NeedsTargets` feeds to the command.
    fn selected(&self, operations: Operations) -> impl Iterator<Item = &String> {
        let install = operations.contains(Operations::INSTALL).then_some(&self.install);
        let upgrade = operations.contains(Operations::UPGRADE).then_some(&self.upgrade);
        let remove = operations.contains(Operations::REMOVE).then_some(&self.remove);
        [install, upgrade, remove].into_iter().flatten().flatten()
    }
}

/// Whether `hook` fires for `summary`, and the sorted targets it matched.
///
/// The target list is empty unless the hook sets `NeedsTargets`. libalpm only accumulates it
/// in that case; collecting it regardless would mean walking every file list of every package
/// for every hook that could not use the result.
///
/// A hook fires if *any* of its triggers does. One part is easy to shortcut wrongly: when
/// `NeedsTargets` is set, every trigger must still be evaluated after one has already matched,
/// because their target lists are joined (`hook.c:423`).
#[must_use]
pub fn triggered(hook: &Hook, summary: &Summary) -> Option<Vec<String>> {
    let mut fired = false;
    let mut targets: BTreeSet<String> = BTreeSet::new();

    for trigger in &hook.triggers {
        let matches = match_trigger(trigger, summary);
        if !matches.fires(trigger.operations) {
            continue;
        }
        fired = true;
        if !hook.needs_targets {
            return Some(Vec::new());
        }
        targets.extend(matches.selected(trigger.operations).cloned());
    }

    fired.then(|| targets.into_iter().collect())
}

/// One trigger against the transaction.
fn match_trigger(trigger: &Trigger, summary: &Summary) -> Matches {
    match trigger.kind {
        Some(TriggerKind::Package) | None => match_packages(trigger, summary),
        Some(TriggerKind::Path) => match_paths(trigger, summary),
    }
}

/// `_alpm_hook_trigger_match_pkg` (`hook.c:359`).
fn match_packages(trigger: &Trigger, summary: &Summary) -> Matches {
    let mut matches = Matches::default();

    for added in &summary.added {
        if !matches_any(&trigger.targets, &added.name) {
            continue;
        }
        if added.replaces_installed {
            matches.upgrade.insert(added.name.clone());
        } else {
            matches.install.insert(added.name.clone());
        }
    }

    for removed in &summary.removed {
        if !matches_any(&trigger.targets, &removed.name) {
            continue;
        }
        // A package that is also being added is not "removed". It is the old half of an
        // upgrade, and counting it would fire a `Remove` trigger on every upgrade.
        if summary.added.iter().any(|added| added.name == removed.name) {
            continue;
        }
        matches.remove.insert(removed.name.clone());
    }

    matches
}

/// `_alpm_hook_trigger_match_file` (`hook.c:254`).
///
/// The three lists are built first, and the intersection is taken afterward, rather than
/// deciding per file. A path counts as an upgrade only by being in *both* halves. The two
/// halves come from different packages often enough that a file-by-file shortcut would be
/// wrong (`alpm-hooks(5)`: "even if the file changes ownership from one package to another").
fn match_paths(trigger: &Trigger, summary: &Summary) -> Matches {
    let mut install: BTreeSet<String> = BTreeSet::new();
    let mut remove: BTreeSet<String> = BTreeSet::new();

    for added in &summary.added {
        for path in &added.files {
            // A `NoExtract` path is never written, so nothing about it changes.
            if matches_any(&summary.no_extract, path) {
                continue;
            }
            if matches_any(&trigger.targets, path) {
                install.insert(path.clone());
            }
        }
        // The version being replaced loses its files, `NoExtract` or not. They are deleted
        // rather than written, so the filter does not apply. libalpm omits it here too.
        for path in &added.old_files {
            if matches_any(&trigger.targets, path) {
                remove.insert(path.clone());
            }
        }
    }

    for removed in &summary.removed {
        for path in &removed.files {
            if matches_any(&trigger.targets, path) {
                remove.insert(path.clone());
            }
        }
    }

    let upgrade: BTreeSet<String> = install.intersection(&remove).cloned().collect();
    Matches {
        install: install.difference(&upgrade).cloned().collect(),
        remove: remove.difference(&upgrade).cloned().collect(),
        upgrade,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::hook::parse::parse;

    fn hook(text: &str) -> Hook {
        parse("test.hook", text).unwrap()
    }

    fn added(name: &str, files: &[&str]) -> Added {
        Added {
            name: name.to_owned(),
            files: files.iter().map(|f| (*f).to_owned()).collect(),
            old_files: Vec::new(),
            replaces_installed: false,
        }
    }

    fn upgraded(name: &str, files: &[&str], old: &[&str]) -> Added {
        Added {
            name: name.to_owned(),
            files: files.iter().map(|f| (*f).to_owned()).collect(),
            old_files: old.iter().map(|f| (*f).to_owned()).collect(),
            replaces_installed: true,
        }
    }

    fn removed(name: &str, files: &[&str]) -> Removed {
        Removed { name: name.to_owned(), files: files.iter().map(|f| (*f).to_owned()).collect() }
    }

    const PACKAGE_INSTALL: &str = "\
[Trigger]
Operation = Install
Type = Package
Target = glibc

[Action]
When = PostTransaction
Exec = /bin/true
";

    #[test]
    fn a_package_trigger_fires_on_a_matching_install() {
        let summary = Summary { added: vec![added("glibc", &[])], ..Summary::default() };
        assert_eq!(triggered(&hook(PACKAGE_INSTALL), &summary), Some(Vec::new()));
    }

    #[test]
    fn a_package_trigger_does_not_fire_on_another_package() {
        let summary = Summary { added: vec![added("bash", &[])], ..Summary::default() };
        assert_eq!(triggered(&hook(PACKAGE_INSTALL), &summary), None);
    }

    /// `Operation = Install` must not fire when the package was already there. This is the
    /// distinction the whole Install/Upgrade split exists for.
    #[test]
    fn an_install_trigger_does_not_fire_on_an_upgrade() {
        let summary = Summary { added: vec![upgraded("glibc", &[], &[])], ..Summary::default() };
        assert_eq!(triggered(&hook(PACKAGE_INSTALL), &summary), None);
    }

    /// "Upgrade" is about presence, not about the version going up. A reinstall or a downgrade
    /// counts as an upgrade for a hook.
    #[test]
    fn an_upgrade_trigger_fires_whenever_something_was_replaced() {
        let text = PACKAGE_INSTALL.replace("Operation = Install", "Operation = Upgrade");
        let summary = Summary { added: vec![upgraded("glibc", &[], &[])], ..Summary::default() };
        assert!(triggered(&hook(&text), &summary).is_some());
    }

    /// The old half of an upgrade is not a removal, or every upgrade would fire every
    /// `Remove` hook.
    #[test]
    fn a_package_being_reinstalled_does_not_count_as_removed() {
        let text = PACKAGE_INSTALL.replace("Operation = Install", "Operation = Remove");
        let summary = Summary {
            added: vec![upgraded("glibc", &[], &[])],
            removed: vec![removed("glibc", &[])],
            ..Summary::default()
        };
        assert_eq!(triggered(&hook(&text), &summary), None);
    }

    #[test]
    fn a_remove_trigger_fires_on_a_real_removal() {
        let text = PACKAGE_INSTALL.replace("Operation = Install", "Operation = Remove");
        let summary = Summary { removed: vec![removed("glibc", &[])], ..Summary::default() };
        assert!(triggered(&hook(&text), &summary).is_some());
    }

    const PATH_HOOK: &str = "\
[Trigger]
Operation = Install
Operation = Upgrade
Type = Path
Target = usr/lib/modules/*

[Action]
When = PostTransaction
Exec = /bin/true
NeedsTargets
";

    #[test]
    fn a_path_trigger_reports_the_paths_it_matched() {
        let summary = Summary {
            added: vec![added("linux", &["usr/lib/modules/6.1/x.ko", "usr/bin/other"])],
            ..Summary::default()
        };
        assert_eq!(
            triggered(&hook(PATH_HOOK), &summary),
            Some(vec!["usr/lib/modules/6.1/x.ko".to_owned()])
        );
    }

    /// A path in both halves is an upgrade and is in neither the install nor the remove set.
    /// Getting this wrong makes an `Operation = Install` path hook fire on every upgrade.
    #[test]
    fn a_path_written_and_taken_away_is_an_upgrade_not_both() {
        let shared = "usr/lib/modules/6.1/x.ko";
        let summary =
            Summary { added: vec![upgraded("linux", &[shared], &[shared])], ..Summary::default() };

        let install_only = "\
[Trigger]
Operation = Install
Type = Path
Target = usr/lib/modules/*

[Action]
When = PostTransaction
Exec = /bin/true
";
        assert_eq!(triggered(&hook(install_only), &summary), None, "counted as an install");

        let upgrade_only = install_only.replace("Operation = Install", "Operation = Upgrade");
        assert!(triggered(&hook(&upgrade_only), &summary).is_some());
    }

    /// The intersection is over paths, not over packages: a file moving between two packages
    /// in one transaction is an upgrade of that path.
    #[test]
    fn a_path_changing_owner_is_an_upgrade() {
        let shared = "usr/lib/modules/6.1/x.ko";
        let summary = Summary {
            added: vec![added("linux-new", &[shared])],
            removed: vec![removed("linux-old", &[shared])],
            ..Summary::default()
        };
        let upgrade_only = "\
[Trigger]
Operation = Upgrade
Type = Path
Target = usr/lib/modules/*

[Action]
When = PostTransaction
Exec = /bin/true
";
        assert!(triggered(&hook(upgrade_only), &summary).is_some());
    }

    /// A path that will never be written triggers nothing.
    #[test]
    fn a_no_extract_path_does_not_trigger() {
        let summary = Summary {
            added: vec![added("linux", &["usr/lib/modules/6.1/x.ko"])],
            no_extract: vec!["usr/lib/modules/*".to_owned()],
            ..Summary::default()
        };
        assert_eq!(triggered(&hook(PATH_HOOK), &summary), None);
    }

    /// The real `60-depmod.hook` shape: match a directory, exclude everything under it.
    #[test]
    fn an_inverted_target_excludes_what_an_earlier_one_matched() {
        let text = "\
[Trigger]
Operation = Install
Type = Path
Target = usr/lib/modules/*
Target = !usr/lib/modules/*/?*

[Action]
When = PostTransaction
Exec = /bin/true
NeedsTargets
";
        let summary = Summary {
            added: vec![added(
                "linux",
                &["usr/lib/modules/6.1/", "usr/lib/modules/6.1/kernel/fs/x.ko"],
            )],
            ..Summary::default()
        };
        assert_eq!(
            triggered(&hook(text), &summary),
            Some(vec!["usr/lib/modules/6.1/".to_owned()]),
            "the excluded path was reported as a target"
        );
    }

    /// Without `NeedsTargets` the list is empty. The walk stops at the first trigger that
    /// fires, since there is nothing left to learn.
    #[test]
    fn targets_are_only_collected_when_the_hook_asks_for_them() {
        let summary = Summary {
            added: vec![added("linux", &["usr/lib/modules/6.1/x.ko"])],
            ..Summary::default()
        };
        let without = PATH_HOOK.replace("NeedsTargets\n", "");
        assert_eq!(triggered(&hook(&without), &summary), Some(Vec::new()));
    }

    /// With `NeedsTargets`, every trigger is evaluated and the lists are joined. Stopping at
    /// the first match would feed the command a short list.
    #[test]
    fn needs_targets_joins_every_trigger() {
        let text = "\
[Trigger]
Operation = Install
Type = Package
Target = alpha

[Trigger]
Operation = Install
Type = Package
Target = beta

[Action]
When = PostTransaction
Exec = /bin/true
NeedsTargets
";
        let summary =
            Summary { added: vec![added("alpha", &[]), added("beta", &[])], ..Summary::default() };
        assert_eq!(
            triggered(&hook(text), &summary),
            Some(vec!["alpha".to_owned(), "beta".to_owned()])
        );
    }

    /// Only the operations the trigger asked for reach the command's stdin.
    #[test]
    fn only_the_selected_operations_are_reported_as_targets() {
        let text = "\
[Trigger]
Operation = Remove
Type = Package
Target = *

[Action]
When = PostTransaction
Exec = /bin/true
NeedsTargets
";
        let summary = Summary {
            added: vec![added("installed-one", &[])],
            removed: vec![removed("removed-one", &[])],
            ..Summary::default()
        };
        assert_eq!(triggered(&hook(text), &summary), Some(vec!["removed-one".to_owned()]));
    }

    /// A masking hook has no triggers, so nothing can set it off.
    #[test]
    fn a_masking_hook_never_fires() {
        let summary = Summary { added: vec![added("anything", &[])], ..Summary::default() };
        assert_eq!(triggered(&hook(""), &summary), None);
    }

    /// An empty transaction fires nothing, whatever the hook says.
    #[test]
    fn an_empty_transaction_fires_nothing() {
        for text in [PACKAGE_INSTALL, PATH_HOOK] {
            assert_eq!(triggered(&hook(text), &Summary::default()), None);
        }
    }
}
