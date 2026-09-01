//! Parses one `.hook` file.
//!
//! This transcribes `_alpm_hook_parse_cb` and `_alpm_hook_validate` (`hook.c:149` and `:113`)
//! over the tokenizer `pacman.conf` uses — the same one libalpm uses here
//! ([`piko_db::config::ini`]).
//!
//! # A hook with no triggers is valid and does nothing
//!
//! That looks like a missing check. It is the opposite. `alpm-hooks(5)` documents disabling a
//! hook by shadowing it with a symlink to `/dev/null` in a higher-priority directory. The
//! symlink parses as an empty file, yielding a hook with no triggers, no `Exec`, and no `When`.
//! `_alpm_hook_validate` returns success for exactly that case — "allow triggerless hooks as a
//! way of creating dummy hooks that can be used to mask lower priority hooks" — and the result
//! never matches any transaction while still occupying its name. Rejecting it would turn every
//! disabled hook into a parse error.

use std::ffi::OsString;

use piko_db::config::ini::{Line, tokenize};

use super::wordsplit;

/// When a hook runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum When {
    /// Before the transaction's first change.
    PreTransaction,
    /// After the transaction's last change.
    PostTransaction,
}

/// Whether a trigger matches package names or archive paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriggerKind {
    /// `Type = Package`.
    Package,
    /// `Type = Path`.
    Path,
}

/// Which kinds of change a trigger reacts to.
///
/// This is a small bitmask rather than a `Vec<Operation>`. `Operation` is repeatable, and the
/// only question ever asked of it is membership — matching `_alpm_hook_op_t` (`hook.c:32`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Operations(u8);

impl Operations {
    /// A package or path appearing where there was none.
    pub const INSTALL: Self = Self(1 << 0);
    /// A package or path replacing an existing one.
    pub const UPGRADE: Self = Self(1 << 1);
    /// A package or path going away.
    pub const REMOVE: Self = Self(1 << 2);

    /// Whether every bit of `other` is set here.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether no operation was named at all.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for Operations {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// One `[Trigger]` section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trigger {
    /// The `Operation` lines, combined.
    pub operations: Operations,
    /// The `Type` line. `None` until one is seen, which validation then refuses.
    pub kind: Option<TriggerKind>,
    /// The `Target` lines, in file order. Order matters: the last one that matches decides
    /// (see [`piko_db::resolve::matches_any`]).
    pub targets: Vec<String>,
}

/// A parsed hook file.
#[derive(Clone, Debug)]
pub struct Hook {
    /// The file name, including the `.hook` suffix. This is its identity for overriding.
    pub name: String,
    /// `Description`, shown while the hook runs.
    pub description: Option<String>,
    /// Every `[Trigger]` section, in file order.
    pub triggers: Vec<Trigger>,
    /// `Depends` lines: packages that must be installed for the hook to run.
    pub depends: Vec<String>,
    /// `Exec`, already split into a program and its arguments.
    pub exec: Vec<OsString>,
    /// `When`. `None` only for a triggerless masking hook, which never runs.
    pub when: Option<When>,
    /// `AbortOnFail`: a non-zero exit stops the transaction. `PreTransaction` only.
    pub abort_on_fail: bool,
    /// `NeedsTargets`: the matched targets are fed to the command on stdin.
    pub needs_targets: bool,
}

impl Hook {
    /// Whether this hook can ever run.
    ///
    /// This is false for a masking hook: one whose only job is to occupy a name so a lower
    /// priority directory's hook of the same name does not load.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.triggers.is_empty() && self.when.is_some() && !self.exec.is_empty()
    }
}

/// Why a `.hook` file was rejected.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{file}: {reason}")]
pub struct ParseError {
    /// The hook file's name.
    pub file: String,
    /// What was wrong with it.
    pub reason: String,
}

/// Parses `text` as the hook file called `name`.
///
/// # Errors
///
/// [`ParseError`] for anything `_alpm_hook_parse_cb` or `_alpm_hook_validate` would refuse: an
/// unknown section or option, an unrecognised value, a trigger missing any of its three
/// required parts, or a hook with triggers but no `Exec`/`When`.
pub fn parse(name: &str, text: &str) -> Result<Hook, ParseError> {
    let mut hook = Hook {
        name: name.to_owned(),
        description: None,
        triggers: Vec::new(),
        depends: Vec::new(),
        exec: Vec::new(),
        when: None,
        abort_on_fail: false,
        needs_targets: false,
    };
    let mut section: Option<Section> = None;
    let mut warnings = Vec::new();

    for token in tokenize(text) {
        let fail = |reason: String| ParseError {
            file: name.to_owned(),
            reason: format!("line {}: {reason}", token.line),
        };
        match token.content {
            Line::Section { name: "Trigger" } => {
                hook.triggers.push(Trigger {
                    operations: Operations::default(),
                    kind: None,
                    targets: Vec::new(),
                });
                section = Some(Section::Trigger);
            }
            Line::Section { name: "Action" } => section = Some(Section::Action),
            Line::Section { name: other } => {
                return Err(fail(format!("invalid section {other}")));
            }
            Line::Directive { key, value } => {
                // A directive before any section header. libalpm's callback gets `section ==
                // NULL` and reports the key as an invalid option.
                let Some(current) = section else {
                    return Err(fail(format!("invalid option {key}")));
                };
                // `ini.c` hands the callback a `NULL` value for a bare key. Every hook
                // directive that takes one dereferences it. Only `AbortOnFail` and
                // `NeedsTargets` are flags.
                let text = value.unwrap_or("");
                match current {
                    Section::Trigger => {
                        let Some(trigger) = hook.triggers.last_mut() else {
                            return Err(fail("a trigger directive with no [Trigger]".to_owned()));
                        };
                        trigger_directive(trigger, key, text, &mut warnings).map_err(&fail)?;
                    }
                    Section::Action => {
                        action_directive(&mut hook, key, text, &mut warnings).map_err(fail)?;
                    }
                }
            }
        }
    }

    validate(&hook).map_err(|reason| ParseError { file: name.to_owned(), reason })?;
    Ok(hook)
}

/// Which section directives are being read into.
#[derive(Clone, Copy, Debug)]
enum Section {
    Trigger,
    Action,
}

/// One directive inside `[Trigger]`.
fn trigger_directive(
    trigger: &mut Trigger,
    key: &str,
    value: &str,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    match key {
        "Operation" => {
            let operation = match value {
                "Install" => Operations::INSTALL,
                "Upgrade" => Operations::UPGRADE,
                "Remove" => Operations::REMOVE,
                other => return Err(format!("invalid value {other}")),
            };
            trigger.operations = trigger.operations | operation;
        }
        "Type" => {
            if trigger.kind.is_some() {
                warnings.push("overwriting previous definition of Type".to_owned());
            }
            trigger.kind = Some(match value {
                "Package" => TriggerKind::Package,
                // `alpm-hooks(5)`: "File is a deprecated alias for Path".
                "Path" | "File" => TriggerKind::Path,
                other => return Err(format!("invalid value {other}")),
            });
        }
        "Target" => trigger.targets.push(value.to_owned()),
        other => return Err(format!("invalid option {other}")),
    }
    Ok(())
}

/// One directive inside `[Action]`.
fn action_directive(
    hook: &mut Hook,
    key: &str,
    value: &str,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    match key {
        "When" => {
            if hook.when.is_some() {
                warnings.push("overwriting previous definition of When".to_owned());
            }
            hook.when = Some(match value {
                "PreTransaction" => When::PreTransaction,
                "PostTransaction" => When::PostTransaction,
                other => return Err(format!("invalid value {other}")),
            });
        }
        "Description" => {
            if hook.description.is_some() {
                warnings.push("overwriting previous definition of Description".to_owned());
            }
            hook.description = Some(value.to_owned());
        }
        "Depends" => hook.depends.push(value.to_owned()),
        "AbortOnFail" => hook.abort_on_fail = true,
        "NeedsTargets" => hook.needs_targets = true,
        "Exec" => {
            if !hook.exec.is_empty() {
                warnings.push("overwriting previous definition of Exec".to_owned());
            }
            hook.exec =
                wordsplit::split(value).map_err(|error| format!("invalid value: {error}"))?;
        }
        other => return Err(format!("invalid option {other}")),
    }
    Ok(())
}

/// `_alpm_hook_validate` (`hook.c:113`).
fn validate(hook: &Hook) -> Result<(), String> {
    // The masking case: a hook with no triggers is complete as it stands. This check runs
    // first, exactly as libalpm does, so the absent `Exec` and `When` checks below never run.
    if hook.triggers.is_empty() {
        return Ok(());
    }

    for (index, trigger) in hook.triggers.iter().enumerate() {
        let position = index.saturating_add(1);
        if trigger.targets.is_empty() {
            return Err(format!("trigger {position} has no Target"));
        }
        if trigger.kind.is_none() {
            return Err(format!("trigger {position} has no Type"));
        }
        if trigger.operations.is_empty() {
            return Err(format!("trigger {position} has no Operation"));
        }
    }

    if hook.exec.is_empty() {
        return Err("it has no Exec".to_owned());
    }
    match hook.when {
        None => Err("it has no When".to_owned()),
        // libalpm warns rather than refusing. The hook is still runnable; the flag is simply
        // meaningless after the transaction has already happened.
        Some(_) => Ok(()),
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

    const REAL: &str = "\
[Trigger]
Operation = Install
Operation = Upgrade
Target = glibc
Type = Package

[Action]
Depends = bash
Depends = glibc
Description = Generating the configured locale...
Exec = /usr/bin/locale-gen
When = PostTransaction
";

    #[test]
    fn parses_a_real_hook() {
        let hook = parse("10-glibc-locale-gen.hook", REAL).unwrap();

        assert_eq!(hook.name, "10-glibc-locale-gen.hook");
        assert_eq!(hook.description.as_deref(), Some("Generating the configured locale..."));
        assert_eq!(hook.depends, ["bash", "glibc"]);
        assert_eq!(hook.exec, [std::ffi::OsStr::new("/usr/bin/locale-gen")]);
        assert_eq!(hook.when, Some(When::PostTransaction));
        assert!(!hook.abort_on_fail);
        assert!(!hook.needs_targets);

        assert_eq!(hook.triggers.len(), 1);
        let trigger = hook.triggers.first().unwrap();
        assert_eq!(trigger.kind, Some(TriggerKind::Package));
        assert_eq!(trigger.targets, ["glibc"]);
        assert!(trigger.operations.contains(Operations::INSTALL));
        assert!(trigger.operations.contains(Operations::UPGRADE));
        assert!(!trigger.operations.contains(Operations::REMOVE));
        assert!(hook.is_active());
    }

    #[test]
    fn multiple_triggers_are_kept_in_file_order() {
        let text = "\
[Trigger]
Operation = Install
Type = Package
Target = a

[Trigger]
Operation = Remove
Type = Path
Target = usr/lib/*

[Action]
When = PreTransaction
Exec = /bin/true
";
        let hook = parse("x.hook", text).unwrap();
        assert_eq!(hook.triggers.len(), 2);
        assert_eq!(hook.triggers.first().unwrap().kind, Some(TriggerKind::Package));
        assert_eq!(hook.triggers.get(1).unwrap().kind, Some(TriggerKind::Path));
    }

    /// The flags take no value.
    #[test]
    fn the_bare_flags_are_recognised() {
        let text = "\
[Trigger]
Operation = Upgrade
Type = Package
Target = *

[Action]
When = PreTransaction
Exec = /bin/true
AbortOnFail
NeedsTargets
";
        let hook = parse("x.hook", text).unwrap();
        assert!(hook.abort_on_fail);
        assert!(hook.needs_targets);
    }

    /// The documented way to disable a hook: shadow it with a symlink to `/dev/null`. That
    /// reads as an empty file. It must parse, and it must never run.
    #[test]
    fn an_empty_file_is_a_valid_masking_hook() {
        let hook = parse("disabled.hook", "").unwrap();
        assert!(hook.triggers.is_empty());
        assert_eq!(hook.when, None);
        assert!(!hook.is_active(), "a masking hook must never run");
    }

    #[test]
    fn file_is_accepted_as_a_deprecated_alias_for_path() {
        let text = "\
[Trigger]
Operation = Install
Type = File
Target = usr/lib/*

[Action]
When = PostTransaction
Exec = /bin/true
";
        let hook = parse("x.hook", text).unwrap();
        assert_eq!(hook.triggers.first().unwrap().kind, Some(TriggerKind::Path));
    }

    #[test]
    fn a_trigger_missing_any_required_part_is_refused() {
        let missing_target = "\
[Trigger]
Operation = Install
Type = Package

[Action]
When = PostTransaction
Exec = /bin/true
";
        let missing_type = "\
[Trigger]
Operation = Install
Target = a

[Action]
When = PostTransaction
Exec = /bin/true
";
        let missing_operation = "\
[Trigger]
Type = Package
Target = a

[Action]
When = PostTransaction
Exec = /bin/true
";
        for (text, wanted) in [
            (missing_target, "no Target"),
            (missing_type, "no Type"),
            (missing_operation, "no Operation"),
        ] {
            let error = parse("x.hook", text).unwrap_err().to_string();
            assert!(error.contains(wanted), "{error}");
        }
    }

    #[test]
    fn a_hook_with_triggers_needs_exec_and_when() {
        let no_exec = "\
[Trigger]
Operation = Install
Type = Package
Target = a

[Action]
When = PostTransaction
";
        let no_when = "\
[Trigger]
Operation = Install
Type = Package
Target = a

[Action]
Exec = /bin/true
";
        assert!(parse("x.hook", no_exec).unwrap_err().to_string().contains("no Exec"));
        assert!(parse("x.hook", no_when).unwrap_err().to_string().contains("no When"));
    }

    #[test]
    fn unknown_sections_options_and_values_are_refused() {
        let cases = [
            ("[Nonsense]\n", "invalid section"),
            ("[Action]\nWhatever = 1\n", "invalid option"),
            ("[Action]\nWhen = Sometimes\n", "invalid value"),
            ("[Trigger]\nOperation = Fiddle\n", "invalid value"),
            ("[Trigger]\nType = Elephant\n", "invalid value"),
            ("[Trigger]\nWhatever = 1\n", "invalid option"),
            ("Exec = /bin/true\n", "invalid option"),
        ];
        for (text, wanted) in cases {
            let error = parse("x.hook", text).unwrap_err().to_string();
            assert!(error.contains(wanted), "{text:?} gave {error}");
        }
    }

    /// The value keeps every `=` after the first, because the tokenizer splits only once.
    #[test]
    fn an_exec_value_may_contain_equals_signs() {
        let text = "\
[Trigger]
Operation = Upgrade
Type = Package
Target = openssh

[Action]
When = PreTransaction
Exec = /usr/bin/systemctl --runtime set-property sshd.service Markers=needs-restart
";
        let hook = parse("x.hook", text).unwrap();
        assert_eq!(hook.exec.last().unwrap(), std::ffi::OsStr::new("Markers=needs-restart"));
    }

    /// An unusable `Exec` refuses the file rather than loading a hook that cannot run.
    #[test]
    fn an_unbalanced_quote_in_exec_refuses_the_hook() {
        let text = "\
[Trigger]
Operation = Install
Type = Package
Target = a

[Action]
When = PostTransaction
Exec = /bin/sh -c 'oops
";
        let error = parse("x.hook", text).unwrap_err().to_string();
        assert!(error.contains("invalid value"), "{error}");
    }

    /// Inverted targets are kept verbatim and in order. Interpreting them is `matches_any`'s
    /// job, and order is what makes it work.
    #[test]
    fn inverted_targets_are_preserved_in_order() {
        let text = "\
[Trigger]
Operation = Install
Type = Path
Target = usr/share/icons/*
Target = !usr/share/icons/*/?*

[Action]
When = PostTransaction
Exec = /bin/true
";
        let hook = parse("x.hook", text).unwrap();
        assert_eq!(
            hook.triggers.first().unwrap().targets,
            ["usr/share/icons/*", "!usr/share/icons/*/?*"]
        );
    }
}
