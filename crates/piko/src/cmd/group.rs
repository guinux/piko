//! `pacman -S <group>`'s member selection, the part of it a library cannot do.
//!
//! What a `%GROUPS%` group expands to, and what an answer does to a target list, are
//! [`piko_db::solve::Resolution::groups`] and [`piko_db::solve::Request::choose_group`]. Any
//! frontend gets those. What is left here is asking: rendering the numbered members, and
//! reading a selection. This module also decides that `--noconfirm` and a read-only preview
//! do not ask at all.

use std::io::Write;

use piko_db::solve::{GroupChoice, GroupTarget, SolvableId, Universe};

use crate::output;

/// Writes the numbered member list, grouped by the repository each member came from.
///
/// The numbering runs across the whole list rather than restarting per repository, because the
/// answer indexes the list, not the repository.
///
/// One member per line. piko reads no terminal width anywhere, and pacman's multi-column
/// layout is the only thing that would need it.
fn print_members(
    out: &mut impl Write,
    universe: &Universe<'_>,
    group: &str,
    members: &[SolvableId],
) -> std::io::Result<()> {
    let count = members.len();
    if count == 1 {
        writeln!(out, ":: There is 1 member in group {group}:")?;
    } else {
        writeln!(out, ":: There are {count} members in group {group}:")?;
    }

    let mut current: Option<String> = None;
    for (index, id) in members.iter().enumerate() {
        let origin = crate::cmd::origin_label(universe, *id);
        if current.as_deref() != Some(origin.as_str()) {
            writeln!(out, ":: {origin}")?;
            current = Some(origin);
        }
        let described = universe.get(*id).map_or_else(
            || "<unknown>".to_owned(),
            |solvable| format!("{} {}", solvable.name(), solvable.version()),
        );
        // `index` is bounded by `members.len()`, and the list is what was just counted.
        writeln!(out, "   {}) {described}", index.saturating_add(1))?;
    }
    Ok(())
}

/// Asks which members of each group in `groups` to install, returning one answer per group.
///
/// Every group gets an answer, including the ones taken whole. The caller's next resolution
/// then plans exactly what was shown. Nothing depends on an absent answer meaning the same
/// thing.
///
/// A write error on the listing takes the whole group. Refusing there would turn a closed pipe
/// into a failed install, over a question the user never saw.
pub fn answer(
    universe: &Universe<'_>,
    groups: &[GroupTarget],
    out: &mut impl Write,
) -> Vec<GroupChoice> {
    let mut choices = Vec::with_capacity(groups.len());
    for group in groups {
        let chosen = if print_members(out, universe, &group.name, &group.members).is_err() {
            group.members.to_vec()
        } else {
            let prompt = "Enter a selection (default=all): ";
            let selected = output::multiselect(out, prompt, group.members.len());
            group
                .members
                .iter()
                .zip(selected.iter())
                .filter(|(_, keep)| **keep)
                .map(|(id, _)| *id)
                .collect()
        };
        choices.push(GroupChoice { group: group.name.clone(), chosen });
    }
    choices
}

/// Reports the groups a non-interactive run took whole.
///
/// `piko plan` never asks, and neither does `--noconfirm`. A preview that blocks on stdin is
/// worse than one that states its assumption. This goes to stderr, so `plan --names` stays
/// diffable against `pacman -Sp`, which takes every member too.
pub fn report_defaults(universe: &Universe<'_>, groups: &[GroupTarget]) {
    if groups.is_empty() {
        return;
    }
    let name_of =
        |id| universe.get(id).map_or_else(|| "<unknown>".to_owned(), |s| s.name().to_string());
    eprintln!(
        "Note: {} group target(s) were taken whole (an interactive `piko install` asks which \
         members to install)",
        groups.len()
    );
    for group in groups {
        // Named rather than counted, but not all of them. `gnome` carries 66 members, and a
        // note is not the prompt. The prompt lists every one, because there the list is what
        // the user answers.
        const SHOWN: usize = 5;
        let listed: Vec<String> = group.members.iter().take(SHOWN).map(|id| name_of(*id)).collect();
        let rest = group.members.len().saturating_sub(listed.len());
        let among = if rest == 0 {
            listed.join(", ")
        } else {
            format!("{}, and {rest} more", listed.join(", "))
        };
        eprintln!("  {}: took all {} members, {among}", group.name, group.members.len());
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
    use piko_db::Limits;
    use piko_db::fixture::{BuiltScenario, PackageSpec, Scenario};
    use piko_db::solve::{Request, UniverseOptions, resolve_targets};

    use super::*;

    /// The listing `print_members` writes for `group`, one entry per line.
    fn lines(scenario: &BuiltScenario, group: &str) -> Vec<String> {
        let universe = Universe::build(
            scenario.local(),
            scenario.repos().iter().map(|db| (piko_db::config::DbUsage::ALL, db)),
            UniverseOptions::new().limits(Limits::default()),
        )
        .unwrap();
        let resolution =
            resolve_targets(&universe, Request::new(), &[group.to_owned()], &Limits::default())
                .unwrap();
        let target = &resolution.groups[0];

        let mut out = Vec::new();
        print_members(&mut out, &universe, &target.name, &target.members).unwrap();
        String::from_utf8(out).unwrap().lines().map(str::to_owned).collect()
    }

    /// The numbering runs across the whole list, so it keeps counting past a repository
    /// heading. It is what the answer indexes.
    #[test]
    fn members_are_numbered_across_every_repository() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("editor", "1.0.0-1").groups(["tools"])])
            .repo(
                "extra",
                [
                    PackageSpec::new("linker", "2.0.0-1").groups(["tools"]),
                    PackageSpec::new("viewer", "3.0.0-1").groups(["tools"]),
                ],
            )
            .build();

        assert_eq!(
            lines(&scenario, "tools"),
            [
                ":: There are 3 members in group tools:",
                ":: Repository core",
                "   1) editor 1.0.0-1",
                ":: Repository extra",
                "   2) linker 2.0.0-1",
                "   3) viewer 3.0.0-1",
            ]
        );
    }

    /// pacman's header has a singular form, and a real system carries one-member groups.
    #[test]
    fn a_single_member_reads_as_one() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("editor", "1.0.0-1").groups(["tools"])])
            .build();

        assert_eq!(lines(&scenario, "tools")[0], ":: There is 1 member in group tools:");
    }
}
