//! Subcommands reading the local database and repository databases together:
//! `check-updates` and `resolve`.

use std::process::ExitCode;

use piko_db::{
    LocalDatabase,
    config::DbUsage,
    repo::RepoDatabase,
    resolve::{IgnoreList, SyncRepo, SyncRepos},
    solve::IgnoredChange,
};

use crate::output::emit;

/// Prints every installed package with a newer version available in `repos`, then a summary.
///
/// Mirrors `pacman -Qu`: `name old -> new`, one per line, in the order
/// [`LocalDatabase::check_updates`] returns (sorted by name). Old and new versions align into
/// a column across the whole listing, computed in one pass before anything prints — the same
/// two-pass shape `cmd::plan::column_widths`/`print_steps` uses.
///
/// There is no icon column here, unlike `crate::style::ChangeKind` or `cmd::search`'s checkmark:
/// both exist to tell rows of different kinds apart, and every row here is the same kind (an
/// upgrade). The new version is still colored blue, the same tone
/// `crate::style::ChangeKind::Upgrade` uses, so an upgrade reads the same way in `piko plan` and
/// `piko check-updates` — echoed by value, not by shared code. The old version is dimmed,
/// matching `cmd::plan`'s treatment of a `Step::Change`'s `from` version.
///
/// In `--quiet` mode, prints just each installed package's name, one per line — no color, no
/// version, no arrow, no summary — matching `cmd::list`/`cmd::search`'s `--quiet` convention.
///
/// # `IgnorePkg`/`IgnoreGroup` rows are withheld, and warned about
///
/// [`LocalDatabase::check_updates`] applies no filter, matching `alpm_sync_get_new_version`,
/// which is also what `pacman -Qu` is built on. pacman then *prints* an ignored row, suffixed
/// `[ignored]`. piko withholds it from the listing and warns about it on stderr instead.
///
/// The reason is what the list is for. `piko check-updates` answers "what will change if I
/// upgrade", and an ignored package will not change — listing it puts the row a user is about
/// to act on beside a row that is already decided. Nothing is hidden, only moved off the list
/// of things that are going to happen: stdout stays the machine-readable answer, and the
/// warning goes where every other diagnostic goes, which is also what keeps `--quiet` a clean
/// list of names.
///
/// The warning is `cmd::plan::print_ignored_change`, the same line `piko update` prints for
/// the same package. Only [`IgnoredChange::Upgrade`] is reachable from here, since
/// [`LocalDatabase::check_updates`] reports a strictly newer repository version and nothing
/// else.
pub fn check_updates(
    local: &LocalDatabase,
    repos: &[RepoDatabase],
    ignores: IgnoreList<'_>,
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut updates = Vec::new();
    let mut ignored = Vec::new();
    for update in local.check_updates(repos) {
        match ignores.reason_for(update.available()) {
            Some(reason) => ignored.push((update, reason)),
            None => updates.push(update),
        }
    }

    if quiet {
        for update in &updates {
            emit!(out, "{}", update.installed().name());
        }
        return ExitCode::SUCCESS;
    }

    let name_width =
        updates.iter().map(|update| update.installed().name().to_string().len()).max().unwrap_or(0);
    let version_width = updates
        .iter()
        .map(|update| update.installed().version().to_string().len())
        .max()
        .unwrap_or(0);

    for update in &updates {
        let name = update.installed().name().to_string();
        let old = update.installed().version().to_string();
        let new = update.available().version().to_string();
        emit!(
            out,
            "{name:name_width$} {} -> {}",
            console::style(format!("{old:<version_width$}")).dim(),
            console::Style::new().blue().apply_to(new)
        );
    }

    emit!(out, "");
    emit!(out, "{} update{} available", updates.len(), if updates.len() == 1 { "" } else { "s" });

    for (update, reason) in &ignored {
        crate::cmd::plan::print_ignored_change(
            (update.installed().name().as_ref(), &update.installed().version().to_string()),
            (update.available().name().as_ref(), &update.available().version().to_string()),
            IgnoredChange::Upgrade,
            reason,
        );
    }
    ExitCode::SUCCESS
}

pub fn resolve_and_print(
    opened: &[(DbUsage, RepoDatabase)],
    ignores: IgnoreList<'_>,
    target: &str,
    out: &mut impl std::io::Write,
) -> ExitCode {
    if opened.is_empty() {
        eprintln!("error: no configured repository could be opened; see warnings above");
        return ExitCode::FAILURE;
    }

    let Ok(dep) = target.parse::<alpm_types::RelationOrSoname>() else {
        eprintln!("error: {target} is not a valid dependency string");
        return ExitCode::FAILURE;
    };

    let repos = SyncRepos::new(opened.iter().map(|(usage, db)| SyncRepo::new(*usage, db)))
        .with_ignores(ignores);

    let matches = repos.find_satisfiers(&dep);

    if matches.is_empty() {
        // Nothing came back. Which of the two reasons it was decides what the user has to fix,
        // so the message has to tell them apart: `IgnorePkg` covering the name is not the name
        // being wrong.
        let ignored = repos.ignored_satisfiers(&dep);
        if ignored.is_empty() {
            eprintln!(
                "error: no package satisfying {target} was found in any configured \
                 repository"
            );
        } else {
            eprintln!("error: every package satisfying {target} is ignored");
            for (resolved, reason) in &ignored {
                eprintln!(
                    "  {}-{} in {} ({reason})",
                    resolved.package().name(),
                    resolved.package().version(),
                    resolved.repo()
                );
            }
        }
        return ExitCode::FAILURE;
    }

    for resolved in &matches {
        emit!(out, "{}", resolved.package().name());
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use piko_db::fixture::{BuiltScenario, PackageSpec, Scenario};

    use super::*;

    /// The listing's lines, styling removed and columns collapsed, as `cmd::list`'s harness
    /// does. Only stdout is captured: the withheld-rows note is a diagnostic and goes to
    /// stderr, which is exactly the split under test.
    fn lines(
        scenario: &BuiltScenario,
        ignore_pkg: &[String],
        ignore_group: &[String],
        quiet: bool,
    ) -> Vec<String> {
        let mut out = Vec::new();
        check_updates(
            scenario.local(),
            scenario.repos(),
            IgnoreList::new(ignore_pkg, ignore_group),
            quiet,
            &mut out,
        );
        let text = String::from_utf8(out).unwrap();
        console::strip_ansi_codes(&text)
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect()
    }

    /// One update that is ignored, one that is not.
    fn scenario() -> BuiltScenario {
        Scenario::new()
            .installed(PackageSpec::new("gedit", "46.2-1"))
            .installed(PackageSpec::new("bash", "5.2-1"))
            .repo("core", [PackageSpec::new("gedit", "47.0-1"), PackageSpec::new("bash", "5.3-1")])
            .build()
    }

    #[test]
    fn an_ignored_update_is_not_listed_and_is_not_counted() {
        let scenario = scenario();
        let ignored = vec!["gedit".to_owned()];
        let lines = lines(&scenario, &ignored, &[], false);

        assert!(
            lines.iter().all(|line| !line.contains("gedit")),
            "the withheld row must not appear on stdout: {lines:?}"
        );
        assert!(lines.iter().any(|line| line.starts_with("bash 5.2-1 -> 5.3-1")));
        assert_eq!(lines.last().unwrap(), "1 update available", "the summary counts what is left");
    }

    /// Without the directive nothing is withheld, so the same fixture lists both rows. This is
    /// what pins the filter to `IgnorePkg` rather than to something else about `gedit`.
    #[test]
    fn without_the_directive_both_updates_are_listed() {
        let lines = lines(&scenario(), &[], &[], false);

        assert!(lines.iter().any(|line| line.starts_with("gedit")));
        assert_eq!(lines.last().unwrap(), "2 updates available");
    }

    /// `IgnoreGroup` withholds through the repository package's `%GROUPS%`, the same test
    /// `alpm_pkg_should_ignore` applies.
    #[test]
    fn an_ignored_group_withholds_its_members() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("gcc", "1.0.0-1"))
            .repo("core", [PackageSpec::new("gcc", "2.0.0-1").groups(["base-devel"])])
            .build();
        let groups = vec!["base-devel".to_owned()];
        let lines = lines(&scenario, &[], &groups, false);

        assert!(lines.iter().all(|line| !line.contains("gcc")), "{lines:?}");
        assert_eq!(lines.last().unwrap(), "0 updates available");
    }

    /// `--quiet` filters the same way but prints names only — no summary, and no note either.
    #[test]
    fn quiet_mode_filters_and_prints_names_only() {
        let scenario = scenario();
        let ignored = vec!["gedit".to_owned()];

        assert_eq!(lines(&scenario, &ignored, &[], true), vec!["bash".to_owned()]);
    }
}
