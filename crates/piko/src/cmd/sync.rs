//! Subcommands reading the local database and repository databases together:
//! `check-updates` and `resolve`.

use std::process::ExitCode;

use piko_db::{
    LocalDatabase,
    config::DbUsage,
    repo::RepoDatabase,
    resolve::{IgnoreList, SyncRepo, SyncRepos},
};

use crate::output::emit;

/// Prints every installed package with a newer version available in `repos`, then a summary.
///
/// Mirrors `pacman -Qu`: `name old -> new`, one per line, in the order
/// [`LocalDatabase::check_updates`] returns (sorted by name). Old and new versions align into
/// a column across the whole listing, computed in one pass before anything prints — the same
/// two-pass shape `cmd::plan::column_widths`/`print_steps` uses.
///
/// There is no icon column here, unlike `cmd::plan::StepKind` or `cmd::search`'s checkmark:
/// both exist to tell rows of different kinds apart, and every row here is the same kind (an
/// upgrade). The new version is still colored blue, the same tone
/// `cmd::plan::StepKind::Upgrade` uses, so an upgrade reads the same way in `piko plan` and
/// `piko check-updates` — echoed by value, not by shared code. The old version is dimmed,
/// matching `cmd::plan`'s treatment of a `Step::Change`'s `from` version.
///
/// In `--quiet` mode, prints just each installed package's name, one per line — no color, no
/// version, no arrow, no summary — matching `cmd::list`/`cmd::search`'s `--quiet` convention.
pub fn check_updates(
    local: &LocalDatabase,
    repos: &[RepoDatabase],
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let updates = local.check_updates(repos);

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
    ExitCode::SUCCESS
}

pub fn resolve_and_print(
    opened: &[(DbUsage, RepoDatabase)],
    ignores: IgnoreList<'_>,
    target: &str,
    out: &mut impl std::io::Write,
) -> ExitCode {
    if opened.is_empty() {
        eprintln!("piko: error: no configured repository could be opened; see warnings above");
        return ExitCode::FAILURE;
    }

    let Ok(dep) = target.parse::<alpm_types::RelationOrSoname>() else {
        eprintln!("piko: error: {target} is not a valid dependency string");
        return ExitCode::FAILURE;
    };

    let repos = SyncRepos::new(opened.iter().map(|(usage, db)| SyncRepo::new(*usage, db)))
        .with_ignores(ignores);

    let matches = repos.find_satisfiers(&dep);

    if matches.is_empty() {
        eprintln!(
            "piko: error: no package satisfying {target} was found in any configured repository"
        );
        return ExitCode::FAILURE;
    }

    for resolved in &matches {
        emit!(out, "{}", resolved.package().name());
    }
    ExitCode::SUCCESS
}
