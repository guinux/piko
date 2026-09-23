//! The `refresh` subcommand: download repository databases, verifying before installing.

use std::{path::Path, process::ExitCode};

use piko_db::config::PacmanConfig;
use piko_net::{
    Cancel, Concurrency, DatabaseKind, FreshnessPolicy, Outcome, Refresher, RepoRefresh,
};

use crate::{cmd::freshness, output::report};

/// How `refresh` fetches, and how it judges what it fetches.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Bypass the conditional request, so a `304` can never come back.
    pub force: bool,
    /// Add each selected repository's `<repo>.files` archive beside its `<repo>.db`.
    pub files: bool,
    /// Whether an older database is accepted, and how old one may be before a warning.
    pub freshness: FreshnessPolicy,
}

/// Downloads each configured repository's database into `<dbpath>/sync`.
///
/// Refreshes named repositories only when `only` is non-empty, every configured one
/// otherwise. See [`Options`] for the rest. pacman fetches `.files` archives through a
/// separate `-Fy` operation.
///
/// What `piko_net` learned about each database's age is printed after the rows, one line per
/// note (see [`freshness::render_note`]). None of it changes the exit code: every note leaves
/// the system on the best database a server had.
///
/// A repository that fails does not stop the others. One dead mirror set should not prevent
/// the rest of the system from being refreshed. The exit code still reports that something
/// failed, so a script cannot mistake a partial refresh for a complete one.
///
/// `ParallelDownloads` of them run at once. Nothing is printed from a worker. `refresh_all`
/// hands back one result per repository in configuration order. They are reported here
/// afterwards, so what the user reads does not depend on which mirror was quick.
///
/// `cancel` is already installed by the caller rather than by this function. `update` runs a
/// refresh immediately before a transaction that installs its own handler. Sharing one
/// registration is required, since `ctrlc::set_handler` accepts only one per process. See
/// `crate::signal`.
pub fn refresh(
    config: &PacmanConfig,
    dbpath: &Path,
    only: &[String],
    options: Options,
    cancel: &Cancel,
    offset: piko_txn::LocalOffset,
) -> ExitCode {
    let Options { force, files, freshness } = options;
    let sync_dir = dbpath.join("sync");
    let refresher = Refresher::default();

    // Opened once, only if some repository will actually use it. A system with no keyring can
    // still refresh repositories whose SigLevel asks for nothing.
    let wants_signatures = config.repositories.iter().any(|repo| {
        piko_sig::Policy::for_database(repo.effective_sig_level(config.options.sig_level)).check
    });
    let keyring = if wants_signatures {
        match piko_sig::Keyring::open(&config.options.gpg_dir) {
            Ok(keyring) => Some(keyring),
            Err(error) => {
                report(&error);
                eprintln!(
                    "Note: a repository's SigLevel requires a signature, so refreshing \
                     cannot continue without a usable keyring"
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    let selected: Vec<&piko_db::config::RepositoryConfig> = config
        .repositories
        .iter()
        .filter(|repo| only.is_empty() || only.contains(&repo.name.to_string()))
        .collect();
    // One entry per file, not per repository: with `--files` a repository contributes two.
    // Its `.db` and its `.files` are separate downloads, each with its own result, its own
    // row, and its own `Last-Modified`. The two entries sit next to each other, so the output
    // reads repository by repository. The pool schedules them in any order.
    let kinds: &[DatabaseKind] =
        if files { &[DatabaseKind::Db, DatabaseKind::Files] } else { &[DatabaseKind::Db] };
    let expanded: Vec<(&piko_db::config::RepositoryConfig, DatabaseKind)> =
        selected.iter().flat_map(|repo| kinds.iter().map(|kind| (*repo, *kind))).collect();
    let targets: Vec<(String, DatabaseKind)> =
        expanded.iter().map(|(repo, kind)| (repo.name.to_string(), *kind)).collect();
    let requests: Vec<RepoRefresh<'_>> = expanded
        .iter()
        .zip(&targets)
        .map(|((repo, kind), (name, _))| RepoRefresh {
            name,
            kind: *kind,
            servers: &repo.servers,
            policy: piko_sig::Policy::for_database(
                repo.effective_sig_level(config.options.sig_level),
            ),
            freshness,
        })
        .collect();

    // One list holds every repository's row, rather than one list per repository. With
    // several refreshes in flight there is no longer a single row at a time to draw.
    let steps = crate::progress::StepList::new();
    let rows: Vec<crate::progress::Row> = targets
        .iter()
        .map(|(name, kind)| steps.download(&format!("Synchronizing {}", label(name, *kind)), 0))
        .collect();
    let sinks: Vec<_> =
        rows.iter().map(|row| crate::progress::database_download_sink(row.clone())).collect();
    let dispatch = |index: usize, event: piko_net::Event| {
        if let Some(sink) = sinks.get(index) {
            sink(event);
        }
    };

    let results = refresher.refresh_all(
        &sync_dir,
        &requests,
        keyring.as_ref(),
        Concurrency::new(config.options.parallel_downloads),
        force,
        cancel,
        &dispatch,
    );

    let mut failed = false;
    let mut notes = Vec::new();
    for (((name, kind), row), result) in targets.iter().zip(rows).zip(results) {
        let file = kind.file_name(name);
        match result {
            Ok(refreshed) => {
                match refreshed.outcome {
                    Outcome::Updated => row.finish(),
                    Outcome::UpToDate => {
                        row.finish_plain(format!("{} (up to date)", label(name, *kind)));
                    }
                    Outcome::Kept => {
                        row.finish_plain(format!(
                            "{} (kept: no newer database)",
                            label(name, *kind)
                        ));
                    }
                }
                notes.extend(
                    refreshed.notes.iter().map(|note| freshness::render_note(&file, note, offset)),
                );
                // After the notes, which name each server that was passed over and why. This
                // line is their conclusion.
                if refreshed.outcome == Outcome::Kept {
                    notes.push(freshness::render_kept(&file, refreshed.publication, offset));
                }
            }
            Err(error) => {
                row.finish();
                steps.suspend(|| report(&error));
                failed = true;
            }
        }
    }
    // After every row, rather than beside its own. A note names its file, and printing it in
    // the middle of the rows would split the list the user reads for what was refreshed.
    for line in &notes {
        steps.suspend(|| eprintln!("{line}"));
    }

    // Through `suspend`, as every other line this function prints. The finished rows still
    // belong to the `MultiProgress`. A bare `eprintln!` writes into the region it draws.
    if !only.is_empty() {
        for wanted in only {
            if !config.repositories.iter().any(|repo| repo.name.to_string() == *wanted) {
                steps.suspend(|| eprintln!("Error: {wanted} is not a configured repository"));
                failed = true;
            }
        }
    }

    if failed {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// The name the output shows for one refresh target.
///
/// A `.db` shows its repository name, as pacman prints it. A `.files` shows its file name. Two
/// rows for one repository then differ by more than the order they were printed in.
fn label(name: &str, kind: DatabaseKind) -> String {
    match kind {
        DatabaseKind::Db => name.to_owned(),
        DatabaseKind::Files => kind.file_name(name),
    }
}
