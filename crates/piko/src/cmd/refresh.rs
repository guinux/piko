//! The `refresh` subcommand: download repository databases, verifying before installing.

use std::{path::Path, process::ExitCode};

use piko_db::config::PacmanConfig;
use piko_net::{Cancel, Concurrency, Outcome, Refresher, RepoRefresh};

use crate::output::report;

/// Downloads each configured repository's database into `<dbpath>/sync`.
///
/// Refreshes named repositories only when `only` is non-empty, every configured one
/// otherwise. `force` bypasses the conditional request, so a `304` can never come back.
///
/// A repository that fails does not stop the others. One dead mirror set should not prevent
/// the rest of the system from being refreshed. The exit code still reports that something
/// failed, so a script cannot mistake a partial refresh for a complete one.
///
/// `ParallelDownloads` of them run at once. Nothing is printed from a worker. `refresh_all`
/// hands back one result per repository in configuration order, and they are reported here
/// afterwards, so what the user reads does not depend on which mirror was quick.
///
/// `cancel` is already installed by the caller rather than by this function. `update` runs a
/// refresh immediately before a transaction that installs its own handler; sharing one
/// registration is required, since `ctrlc::set_handler` accepts only one per process. See
/// `crate::signal`.
pub fn refresh(
    config: &PacmanConfig,
    dbpath: &Path,
    only: &[String],
    force: bool,
    cancel: &Cancel,
) -> ExitCode {
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
                    "piko: note: a repository's SigLevel requires a signature, so refreshing \
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
    let names: Vec<String> = selected.iter().map(|repo| repo.name.to_string()).collect();
    let requests: Vec<RepoRefresh<'_>> = selected
        .iter()
        .zip(&names)
        .map(|(repo, name)| RepoRefresh {
            name,
            servers: &repo.servers,
            policy: piko_sig::Policy::for_database(
                repo.effective_sig_level(config.options.sig_level),
            ),
        })
        .collect();

    // One list holds every repository's row, rather than one list per repository. With
    // several refreshes in flight there is no longer a single row at a time to draw.
    let steps = crate::progress::StepList::new();
    let rows: Vec<crate::progress::Row> =
        names.iter().map(|name| steps.download(&format!("Synchronizing {name}"), 0)).collect();
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
    for ((name, row), result) in names.iter().zip(rows).zip(results) {
        match result {
            Ok(Outcome::Updated) => row.finish(),
            Ok(Outcome::UpToDate) => row.finish_plain(format!("{name} (up to date)")),
            Err(error) => {
                row.finish();
                steps.suspend(|| report(&error));
                failed = true;
            }
        }
    }

    if !only.is_empty() {
        for wanted in only {
            if !config.repositories.iter().any(|repo| repo.name.to_string() == *wanted) {
                eprintln!("piko: error: {wanted} is not a configured repository");
                failed = true;
            }
        }
    }

    if failed {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
