//! The `refresh` subcommand: download repository databases, verifying before installing.

use std::{path::Path, process::ExitCode};

use piko_db::config::PacmanConfig;
use piko_net::{
    Cancel, Concurrency, DatabaseKind, FreshnessPolicy, Outcome, RefreshTargets, Refresher,
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
/// `<dbpath>/db.lck` is held for the whole refresh, and taken before anything else, as
/// libalpm's `alpm_db_update` does (`be_sync.c:163`). A held lock fails the command at once,
/// before any download. The lock is released when this function returns, so `update` can take
/// it again for its transaction, as pacman's `-Syu` does. A lock file that cannot be removed is
/// a warning, and leaves the exit code as it was, as in libalpm.
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
/// registration is required, since a second one would answer every signal twice. See
/// `crate::signal`.
pub fn refresh(
    config: &PacmanConfig,
    dbpath: &Path,
    only: &[String],
    options: Options,
    cancel: &Cancel,
    zone: piko_txn::history::LocalZone,
) -> ExitCode {
    let lock = match piko_db_write::DbLock::acquire(dbpath) {
        Ok(lock) => lock,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };
    let code = refresh_locked(config, dbpath, &lock, only, options, cancel, zone);
    crate::cmd::release_lock(lock);
    code
}

/// [`refresh`] once `db.lck` is held. The caller releases the lock, whatever this returns.
fn refresh_locked(
    config: &PacmanConfig,
    dbpath: &Path,
    lock: &piko_db_write::DbLock,
    only: &[String],
    options: Options,
    cancel: &Cancel,
    zone: piko_txn::history::LocalZone,
) -> ExitCode {
    let Options { force, files, freshness } = options;
    let sync_dir = dbpath.join("sync");
    let refresher =
        Refresher::default().with_sandbox(piko_net::Sandbox::from_options(&config.options));

    // Which archives, under which policy, checked by which keyring: `RefreshTargets`
    // decides all three from the configuration.
    let targets = match RefreshTargets::new(config, only, files, freshness) {
        Ok(targets) => targets,
        Err(piko_net::Error::KeyringUnusable { source }) => {
            report(&source);
            eprintln!(
                "Note: a repository's SigLevel requires a signature, so refreshing \
                 cannot continue without a usable keyring"
            );
            return ExitCode::FAILURE;
        }
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };
    let requests = targets.requests();

    // One list holds every repository's row, rather than one list per repository. With
    // several refreshes in flight there is no longer a single row at a time to draw.
    let steps = crate::progress::StepList::new();
    let rows: Vec<crate::progress::Row> = requests
        .iter()
        .map(|request| {
            steps.download(&format!("Synchronizing {}", label(request.name, request.kind)), 0)
        })
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
        lock,
        requests,
        targets.keyring(),
        Concurrency::new(config.options.parallel_downloads),
        force,
        cancel,
        &dispatch,
    );

    let mut failed = false;
    let mut notes = Vec::new();
    for ((request, row), result) in requests.iter().zip(rows).zip(results) {
        let (name, kind) = (request.name, &request.kind);
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
                    // An outcome this frontend does not know yet: show the target, no detail.
                    _ => row.finish_plain(label(name, *kind)),
                }
                notes.extend(
                    refreshed.notes.iter().map(|note| freshness::render_note(&file, note, zone)),
                );
                // After the notes, which name each server that was passed over and why. This
                // line is their conclusion.
                if refreshed.outcome == Outcome::Kept {
                    notes.push(freshness::render_kept(&file, refreshed.publication, zone));
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
    for wanted in targets.unknown() {
        steps.suspend(|| eprintln!("Error: {wanted} is not a configured repository"));
        failed = true;
    }
    // Only a repository the command line named. A full refresh skips one silently, as
    // `pacman -Sy` does.
    if !only.is_empty() {
        for skipped in targets.unsynced() {
            steps.suspend(|| {
                eprintln!("Note: {skipped} is not refreshed: its Usage does not include Sync");
            });
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
