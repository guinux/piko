//! The subcommands that can change a system: `install`, `remove` and `report`.
//!
//! # `--root`
//!
//! With no `--root`, the effective root falls back to `RootDir` from the parsed pacman.conf —
//! see `crate::context::resolve_root_dir`, the same resolution `piko check` already used.
//! `--root /` (or an omitted `--root` whose `pacman.conf` names `/`) targets the running
//! system.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::ExitCode,
};

use piko_db::EntryName;
use piko_db::config::{DbUsage, RepositoryConfig, SigLevel};
use piko_db::repo::RepoDatabase;
use piko_db::resolve::IgnoreList;
use piko_db::solve::{
    Plan, Request, SolvableId, Universe, UniverseOptions, resolve_targets, solve_with_removals,
};
use piko_db::{Limits, LocalDatabase};
use piko_sig::Policy;
use piko_txn::{
    CacheDirSource, DownloadingSource, PackageSource, Step, Transaction,
    conflict::Overwrite,
    journal::{self, Intent},
    transaction::Verification,
};

use crate::output::{emit, report as report_error};

/// Writes one frontend line to the transaction log, warning if it cannot be written.
///
/// The counterpart of pacman's `[PACMAN]` lines: what the user ran, and the two markers a
/// refresh and a sysupgrade put in the log before any transaction starts. A log that cannot
/// be written is a warning here for the same reason it is one inside a transaction — the
/// command the user asked for still runs. See [`piko_txn::history`].
pub fn note(recording: &piko_txn::Recording, message: &str) {
    if let Err(problem) = piko_txn::history::note(recording, message) {
        eprintln!("piko: warning: {problem}");
    }
}

/// The install-side options, gathered so the entry point keeps a readable signature.
#[derive(Clone, Debug, Default)]
pub struct InstallOptions {
    /// Record the packages as dependencies rather than explicitly installed.
    pub as_deps: bool,
    /// `--overwrite` glob patterns, matched against each path.
    pub overwrite: Vec<String>,
    /// The GnuPG keyring directory, from `pacman.conf`'s `GPGDir`.
    pub gpg_dir: PathBuf,
    /// The fallback `SigLevel` for a package whose repository could not be resolved.
    ///
    /// Plain `SigLevel`, not `LocalFileSigLevel`. See [`crate::context::signing_policy`]. Every
    /// package this function actually installs is checked against its own repository's
    /// `SigLevel` instead, resolved per candidate and fed to
    /// [`piko_txn::Transaction::policy_overrides`]. This value is only the defensive fallback.
    pub sig_level: SigLevel,
    /// What the transaction is allowed to run.
    pub side_effects: SideEffects,
    /// `pacman.conf`'s `NoExtract` and `NoUpgrade`.
    pub patterns: piko_txn::Patterns,
    /// Skip the confirmation prompt and proceed as if the user answered yes.
    pub noconfirm: bool,
    /// `piko update`'s `-u`: also upgrade every installed package a repository has moved on
    /// from, `%REPLACES%` pairs included. The `bool` is `--downgrade` (`-Suu`): accept a
    /// repository version older than the installed one.
    pub sysupgrade: Option<bool>,
    /// Download every missing package into the cache without installing anything (`-w`).
    pub download_only: bool,
    /// `pacman.conf`'s `ParallelDownloads`, raw. Clamped where it is used — see
    /// [`piko_net::Concurrency::new`].
    pub parallel_downloads: u32,
    /// A `SIGINT` handler already installed by an earlier step (`update`'s pre-refresh),
    /// reused instead of installing a second one. `ctrlc::set_handler` accepts exactly one
    /// registration per process; a second call would panic. `None` when nothing installed
    /// one yet — `install` installs its own here.
    pub pre_cancel: Option<crate::signal::Handoff>,
}

/// The code a transaction runs besides moving files: scriptlets and hooks.
///
/// Gathered together because they share a security posture. Both execute programs with piko's
/// privileges inside `--root`, and both are on by default here. A package whose `post_install`
/// did not run is installed but not set up. pacman runs them, so a piko that quietly did not
/// would produce a system that only looks the same.
#[derive(Clone, Debug, Default)]
pub struct SideEffects {
    /// Run each package's `.INSTALL`. `--noscriptlet` turns this off.
    pub scriptlets: bool,
    /// Where to read `.hook` files from, in increasing priority.
    ///
    /// The system directory is resolved inside `--root`; a configured `HookDir` is a host
    /// path. `crate::context::hook_dirs` explains why libalpm draws that line. Empty runs no
    /// hooks.
    pub hook_dirs: Vec<PathBuf>,
    /// Where the transaction is recorded: the `LogFile` pacman shares, and the history store
    /// beside the database. The default records nothing.
    pub recording: piko_txn::Recording,
}

/// What `install` resolves targets against, gathered so the entry point keeps a readable
/// signature.
pub struct Catalog<'a> {
    /// The installed set.
    pub local: &'a LocalDatabase,
    /// The configured repositories, in priority order.
    pub repos: &'a [(DbUsage, RepoDatabase)],
    /// `pacman.conf`'s `IgnorePkg`/`IgnoreGroup`.
    pub ignores: IgnoreList<'a>,
    /// The parsed configuration for every repository in [`Catalog::repos`] — servers, cache
    /// servers, and `SigLevel` — for resolving where a missing package can be downloaded from.
    pub configs: &'a [RepositoryConfig],
}

/// Installs packages by name, resolving dependencies through the configured repositories. With
/// `options.sysupgrade` set, this also runs `piko update`'s full-system upgrade.
///
/// Targets are resolved exactly as `piko plan` resolves them: a literal name or dependency
/// string first, a `%GROUPS%` member expansion second. The whole transitive closure of
/// dependencies, conflicts, and replacements is planned through the same solver before anything
/// is committed. What that plan reports is what `run` applies. `piko install foo` is `piko
/// plan foo` turned into a transaction — the same relationship `piko remove` already has with
/// `piko plan -R` (see [`crate::cmd::removal`]) and `piko update` has with `piko plan -u`.
///
/// A package already in a cache directory is used as-is. A missing one is downloaded from its
/// own repository's configured servers before installing. See [`DownloadingSource`].
pub fn install(
    root: &Path,
    dbpath: &Path,
    cache_dirs: Vec<std::path::PathBuf>,
    catalog: Catalog<'_>,
    targets: &[String],
    options: InstallOptions,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let limits = Limits::default();

    // Built before anything else, so an unusable `CacheDir` list is reported before a plan is
    // solved, not after. It is the plan's download-size oracle and the offline half of the
    // `DownloadingSource` below. That is what keeps "what will be downloaded" and "what is
    // downloaded from" from ever disagreeing.
    let cache = match CacheDirSource::new(cache_dirs.clone()) {
        Ok(cache) => cache,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let steplist = crate::progress::StepList::new();
    let resolving = steplist.spinner("Resolving dependencies");

    let universe = match Universe::build(
        catalog.local,
        catalog.repos.iter().map(|(usage, db)| (*usage, db)),
        UniverseOptions::new().ignores(catalog.ignores).limits(limits),
    ) {
        Ok(universe) => universe,
        Err(error) => {
            crate::progress::settle_row(&steplist, out, resolving, "Resolving dependencies");
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let mut request = match resolve_targets(&universe, Request::new(), targets) {
        Ok(request) => request,
        Err(failure) => {
            crate::progress::settle_row(&steplist, out, resolving, "Resolving dependencies");
            crate::cmd::plan::report_target_resolution_failure(&failure);
            return ExitCode::FAILURE;
        }
    };

    // The ids named on the command line, captured before `--sysupgrade` adds its own. These
    // decide `Explicit` vs `Depend` below. A package `-u` pulled in on its own was not named by
    // anyone, whatever `request.targets()` grows into next.
    let explicit_targets: Vec<SolvableId> = request.targets().to_vec();

    // `-u`: everything the repositories have moved on from becomes a target too. Each
    // `%REPLACES%` pair becomes a target plus the removal it displaces. This mirrors `piko plan
    // -u`'s own handling (`cmd::plan::plan`) exactly, since this is the same operation
    // committed rather than only printed.
    if let Some(downgrade) = options.sysupgrade {
        request = request.with_sysupgrade(&universe, downgrade);
    }

    let planned = match solve_with_removals(&universe, &request, &limits) {
        Ok(Ok(planned)) => planned,
        Ok(Err(encoded)) => {
            crate::progress::settle_row(&steplist, out, resolving, "Resolving dependencies");
            crate::cmd::plan::report_unsatisfiable(&universe, encoded, &limits);
            return ExitCode::FAILURE;
        }
        Err(error) => {
            crate::progress::settle_row(&steplist, out, resolving, "Resolving dependencies");
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let built = Plan::assemble(&universe, &planned, request.targets(), &limits, &cache);
    crate::progress::settle_row(&steplist, out, resolving, "Resolving dependencies");
    crate::cmd::plan::print_diagnostics(&universe, &built);

    if built.steps().is_empty() {
        emit!(out, "nothing to do");
        return ExitCode::SUCCESS;
    }

    // Blank line separating the settled "Resolving dependencies" row from the step list below.
    emit!(out, "");
    let code =
        crate::cmd::plan::print_steps(&universe, &built, crate::cmd::plan::Format::Full, out);
    if code != ExitCode::SUCCESS {
        return code;
    }

    emit!(out, "");
    let prompt = if options.download_only {
        "Proceed with download? [Y/n] "
    } else {
        "Proceed with installation? [Y/n] "
    };
    // `update`'s pre-refresh step (`main::sync`) may already have a handler installed, for
    // the refresh that just ran. Bracketing the prompt in `during_prompt` still kills the
    // process on the first Ctrl+C here, exactly as when no handler exists yet (the `None`
    // branch below) — nothing at the prompt itself needs a graceful stop.
    let answered = match &options.pre_cancel {
        Some(handoff) => handoff.mode.during_prompt(|| proceed(out, options.noconfirm, prompt)),
        None => proceed(out, options.noconfirm, prompt),
    };
    if !answered {
        return ExitCode::SUCCESS;
    }

    // Only from here on can anything reach the network. See `crate::signal` for why this is
    // not installed earlier: it would make Ctrl+C at the prompt above require two presses.
    // `update`'s pre-refresh step already installed one when it refreshed ahead of this
    // prompt; `pre_cancel` carries that registration so this does not install a second, which
    // `ctrlc::set_handler` would refuse.
    let cancel = match options.pre_cancel {
        Some(handoff) => handoff.cancel,
        None => crate::signal::install_cancel_handler().0,
    };

    let steps = match piko_txn::install_steps(&universe, &built, &explicit_targets, options.as_deps)
    {
        Ok(steps) => steps,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let package_targets =
        piko_txn::download_targets(&universe, &built, catalog.configs, options.sig_level);
    let (verification, policy_overrides) =
        match piko_txn::verification_from(&options.gpg_dir, options.sig_level, &package_targets) {
            Ok(result) => result,
            Err(error) => {
                report_error(&error);
                eprintln!(
                    "piko: note: set SigLevel = Never in pacman.conf to install without \
                     checking signatures"
                );
                return ExitCode::FAILURE;
            }
        };

    // No row at all when nothing needs downloading: a removal-only plan, or one whose every
    // candidate is already in a cache directory, since `Plan::assemble` was given `cache`
    // above.
    let rig = crate::progress::download_rig(&steplist, built.download_size());
    let source = match DownloadingSource::new(
        cache_dirs,
        package_targets,
        cancel,
        piko_net::Concurrency::new(options.parallel_downloads),
        rig.sink,
    ) {
        Ok(source) => source,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };
    report_download_dir(&steplist, source.download_dir());

    if options.download_only {
        let code = download_only(&source, &cache, &steps, &verification, &policy_overrides, out);
        if let Some(head) = rig.head {
            head.finish_and_clear();
        }
        if let Some(row) = rig.row {
            row.finish_as("Downloading packages");
        }
        return code;
    }

    let settings = Settings {
        overwrite: overwrite_from(options.overwrite),
        verification,
        policy_overrides,
        scriptlets: options.side_effects.scriptlets,
        hook_dirs: options.side_effects.hook_dirs.clone(),
        patterns: options.patterns,
        recording: options.side_effects.recording.clone(),
    };
    run(
        root,
        dbpath,
        steps,
        &source,
        Progress { steplist: &steplist, download: rig.row, download_head: rig.head },
        settings,
        out,
    )
}

/// Reports what the download-directory selection passed over, and whether it created one.
///
/// libalpm logs both at `ALPM_LOG_DEBUG` (`util.c:916`, `:924`). piko has no debug channel,
/// and a configured `CacheDir` silently ignored is exactly the mistake worth naming. Both
/// facts are absent in the ordinary case, so a normal run prints nothing.
///
/// Written through `StepList::suspend`, because the download rows are already live by the
/// time this runs and a bare `eprintln!` would be overdrawn mid-line.
fn report_download_dir(steplist: &crate::progress::StepList, dir: &piko_txn::DownloadDir) {
    if dir.rejected().is_empty() && !dir.created() {
        return;
    }
    steplist.suspend(|| {
        for rejected in dir.rejected() {
            eprintln!("piko: warning: {rejected}");
        }
        if dir.created() {
            eprintln!("piko: warning: no {} cache exists, creating...", dir.path().display());
        }
    });
}

/// Downloads every missing package named in `steps` into the cache, installing nothing.
///
/// A thin CLI wrapper around [`piko_txn::download_only`]. See there for what it does and why.
/// This only turns each [`piko_txn::DownloadOnlyOutcome`] into a printed line, and any
/// [`piko_txn::Error`] it stops on into a reported one.
///
/// A write failure is ignored, rather than turned into an early return, matching
/// `crate::progress::print_step_result`'s policy for the same situation. This runs while
/// packages are still being downloaded, and there is nothing to gain from stopping early just
/// because the terminal on the other end of `out` went away. A dead `out` is instead caught by
/// the next `emit!` call after this returns, the same way a live commit handles it.
fn download_only(
    source: &DownloadingSource,
    cache: &CacheDirSource,
    steps: &[Step],
    verification: &Verification,
    policy_overrides: &HashMap<String, Policy>,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let result =
        piko_txn::download_only(source, cache, steps, verification, policy_overrides, |outcome| {
            let verb = if outcome.was_cached { "already in cache:" } else { "downloaded" };
            let checked = if outcome.verified { ", signature verified" } else { "" };
            let _ = writeln!(out, "{verb} {} ({} bytes{checked})", outcome.package, outcome.size);
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_error(&error);
            ExitCode::FAILURE
        }
    }
}

/// Writes a line to `out`, translating a broken pipe into a clean stop and any other write
/// failure into a reported one.
///
/// The `Result`-returning equivalent of [`crate::output::emit`]. It exists for a function that
/// cannot use that macro because it returns `Result<_, ExitCode>`, not `ExitCode` itself.
fn emit_line(out: &mut impl std::io::Write, line: &str) -> Result<(), ExitCode> {
    if let Err(error) = writeln!(out, "{line}") {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            return Err(ExitCode::SUCCESS);
        }
        eprintln!("piko: error: failed to write output: {error}");
        return Err(ExitCode::FAILURE);
    }
    Ok(())
}

/// Prints `prompt` and waits for a yes/no answer, matching pacman's own default-yes prompt.
///
/// A thin name for [`crate::output::confirm`] with pacman's `yesno` preset. This lets the
/// transaction prompts read as what they are, and keeps the `HoldPkg` guard's `noyes` preset
/// visible as the exception it is.
fn confirm(out: &mut impl std::io::Write, prompt: &str) -> bool {
    crate::output::confirm(out, prompt, true)
}

/// Whether the transaction should proceed: `true` outright under `--noconfirm`, otherwise
/// `confirm`'s answer.
///
/// [`crate::output::confirm`] flushes `out` before it writes the prompt. That flush ordinarily
/// guarantees the plan already printed there is visible before anything past this point runs.
/// `--noconfirm` skips calling it entirely, and skips that flush along with it. Without the
/// explicit flush here, the plan was left sitting in `out`'s buffer, invisible once downloading
/// or installing started printing to a different stream (`indicatif`'s rows are on stderr). The
/// plan's own last line appeared only once that other stream flushed `out` for an unrelated
/// reason.
fn proceed(out: &mut impl std::io::Write, noconfirm: bool, prompt: &str) -> bool {
    if noconfirm {
        let _ = out.flush();
        return true;
    }
    confirm(out, prompt)
}

/// The removal-side options, gathered so the entry point keeps a readable signature.
#[derive(Clone, Debug, Default)]
pub struct RemoveOptions {
    /// Do not create `.pacsave` files for modified configuration files (`-n`).
    pub no_save: bool,
    /// Also remove dependencies that nothing needs any more (`-s`).
    pub recursive: bool,
    /// Remove dependents too, instead of refusing (`-c`).
    pub cascade: bool,
    /// Remove exactly what was named, checking nothing (`--nodeps`).
    pub nodeps: bool,
    /// `pacman.conf`'s `NoExtract` and `NoUpgrade`.
    ///
    /// A removal writes nothing, so only `NoUpgrade` bites. It does: `should_skip_file`
    /// (`remove.c:592`) consults it before deleting, so a file the user told piko never to
    /// touch is not one a removal may take away either.
    pub patterns: piko_txn::Patterns,
    /// `pacman.conf`'s `HoldPkg`: names whose removal must be confirmed separately, and which
    /// `noconfirm` refuses rather than accepts — see [`crate::cmd::removal::hold_pkg_allows`].
    pub hold_pkg: Vec<String>,
    /// Skip the confirmation prompt and proceed as if the user answered yes.
    pub noconfirm: bool,
}

/// Removes installed packages from a root, and whatever the removal implies.
///
/// The set of packages is decided by the same planner `piko plan -R` prints, so what that
/// command shows is what this command does — see [`crate::cmd::removal`].
pub fn remove(
    root: &Path,
    dbpath: &Path,
    cache_dirs: Vec<std::path::PathBuf>,
    entries: &[String],
    options: RemoveOptions,
    side_effects: SideEffects,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let source = match CacheDirSource::new(cache_dirs) {
        Ok(source) => source,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let local = match piko_db::LocalDatabase::open(dbpath.join("local")) {
        Ok(local) => local,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let steplist = crate::progress::StepList::new();
    let entries_to_remove = if options.nodeps {
        match named_only(&local, entries, &options, out) {
            Ok(found) => found,
            Err(code) => return code,
        }
    } else {
        match planned(&steplist, &local, entries, &options, out) {
            Ok(found) => found,
            Err(code) => return code,
        }
    };

    let steps = entries_to_remove
        .into_iter()
        .map(|entry| Step::Remove { entry, no_save: options.no_save })
        .collect();

    // Verification and `--overwrite` are install-side: a removal installs no package, so there
    // is nothing to verify and it writes no file. Scriptlets and hooks are not. `pre_remove`
    // and `post_remove` exist, and `Operation = Remove` is a hook trigger.
    let settings = Settings {
        scriptlets: side_effects.scriptlets,
        hook_dirs: side_effects.hook_dirs.clone(),
        // `NoUpgrade` is not install-only: `should_skip_file` (`remove.c:592`) consults it
        // before deleting, so a file the user told piko never to touch survives a removal.
        patterns: options.patterns,
        recording: side_effects.recording.clone(),
        ..Settings::default()
    };
    run(
        root,
        dbpath,
        steps,
        &source,
        Progress { steplist: &steplist, download: None, download_head: None },
        settings,
        out,
    )
}

/// `--nodeps`: exactly the packages named, in the order named, with nothing checked.
///
/// An explicit escape hatch, matching pacman's `-Rdd`. It can leave the system with
/// unsatisfied dependencies, which is the user's stated intent when they pass it. There is no
/// solved plan to show for it, since nothing was checked. So this prints the plain list of
/// names instead of a full [`crate::cmd::plan::print_steps`] rendering.
fn named_only(
    local: &piko_db::LocalDatabase,
    entries: &[String],
    options: &RemoveOptions,
    out: &mut impl std::io::Write,
) -> Result<Vec<EntryName>, ExitCode> {
    let mut found = Vec::new();
    let mut names = Vec::new();
    for name in entries {
        let Some(package) = local.get_str(name) else {
            eprintln!("piko: error: package {name} is not installed");
            return Err(ExitCode::FAILURE);
        };
        match EntryName::new(package.name(), package.version()) {
            Ok(entry) => found.push(entry),
            Err(error) => {
                eprintln!("piko: error: {name} has no usable entry name: {error}");
                return Err(ExitCode::FAILURE);
            }
        }
        names.push(package.name().to_string());
    }

    // `HoldPkg` is checked here too. pacman's guard sits in `pacman_remove`, above everything
    // the flags select, so `-Rdd` is no more exempt from it than `-Rcs` is. The names are the
    // ones the database holds, not the ones typed, since a target may have been given as a
    // `%PROVIDES%`-style string that is not the package's own name.
    if !crate::cmd::removal::hold_pkg_allows(&names, &options.hold_pkg, options.noconfirm, out) {
        return Err(ExitCode::FAILURE);
    }

    emit_line(out, &format!("removing {} package(s):", found.len()))?;
    for entry in &found {
        emit_line(out, &format!("  {}", entry.as_str()))?;
    }
    if !proceed(out, options.noconfirm, "Do you want to remove these packages? [Y/n] ") {
        return Err(ExitCode::SUCCESS);
    }

    Ok(found)
}

/// Plans the removal, printing what it will take away before it takes it.
///
/// The universe is built from the local database alone. A removal-only request never selects
/// a repository candidate, and requiring a sync database would make this fail in a chroot
/// that has none. That equivalence is checked against the real database, not assumed. See
/// [`crate::cmd::removal`].
fn planned(
    steplist: &crate::progress::StepList,
    local: &piko_db::LocalDatabase,
    entries: &[String],
    options: &RemoveOptions,
    out: &mut impl std::io::Write,
) -> Result<Vec<EntryName>, ExitCode> {
    let resolving = steplist.spinner("Resolving dependencies");
    let limits = piko_db::Limits::default();
    let universe = match piko_db::solve::Universe::build(
        local,
        std::iter::empty::<(piko_db::config::DbUsage, &piko_db::repo::RepoDatabase)>(),
        piko_db::solve::UniverseOptions::new().limits(limits),
    ) {
        Ok(universe) => universe,
        Err(error) => {
            crate::progress::settle_row(steplist, out, resolving, "Resolving dependencies");
            report_error(&error);
            return Err(ExitCode::FAILURE);
        }
    };

    let plan = match piko_db::solve::plan_removal(
        local,
        &universe,
        entries,
        piko_db::solve::RemovalOptions { recursive: options.recursive, cascade: options.cascade },
        &limits,
    ) {
        Ok(plan) => plan,
        Err(failure) => {
            crate::progress::settle_row(steplist, out, resolving, "Resolving dependencies");
            crate::cmd::removal::report(&failure);
            return Err(ExitCode::FAILURE);
        }
    };
    crate::progress::settle_row(steplist, out, resolving, "Resolving dependencies");

    crate::cmd::plan::print_diagnostics(&universe, &plan);

    // Before the step list is printed, matching `pacman_remove`'s own order. Otherwise the
    // guard's warnings would be buried under a plan the user is about to be refused. It runs
    // over the solved removal set, so a `-Rc` cascade that reaches a held package without
    // naming it is caught.
    if !crate::cmd::removal::hold_pkg_allows(
        &piko_db::solve::removal_names(&universe, &plan),
        &options.hold_pkg,
        options.noconfirm,
        out,
    ) {
        return Err(ExitCode::FAILURE);
    }

    let mut found = Vec::new();
    for step in plan.steps() {
        let piko_db::solve::Step::Remove { package } = step else {
            // A removal-only request restricts candidates to what is installed, so the solver
            // has nothing to install. Reaching here means that invariant broke. Refusing is
            // the only safe answer, because the commit engine would carry out whatever this is.
            eprintln!("piko: error: the removal plan contains a step that is not a removal");
            eprintln!("piko: note: this is a bug; run `piko plan -R` to see the plan");
            return Err(ExitCode::FAILURE);
        };
        let Some(solvable) = universe.get(*package) else {
            eprintln!("piko: error: the plan names a package the universe does not know");
            return Err(ExitCode::FAILURE);
        };
        match EntryName::new(solvable.name(), solvable.version()) {
            Ok(entry) => found.push(entry),
            Err(error) => {
                eprintln!("piko: error: {} has no usable entry name: {error}", solvable.name());
                return Err(ExitCode::FAILURE);
            }
        }
    }

    if found.is_empty() {
        return Ok(found);
    }

    // Blank line separating the settled "Resolving dependencies" row from the step list below.
    emit_line(out, "")?;
    let code = crate::cmd::plan::print_steps(&universe, &plan, crate::cmd::plan::Format::Full, out);
    if code != ExitCode::SUCCESS {
        return Err(code);
    }

    emit_line(out, "")?;
    if !proceed(out, options.noconfirm, "Do you want to remove these packages? [Y/n] ") {
        return Err(ExitCode::SUCCESS);
    }

    Ok(found)
}

/// How a transaction is configured, apart from what it does.
#[derive(Debug, Default)]
struct Settings {
    /// Which paths are released from file-conflict detection.
    overwrite: Overwrite,
    /// How package signatures are checked.
    verification: Verification,
    /// Per-file overrides for `verification`'s policy, keyed by cache file name — see
    /// [`piko_txn::Transaction::policy_overrides`].
    policy_overrides: HashMap<String, Policy>,
    /// Whether `.INSTALL` scriptlets run.
    scriptlets: bool,
    /// The `HookDir`s the hooks to run before and after are read from.
    ///
    /// The directories, not an already-collected `Hooks`. The set of hook files is read once
    /// per phase, inside the transaction. See `piko_txn::Transaction::hook_dirs`.
    hook_dirs: Vec<PathBuf>,
    /// `NoExtract`/`NoUpgrade`, obeyed by extraction, by removal, and by the hook triggers.
    patterns: piko_txn::Patterns,
    /// Where the transaction records what it does.
    recording: piko_txn::Recording,
}

/// The live step list `run` drives, bundled so its own parameter count stays under clippy's
/// `too_many_arguments`. See `piko_net::refresh`'s `Target`/`Controls` for the same pattern.
struct Progress<'a> {
    steplist: &'a crate::progress::StepList,
    /// The row [`crate::progress::download_sink`] drives live. Finished right after
    /// `verify_with_progress` returns, since that is the only phase that can still report a
    /// download event. `install` passes one; `remove` (which never downloads) passes `None`.
    download: Option<crate::progress::Row>,
    /// The row naming in-flight downloads, above `download`. Cleared, not just finished, once
    /// `verify_with_progress` moves past the download phase (see
    /// [`crate::progress::VerifyDriver::finish_download`]).
    download_head: Option<crate::progress::Row>,
}

/// Drives one transaction from planning to report.
fn run(
    root: &Path,
    dbpath: &Path,
    steps: Vec<Step>,
    source: &dyn PackageSource,
    progress: Progress<'_>,
    settings: Settings,
    out: &mut impl std::io::Write,
) -> ExitCode {
    if steps.is_empty() {
        emit!(out, "nothing to do");
        return ExitCode::SUCCESS;
    }

    // A journal already there means a previous run did not finish. Refusing is the safe
    // answer: piko cannot know what state the system is in, and layering another
    // transaction on top would make it harder to work out later.
    match journal::read(dbpath) {
        Ok(Some(_)) => {
            eprintln!(
                "piko: error: an unfinished transaction is recorded in this database; \
                 run `piko report` to see it"
            );
            return ExitCode::FAILURE;
        }
        Ok(None) => {}
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    }

    let lock = match piko_db_write::DbLock::acquire(dbpath) {
        Ok(lock) => lock,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let planned = Transaction::new(root, dbpath, steps)
        .overwrite(settings.overwrite)
        .verification(settings.verification)
        .policy_overrides(settings.policy_overrides)
        .scriptlets(settings.scriptlets)
        .hook_dirs(settings.hook_dirs)
        .patterns(settings.patterns)
        .recording(settings.recording);

    let mut verify_driver = crate::progress::VerifyDriver::new(
        progress.steplist,
        &mut *out,
        progress.download,
        progress.download_head,
    );
    let verified = planned.verify_with_progress(source, &mut |event| verify_driver.handle(event));
    verify_driver.finish();
    let staged = match verified.and_then(|verified| verified.stage(&lock)) {
        Ok(staged) => staged,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let mut commit_driver = crate::progress::CommitDriver::new(progress.steplist, out);
    let result = staged.commit_with_progress(&mut |event| commit_driver.handle(event));
    commit_driver.finish();

    match result {
        Ok(report) => {
            report_side_effects(&report);
            let _ = lock.release();
            ExitCode::SUCCESS
        }
        Err(error) => {
            // A hook that aborted the run explains itself through the error, which already
            // carries what it printed. See `Error::HookAborted`.
            report_error(&error);
            if !matches!(error, piko_txn::Error::HookAborted { .. }) {
                eprintln!(
                    "piko: error: the transaction stopped part-way; \
                     run `piko report` to see what was applied"
                );
            }
            let _ = lock.release();
            ExitCode::FAILURE
        }
    }
}

/// Prints what the scriptlets and hooks did that could not have been known until the whole
/// transaction finished.
///
/// Their output text itself is not here. `CommitDriver` already streamed it live, line by
/// line, through [`piko_txn::progress::Event`] as each scriptlet/hook ran (see
/// `crate::progress`). This function only covers what settles once the final [`piko_txn::Report`]
/// is in hand: truncation, failure, a hook file that did not parse, or a hook skipped for an
/// unsatisfied `Depends`.
///
/// Failures are printed but do not change the exit code, because they do not change the
/// outcome. libalpm discards a scriptlet's status entirely, and a hook only stops a
/// transaction through `AbortOnFail`, which arrives as an error, not through here.
fn report_side_effects(report: &piko_txn::Report) {
    for run in &report.scriptlets {
        if run.outcome.truncated {
            eprintln!("piko: warning: {}'s scriptlet output was truncated", run.package);
        }
        if !run.outcome.succeeded() {
            eprintln!(
                "piko: warning: {}'s {} scriptlet {}",
                run.package,
                run.kind.as_str(),
                run.outcome.describe()
            );
        }
    }

    // A broken hook file is a warning, not an error, matching libalpm for the
    // `PostTransaction` case. It diverges for `PreTransaction`, where libalpm refuses the whole
    // run (`hook.c:625`). A file that did not parse has no `When`, so there is no phase to
    // attribute it to, and piko reports and continues either way.
    //
    // Printed after the run, not before it, because the hook files are read once per phase
    // inside the transaction. That is the same reason every other hook diagnostic here is late.
    for problem in &report.hook_problems {
        eprintln!("piko: warning: {problem}");
    }

    // Neither record can fail a transaction, so a problem with one arrives here rather than
    // as an error. See `piko_txn::history`.
    for problem in &report.history_problems {
        eprintln!("piko: warning: {problem}");
    }

    for run in &report.hooks {
        if let Some(missing) = &run.unsatisfied {
            eprintln!(
                "piko: warning: skipping hook {}: nothing installed satisfies {missing}",
                run.name
            );
            continue;
        }
        let Some(outcome) = &run.outcome else {
            continue;
        };
        if outcome.truncated {
            eprintln!("piko: warning: hook {}'s output was truncated", run.name);
        }
        if !outcome.succeeded() {
            eprintln!("piko: warning: hook {} {}", run.name, outcome.describe());
        }
    }
}

/// Turns `--overwrite` patterns into the predicate the commit engine takes.
///
/// Matched with `piko_db::resolve::matches_any`, which is libalpm's `_alpm_fnmatch_patterns`.
/// This is the same function pacman uses for this flag, for `NoExtract`, and for `NoUpgrade`.
fn overwrite_from(patterns: Vec<String>) -> Overwrite {
    if patterns.is_empty() {
        return Overwrite::default();
    }
    Overwrite::new(move |path| piko_db::resolve::matches_any(&patterns, &path.to_string_lossy()))
}

/// Reports an unfinished transaction, if the database records one.
///
/// Read-only. It describes; it does not repair. There is nothing to repair to. See the
/// note on atomicity in [`piko_txn::journal`].
pub fn report(dbpath: &Path, out: &mut impl std::io::Write) -> ExitCode {
    let record = match journal::read(dbpath) {
        Ok(Some(record)) => record,
        Ok(None) => {
            emit!(out, "no unfinished transaction is recorded");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    if !record.begun {
        emit!(out, "a transaction was recorded but never started; the system is unchanged");
        emit!(out, "remove {}/piko-journal to clear it", dbpath.display());
        return ExitCode::SUCCESS;
    }

    emit!(out, "an unfinished transaction was interrupted");
    emit!(out, "  root:   {}", record.root.display());
    emit!(out, "  dbpath: {}", record.dbpath.display());
    emit!(out, "  {} of {} steps completed", record.completed.len(), record.steps.len());

    let outstanding = record.outstanding();
    if outstanding.is_empty() {
        emit!(out, "every step completed; only the journal itself was left behind");
    } else {
        emit!(out, "not applied:");
        for intent in outstanding {
            match intent {
                Intent::Install { package } => emit!(out, "  install {package}"),
                Intent::Remove { entry } => emit!(out, "  remove {entry}"),
            }
        }
    }

    emit!(out, "");
    emit!(out, "piko cannot undo what was applied; re-run the operation to finish it,");
    emit!(out, "then remove {}/piko-journal", dbpath.display());
    ExitCode::SUCCESS
}
