//! The subcommands that can change a system: `install`, `remove` and `report`.
//!
//! # `--root`
//!
//! With no `--root`, the effective root falls back to `RootDir` from the parsed pacman.conf.
//! See `crate::context::resolve_root_dir`, the same resolution `piko check` uses.
//! `--root /` (or an omitted `--root` whose `pacman.conf` names `/`) targets the running
//! system.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::ExitCode,
};

use alpm_types::PackageInstallReason;
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
    CacheDirSource, DownloadingSource, FileSource, FileTarget, PackageSource, Step, TargetKind,
    Transaction,
    conflict::Overwrite,
    file_target,
    journal::{self, Intent},
    transaction::Verification,
};

use crate::output::{emit, report as report_error};

/// Writes one frontend line to the transaction log, warning if it cannot be written.
///
/// The counterpart of pacman's `[PACMAN]` lines. It records what the user ran. It also records
/// the two markers a refresh and a sysupgrade put in the log before any transaction starts. A log
/// that
/// cannot be written is a warning here, for the same reason it is one inside a transaction. The
/// command the user asked for still runs. See [`piko_txn::history`].
pub fn note(recording: &piko_txn::Recording, message: &str) {
    if let Err(problem) = piko_txn::history::note(recording, message) {
        eprintln!("Warning: {problem}");
    }
}

/// The install-side options, gathered so the entry point keeps a readable signature.
#[derive(Clone, Debug, Default)]
pub struct InstallOptions {
    /// `--asdeps`/`--asexplicit`: what install reason each incoming package is recorded with.
    pub reasons: piko_txn::ReasonPolicy,
    /// `--needed`: drop a target already at the version that would be installed, rather than
    /// reinstalling it.
    ///
    /// It governs the named targets only. A dependency is never a reinstall, since piko
    /// installs one only where something needs it. `--sysupgrade` compares versions on its
    /// own, so it is unaffected too.
    pub needed: bool,
    /// `--overwrite` glob patterns, matched against each path.
    pub overwrite: Vec<String>,
    /// The GnuPG keyring directory, from `pacman.conf`'s `GPGDir`.
    pub gpg_dir: PathBuf,
    /// The fallback `SigLevel` for a package whose repository could not be resolved.
    ///
    /// A package resolved through a repository is checked against that repository's own
    /// `SigLevel`, resolved per candidate and fed to
    /// [`piko_txn::Transaction::policy_overrides`]. This value is only the defensive fallback.
    /// See [`crate::context::signing_policy`] for the three directives and which target each
    /// one governs.
    pub sig_level: SigLevel,
    /// `LocalFileSigLevel`: the policy for a package file named by path.
    pub local_file_sig_level: SigLevel,
    /// `RemoteFileSigLevel`: the policy for a package file named by URL.
    pub remote_file_sig_level: SigLevel,
    /// `pacman.conf`'s `Architecture`, for `check_arch` on a package file. Empty skips the
    /// check, as it does in libalpm.
    pub architecture: Vec<alpm_types::Architecture>,
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
    /// `pacman.conf`'s `CheckSpace`: weigh the transaction against free disk space before
    /// writing anything. There is no flag for it, because pacman has none either.
    pub check_space: bool,
    /// A `SIGINT` handler already installed by an earlier step (`update`'s pre-refresh),
    /// reused instead of installing a second one. `ctrlc::set_handler` accepts exactly one
    /// registration per process, and a second call would panic. `None` when nothing installed
    /// one yet. `install` installs its own, either when it fetches a package URL or, failing
    /// that, once its confirmation prompt has been answered.
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
    /// The parsed configuration for every repository in [`Catalog::repos`]: servers, cache
    /// servers, and `SigLevel`. It resolves where a missing package can be downloaded from.
    pub configs: &'a [RepositoryConfig],
}

/// Installs packages by name, resolving dependencies through the configured repositories.
///
/// With `options.sysupgrade` set, this also runs `piko update`'s full-system upgrade.
///
/// Targets are resolved exactly as `piko plan` resolves them: a literal name or dependency
/// string first, a `%GROUPS%` member expansion second. The whole transitive closure of
/// dependencies, conflicts, and replacements is planned through the same solver before anything
/// is committed. What that plan reports is what `run` applies. `piko install foo` is `piko
/// plan foo` turned into a transaction. `piko remove` stands in the same relationship to
/// `piko plan -R` (see [`crate::cmd::removal`]), and `piko update` to `piko plan -u`.
///
/// A target that names a package **file**, as a path or a URL, is `pacman -U`. It is read before
/// the plan is solved. It joins the universe as a candidate the repositories do not carry, and
/// wins over any repository package of the same name. Its dependencies are still resolved from
/// the repositories, exactly as pacman's `-U` hands off to `_alpm_sync_prepare`. See
/// [`piko_txn::classify`] for how a target is told apart from a name.
///
/// A package already in a cache directory is used as-is. A missing one is downloaded from its
/// own repository's configured servers before installing. See [`DownloadingSource`].
pub fn install(
    root: &Path,
    dbpath: &Path,
    cache_dirs: Vec<std::path::PathBuf>,
    catalog: Catalog<'_>,
    targets: &[String],
    mut options: InstallOptions,
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

    // Targets that name a file are read before anything else is planned. The plan cannot be
    // solved without them, since they are candidates no repository carries. A URL is fetched
    // here too, which is why this precedes the confirmation prompt. `alpm_fetch_pkgurl` runs in
    // the same order, ahead of `trans_init` (`upgrade.c`).
    let mut pre_cancel = options.pre_cancel.take();
    let prepared =
        match prepare_file_targets(targets, &cache, &catalog, &options, &mut pre_cancel, out) {
            Ok(prepared) => prepared,
            Err(code) => return code,
        };
    let file_candidates = prepared.candidates();

    let steplist = crate::progress::StepList::new();
    let resolving = steplist.spinner("Resolving dependencies");

    let universe = match Universe::build(
        catalog.local,
        catalog.repos.iter().map(|(usage, db)| (*usage, db)),
        UniverseOptions::new().ignores(catalog.ignores).limits(limits).files(&file_candidates),
    ) {
        Ok(universe) => universe,
        Err(error) => {
            crate::progress::settle_row(&steplist, out, resolving, "Resolving dependencies");
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let base = Request::new().needed(options.needed);
    let mut resolution = match resolve_targets(&universe, base.clone(), &prepared.names, &limits) {
        Ok(resolved) => resolved,
        Err(failure) => {
            crate::progress::settle_row(&steplist, out, resolving, "Resolving dependencies");
            crate::cmd::plan::report_target_resolution_failure(&failure);
            return ExitCode::FAILURE;
        }
    };

    // Ask which members of each group target to install. Then resolve once more with the
    // answers. A group names several targets, so an answer settles the target list rather than
    // a clause inside the solve. That is why this is two calls, not the provider question's
    // open-ended loop. The second call cannot uncover a group the first did not. Expansion
    // reads the universe and the target list, never the answers.
    if !resolution.groups.is_empty() && !options.noconfirm {
        let choices = steplist.suspend(|| {
            let mut ask = || crate::cmd::group::answer(&universe, &resolution.groups, out);
            match &pre_cancel {
                Some(handoff) => handoff.mode.during_prompt(ask),
                None => ask(),
            }
        });
        let mut answered = base;
        for choice in choices {
            answered = answered.choose_group(choice);
        }
        resolution = match resolve_targets(&universe, answered, &prepared.names, &limits) {
            Ok(resolved) => resolved,
            Err(failure) => {
                crate::progress::settle_row(&steplist, out, resolving, "Resolving dependencies");
                crate::cmd::plan::report_target_resolution_failure(&failure);
                return ExitCode::FAILURE;
            }
        };
    }

    let mut request = resolution.request;
    // Through `suspend`, since the spinner is still running: an ordinary `eprintln!` here
    // lands inside the row indicatif is redrawing.
    if !resolution.expansions.is_empty() {
        steplist.suspend(|| crate::cmd::plan::print_expansions(&resolution.expansions));
    }
    if !resolution.ignored.is_empty() {
        steplist.suspend(|| crate::cmd::plan::print_ignored_targets(&resolution.ignored));
    }

    // Each file candidate is targeted by its id, not by a name. Resolving it by name would find
    // whichever candidate the universe prefers, which is the file only by construction. It would
    // then silently install a repository package the day that construction changed.
    let file_ids = universe.file_candidates();
    if file_ids.len() != prepared.files.len() {
        crate::progress::settle_row(&steplist, out, resolving, "Resolving dependencies");
        eprintln!("Internal error: the universe lost a package file candidate");
        return ExitCode::FAILURE;
    }
    for id in file_ids {
        request = request.target(id);
    }

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
        if !request.ignored_upgrades().is_empty() {
            steplist.suspend(|| {
                crate::cmd::plan::print_ignored_upgrades(&universe, request.ignored_upgrades());
            });
        }
    }

    // Ask, answer, solve again. An answered requirement is encoded with one satisfier, so it is
    // never raised a second time. And the set of requirements the cone can raise does not depend
    // on the answers. So the loop adds at least one answer per round, and runs out of questions.
    // Two rounds is the common case, because a chosen provider brings its own dependencies,
    // which may be ambiguous in turn.
    let mut answered: std::collections::HashMap<String, SolvableId> =
        std::collections::HashMap::new();
    let planned = loop {
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

        let questions =
            piko_db::solve::ambiguities(&universe, &planned.encoded, &planned.selected, &limits);
        if questions.is_empty() {
            break planned;
        }
        // `--noconfirm` takes libalpm's own `use_index = 0` for every question: the first
        // candidate in repository priority order. Reported rather than silent, so an
        // unattended run still says a choice was made on its behalf. Unlike `HoldPkg` and
        // `IgnorePkg`, there is no standing instruction in `pacman.conf` for that default to
        // contradict, so it needs no refusal.
        if options.noconfirm {
            steplist.suspend(|| crate::cmd::provider::report_defaults(&universe, &questions));
            break planned;
        }

        // Through `suspend`: the "Resolving dependencies" spinner is still redrawing its row,
        // and would overwrite the question. `during_prompt` brackets it the way the
        // "Proceed with installation?" prompt below is bracketed.
        let choices = steplist.suspend(|| {
            let mut ask =
                || crate::cmd::provider::answer(&universe, &questions, &mut answered, out);
            match &pre_cancel {
                Some(handoff) => handoff.mode.during_prompt(ask),
                None => ask(),
            }
        });
        if questions.dropped() > 0 {
            steplist.suspend(|| {
                eprintln!(
                    "Warning: {} further provider question(s) not asked; the first candidate \
                     was taken",
                    questions.dropped()
                );
            });
        }
        for choice in choices {
            request = request.choose_provider(choice);
        }
    };

    let built = Plan::assemble(&universe, &planned, request.targets(), &limits, &cache);
    crate::progress::settle_row(&steplist, out, resolving, "Resolving dependencies");
    // `piko update` decides something about every installed package, so it is the command
    // that reports a dependency broken before it ran. `piko install foo` was asked about
    // `foo`.
    let reach = if options.sysupgrade.is_some() {
        crate::cmd::plan::Reach::WholeSystem
    } else {
        crate::cmd::plan::Reach::NamedTargets
    };
    crate::cmd::plan::print_diagnostics(&universe, &built, reach);

    if built.steps().is_empty() {
        emit!(out, "Nothing to do");
        return ExitCode::SUCCESS;
    }

    // Blank line separating the settled "Resolving dependencies" row from the step list below.
    emit!(out, "");
    let code =
        crate::cmd::plan::print_steps(&universe, &built, crate::cmd::plan::Format::Full, None, out);
    if code != ExitCode::SUCCESS {
        return code;
    }

    emit!(out, "");
    let prompt = if options.download_only {
        "Proceed with download? [Y/n] "
    } else {
        "Proceed with installation? [Y/n] "
    };
    // A handler may already be installed: by `update`'s pre-refresh step (`main::sync`), or by
    // `prepare_file_targets` for a package URL it had to fetch. Both happened before this
    // prompt, which is why there is one `pre_cancel` and one branch. Bracketing the prompt in
    // `during_prompt` still kills the process on the first Ctrl+C here. That is exactly what
    // happens when no handler exists yet (the `None` branch). Nothing at the prompt needs a
    // graceful stop.
    let answered = match &pre_cancel {
        Some(handoff) => handoff.mode.during_prompt(|| proceed(out, options.noconfirm, prompt)),
        None => proceed(out, options.noconfirm, prompt),
    };
    if !answered {
        return ExitCode::SUCCESS;
    }

    // Only from here on can *this* step reach the network. See `crate::signal` for why a handler
    // is not installed earlier than it has to be. An earlier one would make Ctrl+C at the prompt
    // above require two presses. `pre_cancel` carries whatever registration an earlier step
    // made, a pre-refresh or a package URL fetch. So this does not install a second one, which
    // `ctrlc::set_handler` would refuse.
    let cancel = match pre_cancel {
        Some(handoff) => handoff.cancel,
        None => crate::signal::install_cancel_handler().0,
    };
    // A second handle on the same flag. `DownloadingSource` takes the one above, and reads
    // it while a download runs. `run` reads this one once, after every download is over.
    let cancel_flag = cancel.clone();

    let steps = match piko_txn::install_steps(&universe, &built, &explicit_targets, options.reasons)
    {
        Ok(steps) => steps,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let package_targets =
        piko_txn::download_targets(&universe, &built, catalog.configs, options.sig_level);
    let (verification, policy_overrides) = match piko_txn::verification_from(
        &options.gpg_dir,
        options.sig_level,
        &package_targets,
        &prepared.files,
    ) {
        Ok(result) => result,
        Err(error) => {
            report_error(&error);
            eprintln!(
                "Note: set SigLevel = Never in pacman.conf to install without \
                 checking signatures"
            );
            return ExitCode::FAILURE;
        }
    };

    // No row at all when nothing needs downloading. That is a removal-only plan, or one whose
    // every candidate is already in a cache directory, since `Plan::assemble` was given `cache`
    // above.
    let rig = crate::progress::download_rig(&steplist, built.download_size());
    let source = match DownloadingSource::new(
        cache_dirs,
        package_targets,
        cancel,
        piko_net::Concurrency::new(options.parallel_downloads),
        rig.sink,
    )
    .map(|source| source.check_space(options.check_space))
    {
        Ok(source) => source,
        Err(error) => {
            crate::progress::clear_download_rows(rig.row, rig.head);
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };
    report_download_dir(&steplist, source.download_dir());
    // The named files go in front of the cache: the plan chose them, so the source must serve
    // them. A `FileSource` with nothing in it is a pass-through, so this costs nothing when no
    // file was named.
    let source = FileSource::new(prepared.paths_by_name(), Box::new(source));

    if options.download_only {
        return download_only(
            &source,
            &cache,
            &steps,
            &verification,
            &policy_overrides,
            Progress { steplist: &steplist, download: rig.row, download_head: rig.head },
            out,
        );
    }

    let settings = Settings {
        overwrite: overwrite_from(options.overwrite),
        verification,
        policy_overrides,
        scriptlets: options.side_effects.scriptlets,
        hook_dirs: options.side_effects.hook_dirs.clone(),
        patterns: options.patterns,
        recording: options.side_effects.recording.clone(),
        check_space: options.check_space,
        cancel: Some(cancel_flag),
        report_pending: !options.download_only,
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

/// The command line, split into what the solver resolves and what was read from a file.
struct PreparedTargets {
    /// Targets to resolve through the repositories, in the order they were given.
    names: Vec<String>,
    /// Every package file named, path and URL alike, in the order they were given.
    files: Vec<FileTarget>,
}

impl PreparedTargets {
    /// The solver's view of each named file, in the order they were given.
    ///
    /// `Universe` borrows these for as long as it lives. So the caller collects them once and
    /// keeps them alongside it, rather than rebuild them.
    fn candidates(&self) -> Vec<&piko_db::solve::FilePackage> {
        self.files.iter().map(FileTarget::candidate).collect()
    }

    /// Where each named file is, keyed by the name a plan step addresses it by.
    fn paths_by_name(&self) -> HashMap<String, PathBuf> {
        self.files
            .iter()
            .map(|target| (target.file_name().to_string(), target.path().to_path_buf()))
            .collect()
    }
}

/// Reads every target that names a package file, fetching the ones named by URL.
///
/// # Why this runs before the plan, and therefore before the prompt
///
/// A package file is a candidate the repositories do not carry. Nothing can be solved until
/// its `.PKGINFO` has been read, and a URL cannot be read until it has been fetched. pacman
/// has the same ordering for the same reason. `pacman_upgrade` calls `alpm_fetch_pkgurl` and
/// then `alpm_pkg_load` for every target, all before `trans_init`.
///
/// So a `piko install <url>` downloads before it asks. `cancel` is threaded out through
/// `pre_cancel` rather than kept here. That lets the confirmation prompt later bracket itself in
/// `PromptMode::during_prompt`. Without that, Ctrl+C at the prompt would ask a finished download
/// to stop instead of killing the process. See `crate::signal`.
///
/// # Errors
///
/// Returns the [`ExitCode`] to exit with. Every failure is reported before returning.
fn prepare_file_targets(
    targets: &[String],
    cache: &CacheDirSource,
    catalog: &Catalog<'_>,
    options: &InstallOptions,
    pre_cancel: &mut Option<crate::signal::Handoff>,
    out: &mut impl std::io::Write,
) -> Result<PreparedTargets, ExitCode> {
    let classified: Vec<TargetKind> =
        targets.iter().map(|target| piko_txn::classify(target)).collect();
    let names: Vec<String> = classified
        .iter()
        .filter_map(|kind| match kind {
            TargetKind::Name(name) => Some(name.clone()),
            TargetKind::File(_) | TargetKind::Url(_) => None,
        })
        .collect();
    if classified.iter().all(|kind| matches!(kind, TargetKind::Name(_))) {
        return Ok(PreparedTargets { names, files: Vec::new() });
    }

    warn_about_ambiguous_targets(&classified, catalog);

    // Only now, and only because a URL has to be fetched before the prompt. A plain
    // `piko install ./foo.pkg.tar.zst` reads a local file and installs no handler here. So
    // Ctrl+C at its prompt still kills the process by the OS's default disposition.
    let has_url = classified.iter().any(|kind| matches!(kind, TargetKind::Url(_)));
    if has_url && pre_cancel.is_none() {
        let (cancel, mode) = crate::signal::install_cancel_handler();
        *pre_cancel = Some(crate::signal::Handoff { cancel, mode });
    }

    let package_limits = piko_txn::extract::PackageLimits::default();
    let mut files = Vec::new();
    for kind in &classified {
        let loaded = match kind {
            TargetKind::Name(_) => continue,
            TargetKind::File(path) => file_target::load(
                path,
                Policy::for_package(options.local_file_sig_level),
                &package_limits,
            ),
            TargetKind::Url(url) => {
                let path = fetch_package_url(url, cache, options, pre_cancel, out)?;
                file_target::load(
                    &path,
                    Policy::for_package(options.remote_file_sig_level),
                    &package_limits,
                )
            }
        };
        match loaded {
            Ok(target) => files.push(target),
            Err(error) => {
                report_error(&error);
                return Err(ExitCode::FAILURE);
            }
        }
    }

    if let Err(error) = file_target::check_duplicates(&files) {
        report_error(&error);
        return Err(ExitCode::FAILURE);
    }
    if let Err(error) = file_target::check_architecture(&files, &options.architecture) {
        report_error(&error);
        return Err(ExitCode::FAILURE);
    }

    Ok(PreparedTargets { names, files })
}

/// Downloads one package named by URL, and reports where it landed.
///
/// # Errors
///
/// Returns the [`ExitCode`] to exit with, having reported the failure.
fn fetch_package_url(
    url: &str,
    cache: &CacheDirSource,
    options: &InstallOptions,
    pre_cancel: &Option<crate::signal::Handoff>,
    out: &mut impl std::io::Write,
) -> Result<PathBuf, ExitCode> {
    // A `Cancel` that no handler will ever request, for the path where no URL forced one to be
    // installed. It cannot happen, because `prepare_file_targets` installs a handler before it
    // calls this. Constructing one is cheaper than making the caller prove it.
    let cancel =
        pre_cancel.as_ref().map_or_else(piko_net::Cancel::new, |handoff| handoff.cancel.clone());

    if writeln!(out, "Fetching {url}").is_err() {
        // Nothing has been fetched yet, so a broken pipe here just ends the run quietly.
        return Err(ExitCode::SUCCESS);
    }
    let policy = Policy::for_package(options.remote_file_sig_level);
    match piko_txn::file_target::fetch_url(url, cache, policy, &cancel, &|_| {}) {
        Ok(path) => Ok(path),
        Err(error) => {
            report_error(&error);
            Err(ExitCode::FAILURE)
        }
    }
}

/// Names a target that could have been read as a package name as well as a path.
///
/// `piko_txn::classify`'s rule 3 resolves the ambiguity by existence on disk. That is right far
/// more often than not, but it is silent. This says so, and only when the other reading is real.
/// The other reading is real when a repository actually carries a package of that literal name.
/// A file whose name no repository knows is not ambiguous at all. Warning about it would be
/// noise on every ordinary `piko install foo-1.0-1-x86_64.pkg.tar.zst`.
fn warn_about_ambiguous_targets(classified: &[TargetKind], catalog: &Catalog<'_>) {
    for spelled in classified.iter().filter_map(TargetKind::ambiguous_name) {
        if catalog.repos.iter().any(|(_, repository)| repository.get_str(spelled).is_some()) {
            eprintln!(
                "Warning: {spelled} names both a file here and a package in a \
                 repository; installing the file (write ./{spelled} to silence this, or \
                 move the file to install the package)"
            );
        }
    }
}

/// Reports what the download-directory selection passed over, and whether it created one.
///
/// libalpm logs both at `ALPM_LOG_DEBUG` (`util.c:916`, `:924`). piko has no debug channel,
/// and a configured `CacheDir` silently ignored is exactly the mistake worth naming. Both
/// facts are absent in the ordinary case, so a normal run prints nothing.
///
/// Written through `StepList::suspend`. The download rows are already live by the time this
/// runs, and a bare `eprintln!` would be overdrawn mid-line.
fn report_download_dir(steplist: &crate::progress::StepList, dir: &piko_txn::DownloadDir) {
    if dir.rejected().is_empty() && !dir.created() {
        return;
    }
    steplist.suspend(|| {
        for rejected in dir.rejected() {
            eprintln!("Warning: {rejected}");
        }
        if dir.created() {
            eprintln!("Warning: no {} cache exists, creating...", dir.path().display());
        }
    });
}

/// Names what the disk-space estimate could not measure.
///
/// Each of these means part of the estimate is missing. A transaction that passed may have
/// passed on incomplete arithmetic. A path on a filesystem nothing could stat is a path charged
/// to nobody. libalpm logs the same facts as warnings. Silence is the ordinary case.
///
/// Written through `StepList::suspend` for the reason [`report_download_dir`] is.
fn report_space_problems(
    steplist: &crate::progress::StepList,
    problems: &[piko_txn::space::Problem],
) {
    if problems.is_empty() {
        return;
    }
    steplist.suspend(|| {
        for problem in problems {
            eprintln!("Warning: {problem}");
        }
    });
}

/// Downloads every missing package named in `steps` into the cache, installing nothing.
///
/// A thin CLI wrapper around [`piko_txn::download_only`]. See there for what it does and why.
/// This drives the live step list. It reports any [`piko_txn::Error`] the call stops on.
///
/// It prints nothing per package. `-w` shows the two rows an install shows for the same work:
/// "Downloading packages" and "Verifying signatures". The cache holds the result.
///
/// The rows come from [`crate::progress::VerifyDriver`], not from a second display. That driver
/// also renders an install's `verify_with_progress`. Each outcome is one package located and
/// signature-checked. [`piko_txn::progress::VerifyEvent::SignatureChecked`] reports exactly
/// that, so both paths render this phase the same way.
///
/// This counts `total` itself, because an outcome carries no index. It is the plan's install
/// count, the same total `Transaction::verify_with_progress` computes.
fn download_only(
    source: &dyn PackageSource,
    cache: &CacheDirSource,
    steps: &[Step],
    verification: &Verification,
    policy_overrides: &HashMap<String, Policy>,
    progress: Progress<'_>,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let total = steps.iter().filter(|step| matches!(step, Step::Install { .. })).count();
    let mut driver = crate::progress::VerifyDriver::new(
        progress.steplist,
        &mut *out,
        progress.download,
        progress.download_head,
    );
    let mut checked = 0_usize;
    let result =
        piko_txn::download_only(source, cache, steps, verification, policy_overrides, |_outcome| {
            checked = checked.saturating_add(1);
            driver.handle(piko_txn::progress::VerifyEvent::SignatureChecked {
                index: checked,
                total,
            });
        });
    // Closes whatever row is still open, on success and on failure alike.
    driver.finish();
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
        eprintln!("Error: failed to write output: {error}");
        return Err(ExitCode::FAILURE);
    }
    Ok(())
}

/// Prints `prompt` and waits for a yes/no answer, matching pacman's own default-yes prompt.
///
/// A thin name for [`crate::output::confirm`] with pacman's `yesno` preset. This lets the
/// transaction prompts read as what they are. It also keeps the `HoldPkg` guard's `noyes` preset
/// visible as the exception it is.
fn confirm(out: &mut impl std::io::Write, prompt: &str) -> bool {
    crate::output::confirm(out, prompt, true)
}

/// Whether the transaction should proceed: `true` outright under `--noconfirm`, otherwise
/// `confirm`'s answer.
///
/// [`crate::output::confirm`] flushes `out` before it writes the prompt. That flush ordinarily
/// guarantees the plan already printed there is visible before anything past this point runs.
/// `--noconfirm` skips calling it entirely, and skips that flush along with it. So the explicit
/// flush here is what `--noconfirm` relies on. Without it the plan sits in `out`'s buffer,
/// invisible once downloading or installing prints to a different stream. `indicatif`'s rows are
/// on stderr. The plan's own last line would then appear only once that other stream flushed
/// `out` for an unrelated reason.
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
    /// A removal writes nothing, so only `NoUpgrade` bites. And it does bite. `should_skip_file`
    /// (`remove.c:592`) consults it before deleting. So a file the user told piko never to touch
    /// is not one a removal may take away either.
    pub patterns: piko_txn::Patterns,
    /// `pacman.conf`'s `HoldPkg`: names whose removal must be confirmed separately, and which
    /// `noconfirm` refuses rather than accepts — see [`crate::cmd::removal::hold_pkg_allows`].
    pub hold_pkg: Vec<String>,
    /// Skip the confirmation prompt and proceed as if the user answered yes.
    pub noconfirm: bool,
}

/// Removes installed packages from a root, and whatever the removal implies.
///
/// The set of packages is decided by the same planner `piko plan -R` prints. So what that
/// command shows is what this command does. See [`crate::cmd::removal`].
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
        // `NoUpgrade` is not install-only. `should_skip_file` (`remove.c:592`) consults it
        // before deleting, so a file the user told piko never to touch survives a removal.
        patterns: options.patterns,
        recording: side_effects.recording.clone(),
        // A removal writes no file, but it does save modified configuration files.
        report_pending: true,
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
    // A pattern is rewritten into installed names before anything is looked up. Groups are
    // deliberately left out here. This path resolves a target with `LocalDatabase::get_str`
    // alone, and accepts no group name. So a pattern must not become the one spelling that does.
    let (entries, expansions) =
        match piko_db::solve::expand_installed_names(local, entries, &piko_db::Limits::default()) {
            Ok(expanded) => expanded,
            Err(failure) => {
                crate::cmd::plan::report_expansion_failure(&failure);
                return Err(ExitCode::FAILURE);
            }
        };
    crate::cmd::plan::print_expansions(&expansions);

    let mut found = Vec::new();
    let mut names = Vec::new();
    for name in &entries {
        let Some(package) = local.get_str(name) else {
            eprintln!("Error: package {name} is not installed");
            return Err(ExitCode::FAILURE);
        };
        match EntryName::new(package.name(), package.version()) {
            Ok(entry) => found.push(entry),
            Err(error) => {
                eprintln!("Error: {name} has no usable entry name: {error}");
                return Err(ExitCode::FAILURE);
            }
        }
        names.push(package.name().to_string());
    }

    // `HoldPkg` is checked here too. pacman's guard sits in `pacman_remove`, above everything
    // the flags select, so `-Rdd` is no more exempt from it than `-Rcs` is. The names are the
    // ones the database holds, not the ones typed. A target may have been given as a
    // `%PROVIDES%`-style string that is not the package's own name.
    if !crate::cmd::removal::hold_pkg_allows(&names, &options.hold_pkg, options.noconfirm, out) {
        return Err(ExitCode::FAILURE);
    }

    emit_line(out, &format!("Removing {} package(s):", found.len()))?;
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
/// The universe is built from the local database alone. A removal-only request never selects a
/// repository candidate. Requiring a sync database would also make this fail in a chroot that has
/// none. That equivalence is checked against the real database, not assumed. See
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

    let removal = match piko_db::solve::plan_removal(
        local,
        &universe,
        entries,
        piko_db::solve::RemovalOptions {
            recursive: options.recursive,
            cascade: options.cascade,
            explain: false,
        },
        &limits,
    ) {
        Ok(removal) => removal,
        Err(failure) => {
            crate::progress::settle_row(steplist, out, resolving, "Resolving dependencies");
            crate::cmd::plan::report_expansion_failure(&failure);
            return Err(ExitCode::FAILURE);
        }
    };
    crate::progress::settle_row(steplist, out, resolving, "Resolving dependencies");

    // Before the outcome either way. A refusal names packages the user may never have typed, and
    // the pattern that pulled them in is what explains the list.
    crate::cmd::plan::print_expansions(&removal.expansions);
    let plan = match removal.outcome {
        Ok(plan) => plan,
        Err(failure) => {
            crate::cmd::removal::report(&failure);
            return Err(ExitCode::FAILURE);
        }
    };

    crate::cmd::plan::print_diagnostics(&universe, &plan, crate::cmd::plan::Reach::NamedTargets);

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
            eprintln!("Error: the removal plan contains a step that is not a removal");
            eprintln!("Note: this is a bug; run `piko plan -R` to see the plan");
            return Err(ExitCode::FAILURE);
        };
        let Some(solvable) = universe.get(*package) else {
            eprintln!("Error: the plan names a package the universe does not know");
            return Err(ExitCode::FAILURE);
        };
        match EntryName::new(solvable.name(), solvable.version()) {
            Ok(entry) => found.push(entry),
            Err(error) => {
                eprintln!("Error: {} has no usable entry name: {error}", solvable.name());
                return Err(ExitCode::FAILURE);
            }
        }
    }

    if found.is_empty() {
        return Ok(found);
    }

    // Blank line separating the settled "Resolving dependencies" row from the step list below.
    emit_line(out, "")?;
    let code =
        crate::cmd::plan::print_steps(&universe, &plan, crate::cmd::plan::Format::Full, None, out);
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
    /// `pacman.conf`'s `CheckSpace`. Always `false` for a removal: a removal only frees space,
    /// and libalpm runs no check for one either.
    check_space: bool,
    /// The `SIGINT` flag, read once between verification and the commit.
    ///
    /// [`run`] holds that check, and explains it. This is `None` for a transaction with no
    /// handler installed, which is every removal.
    cancel: Option<piko_net::Cancel>,
    /// Whether a finished commit names the configuration files it left behind.
    ///
    /// False for `-w`, which commits nothing and so leaves none.
    report_pending: bool,
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

impl Progress<'_> {
    /// Clears both download rows. A run that stops before anything is fetched calls this.
    /// See [`crate::progress::clear_download_rows`].
    fn clear_downloads(&mut self) {
        crate::progress::clear_download_rows(self.download.take(), self.download_head.take());
    }
}

/// Drives one transaction from planning to report.
fn run(
    root: &Path,
    dbpath: &Path,
    steps: Vec<Step>,
    source: &dyn PackageSource,
    mut progress: Progress<'_>,
    settings: Settings,
    out: &mut impl std::io::Write,
) -> ExitCode {
    // `install` opens its download rows before it knows whether this function downloads
    // anything. Those rows tick until `VerifyDriver` takes them over. So every refusal below
    // clears them first, for two reasons. A live row redraws over a bare `eprintln!` mid-line.
    // And a row left ticking on a stopped run still claims a download that never starts.
    // `remove` passes no rows, so the call costs it nothing.
    if steps.is_empty() {
        progress.clear_downloads();
        emit!(out, "Nothing to do");
        return ExitCode::SUCCESS;
    }

    // A journal already there means a previous run did not finish. Refusing is the safe answer.
    // piko cannot know what state the system is in. Layering another transaction on top would
    // make that state harder to work out later. A journal this build cannot read is refused
    // too: only a missing file means that no transaction is unfinished.
    match journal::read(dbpath) {
        Ok(Some(_)) => {
            progress.clear_downloads();
            eprintln!(
                "Error: an unfinished transaction is recorded in this database; \
                 run `piko report` to see it"
            );
            return ExitCode::FAILURE;
        }
        Ok(None) => {}
        Err(error @ piko_txn::Error::JournalUnreadable { .. }) => {
            progress.clear_downloads();
            report_error(&error);
            eprintln!("A previous transaction did not finish; run `piko report` to see it");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            progress.clear_downloads();
            report_error(&error);
            return ExitCode::FAILURE;
        }
    }

    let lock = match piko_db_write::DbLock::acquire(dbpath) {
        Ok(lock) => lock,
        Err(error) => {
            progress.clear_downloads();
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let total_steps = steps.len();
    let planned = Transaction::new(root, dbpath, steps)
        .overwrite(settings.overwrite)
        .verification(settings.verification)
        .policy_overrides(settings.policy_overrides)
        .scriptlets(settings.scriptlets)
        .hook_dirs(settings.hook_dirs)
        .patterns(settings.patterns)
        .recording(settings.recording)
        .check_space(settings.check_space);
    // The commit reads the same flag the check below reads. It stops between two steps.
    // `Cancel` is a cheap handle, so both readers hold one.
    let planned = match settings.cancel.clone() {
        Some(cancel) => planned.cancel(cancel),
        None => planned,
    };

    let mut verify_driver = crate::progress::VerifyDriver::new(
        progress.steplist,
        &mut *out,
        progress.download,
        progress.download_head,
    );
    let verified = planned.verify_with_progress(source, &mut |event| verify_driver.handle(event));
    verify_driver.finish();
    let verified = match verified {
        Ok(verified) => verified,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };
    report_space_problems(progress.steplist, verified.space_problems());

    // This covers the window between verification's last read and the commit's first. It is
    // also the last point where a stop leaves nothing behind. `stage` opens the journal, and
    // a stop past it leaves that journal for `piko report`.
    //
    // This builds the error rather than printing prose of its own. One Ctrl+C then says the
    // same thing wherever it lands.
    if settings.cancel.as_ref().is_some_and(piko_net::Cancel::is_requested) {
        report_error(&piko_txn::Error::Cancelled { completed: 0, total: total_steps });
        return ExitCode::FAILURE;
    }

    let staged = match verified.stage(&lock) {
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
            // Released before the follow-up, not after. An editor left open for ten minutes
            // must not hold `db.lck`. What is on disk is already final: the `PostTransaction`
            // hooks ran inside `commit`, and the scan that follows reopens the local database
            // read-only, which needs no lock.
            let _ = lock.release();
            if settings.report_pending {
                crate::cmd::merge::report_pending(root, &report, out);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            // A hook that aborted the run explains itself through the error, which already
            // carries what it printed. See `Error::HookAborted`.
            report_error(&error);
            match error {
                piko_txn::Error::HookAborted { .. } => {}
                // The user requested this stop, so it is not reported as a breakage. The
                // journal is left in place. The lock is released just below.
                piko_txn::Error::Cancelled { .. } => eprintln!(
                    "Note: the steps that ran are recorded; \
                     run `piko report` to see them, then re-run to finish"
                ),
                _ => eprintln!(
                    "Error: the transaction stopped part-way; \
                     run `piko report` to see what was applied"
                ),
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
/// `crate::progress`). This function only covers what settles once the final
/// [`piko_txn::Report`] is in hand. That is truncation, failure, a hook file that did not parse,
/// or a hook skipped for an unsatisfied `Depends`.
///
/// Failures are printed but do not change the exit code, because they do not change the outcome.
/// libalpm discards a scriptlet's status entirely. And a hook only stops a transaction through
/// `AbortOnFail`, which arrives as an error rather than through here.
fn report_side_effects(report: &piko_txn::Report) {
    for run in &report.scriptlets {
        if run.outcome.truncated {
            eprintln!("Warning: {}'s scriptlet output was truncated", run.package);
        }
        if !run.outcome.succeeded() {
            eprintln!(
                "Warning: {}'s {} scriptlet {}",
                run.package,
                run.kind.as_str(),
                run.outcome.describe()
            );
        }
    }

    // A broken hook file is a warning, not an error, matching libalpm for the
    // `PostTransaction` case. It diverges for `PreTransaction`, where libalpm refuses the whole
    // run (`hook.c:625`). A file that did not parse has no `When`, so there is no phase to
    // attribute it to. piko reports and continues either way.
    //
    // Printed after the run, not before it, because the hook files are read once per phase
    // inside the transaction. That is the same reason every other hook diagnostic here is late.
    for problem in &report.hook_problems {
        eprintln!("Warning: {problem}");
    }

    // Neither record can fail a transaction, so a problem with one arrives here rather than
    // as an error. See `piko_txn::history`.
    for problem in &report.history_problems {
        eprintln!("Warning: {problem}");
    }

    // A backup file that could not be preserved is a warning about that file. The package it
    // belonged to is gone either way, so failing the transaction over it would report a
    // completed removal as a broken one.
    for problem in &report.backup_problems {
        eprintln!("Warning: {problem}");
    }

    // One place decides what a hook's failure is called. So this warning and the `AbortOnFail`
    // refusal name the same cause the same way.
    for run in &report.hooks {
        if run.outcome.as_ref().is_some_and(|outcome| outcome.truncated) {
            eprintln!("Warning: hook {}'s output was truncated", run.name);
        }
        if !run.succeeded() {
            eprintln!("Warning: hook {} {}", run.name, run.failure_reason());
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

/// Reports an unfinished transaction, if the database records one, and the commands that
/// finish it.
///
/// Read-only. It describes; it does not repair. There is nothing to roll back to. See the
/// note on atomicity in [`piko_txn::journal`]. What is left to do is decided by
/// [`journal::Record::recovery`]. This function only spells it as command lines.
///
/// `dbpath_flag` is the `--dbpath` the user gave, if any. The commands repeat it, so they act
/// on the database this report read.
pub fn report(
    dbpath: &Path,
    dbpath_flag: Option<&Path>,
    out: &mut impl std::io::Write,
) -> ExitCode {
    // `join` normalizes a `dbpath` the caller spelled with a trailing separator, which a
    // formatted "{dbpath}/piko-journal" would print as a doubled slash.
    let journal_path = dbpath.join(journal::JOURNAL_FILE);
    let record = match journal::read(dbpath) {
        Ok(Some(record)) => record,
        Ok(None) => {
            emit!(out, "No unfinished transaction is recorded");
            return ExitCode::SUCCESS;
        }
        Err(piko_txn::Error::JournalUnreadable { reason, .. }) => {
            // The journal is there, so a previous run did not finish. What it did is unknown,
            // so no command can finish it. Removing the journal is the only way to run a
            // transaction again, and only the user can decide that it is safe.
            emit!(out, "An unfinished transaction is recorded, but its journal cannot be read");
            emit!(out, "  Journal: {}", journal_path.display());
            emit!(out, "  Reason:  {reason}");
            emit!(out, "");
            emit!(out, "piko refuses every transaction while the journal is there. The system");
            emit!(out, "can be partly changed. Read the journal, and check the packages it names.");
            emit!(out, "Then remove it:");
            emit!(out, "  rm {}", shell_word(&journal_path.to_string_lossy()));
            return ExitCode::FAILURE;
        }
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    if !record.begun {
        emit!(out, "A transaction was recorded but never started; the system is unchanged");
        emit!(out, "Remove the journal to clear it:");
        emit!(out, "  rm {}", shell_word(&journal_path.to_string_lossy()));
        return ExitCode::SUCCESS;
    }

    emit!(out, "An unfinished transaction was interrupted");
    emit!(out, "  Root:   {}", record.root.display());
    emit!(out, "  DBPath: {}", record.dbpath.display());
    emit!(out, "  {} of {} steps completed", record.completed.len(), record.steps.len());

    let outstanding = record.outstanding();
    if outstanding.is_empty() {
        emit!(out, "Every step completed; only the journal itself was left behind");
    } else {
        emit!(out, "Not applied:");
        for intent in outstanding {
            match intent {
                Intent::Install { package, .. } => emit!(out, "  Install {package}"),
                Intent::Remove { entry } => emit!(out, "  Remove {entry}"),
            }
        }
    }

    emit!(out, "");
    let local = match LocalDatabase::open(dbpath.join("local")) {
        Ok(local) => local,
        Err(error) => {
            // Without the database, piko cannot tell which removals are still to do. The
            // journal can still go, and the operation can be run again by hand.
            report_error(&error);
            emit!(out, "The applied steps cannot be undone. Remove the journal:");
            emit!(out, "  rm {}", shell_word(&journal_path.to_string_lossy()));
            emit!(out, "Then run the operation again");
            return ExitCode::FAILURE;
        }
    };
    let recovery = record.recovery(&local);

    emit!(out, "The applied steps cannot be undone. To finish the transaction, run in order:");
    for command in recovery_commands(&recovery, &record.root, dbpath_flag, &journal_path) {
        emit!(out, "  {command}");
    }
    if recovery.interrupted.is_some() {
        emit!(out, "");
        emit!(out, "The interruption can have cut the first install part-way. Then some of its");
        emit!(out, "files are on disk with no package that owns them. `--overwrite '*'` applies");
        emit!(out, "to that package only, and lets it replace them.");
    }
    if !recovery.unreadable.is_empty() {
        emit!(out, "");
        emit!(out, "These steps cannot be read from the journal, and are not in the commands:");
        for step in &recovery.unreadable {
            emit!(out, "  {step}");
        }
    }
    ExitCode::SUCCESS
}

/// Spells a [`journal::Recovery`] as the command lines that carry it out, in order.
///
/// The journal goes first, because piko refuses every transaction while it is there. Then the
/// cut install, on its own so that `--overwrite` covers nothing else. Then the removals, then
/// the installs, one command per install reason.
fn recovery_commands(
    recovery: &journal::Recovery,
    root: &Path,
    dbpath_flag: Option<&Path>,
    journal_path: &Path,
) -> Vec<String> {
    let mut piko = String::from("piko");
    if let Some(dbpath) = dbpath_flag {
        piko.push_str(" --dbpath ");
        piko.push_str(&shell_word(&dbpath.to_string_lossy()));
    }
    let root_flag = if root == Path::new("/") {
        String::new()
    } else {
        format!(" --root {}", shell_word(&root.to_string_lossy()))
    };
    let names = |targets: &[&journal::Reinstall]| {
        targets.iter().map(|target| target.name.to_string()).collect::<Vec<_>>().join(" ")
    };

    let mut commands = vec![format!("rm {}", shell_word(&journal_path.to_string_lossy()))];
    if let Some(target) = &recovery.interrupted {
        commands.push(format!(
            "{piko} install{root_flag}{} --overwrite '*' {}",
            reason_flag(target.reason),
            target.name
        ));
    }
    if !recovery.remove.is_empty() {
        let names = recovery.remove.iter().map(ToString::to_string).collect::<Vec<_>>();
        commands.push(format!("{piko} remove{root_flag} --nodeps {}", names.join(" ")));
    }
    // Dependencies first, so each explicit package finds what it needs already there.
    for reason in [Some(PackageInstallReason::Depend), Some(PackageInstallReason::Explicit), None] {
        let targets =
            recovery.install.iter().filter(|target| target.reason == reason).collect::<Vec<_>>();
        if !targets.is_empty() {
            commands.push(format!(
                "{piko} install{root_flag}{} {}",
                reason_flag(reason),
                names(&targets)
            ));
        }
    }
    commands
}

/// The `piko install` flag that gives a package its install reason again.
///
/// No flag when the journal does not record the reason. A plain install then keeps the reason
/// of a package already installed, and marks a new one explicit.
const fn reason_flag(reason: Option<PackageInstallReason>) -> &'static str {
    match reason {
        Some(PackageInstallReason::Depend) => " --asdeps",
        Some(PackageInstallReason::Explicit) => " --asexplicit",
        None => "",
    }
}

/// Quotes `text` for a POSIX shell, only when it needs quoting.
///
/// A printed command is copied into a shell. A path with a space in it, unquoted, would name
/// two arguments.
fn shell_word(text: &str) -> std::borrow::Cow<'_, str> {
    let plain = !text.is_empty()
        && text.chars().all(|c| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c));
    if plain {
        std::borrow::Cow::Borrowed(text)
    } else {
        std::borrow::Cow::Owned(format!("'{}'", text.replace('\'', "'\\''")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use piko_txn::journal::{Recovery, Reinstall};

    use super::*;

    fn reinstall(name: &str, reason: Option<PackageInstallReason>) -> Reinstall {
        Reinstall { name: name.parse().unwrap(), reason }
    }

    const JOURNAL: &str = "/var/lib/pacman/piko-journal";

    /// The journal goes first, since piko refuses every transaction while it is there. The cut
    /// install is alone, so `--overwrite` covers nothing else. Dependencies install before
    /// explicit packages.
    #[test]
    fn the_commands_run_in_the_order_that_finishes_the_transaction() {
        let recovery = Recovery {
            interrupted: Some(reinstall("foo", Some(PackageInstallReason::Explicit))),
            remove: vec!["old".parse().unwrap(), "older".parse().unwrap()],
            install: vec![
                reinstall("bar", Some(PackageInstallReason::Explicit)),
                reinstall("libbar", Some(PackageInstallReason::Depend)),
                reinstall("baz", None),
            ],
            unreadable: Vec::new(),
        };

        let commands = recovery_commands(&recovery, Path::new("/"), None, Path::new(JOURNAL));
        assert_eq!(
            commands,
            [
                "rm /var/lib/pacman/piko-journal",
                "piko install --asexplicit --overwrite '*' foo",
                "piko remove --nodeps old older",
                "piko install --asdeps libbar",
                "piko install --asexplicit bar",
                "piko install baz",
            ]
        );
    }

    /// The commands act on the root and the database the transaction changed.
    #[test]
    fn the_commands_carry_the_root_and_the_dbpath() {
        let recovery = Recovery { remove: vec!["old".parse().unwrap()], ..Recovery::default() };

        let commands = recovery_commands(
            &recovery,
            Path::new("/mnt/new root"),
            Some(Path::new("/mnt/db")),
            Path::new("/mnt/db/piko-journal"),
        );
        assert_eq!(
            commands,
            [
                "rm /mnt/db/piko-journal",
                "piko --dbpath /mnt/db remove --root '/mnt/new root' --nodeps old",
            ]
        );
    }

    /// Nothing left to do: only the journal goes.
    #[test]
    fn an_empty_recovery_only_removes_the_journal() {
        let commands =
            recovery_commands(&Recovery::default(), Path::new("/"), None, Path::new(JOURNAL));
        assert_eq!(commands, ["rm /var/lib/pacman/piko-journal"]);
    }

    #[test]
    fn a_word_is_quoted_only_when_a_shell_would_split_or_expand_it() {
        assert_eq!(shell_word("/var/lib/pacman"), "/var/lib/pacman");
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("*"), "'*'");
        assert_eq!(shell_word("it's"), "'it'\\''s'");
        assert_eq!(shell_word(""), "''");
    }
}
