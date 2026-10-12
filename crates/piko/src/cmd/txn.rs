//! The subcommands that can change a system: `install`, `remove` and `report`.
//!
//! # `--root`
//!
//! With no `--root`, the effective root falls back to `RootDir` from the parsed pacman.conf.
//! See `crate::context::resolve_root_dir`, the same resolution `piko check` uses.
//! `--root /` (or an omitted `--root` whose `pacman.conf` names `/`) targets the running
//! system.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use alpm_types::PackageInstallReason;
use piko_db::config::{DbUsage, RepositoryConfig, SigLevel};
use piko_db::repo::RepoDatabase;
use piko_db::resolve::IgnoreList;
use piko_db::solve::{
    Ambiguity, GroupChoice, GroupTarget, InstallPlan, InstallQuestions, NamedRemovalFailure,
    ResolutionNotes, SolvableId, Universe, UniverseOptions, plan_install,
};
use piko_db::{Limits, local::LocalDatabase};
use piko_sig::Policy;
use piko_txn::{
    CacheDirSource, PackageOrigins, PackageSource, Step, TargetKind, Transaction, TransactionPlan,
    conflict::Overwrite,
    file_target::{self, FilePolicies, Targets, Urls},
    journal::{self, Intent},
};

use crate::output::{emit, report as report_error};

/// Writes one frontend line to the transaction log, warning if it cannot be written.
///
/// The counterpart of pacman's `[PACMAN]` lines. It records what the user ran. It also records
/// the two markers a refresh and a sysupgrade put in the log before any transaction starts. A log
/// that
/// cannot be written is a warning here, for the same reason it is one inside a transaction. The
/// command the user asked for still runs. See [`piko_txn::history`].
pub fn note(recording: &piko_txn::history::Recording, message: &str) {
    if let Err(problem) = piko_txn::history::note(recording, message) {
        crate::output::warn(problem);
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
    /// `[options]`' `SigLevel`, which a repository with no `SigLevel` of its own inherits.
    ///
    /// A package resolved through a repository is checked against that repository's own
    /// `SigLevel`, which [`piko_txn::TransactionPlan::new`] resolves per candidate.
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
    /// The download sandbox `pacman.conf` configures.
    pub sandbox: piko_net::Sandbox,
    /// A signal handler already installed by an earlier step (`update`'s pre-refresh), reused
    /// instead of installing a second one. A second registration would receive every signal
    /// the first one does. `None` when nothing installed one yet. `install` installs its own,
    /// either when it fetches a package URL or, failing that, once its confirmation prompt has
    /// been answered.
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
    /// path. `piko_txn::hook::directories` explains why libalpm draws that line. Empty runs no
    /// hooks.
    pub hook_dirs: Vec<PathBuf>,
    /// Where the transaction is recorded: the `LogFile` pacman shares, and the history store
    /// beside the database. The default records nothing.
    pub recording: piko_txn::history::Recording,
}

/// What `install` resolves targets against, gathered so the entry point keeps a readable
/// signature.
pub struct Catalog<'a> {
    /// The installed set.
    pub local: &'a LocalDatabase,
    /// The configured repositories, in priority order.
    pub repos: &'a [(DbUsage, RepoDatabase)],
    /// `pacman.conf`'s `IgnorePkg`/`IgnoreGroup`.
    pub ignores: &'a IgnoreList,
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
/// own repository's configured servers before installing. See
/// [`piko_txn::TransactionPlan::source`].
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
    let loaded =
        match prepare_file_targets(targets, &cache, &catalog, &options, &mut pre_cancel, out) {
            Ok(loaded) => loaded,
            Err(code) => return code,
        };
    let file_candidates = loaded.candidates();

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

    // Every question is asked through `Prompts`, the notes printed through it too, while the
    // "Resolving dependencies" spinner is still running. The order in which they come is
    // `plan_install`'s.
    let mut questions = Prompts {
        steplist: &steplist,
        pre_cancel: &pre_cancel,
        out: &mut *out,
        noconfirm: options.noconfirm,
    };
    let planned = plan_install(
        &universe,
        &loaded.names,
        piko_db::solve::InstallOptions {
            needed: options.needed,
            sysupgrade: options.sysupgrade,
            explain: false,
        },
        &mut questions,
        &cache,
        &limits,
    );
    // `--noconfirm` takes libalpm's own `use_index = 0` for every provider question: the first
    // candidate in repository priority order. Reported rather than silent, so an unattended
    // run still says a choice was made on its behalf. Unlike `HoldPkg` and `IgnorePkg`, there
    // is no standing instruction in `pacman.conf` for that default to contradict, so it needs
    // no refusal.
    if let Ok(planned) = &planned
        && !planned.defaulted.is_empty()
    {
        steplist.suspend(|| crate::cmd::provider::report_defaults(&universe, &planned.defaulted));
    }
    crate::progress::settle_row(&steplist, out, resolving, "Resolving dependencies");
    let InstallPlan { plan: built, explicit: explicit_targets, .. } = match planned {
        Ok(planned) => planned,
        Err(failure) => {
            crate::cmd::plan::report_install_failure(&failure);
            return ExitCode::FAILURE;
        }
    };
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
    // would answer every signal twice.
    let cancel = match pre_cancel {
        Some(handoff) => handoff.cancel,
        None => crate::signal::install_cancel_handler().0,
    };
    // A second handle on the same flag. `DownloadingSource` takes the one above, and reads
    // it while a download runs. `run` reads this one once, after every download is over.
    let cancel_flag = cancel.clone();

    // The steps, and what each incoming package must be: the fields its `.PKGINFO` repeats
    // from the plan, a repository package's `%SHA256SUM%` and `%PGPSIG%`, where it is
    // downloaded from, the signature policy it is held to, and the keyring that checks it.
    // Built together, from one plan, so no install step goes without them.
    let origins = PackageOrigins {
        repos: catalog.configs,
        sig_level: options.sig_level,
        files: &loaded.files,
        gpg_dir: &options.gpg_dir,
        architectures: &options.architecture,
    };
    let plan = match TransactionPlan::new(
        &universe,
        &built,
        &explicit_targets,
        options.reasons,
        origins,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            report_error(&error);
            if matches!(error, piko_txn::Error::KeyringUnusable { .. }) {
                eprintln!(
                    "Note: set SigLevel = Never in pacman.conf to install without \
                     checking signatures"
                );
            }
            return ExitCode::FAILURE;
        }
    };

    // No row at all when nothing needs downloading. That is a removal-only plan, or one whose
    // every candidate is already in a cache directory, since `Plan::assemble` was given `cache`
    // above.
    let rig = crate::progress::download_rig(&steplist, built.download_size());
    // The named files in front of the cache, each from a private copy; see
    // `TransactionPlan::source`. It lives until `run` returns, past the commit.
    let source = match plan.source(
        cache_dirs,
        cancel,
        piko_net::Concurrency::new(options.parallel_downloads),
        options.check_space,
        options.sandbox.clone(),
        rig.sink,
    ) {
        Ok(source) => source,
        Err(error) => {
            crate::progress::clear_download_rows(rig.row, rig.head);
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };
    report_download_dir(&steplist, source.download_dir());

    let settings = Settings {
        overwrite: Overwrite::from_patterns(options.overwrite),
        scriptlets: options.side_effects.scriptlets,
        hook_dirs: options.side_effects.hook_dirs.clone(),
        patterns: options.patterns,
        recording: options.side_effects.recording.clone(),
        check_space: options.check_space,
        cancel: Some(cancel_flag),
        report_pending: !options.download_only,
        problems_shown: loaded
            .files
            .iter()
            .map(|target| target.candidate().name().to_string())
            .collect(),
    };
    if options.download_only {
        return download_only(
            &source,
            &cache,
            &plan,
            Progress { steplist: &steplist, download: rig.row, download_head: rig.head },
            out,
        );
    }
    run(
        root,
        dbpath,
        plan,
        &source,
        Progress { steplist: &steplist, download: rig.row, download_head: rig.head },
        settings,
        out,
    )
}

/// How `piko install` answers the questions a plan raises: at the terminal, or not at all
/// under `--noconfirm`.
///
/// Every line goes through `StepList::suspend`, since the "Resolving dependencies" spinner is
/// still running: an ordinary `eprintln!` would land inside the row indicatif is redrawing. A
/// prompt is also bracketed in `during_prompt`, the way the "Proceed with installation?"
/// prompt is.
struct Prompts<'a, W: std::io::Write> {
    steplist: &'a crate::progress::StepList,
    pre_cancel: &'a Option<crate::signal::Handoff>,
    out: &'a mut W,
    noconfirm: bool,
}

impl<W: std::io::Write> Prompts<'_, W> {
    /// Runs `ask` with the spinner suspended, and with Ctrl+C killing the process.
    fn prompt<T>(
        steplist: &crate::progress::StepList,
        pre_cancel: &Option<crate::signal::Handoff>,
        ask: impl FnOnce() -> T,
    ) -> T {
        steplist.suspend(|| match pre_cancel {
            Some(handoff) => handoff.mode.during_prompt(ask),
            None => ask(),
        })
    }
}

impl<W: std::io::Write> InstallQuestions for Prompts<'_, W> {
    fn resolved(&mut self, universe: &Universe<'_>, notes: &ResolutionNotes<'_>) {
        if !notes.expansions.is_empty() {
            self.steplist.suspend(|| crate::cmd::plan::print_expansions(notes.expansions));
        }
        if !notes.ignored.is_empty() {
            self.steplist.suspend(|| crate::cmd::plan::print_ignored_targets(notes.ignored));
        }
        if !notes.ignored_upgrades.is_empty() {
            self.steplist.suspend(|| {
                crate::cmd::plan::print_ignored_upgrades(universe, notes.ignored_upgrades);
            });
        }
    }

    /// `--noconfirm` takes every member without refusing, unlike `HoldPkg` and `IgnorePkg`. A
    /// group name is the command line, not a standing `pacman.conf` directive.
    fn groups(
        &mut self,
        universe: &Universe<'_>,
        groups: &[GroupTarget],
    ) -> Option<Vec<GroupChoice>> {
        if self.noconfirm {
            return None;
        }
        let out = &mut *self.out;
        Some(Self::prompt(self.steplist, self.pre_cancel, || {
            crate::cmd::group::answer(universe, groups, out)
        }))
    }

    fn asks_providers(&self) -> bool {
        !self.noconfirm
    }

    fn provider(
        &mut self,
        universe: &Universe<'_>,
        question: &Ambiguity,
        relation: &str,
    ) -> SolvableId {
        let out = &mut *self.out;
        Self::prompt(self.steplist, self.pre_cancel, || {
            crate::cmd::provider::ask(universe, question, relation, out)
        })
    }

    fn withheld(&mut self, count: usize) {
        self.steplist.suspend(|| {
            eprintln!(
                "Warning: {count} further provider question(s) not asked; the first candidate \
                 was taken"
            );
        });
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
) -> Result<Targets, ExitCode> {
    let kinds: Vec<TargetKind> = targets.iter().map(|target| piko_txn::classify(target)).collect();
    warn_about_ambiguous_targets(&kinds, catalog);

    // Only now, and only because a URL has to be fetched before the prompt. A plain
    // `piko install ./foo.pkg.tar.zst` reads a local file and installs no handler here. So
    // Ctrl+C at its prompt still kills the process by the OS's default disposition.
    if kinds.iter().any(|kind| matches!(kind, TargetKind::Url(_))) && pre_cancel.is_none() {
        let (cancel, mode) = crate::signal::install_cancel_handler();
        *pre_cancel = Some(crate::signal::Handoff { cancel, mode });
    }

    // Set when the "Fetching" line cannot be written. The error the callback returns then only
    // stops the load. Nothing has been fetched yet, so the run ends quietly.
    let mut stopped = false;
    let mut fetch = |url: &str| {
        if writeln!(out, "Fetching {}", piko_net::without_credentials(url)).is_err() {
            stopped = true;
            return Err(piko_txn::Error::Cancelled { completed: 0, total: 0 });
        }
        fetch_package_url(url, cache, options, pre_cancel)
    };
    let policies = FilePolicies {
        local: Policy::for_package(options.local_file_sig_level),
        remote: Policy::for_package(options.remote_file_sig_level),
    };
    let loaded = file_target::load_targets(
        &kinds,
        policies,
        &options.architecture,
        Urls::Fetch(&mut fetch),
        &piko_txn::extract::PackageLimits::default(),
    );
    match loaded {
        Ok(loaded) => {
            report_file_problems(&loaded);
            Ok(loaded)
        }
        Err(_) if stopped => Err(ExitCode::SUCCESS),
        Err(error) => {
            report_error(&error);
            Err(ExitCode::FAILURE)
        }
    }
}

/// Names, for each package file named, what its `.PKGINFO` holds that the install reads past.
///
/// Printed before the plan and its prompt, as libalpm warns when it loads a file. `piko plan`
/// prints the same lines, from the same [`piko_txn::file_target::FileTarget::problems`].
pub(crate) fn report_file_problems(loaded: &piko_txn::file_target::Targets) {
    for target in &loaded.files {
        report_package_problems(target.candidate().name().as_ref(), target.problems());
    }
}

/// Names what one package's `.PKGINFO` holds that the install reads past, one warning a line.
///
/// None of these refuses the package. The key and the reason are bytes the package chose, so
/// [`crate::output::warn`] escapes them.
fn report_package_problems(package: &str, problems: &[piko_txn::pkginfo::Problem]) {
    for problem in problems {
        crate::output::warn(format!("{package}: {problem}"));
    }
}

/// Downloads one package named by URL, and returns where it landed.
///
/// # Errors
///
/// Whatever [`file_target::fetch_url`] returns.
fn fetch_package_url(
    url: &str,
    cache: &CacheDirSource,
    options: &InstallOptions,
    pre_cancel: &Option<crate::signal::Handoff>,
) -> piko_txn::Result<PathBuf> {
    // A `Cancel` that no handler will ever request, for the path where no URL forced one to be
    // installed. It cannot happen, because `prepare_file_targets` installs a handler before it
    // calls this. Constructing one is cheaper than making the caller prove it.
    let cancel =
        pre_cancel.as_ref().map_or_else(piko_net::Cancel::new, |handoff| handoff.cancel.clone());
    file_target::fetch_url(
        url,
        cache,
        Policy::for_package(options.remote_file_sig_level),
        options.sandbox.clone(),
        &cancel,
        &|_| {},
    )
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
            crate::output::warn(rejected);
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
            crate::output::warn(problem);
        }
    });
}

/// Downloads every missing package `plan` installs into the cache, installing nothing.
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
    plan: &TransactionPlan,
    progress: Progress<'_>,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let total = plan.steps().iter().filter(|step| matches!(step, Step::Install { .. })).count();
    let mut driver = crate::progress::VerifyDriver::new(
        progress.steplist,
        &mut *out,
        progress.download,
        progress.download_head,
    );
    let mut checked = 0_usize;
    let result = piko_txn::download_only(source, cache, plan, |_outcome| {
        checked = checked.saturating_add(1);
        driver.handle(piko_txn::progress::VerifyEvent::SignatureChecked { index: checked, total });
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

    let local = match piko_db::local::LocalDatabase::open(dbpath.join("local")) {
        Ok(local) => local,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let steplist = crate::progress::StepList::new();
    let planned = if options.nodeps {
        named_only(&local, entries, &options, out)
    } else {
        planned(&steplist, &local, entries, &options, out)
    };
    let plan = match planned {
        Ok(plan) => plan,
        Err(code) => return code,
    };

    // `--overwrite` is install-side: a removal writes no file. A removal plan checks no
    // signature, because it installs no package. Scriptlets and hooks are not install-side.
    // `pre_remove` and `post_remove` exist, and `Operation = Remove` is a hook trigger.
    let settings = Settings {
        scriptlets: side_effects.scriptlets,
        hook_dirs: side_effects.hook_dirs.clone(),
        // `NoUpgrade` is not install-only. `should_skip_file` (`remove.c:592`) consults it
        // before deleting, so a file the user told piko never to touch survives a removal.
        patterns: options.patterns,
        recording: side_effects.recording,
        // A removal writes no file, but it does save modified configuration files.
        report_pending: true,
        ..Settings::default()
    };
    run(
        root,
        dbpath,
        plan,
        &source,
        Progress { steplist: &steplist, download: None, download_head: None },
        settings,
        out,
    )
}

/// `--nodeps`: exactly the packages named, in the order named, with nothing checked.
///
/// An explicit escape hatch, matching pacman's `-Rdd`. Which entries it names is
/// [`piko_db::solve::named_removal`]'s. There is no solved plan to show for it, since nothing
/// was checked. So this prints the plain list of names instead of a full
/// [`crate::cmd::plan::print_steps`] rendering.
fn named_only(
    local: &piko_db::local::LocalDatabase,
    entries: &[String],
    options: &RemoveOptions,
    out: &mut impl std::io::Write,
) -> Result<TransactionPlan, ExitCode> {
    let removal = match piko_db::solve::named_removal(local, entries, &piko_db::Limits::default()) {
        Ok(removal) => removal,
        Err(failure) => {
            crate::cmd::plan::report_expansion_failure(&failure);
            return Err(ExitCode::FAILURE);
        }
    };
    crate::cmd::plan::print_expansions(&removal.expansions);
    let found = match removal.outcome {
        Ok(found) => found,
        Err(NamedRemovalFailure::NotInstalled(name)) => {
            eprintln!("Error: package {name} is not installed");
            return Err(ExitCode::FAILURE);
        }
        // A failure this frontend does not know yet.
        Err(other) => {
            eprintln!("Error: {other:?}");
            return Err(ExitCode::FAILURE);
        }
    };

    // `HoldPkg` is checked here too. pacman's guard sits in `pacman_remove`, above everything
    // the flags select, so `-Rdd` is no more exempt from it than `-Rcs` is. The names are the
    // ones the database holds, not the ones typed. A target may have been given as a
    // `%PROVIDES%`-style string that is not the package's own name.
    let names: Vec<String> = found.iter().map(|entry| entry.name_str().to_owned()).collect();
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

    Ok(TransactionPlan::removal(found, options.no_save))
}

/// Plans the removal, printing what it will take away before it takes it.
///
/// The universe is built from the local database alone. A removal-only request never selects a
/// repository candidate. Requiring a sync database would also make this fail in a chroot that has
/// none. That equivalence is checked against the real database, not assumed. See
/// [`crate::cmd::removal`].
fn planned(
    steplist: &crate::progress::StepList,
    local: &piko_db::local::LocalDatabase,
    entries: &[String],
    options: &RemoveOptions,
    out: &mut impl std::io::Write,
) -> Result<TransactionPlan, ExitCode> {
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

    let transaction = match TransactionPlan::from_removal(&universe, &plan, options.no_save) {
        Ok(transaction) => transaction,
        Err(error) => {
            report_error(&error);
            if matches!(error, piko_txn::Error::NotARemoval) {
                eprintln!("Note: this is a bug; run `piko plan -R` to see the plan");
            }
            return Err(ExitCode::FAILURE);
        }
    };
    if transaction.steps().is_empty() {
        return Ok(transaction);
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

    Ok(transaction)
}

/// How a transaction is configured, apart from what it does.
#[derive(Debug, Default)]
struct Settings {
    /// Which paths are released from file-conflict detection.
    overwrite: Overwrite,
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
    recording: piko_txn::history::Recording,
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
    /// The packages whose `.PKGINFO` problems were shown before the prompt, by `pkgname`: the
    /// named files. `verify` reads every package again, and these are not named twice.
    problems_shown: Vec<String>,
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
    plan: TransactionPlan,
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
    if plan.steps().is_empty() {
        progress.clear_downloads();
        emit!(out, "Nothing to do");
        return ExitCode::SUCCESS;
    }

    let lock = match piko_db_write::DbLock::acquire(dbpath) {
        Ok(lock) => lock,
        Err(error) => {
            progress.clear_downloads();
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };

    let report_pending = settings.report_pending;
    let (code, report) = run_locked(root, dbpath, &lock, plan, source, progress, settings, out);
    // Released before the follow-up, and on every path out of `run_locked`. What is on disk is
    // already final: the `PostTransaction` hooks ran inside `commit`, and the follow-up reads
    // only the report.
    crate::cmd::release_lock(lock);
    if let Some(report) = report.filter(|_| report_pending) {
        crate::cmd::merge::report_pending(root, &report, out);
    }
    code
}

/// [`run`] once `db.lck` is held: verifies, stages and commits.
///
/// Returns the exit code, and the commit's report when the commit succeeded. The caller
/// releases the lock, whatever this returns.
#[expect(
    clippy::too_many_arguments,
    reason = "`run`'s own parameters plus the lock it took; `run` exists to release that lock \
              on every path out of this function"
)]
fn run_locked(
    root: &Path,
    dbpath: &Path,
    lock: &piko_db_write::DbLock,
    plan: TransactionPlan,
    source: &dyn PackageSource,
    progress: Progress<'_>,
    settings: Settings,
    out: &mut impl std::io::Write,
) -> (ExitCode, Option<piko_txn::Report>) {
    let total_steps = plan.steps().len();
    let planned = Transaction::from_plan(root, dbpath, plan)
        .overwrite(settings.overwrite)
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
    let verified =
        planned.verify_with_progress(lock, source, &mut |event| verify_driver.handle(event));
    verify_driver.finish();
    let verified = match verified {
        Ok(verified) => verified,
        Err(error) => {
            report_refusal(&error);
            return (ExitCode::FAILURE, None);
        }
    };
    report_space_problems(progress.steplist, verified.space_problems());
    progress.steplist.suspend(|| {
        for (package, problems) in verified.package_problems() {
            if !settings.problems_shown.iter().any(|shown| shown == package) {
                report_package_problems(package, &problems);
            }
        }
    });

    // This covers the window between verification's last read and the commit's first. It is
    // also the last point where a stop leaves nothing behind. `stage` opens the journal, and
    // a stop past it leaves that journal for `piko report`.
    //
    // This builds the error rather than printing prose of its own. One Ctrl+C then says the
    // same thing wherever it lands.
    if settings.cancel.as_ref().is_some_and(piko_net::Cancel::is_requested) {
        report_error(&piko_txn::Error::Cancelled { completed: 0, total: total_steps });
        return (ExitCode::FAILURE, None);
    }

    let staged = match verified.stage() {
        Ok(staged) => staged,
        Err(error) => {
            report_refusal(&error);
            return (ExitCode::FAILURE, None);
        }
    };

    let mut commit_driver = crate::progress::CommitDriver::new(progress.steplist, out);
    let result = staged.commit_with_progress(&mut |event| commit_driver.handle(event));
    commit_driver.finish();

    match result {
        Ok(report) => {
            report_side_effects(&report);
            (ExitCode::SUCCESS, Some(report))
        }
        Err(error) => {
            report_error(&error);
            // Asked of the disk rather than decided from the error. A commit removes its
            // journal when it stops before its first step, and only then, so no journal means
            // nothing was changed. An unreadable one counts as present.
            let journal_left = !matches!(journal::read(dbpath), Ok(None));
            if let Some(note) = stop_note(&error, journal_left) {
                eprintln!("{note}");
            }
            (ExitCode::FAILURE, None)
        }
    }
}

/// The line printed after a commit that failed, telling the user what the failure left.
///
/// `journal_left` is whether the journal is still on disk.
fn stop_note(error: &piko_txn::Error, journal_left: bool) -> Option<&'static str> {
    match error {
        // A hook that aborted the run explains itself through the error, which already
        // carries what it printed. See `Error::HookAborted`. It never leaves a journal.
        piko_txn::Error::HookAborted { .. } => None,
        _ if !journal_left => Some("Note: nothing was changed; no step of the transaction ran"),
        // The user requested this stop, so it is not reported as a breakage.
        piko_txn::Error::Cancelled { .. } => Some(
            "Note: the steps that ran are recorded; \
             run `piko report` to see them, then re-run to finish",
        ),
        _ => Some(
            "Error: the transaction stopped part-way; \
             run `piko report` to see what was applied",
        ),
    }
}

/// Reports an error that refused a transaction before it changed anything.
///
/// A journal left by a previous run is refused by `Transaction::verify`, and again by `stage`.
/// Either way the user is sent to `piko report`, which prints what that run did.
fn report_refusal(error: &piko_txn::Error) {
    report_error(error);
    if matches!(
        error,
        piko_txn::Error::UnfinishedTransaction { .. } | piko_txn::Error::JournalUnreadable { .. }
    ) {
        eprintln!("A previous transaction did not finish; run `piko report` to see it");
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
        crate::output::warn(problem);
    }

    // Neither record can fail a transaction, so a problem with one arrives here rather than
    // as an error. See `piko_txn::history`.
    for problem in &report.history_problems {
        crate::output::warn(problem);
    }

    // A backup file that could not be preserved is a warning about that file. The package it
    // belonged to is gone either way, so failing the transaction over it would report a
    // completed removal as a broken one.
    for problem in &report.backup_problems {
        crate::output::warn(problem);
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
            emit!(out, "  Reason:  {}", piko_db::printable_lines(&reason.to_string()));
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
    if !recovery.interrupted.is_empty() {
        emit!(out, "");
        emit!(out, "The interruption can have cut the first installs part-way. Then some of their");
        emit!(out, "files are on disk with no package that owns them. `--overwrite '*'` applies");
        emit!(out, "to those packages only, and lets them replace these files.");
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
/// cut installs, apart from the others so that `--overwrite` covers nothing else. Then the
/// removals, then the installs. The cut and the other installs each take one command per
/// install reason.
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
    for reason in [Some(PackageInstallReason::Depend), Some(PackageInstallReason::Explicit), None] {
        let targets = recovery
            .interrupted
            .iter()
            .filter(|target| target.reason == reason)
            .collect::<Vec<_>>();
        if !targets.is_empty() {
            commands.push(format!(
                "{piko} install{root_flag}{} --overwrite '*' {}",
                reason_flag(reason),
                names(&targets)
            ));
        }
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
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use piko_txn::journal::{Recovery, Reinstall};

    use super::*;

    fn reinstall(name: &str, reason: Option<PackageInstallReason>) -> Reinstall {
        Reinstall { name: name.parse().unwrap(), reason }
    }

    const JOURNAL: &str = "/var/lib/pacman/piko-journal";

    /// A failure that left no journal changed nothing, and says so rather than sending the
    /// user to `piko report`. One that left a journal still does.
    #[test]
    fn a_failure_without_a_journal_says_that_nothing_changed() {
        let failure = piko_txn::Error::UnusableSource {
            path: PathBuf::from("/var/cache/pacman/pkg/foo-1.0-1-x86_64.pkg.tar.zst"),
            reason: "unreadable".to_owned(),
        };
        let cancelled = piko_txn::Error::Cancelled { completed: 0, total: 2 };

        for error in [&failure, &cancelled] {
            let note = stop_note(error, false).unwrap();
            assert!(note.contains("nothing was changed"), "{note}");
            assert!(!note.contains("piko report"), "{note}");
        }
        assert!(stop_note(&failure, true).unwrap().contains("stopped part-way"));
        assert!(stop_note(&cancelled, true).unwrap().contains("steps that ran are recorded"));
    }

    /// The journal goes first, since piko refuses every transaction while it is there. The cut
    /// installs are apart, so `--overwrite` covers nothing else. Dependencies install before
    /// explicit packages.
    #[test]
    fn the_commands_run_in_the_order_that_finishes_the_transaction() {
        let recovery = Recovery {
            interrupted: vec![
                reinstall("foo", Some(PackageInstallReason::Explicit)),
                reinstall("libfoo", Some(PackageInstallReason::Depend)),
                reinstall("qux", Some(PackageInstallReason::Explicit)),
            ],
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
                "piko install --asdeps --overwrite '*' libfoo",
                "piko install --asexplicit --overwrite '*' foo qux",
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
