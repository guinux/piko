//! The `plan` subcommand: what a transaction would do, without doing any of it.

use std::process::ExitCode;

use piko_db::{
    Limits, LocalDatabase,
    config::DbUsage,
    repo::RepoDatabase,
    resolve::IgnoreList,
    solve::{
        Change, Encoded, Fidelity, PackageCache, Plan, PlanDiagnostic, RemovalOptions, Request,
        SolvableId, Step, TargetResolutionFailure, Universe, UniverseOptions, plan_removal,
        removal_names, resolve_targets, solve_with_removals,
    },
};

use crate::output::{emit, report};
use crate::style::ChangeKind;

/// How the step list is rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    /// One line per package: name, version, and what is happening to it.
    Full,
    /// Just the names, one per line — comparable with `pacman -Sp --print-format '%n'`.
    Names,
}

/// Which direction the transaction runs.
#[derive(Clone, Copy, Debug)]
pub enum Mode<'a> {
    /// Install or upgrade the targets, optionally alongside a full system upgrade.
    Install {
        /// Skip a target already installed at the same version.
        needed: bool,
        /// `-u`: also upgrade every installed package that a repository has moved on from.
        sysupgrade: bool,
        /// `-uu`: accept a repository version older than the installed one.
        downgrade: bool,
    },
    /// Remove the targets.
    Remove {
        /// `-s`: also remove dependencies nothing needs any more.
        recursive: bool,
        /// `-c`: remove dependents too, instead of refusing.
        cascade: bool,
        /// `pacman.conf`'s `HoldPkg`. Carried on the variant, not as a parameter of [`plan`],
        /// because it applies only to removal. pacman has no `HoldPkg` check on the sync side
        /// at all (see `src/pacman/sync.c`).
        hold_pkg: &'a [String],
    },
}

/// Prints why [`resolve_targets`] could not resolve a target.
pub(crate) fn report_target_resolution_failure(failure: &TargetResolutionFailure) {
    match failure {
        TargetResolutionFailure::InvalidDependencyString(target) => {
            eprintln!("piko: error: {target} is not a valid dependency string");
        }
        TargetResolutionFailure::NotFound(target) => {
            eprintln!(
                "piko: error: no package satisfying {target} was found in any configured \
                 repository"
            );
        }
    }
}

/// Reports why a request had no solution, re-solving once to recover the unsatisfiable core.
///
/// The failure carries the encoding rather than the core itself, so recovering it costs one
/// more (fast — the problem is already compiled) solve. Shared with `cmd::txn::install`, which
/// fails the same way `piko plan` does when the targets it was given have no valid plan.
pub(crate) fn report_unsatisfiable(universe: &Universe<'_>, encoded: Encoded, limits: &Limits) {
    eprintln!("piko: error: the requested transaction has no solution");
    for fact in encoded.explain(universe, limits) {
        eprintln!("  {fact}");
    }
}

/// Prints a plan's diagnostics: what it noticed while assembling steps, not the steps
/// themselves. Shared with `cmd::txn::install`, which assembles a plan the same way `piko
/// plan` does before turning it into commit-engine steps.
pub(crate) fn print_diagnostics(universe: &Universe<'_>, built: &Plan) {
    for diagnostic in built.diagnostics() {
        match diagnostic {
            PlanDiagnostic::DependencyCycle { package } => {
                let name = universe
                    .get(*package)
                    .map_or_else(|| "<unknown>".to_owned(), |solvable| solvable.name().to_string());
                eprintln!(
                    "piko: warning: {name} is on a dependency cycle; it may be installed \
                     before something it depends on"
                );
            }
            // `PlanDiagnostic` is `#[non_exhaustive]`. A kind added later must still be
            // shown, not silently dropped.
            other => eprintln!("piko: warning: {other:?}"),
        }
    }
    if built.diagnostics_dropped() > 0 {
        eprintln!("piko: warning: {} further problem(s) not shown", built.diagnostics_dropped());
    }
    print_divergences(universe, built);
}

/// Reports the requirements where the solver did not take libalpm's first choice.
///
/// This is not a failure. Both situations that produce a divergence still leave pacman able to
/// plan the transaction. pacman simply plans a different one, of the same size or larger, and
/// its answer depends on the order targets were named — this one does not. It is not a case
/// pacman would have failed on.
fn print_divergences(universe: &Universe<'_>, built: &Plan) {
    let Fidelity::Diverged { requirements } = built.fidelity() else { return };

    let name_of =
        |id| universe.get(id).map_or_else(|| "<unknown>".to_owned(), |s| s.name().to_string());
    eprintln!(
        "piko: note: {requirements} dependency requirement(s) were satisfied by a candidate \
         pacman would not have tried first; the plan is valid and may differ from `pacman -Sp`"
    );
    for divergence in built.divergences() {
        let relation = universe
            .get(divergence.dependent)
            .and_then(|s| s.depends().ok())
            .and_then(|depends| depends.get(divergence.dependency).map(ToString::to_string))
            .unwrap_or_else(|| "?".to_owned());
        eprintln!(
            "piko:   {} requires {relation}: took {}, pacman would have tried {}",
            name_of(divergence.dependent),
            name_of(divergence.selected),
            name_of(divergence.preferred),
        );
    }
    if built.divergences_dropped() > 0 {
        eprintln!("piko:   {} further requirement(s) not shown", built.divergences_dropped());
    }
}

/// Splits `targets` into names to resolve and package files to read.
///
/// The same classification `piko install` uses (`piko_txn::classify`), minus the one thing a
/// preview must not do: fetching a URL. `piko plan` reads nothing but what is already here.
///
/// # Errors
///
/// Returns the [`ExitCode`] to exit with, having reported the failure.
fn read_file_targets(
    targets: &[String],
    architecture: &[alpm_types::Architecture],
) -> Result<(Vec<String>, Vec<piko_txn::FileTarget>), ExitCode> {
    let limits = piko_txn::extract::PackageLimits::default();
    // A preview verifies nothing, so the policy it loads a file under is never consulted.
    // `SigLevel::default()` names that plainly rather than picking a directive that would
    // suggest otherwise.
    let policy = piko_sig::Policy::for_package(piko_db::config::SigLevel::default());

    let mut names = Vec::new();
    let mut files = Vec::new();
    for target in targets {
        match piko_txn::classify(target) {
            piko_txn::TargetKind::Name(name) => names.push(name),
            piko_txn::TargetKind::File(path) => {
                match piko_txn::file_target::load(&path, policy, &limits) {
                    Ok(loaded) => files.push(loaded),
                    Err(error) => {
                        report(&error);
                        return Err(ExitCode::FAILURE);
                    }
                }
            }
            piko_txn::TargetKind::Url(url) => {
                eprintln!(
                    "piko: error: cannot plan {url}: previewing a package URL would have to \
                     download it; use `piko install` instead"
                );
                return Err(ExitCode::FAILURE);
            }
        }
    }
    // The same two refusals `piko install` makes, in the same order. A preview that plans
    // what the install would refuse is worse than no preview: it is a wrong answer.
    if let Err(error) = piko_txn::file_target::check_duplicates(&files) {
        report(&error);
        return Err(ExitCode::FAILURE);
    }
    if let Err(error) = piko_txn::file_target::check_architecture(&files, architecture) {
        report(&error);
        return Err(ExitCode::FAILURE);
    }
    Ok((names, files))
}

/// Plans a transaction over `targets`, printing what would change.
///
/// `cache` decides only what the download size reports, not what the plan does. It is the
/// caller's `CacheDir` list, not [`NoCache`](piko_db::solve::NoCache), so `piko plan foo` and
/// `piko install foo` report the same number for the same plan. This parameter exists to
/// prevent the two commands from disagreeing.
///
/// A target naming a package **file** is read and planned exactly as `piko install` reads it,
/// so this previews a `pacman -U` too. A target naming a **URL** is refused instead: previewing
/// it would mean downloading it, and a command whose whole purpose is to change nothing must
/// not reach the network.
#[allow(
    clippy::too_many_arguments,
    reason = "each parameter names one concern the caller must decide, the same justification \
              `piko_net::Refresher::fetch_package_with_progress` carries"
)]
pub fn plan(
    local: &LocalDatabase,
    repos: &[(DbUsage, RepoDatabase)],
    ignores: IgnoreList<'_>,
    targets: &[String],
    mode: Mode<'_>,
    format: Format,
    cache: &dyn PackageCache,
    architecture: &[alpm_types::Architecture],
    out: &mut impl std::io::Write,
) -> ExitCode {
    let limits = Limits::default();
    // Not in `-R` mode: a removal names installed packages, so every target there is a name
    // and a path-shaped one is a mistake to report as "not installed" rather than to open.
    let (names, files) = if matches!(mode, Mode::Remove { .. }) {
        (targets.to_vec(), Vec::new())
    } else {
        match read_file_targets(targets, architecture) {
            Ok(split) => split,
            Err(code) => return code,
        }
    };
    let file_candidates: Vec<&piko_db::solve::FilePackage> =
        files.iter().map(piko_txn::FileTarget::candidate).collect();
    let universe = match Universe::build(
        local,
        repos.iter().map(|(usage, db)| (*usage, db)),
        UniverseOptions::new().ignores(ignores).limits(limits).files(&file_candidates),
    ) {
        Ok(universe) => universe,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    // `plan_removal` is also `piko remove`'s planner, so it lives in one place in
    // `piko_db::solve` — see there for why that sharing matters, not just for tidiness.
    // `HoldPkg` has no libalpm equivalent, so it stays a CLI concern. See `cmd::removal`.
    if let Mode::Remove { recursive, cascade, hold_pkg } = mode {
        let options = RemovalOptions { recursive, cascade };
        return match plan_removal(local, &universe, targets, options, &limits) {
            Ok(built) => {
                // `HoldPkg` guards the preview as well as the removal. pacman's check sits
                // above its `config->print` early exit, so `pacman -Rc <held> --print` refuses
                // instead of printing a plan it would never carry out.
                //
                // The `true` here is `--print`'s own doing, not an assumption. `pacman.c:1295`
                // sets `config->noconfirm = 1` for every `--print` run, and `noyes` returns its
                // preset under `noconfirm`. So a held package makes `--print` refuse
                // unconditionally, with no answer that continues. Measured:
                // `printf 'y\n' | pacman -Rc binutils --print` still exits 1, and the prompt
                // comes out on stdout. That is the tell — `question` only uses stdout when
                // `noconfirm` is set. A preview blocking on stdin would be worse anyway.
                let names = removal_names(&universe, &built);
                if !crate::cmd::removal::hold_pkg_allows(&names, hold_pkg, true, out) {
                    return ExitCode::FAILURE;
                }
                render(&universe, &built, format, out)
            }
            Err(failure) => {
                crate::cmd::removal::report(&failure);
                ExitCode::FAILURE
            }
        };
    }

    let request = Request::new().needed(matches!(mode, Mode::Install { needed: true, .. }));
    let mut request = match resolve_targets(&universe, request, &names) {
        Ok(request) => request,
        Err(failure) => {
            report_target_resolution_failure(&failure);
            return ExitCode::FAILURE;
        }
    };
    // Targeted by id, for the reason `cmd::txn::install` gives: a name would find whichever
    // candidate the universe prefers rather than the file that was named.
    let file_ids = universe.file_candidates();
    if file_ids.len() != files.len() {
        eprintln!("piko: internal error: the universe lost a package file candidate");
        return ExitCode::FAILURE;
    }
    for id in file_ids {
        request = request.target(id);
    }

    // `-Su`: everything the repositories have moved on from becomes a target too. Each
    // `%REPLACES%` pair becomes a target plus the removal it displaces.
    if let Mode::Install { sysupgrade: true, downgrade, .. } = mode {
        request = request.with_sysupgrade(&universe, downgrade);
    }

    let planned = match solve_with_removals(&universe, &request, &limits) {
        Ok(Ok(planned)) => planned,
        Ok(Err(encoded)) => {
            report_unsatisfiable(&universe, encoded, &limits);
            return ExitCode::FAILURE;
        }
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    let built = Plan::assemble(&universe, &planned, request.targets(), &limits, cache);
    render(&universe, &built, format, out)
}

/// Prints a plan's diagnostics and steps.
///
/// Shared by the install and removal paths, so the two render identically. `--names` is the
/// verification hook for both (`pacman -Sp --print-format '%n'` and `pacman -R --print`). A
/// difference in how they print would show up as a false diff against the oracle.
fn render(
    universe: &Universe<'_>,
    built: &Plan,
    format: Format,
    out: &mut impl std::io::Write,
) -> ExitCode {
    print_diagnostics(universe, built);
    print_steps(universe, built, format, out)
}

/// The kind a [`Change`] renders as. The icon and color live in [`crate::style::ChangeKind`],
/// which `piko history` reads the same way.
const fn kind_of(change: Change) -> ChangeKind {
    match change {
        Change::Upgrade => ChangeKind::Upgrade,
        Change::Downgrade => ChangeKind::Downgrade,
        Change::Reinstall => ChangeKind::Reinstall,
    }
}

/// The word, present tense, left-padded to 9 characters.
///
/// `downgrade`/`reinstall`, the longest, need no padding; the rest line up under them. No word
/// here is shortened to fit. The tense is this command's own: a plan says what *will* happen.
/// `piko history` pads its own past-tense set to its own width.
const fn verb(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Install => "install  ",
        ChangeKind::Upgrade => "upgrade  ",
        ChangeKind::Downgrade => "downgrade",
        ChangeKind::Reinstall => "reinstall",
        ChangeKind::Remove => "remove   ",
    }
}

/// The bare word, for the summary tally ("N to install", "M to upgrade", …).
const fn name(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Install => "install",
        ChangeKind::Upgrade => "upgrade",
        ChangeKind::Downgrade => "downgrade",
        ChangeKind::Reinstall => "reinstall",
        ChangeKind::Remove => "remove",
    }
}

/// The colored `"{icon} {verb}"` a line starts with.
fn prefix(kind: ChangeKind) -> console::StyledObject<String> {
    kind.prefix(self::verb(kind))
}

/// How many steps of each kind a plan has. Tallied once while [`print_steps`] prints the
/// listing, so the summary line does not walk `built.steps()` a second time.
#[derive(Default)]
struct Tally {
    install: usize,
    upgrade: usize,
    downgrade: usize,
    reinstall: usize,
    remove: usize,
}

impl Tally {
    fn bump(&mut self, kind: ChangeKind) {
        let count = match kind {
            ChangeKind::Install => &mut self.install,
            ChangeKind::Upgrade => &mut self.upgrade,
            ChangeKind::Downgrade => &mut self.downgrade,
            ChangeKind::Reinstall => &mut self.reinstall,
            ChangeKind::Remove => &mut self.remove,
        };
        *count = count.saturating_add(1);
    }

    /// Every non-zero count, in the same order [`ChangeKind`]'s variants are declared in —
    /// install,
    /// upgrade, downgrade, reinstall, remove.
    fn counted(&self) -> impl Iterator<Item = (ChangeKind, usize)> {
        [
            (ChangeKind::Install, self.install),
            (ChangeKind::Upgrade, self.upgrade),
            (ChangeKind::Downgrade, self.downgrade),
            (ChangeKind::Reinstall, self.reinstall),
            (ChangeKind::Remove, self.remove),
        ]
        .into_iter()
        .filter(|(_, count)| *count > 0)
    }
}

/// A step's package name and the version(s) that matter for it: its own version for
/// [`Step::Install`]/[`Step::Remove`], or the installed version it replaces for
/// [`Step::Change`]. Returns `<unknown>`/empty if `id` is not in `universe`. That case is
/// unreachable in practice — the plan was built from it — but `Universe::get` is fallible, so
/// this is too.
fn render_id(universe: &Universe<'_>, id: SolvableId) -> (String, String) {
    universe.get(id).map_or_else(
        || ("<unknown>".to_owned(), String::new()),
        |solvable| (solvable.name().to_string(), solvable.version().to_string()),
    )
}

/// How wide the name and (first) version columns need to be for every line in `built` to line
/// up. See [`print_steps`]. `version_width` covers [`Step::Install`]/[`Step::Remove`]'s own
/// version and [`Step::Change`]'s old version alike, since those all print in the same column.
/// A change's new version always follows right after, so padding that column consistently
/// keeps every arrow, and what follows it, aligned too.
fn column_widths(universe: &Universe<'_>, built: &Plan) -> (usize, usize) {
    let mut name_width = 0;
    let mut version_width = 0;
    for step in built.steps() {
        let (name, version) = match step {
            Step::Install { candidate, .. } => render_id(universe, *candidate),
            Step::Remove { package } => render_id(universe, *package),
            Step::Change { from, .. } => render_id(universe, *from),
        };
        name_width = name_width.max(name.len());
        version_width = version_width.max(version.len());
    }
    (name_width, version_width)
}

/// Prints a plan's steps and summary, without its diagnostics.
///
/// Split out from [`render`] so `cmd::txn`'s `install`/`remove` can show the same listing
/// before asking the user to confirm. Those paths already print diagnostics themselves; calling
/// [`render`] there would print them twice.
pub(crate) fn print_steps(
    universe: &Universe<'_>,
    built: &Plan,
    format: Format,
    out: &mut impl std::io::Write,
) -> ExitCode {
    // Only `Format::Full` lines up into columns. `Format::Names` does not need the widths, so
    // the pass that computes them is skipped for it.
    let (name_width, version_width) =
        if format == Format::Full { column_widths(universe, built) } else { (0, 0) };

    let mut tally = Tally::default();
    for step in built.steps() {
        let render = |id| render_id(universe, id);
        match format {
            Format::Names => match step {
                // For an install this is what `pacman -Sp` prints. For a removal it is what
                // `pacman -R --print` prints. Each is that subcommand's own oracle.
                Step::Install { candidate, .. } => emit!(out, "{}", render(*candidate).0),
                Step::Change { to, .. } => emit!(out, "{}", render(*to).0),
                Step::Remove { package } => emit!(out, "{}", render(*package).0),
            },
            Format::Full => match step {
                Step::Remove { package } => {
                    let (name, version) = render(*package);
                    let kind = ChangeKind::Remove;
                    tally.bump(kind);
                    emit!(
                        out,
                        "{} {name:name_width$} {}",
                        prefix(kind),
                        // Padded before styling, not after. A `StyledObject` writes its ANSI
                        // codes straight through `write!`, not `Formatter::pad`. So an outer
                        // `{:width$}` around a styled value pads the wrong thing, or silently
                        // does not pad at all. Padding the plain string first is always correct.
                        kind.style().apply_to(format!("{version:<version_width$}"))
                    );
                }
                Step::Install { candidate, .. } => {
                    let (name, version) = render(*candidate);
                    let kind = ChangeKind::Install;
                    tally.bump(kind);
                    emit!(
                        out,
                        "{} {name:name_width$} {}",
                        prefix(kind),
                        kind.style().apply_to(format!("{version:<version_width$}"))
                    );
                }
                Step::Change { from, to, kind } => {
                    let (name, new) = render(*to);
                    let (_, old) = render(*from);
                    let kind = kind_of(*kind);
                    tally.bump(kind);
                    emit!(
                        out,
                        "{} {name:name_width$} {} -> {}",
                        prefix(kind),
                        console::style(format!("{old:<version_width$}")).dim(),
                        kind.style().apply_to(new)
                    );
                }
            },
        }
    }

    if format == Format::Full {
        emit!(out, "");
        let counts = tally
            .counted()
            .map(|(kind, count)| {
                kind.style().apply_to(format!("{count} to {}", name(kind))).to_string()
            })
            .collect::<Vec<_>>()
            .join(", ");
        // The download clause is dropped entirely when nothing has to be fetched, instead of
        // printed as "0 B". `Plan::assemble` receives the caller's cache directories, so a
        // zero here is a fact about this machine: every candidate is already downloaded.
        // Announcing a transfer of nothing made piko look like it re-fetched what it already
        // had.
        let download = if built.download_size() == 0 {
            String::new()
        } else {
            format!(" — {} to download", crate::output::human_size(built.download_size()))
        };
        emit!(
            out,
            "{counts}{download} — {} installed size",
            signed_size(built.installed_size_delta())
        );
    }

    ExitCode::SUCCESS
}

/// Renders a signed byte count, so a transaction that frees space reads as such. Colored to
/// match: green for a net decrease, amber for a net increase. These are the same tones
/// [`ChangeKind::style`] uses for a removal-flavored and an install-flavored number.
fn signed_size(delta: i64) -> console::StyledObject<String> {
    if delta < 0 {
        console::Style::new()
            .green()
            .apply_to(format!("-{}", crate::output::human_size(delta.unsigned_abs())))
    } else {
        console::Style::new()
            .yellow()
            .apply_to(format!("+{}", crate::output::human_size(delta.unsigned_abs())))
    }
}
