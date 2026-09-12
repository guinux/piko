//! The `plan` subcommand: what a transaction would do, without doing any of it.

use std::process::ExitCode;

use piko_db::{
    Limits, LocalDatabase,
    config::DbUsage,
    repo::RepoDatabase,
    resolve::IgnoreList,
    solve::{
        Change, Encoded, Expansion, ExpansionFailure, Fidelity, IgnoredChange, IgnoredTarget,
        IgnoredUpgrade, PackageCache, Plan, PlanDiagnostic, RemovalOptions, Request, Side,
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
            eprintln!("error: {target} is not a valid dependency string");
        }
        TargetResolutionFailure::NotFound(target) => {
            eprintln!(
                "error: no package satisfying {target} was found in any configured \
                 repository"
            );
        }
        TargetResolutionFailure::Pattern(failure) => report_expansion_failure(failure),
        // Not the same failure as `NotFound`, and saying so is the whole point: the name is
        // right, `pacman.conf` says not to touch it. pacman asks whether to install it anyway;
        // piko does not, so the message has to name the directive that has to change instead.
        TargetResolutionFailure::Ignored { target, candidates } => {
            // A pattern names a set, a literal names one thing. "satisfying" reads as the
            // dependency relation, which is the wrong relation for a glob.
            if piko_db::is_pattern(target) {
                eprintln!("error: every package matching {target} is ignored");
            } else {
                eprintln!("error: every package satisfying {target} is ignored");
            }
            for candidate in candidates {
                eprintln!("  {}-{} ({})", candidate.name, candidate.version, candidate.reason);
            }
            eprintln!(
                "note: piko never installs an ignored package; edit IgnorePkg or \
                 IgnoreGroup in pacman.conf to allow it"
            );
        }
    }
}

/// Warns about the members of a named group that `IgnorePkg`/`IgnoreGroup` left out.
///
/// libalpm's `resolvedep` prints exactly this line on its non-prompt path
/// (`"ignoring package %s-%s\n"`, `deps.c:670`). Printed before the step list, for the reason
/// `cmd::removal::hold_pkg_allows` gives: a warning under a plan is a warning nobody reads.
pub(crate) fn print_ignored_targets(ignored: &[IgnoredTarget]) {
    for target in ignored {
        eprintln!("warning: ignoring package {}-{}", target.name, target.version);
        if let Some(detail) = ignore_detail(target.name.as_ref(), &target.reason) {
            eprintln!("  {detail}");
        }
    }
}

/// How many names an expansion lists before it stops and counts the rest.
const EXPANSION_PREVIEW: usize = 20;

/// Says what each glob target selected, before the plan that acts on it.
///
/// A step list whose package set has no visible cause is a bad message. The pattern is the
/// cause, and the pattern is the one thing the list below cannot show. Printed on stderr, like
/// every other diagnostic here, so a piped step list stays machine-readable.
pub(crate) fn print_expansions(expansions: &[Expansion]) {
    for expansion in expansions {
        eprintln!("note: {} matched {}", expansion.pattern, counts(expansion));
        if !expansion.groups.is_empty() {
            eprintln!("  groups: {}", listed(&expansion.groups));
            eprintln!("  packages: {}", listed(&expansion.names));
        } else {
            eprintln!("  {}", listed(&expansion.names));
        }
    }
}

/// `"4 packages"`, or `"2 groups and 47 packages"` when a group was matched too.
fn counts(expansion: &Expansion) -> String {
    let packages = plural(expansion.names.len(), "package");
    if expansion.groups.is_empty() {
        packages
    } else {
        format!("{} and {packages}", plural(expansion.groups.len(), "group"))
    }
}

fn plural(count: usize, noun: &str) -> String {
    if count == 1 { format!("1 {noun}") } else { format!("{count} {noun}s") }
}

/// `items`, comma-separated, cut off at [`EXPANSION_PREVIEW`] entries.
fn listed(items: &[String]) -> String {
    let shown = items.iter().take(EXPANSION_PREVIEW).cloned().collect::<Vec<_>>().join(", ");
    match items.len().checked_sub(EXPANSION_PREVIEW) {
        Some(rest) if rest > 0 => format!("{shown}, and {rest} more"),
        _ => shown,
    }
}

/// Says why a glob target could not be expanded.
///
/// Shared by the install and removal sides, so one pattern gets one wording whichever command
/// refused it.
pub(crate) fn report_expansion_failure(failure: &ExpansionFailure) {
    match failure {
        ExpansionFailure::NoMatch { pattern, side: Side::Installable } => {
            eprintln!(
                "error: no package or group matching {pattern} was found in any configured \
                 repository"
            );
        }
        ExpansionFailure::NoMatch { pattern, side: Side::Installed } => {
            eprintln!("error: no installed package or group matches {pattern}");
        }
        ExpansionFailure::TooBroad { pattern, limit } => {
            eprintln!("error: {pattern} matches more than {limit} packages");
            eprintln!("note: name the packages, or narrow the pattern");
        }
        ExpansionFailure::Versioned(target) => {
            eprintln!("error: {target} is a glob pattern with a version requirement");
            eprintln!(
                "note: a pattern expands to names only; name the package to constrain its \
                 version"
            );
        }
        // Raised by the expansion, converted to `TargetResolutionFailure::Ignored` before it
        // reaches a frontend, so that a pattern and a literal report an ignored target alike.
        ExpansionFailure::AllIgnored { pattern, .. } => {
            eprintln!("error: every package matching {pattern} is ignored");
        }
    }
}

/// Warns about every change `-u` would have made had `IgnorePkg`/`IgnoreGroup` not covered
/// one of the packages involved.
///
/// The three wordings are libalpm's own (`sync.c:96`, `sync.c:106`, `sync.c:156`). Without
/// them a held-back package is indistinguishable from one the repositories have not moved on
/// from, which is the state a user consults `pacman.conf` to explain.
pub(crate) fn print_ignored_upgrades(universe: &Universe<'_>, ignored: &[IgnoredUpgrade]) {
    for entry in ignored {
        let Some(installed) = universe.get(entry.installed) else { continue };
        print_ignored_change(
            (installed.name().as_ref(), &installed.version().to_string()),
            (entry.name.as_ref(), &entry.version.to_string()),
            entry.kind,
            &entry.reason,
        );
    }
}

/// Prints one "ignoring package …" warning, in the terms libalpm prints it.
///
/// The single place any of the three wordings is written. `piko update` reaches it through
/// [`print_ignored_upgrades`], and `piko check-updates` reaches it with the same pair read
/// straight off an `Update` — a package held back is the same event whichever command noticed
/// it, so the two must not describe it in two ways. Taking plain name/version pairs rather
/// than a [`Universe`] is what lets the second caller in: `check-updates` builds no universe.
pub(crate) fn print_ignored_change(
    installed: (&str, &str),
    available: (&str, &str),
    kind: IgnoredChange,
    reason: &piko_db::resolve::IgnoreReason,
) {
    let (old_name, old_version) = installed;
    let (new_name, new_version) = available;
    match kind {
        IgnoredChange::Upgrade => eprintln!(
            "warning: {old_name}: ignoring package upgrade ({old_version} => {new_version})"
        ),
        IgnoredChange::Downgrade => eprintln!(
            "warning: {old_name}: ignoring package downgrade ({old_version} => {new_version})"
        ),
        IgnoredChange::Replacement => eprintln!(
            "warning: ignoring package replacement ({old_name}-{old_version} => \
             {new_name}-{new_version})"
        ),
    }
    if let Some(detail) = ignore_detail(old_name, reason) {
        eprintln!("  {detail}");
    }
}

/// The extra line naming *why* a package is ignored, or `None` when the reason is already
/// obvious from the message above it.
///
/// `IgnorePkg = gedit` covering `gedit` explains itself, and pacman prints nothing more. A
/// glob or a group does not: `IgnorePkg = linux*` holding back `linux-firmware` is otherwise
/// a decision with no visible cause, and the user has to guess which of several entries to
/// edit.
fn ignore_detail(name: &str, reason: &piko_db::resolve::IgnoreReason) -> Option<String> {
    match reason {
        piko_db::resolve::IgnoreReason::Package { pattern } if pattern == name => None,
        other => Some(other.to_string()),
    }
}

/// Reports why a request had no solution, re-solving once to recover the unsatisfiable core.
///
/// The failure carries the encoding rather than the core itself, so recovering it costs one
/// more (fast — the problem is already compiled) solve. Shared with `cmd::txn::install`, which
/// fails the same way `piko plan` does when the targets it was given have no valid plan.
pub(crate) fn report_unsatisfiable(universe: &Universe<'_>, encoded: Encoded, limits: &Limits) {
    eprintln!("error: the requested transaction has no solution");
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
                    "warning: {name} is on a dependency cycle; it may be installed \
                     before something it depends on"
                );
            }
            // `PlanDiagnostic` is `#[non_exhaustive]`. A kind added later must still be
            // shown, not silently dropped.
            other => eprintln!("warning: {other:?}"),
        }
    }
    if built.diagnostics_dropped() > 0 {
        eprintln!("warning: {} further problem(s) not shown", built.diagnostics_dropped());
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
        "note: {requirements} dependency requirement(s) were satisfied by a candidate \
         pacman would not have tried first; the plan is valid and may differ from `pacman -Sp`"
    );
    for divergence in built.divergences() {
        let relation = universe
            .get(divergence.dependent)
            .and_then(|s| s.depends().ok())
            .and_then(|depends| depends.get(divergence.dependency).map(ToString::to_string))
            .unwrap_or_else(|| "?".to_owned());
        eprintln!(
            "  {} requires {relation}: took {}, pacman would have tried {}",
            name_of(divergence.dependent),
            name_of(divergence.selected),
            name_of(divergence.preferred),
        );
    }
    if built.divergences_dropped() > 0 {
        eprintln!("  {} further requirement(s) not shown", built.divergences_dropped());
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
                    "error: cannot plan {url}: previewing a package URL would have to \
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
        let removal = match plan_removal(local, &universe, targets, options, &limits) {
            Ok(removal) => removal,
            Err(failure) => {
                report_expansion_failure(&failure);
                return ExitCode::FAILURE;
            }
        };
        // Before the outcome either way: a refusal names packages the user may never have
        // typed, and the pattern that pulled them in is what explains the list.
        print_expansions(&removal.expansions);
        return match removal.outcome {
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
    let resolution = match resolve_targets(&universe, request, &names, &limits) {
        Ok(resolved) => resolved,
        Err(failure) => {
            report_target_resolution_failure(&failure);
            return ExitCode::FAILURE;
        }
    };
    let mut request = resolution.request;
    print_expansions(&resolution.expansions);
    print_ignored_targets(&resolution.ignored);
    // Targeted by id, for the reason `cmd::txn::install` gives: a name would find whichever
    // candidate the universe prefers rather than the file that was named.
    let file_ids = universe.file_candidates();
    if file_ids.len() != files.len() {
        eprintln!("internal error: the universe lost a package file candidate");
        return ExitCode::FAILURE;
    }
    for id in file_ids {
        request = request.target(id);
    }

    // `-Su`: everything the repositories have moved on from becomes a target too. Each
    // `%REPLACES%` pair becomes a target plus the removal it displaces.
    if let Mode::Install { sysupgrade: true, downgrade, .. } = mode {
        request = request.with_sysupgrade(&universe, downgrade);
        print_ignored_upgrades(&universe, request.ignored_upgrades());
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

/// Which block of the listing a line belongs to, and in which order the blocks print.
///
/// This is the listing's own order, not [`ChangeKind`]'s declaration order: a reinstall
/// changes nothing on disk and leads, the two version changes stay neighbors, an install
/// follows, and a removal — the one irreversible kind — comes last. [`Tally::counted`] reads
/// the same ranking, so the summary line and the listing cannot be read in two different
/// orders. `piko history` keeps [`ChangeKind`]'s own order; it reports one transaction at a
/// time and has no blocks to sort.
const fn group_rank(kind: ChangeKind) -> u8 {
    match kind {
        ChangeKind::Reinstall => 0,
        ChangeKind::Upgrade => 1,
        ChangeKind::Downgrade => 2,
        ChangeKind::Install => 3,
        ChangeKind::Remove => 4,
    }
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

    /// Every non-zero count, in the order [`group_rank`] gives the listing's blocks —
    /// reinstall, upgrade, downgrade, install, remove.
    fn counted(&self) -> impl Iterator<Item = (ChangeKind, usize)> {
        [
            (ChangeKind::Reinstall, self.reinstall),
            (ChangeKind::Upgrade, self.upgrade),
            (ChangeKind::Downgrade, self.downgrade),
            (ChangeKind::Install, self.install),
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

/// One line of the [`Format::Full`] listing, rendered before anything is ordered or printed.
///
/// `version` is the package's own version for a [`Step::Install`]/[`Step::Remove`], and the
/// installed version being replaced for a [`Step::Change`], whose new version is `new_version`.
/// Materializing the whole listing is what lets it be grouped by [`group_rank`] and sorted by
/// name, without disturbing [`Plan::steps`] — that slice is the commit engine's execution
/// order, and removals-first / dependencies-before-dependents is a correctness invariant there
/// rather than a presentation choice.
#[derive(Debug)]
struct Row {
    kind: ChangeKind,
    name: String,
    version: String,
    new_version: Option<String>,
}

/// Every step of `built`, rendered into a [`Row`], in [`Plan::steps`] order.
fn rows(universe: &Universe<'_>, built: &Plan) -> Vec<Row> {
    built
        .steps()
        .iter()
        .map(|step| match step {
            Step::Install { candidate, .. } => {
                let (name, version) = render_id(universe, *candidate);
                Row { kind: ChangeKind::Install, name, version, new_version: None }
            }
            Step::Remove { package } => {
                let (name, version) = render_id(universe, *package);
                Row { kind: ChangeKind::Remove, name, version, new_version: None }
            }
            Step::Change { from, to, kind } => {
                let (name, new) = render_id(universe, *to);
                let (_, old) = render_id(universe, *from);
                Row { kind: kind_of(*kind), name, version: old, new_version: Some(new) }
            }
        })
        .collect()
}

/// Orders `rows` the way the listing prints them: by [`group_rank`], then by name inside each
/// block.
///
/// A long transaction is read one kind at a time — "what is being removed?" is a different
/// question from "what is being upgraded?" — and a name is what a reader looks a package up by.
/// The sort is stable, so anything the two keys tie on keeps [`Plan::steps`] order.
fn order_rows(rows: &mut [Row]) {
    rows.sort_by(|a, b| {
        group_rank(a.kind).cmp(&group_rank(b.kind)).then_with(|| a.name.cmp(&b.name))
    });
}

/// How wide the name and (first) version columns need to be for every line to line up. See
/// [`print_steps`]. `version_width` covers [`Step::Install`]/[`Step::Remove`]'s own version and
/// [`Step::Change`]'s old version alike, since those all print in the same column. A change's
/// new version always follows right after, so padding that column consistently keeps every
/// arrow, and what follows it, aligned too.
fn column_widths(rows: &[Row]) -> (usize, usize) {
    let mut name_width = 0;
    let mut version_width = 0;
    for row in rows {
        name_width = name_width.max(row.name.len());
        version_width = version_width.max(row.version.len());
    }
    (name_width, version_width)
}

/// Prints a plan's steps and summary, without its diagnostics.
///
/// Split out from [`render`] so `cmd::txn`'s `install`/`remove` can show the same listing
/// before asking the user to confirm. Those paths already print diagnostics themselves; calling
/// [`render`] there would print them twice.
///
/// [`Format::Full`] groups the listing by kind (see [`order_rows`]). [`Format::Names`] prints
/// [`Plan::steps`] order untouched: it is the oracle for `pacman -Sp --print-format '%n'` and
/// `pacman -R --print`, both of which print the transaction in the order it runs.
pub(crate) fn print_steps(
    universe: &Universe<'_>,
    built: &Plan,
    format: Format,
    out: &mut impl std::io::Write,
) -> ExitCode {
    if format == Format::Names {
        for step in built.steps() {
            // For an install this is what `pacman -Sp` prints. For a removal it is what
            // `pacman -R --print` prints. Each is that subcommand's own oracle.
            let id = match step {
                Step::Install { candidate, .. } => *candidate,
                Step::Change { to, .. } => *to,
                Step::Remove { package } => *package,
            };
            emit!(out, "{}", render_id(universe, id).0);
        }
        return ExitCode::SUCCESS;
    }

    let mut listing = rows(universe, built);
    order_rows(&mut listing);
    let (name_width, version_width) = column_widths(&listing);

    let mut tally = Tally::default();
    for Row { kind, name, version, new_version } in &listing {
        tally.bump(*kind);
        // Padded before styling, not after. A `StyledObject` writes its ANSI codes straight
        // through `write!`, not `Formatter::pad`. So an outer `{:width$}` around a styled value
        // pads the wrong thing, or silently does not pad at all. Padding the plain string first
        // is always correct.
        match new_version {
            None => emit!(
                out,
                "{} {name:name_width$} {}",
                prefix(*kind),
                kind.style().apply_to(format!("{version:<version_width$}"))
            ),
            Some(new) => emit!(
                out,
                "{} {name:name_width$} {} -> {}",
                prefix(*kind),
                console::style(format!("{version:<version_width$}")).dim(),
                kind.style().apply_to(new)
            ),
        }
    }

    emit!(out, "");
    let counts = tally
        .counted()
        .map(|(kind, count)| {
            kind.style().apply_to(format!("{count} to {}", name(kind))).to_string()
        })
        .collect::<Vec<_>>()
        .join(", ");
    // The download clause is dropped entirely when nothing has to be fetched, instead of
    // printed as "0 B". `Plan::assemble` receives the caller's cache directories, so a zero
    // here is a fact about this machine: every candidate is already downloaded. Announcing a
    // transfer of nothing made piko look like it re-fetched what it already had.
    let download = if built.download_size() == 0 {
        String::new()
    } else {
        format!(" — {} to download", crate::output::human_size(built.download_size()))
    };
    emit!(out, "{counts}{download} — {} installed size", signed_size(built.installed_size_delta()));

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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn row(kind: ChangeKind, name: &str) -> Row {
        Row { kind, name: name.to_owned(), version: "1-1".to_owned(), new_version: None }
    }

    #[test]
    fn the_listing_groups_by_kind_and_sorts_each_block_by_name() {
        // Deliberately interleaved, the way `Plan::steps` hands them over: removals first,
        // then everything else in dependency order.
        let mut rows = vec![
            row(ChangeKind::Remove, "zsh"),
            row(ChangeKind::Remove, "acl"),
            row(ChangeKind::Install, "vim"),
            row(ChangeKind::Upgrade, "bash"),
            row(ChangeKind::Install, "curl"),
            row(ChangeKind::Downgrade, "glibc"),
            row(ChangeKind::Reinstall, "pacman"),
            row(ChangeKind::Upgrade, "awk"),
            row(ChangeKind::Reinstall, "coreutils"),
        ];
        order_rows(&mut rows);

        let seen: Vec<_> = rows.iter().map(|r| (r.kind, r.name.as_str())).collect();
        assert_eq!(
            seen,
            vec![
                (ChangeKind::Reinstall, "coreutils"),
                (ChangeKind::Reinstall, "pacman"),
                (ChangeKind::Upgrade, "awk"),
                (ChangeKind::Upgrade, "bash"),
                (ChangeKind::Downgrade, "glibc"),
                (ChangeKind::Install, "curl"),
                (ChangeKind::Install, "vim"),
                (ChangeKind::Remove, "acl"),
                (ChangeKind::Remove, "zsh"),
            ]
        );
    }

    #[test]
    fn the_summary_counts_in_the_same_order_as_the_listing() {
        let tally = Tally { install: 2, upgrade: 1, downgrade: 0, reinstall: 3, remove: 4 };

        let counted: Vec<_> = tally.counted().collect();
        assert_eq!(
            counted,
            vec![
                (ChangeKind::Reinstall, 3),
                (ChangeKind::Upgrade, 1),
                (ChangeKind::Install, 2),
                (ChangeKind::Remove, 4),
            ],
            "a zero count is dropped, and the rest follow `group_rank`"
        );
    }
}
