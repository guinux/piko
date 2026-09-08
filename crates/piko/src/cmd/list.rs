//! `piko list`: installed packages, a single repository's packages, configured repository
//! names, or the groups either side defines.
//!
//! Rendering follows the icon-column/aligned-columns/summary shape [`crate::cmd::search`]
//! established, with one addition: `--quiet` drops all of it (color, checkmark, version
//! column, summary) down to one bare name per line, for scripting. This is the `pacman -Qq`/
//! `pacman -Sql` equivalent. It also never opens a package's `desc`, matching `list`'s
//! original behavior: only the directory-name-derived name and version are read.

use std::collections::BTreeSet;
use std::process::ExitCode;

use alpm_types::PackageInstallReason;
use piko_db::LocalDatabase;
use piko_db::config::PacmanConfig;
use piko_db::repo::RepoDatabase;
use piko_db::solve::{Universe, UniverseOptions};

use crate::output::{emit, report};
use crate::style::checkmark;

/// One name/version line. Installed packages and a single repository's packages both reduce
/// to this. Only [`installed`] draws the checkmark.
struct Row {
    /// The group this row was listed under, printed as a first column. `None` for every
    /// listing that is not a group listing.
    group: Option<String>,
    name: String,
    version: String,
}

impl Row {
    /// A row with no group column.
    fn new(name: String, version: String) -> Self {
        Self { group: None, name, version }
    }
}

/// Prints every row.
///
/// In quiet mode, prints just `row.name`, one per line, nothing else — which is also what
/// `pacman -Qgq`/`-Sgq` print for a group listing. Otherwise, aligns rows into
/// group/name/version columns computed from the widest entry in `rows`; the group column is
/// left out entirely unless some row carries one. `with_icon` prefixes each line with
/// [`checkmark`], used only for installed packages, since a repository listing does not check
/// what is installed at all. A blank line and `"{rows.len()} {summary_word}"` follow.
fn print_rows(
    rows: &[Row],
    with_icon: bool,
    quiet: bool,
    summary_word: &str,
    out: &mut impl std::io::Write,
) -> ExitCode {
    if quiet {
        for row in rows {
            emit!(out, "{}", row.name);
        }
        return ExitCode::SUCCESS;
    }

    let group_width = rows.iter().filter_map(|row| row.group.as_deref()).map(str::len).max();
    let name_width = rows.iter().map(|row| row.name.len()).max().unwrap_or(0);
    let version_width = rows.iter().map(|row| row.version.len()).max().unwrap_or(0);

    for row in rows {
        let version =
            console::Style::new().cyan().apply_to(format!("{:<version_width$}", row.version));
        let group = group_width.map_or_else(String::new, |width| {
            format!("{:<width$} ", row.group.as_deref().unwrap_or(""))
        });
        if with_icon {
            emit!(out, "{} {group}{:<name_width$} {version}", checkmark(), row.name);
        } else {
            emit!(out, "{group}{:<name_width$} {version}", row.name);
        }
    }

    emit!(out, "");
    emit!(out, "{} {summary_word}", rows.len());
    ExitCode::SUCCESS
}

/// `piko list` / `piko list --installed`: every installed package.
pub fn installed(db: &LocalDatabase, quiet: bool, out: &mut impl std::io::Write) -> ExitCode {
    let rows: Vec<Row> = db
        .iter()
        .map(|package| Row::new(package.name().to_string(), package.version().to_string()))
        .collect();
    print_rows(&rows, true, quiet, "installed", out)
}

/// `piko list --repo <name>`: every package in that repository.
pub fn repo(db: &RepoDatabase, quiet: bool, out: &mut impl std::io::Write) -> ExitCode {
    let rows: Vec<Row> = db
        .iter()
        .map(|package| Row::new(package.name().to_string(), package.version().to_string()))
        .collect();
    print_rows(&rows, false, quiet, "listed", out)
}

/// `piko list -r`/`--repos`: every repository configured in `config`, one per line, in file
/// (priority) order. No database is opened.
pub fn repo_names(config: &PacmanConfig, quiet: bool, out: &mut impl std::io::Write) -> ExitCode {
    for repo in &config.repositories {
        emit!(out, "{}", repo.name);
    }
    if !quiet {
        emit!(out, "");
        emit!(out, "{} configured", config.repositories.len());
    }
    ExitCode::SUCCESS
}

/// `piko list -e`/`--explicit`: every explicitly installed package, `pacman -Qe`.
///
/// Unlike [`installed`], this forces a `desc` read per installed package to check `%REASON%`,
/// so it does not keep `list`'s directory-name-only laziness. A package whose `desc` cannot be
/// read is reported to stderr and excluded. This is the same continue-past-a-miss convention
/// [`crate::cmd::files::files_installed`] uses. The exit code is a failure only once something
/// was unreadable.
pub fn explicit(db: &LocalDatabase, quiet: bool, out: &mut impl std::io::Write) -> ExitCode {
    let mut rows = Vec::new();
    let mut ok = true;

    for package in db.iter() {
        match package.desc() {
            Ok(desc) if desc.install_reason() == PackageInstallReason::Explicit => {
                rows.push(Row::new(package.name().to_string(), package.version().to_string()));
            }
            Ok(_) => {}
            Err(error) => {
                report(&*error);
                ok = false;
            }
        }
    }

    let code = print_rows(&rows, true, quiet, "explicitly installed", out);
    if ok { code } else { ExitCode::FAILURE }
}

/// `piko list -o`/`--orphans`: every installed package pulled in only as a dependency that
/// nothing installed still requires via `%DEPENDS%`. Matches `pacman -Qdttq`. `%OPTDEPENDS%`
/// never counts; see [`piko_db::solve::orphans`].
///
/// Builds a [`Universe`] over the installed set alone, the same as `piko why` — no repository
/// is opened, since the question is only about what is already installed.
pub fn orphans(local: &LocalDatabase, quiet: bool, out: &mut impl std::io::Write) -> ExitCode {
    let universe = match Universe::build(local, [], UniverseOptions::new()) {
        Ok(universe) => universe,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    let rows: Vec<Row> = piko_db::solve::orphans(&universe)
        .into_iter()
        .filter_map(|id| universe.get(id))
        .map(|solvable| Row::new(solvable.name().to_string(), solvable.version().to_string()))
        .collect();

    print_rows(&rows, true, quiet, "orphaned", out)
}

/// `piko list -m`/`--foreign`: every installed package whose name is not found in any of
/// `repos`, `pacman -Qm`. See [`piko_db::LocalDatabase::foreign`] for the exact rule.
pub fn foreign<'a>(
    local: &'a LocalDatabase,
    repos: impl IntoIterator<Item = &'a RepoDatabase>,
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let rows: Vec<Row> = local
        .foreign(repos)
        .into_iter()
        .map(|package| Row::new(package.name().to_string(), package.version().to_string()))
        .collect();

    print_rows(&rows, true, quiet, "foreign", out)
}

/// Prints group `names`, one per line, with `list`'s summary line.
fn print_group_names(
    names: &BTreeSet<String>,
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    for name in names {
        emit!(out, "{name}");
    }
    if !quiet {
        emit!(out, "");
        emit!(out, "{} group(s)", names.len());
    }
    ExitCode::SUCCESS
}

/// Reports every name in `wanted` that `seen` does not carry, the way pacman reports a group
/// it cannot find. Returns whether every name was found.
fn report_missing_groups(wanted: &[String], seen: &BTreeSet<String>) -> bool {
    let mut ok = true;
    for name in wanted.iter().filter(|name| !seen.contains(*name)) {
        eprintln!("piko: error: group {name} was not found");
        ok = false;
    }
    ok
}

/// Whether a group listing should emit a row per member, rather than the group names alone.
const fn lists_members(names: &[String], with_members: bool) -> bool {
    with_members || !names.is_empty()
}

/// `piko list -g`/`--groups`: the groups installed packages belong to, `pacman -Qg`.
///
/// With `names` given, prints each named group's installed members. With none, prints every
/// group name at least one installed package belongs to — unless `with_members` asks for each
/// group's members as well, which is what `pacman -Qg` alone prints. A named group nothing
/// installed belongs to is reported to stderr, and makes the exit code a failure.
///
/// Forces a `desc` read per installed package, the same caveat as [`explicit`]. A package
/// whose `desc` cannot be read is reported to stderr and excluded.
pub fn groups(
    db: &LocalDatabase,
    names: &[String],
    with_members: bool,
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut ok = true;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut rows = Vec::new();
    let members = lists_members(names, with_members);

    for package in db.iter() {
        match package.desc() {
            Ok(desc) => {
                for group in desc.groups() {
                    seen.insert(group.clone());
                    if members && (names.is_empty() || names.iter().any(|name| name == group)) {
                        rows.push(Row {
                            group: Some(group.clone()),
                            name: package.name().to_string(),
                            version: package.version().to_string(),
                        });
                    }
                }
            }
            Err(error) => {
                report(&*error);
                ok = false;
            }
        }
    }

    if !members {
        let code = print_group_names(&seen, quiet, out);
        return if ok { code } else { ExitCode::FAILURE };
    }

    ok &= report_missing_groups(names, &seen);
    sort_group_rows(&mut rows);
    let code = print_rows(&rows, true, quiet, "listed", out);
    if ok { code } else { ExitCode::FAILURE }
}

/// `piko list -g --repos`/`--repo <NAME>`: the groups `repos` define, `pacman -Sg`.
///
/// The repository counterpart of [`groups`], reading the same three forms: named groups'
/// members, every group name, or — with `with_members` — every group and its members, which is
/// `pacman -Sgg`. A named group no repository defines is reported to stderr, and makes the
/// exit code a failure.
///
/// Nothing here can fail to parse: a repository package's `%GROUPS%` is one of the eagerly
/// converted fields, so this opens no deferred `desc`.
pub fn repo_groups<'a>(
    repos: impl IntoIterator<Item = &'a RepoDatabase>,
    names: &[String],
    with_members: bool,
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut rows = Vec::new();
    let members = lists_members(names, with_members);

    for db in repos {
        for package in db.iter() {
            for group in package.groups() {
                let group: &str = group.as_ref();
                seen.insert(group.to_owned());
                if members && (names.is_empty() || names.iter().any(|name| name == group)) {
                    rows.push(Row {
                        group: Some(group.to_owned()),
                        name: package.name().to_string(),
                        version: package.version().to_string(),
                    });
                }
            }
        }
    }

    if !members {
        return print_group_names(&seen, quiet, out);
    }

    let ok = report_missing_groups(names, &seen);
    sort_group_rows(&mut rows);
    let code = print_rows(&rows, false, quiet, "listed", out);
    if ok { code } else { ExitCode::FAILURE }
}

/// Orders a group listing by group, then by package name.
///
/// pacman prints its group cache in database and scan order instead. Sorting is what makes
/// `piko list -g` reproducible across two runs, and it is already how the group *names* come
/// out, since they are collected into a [`BTreeSet`].
fn sort_group_rows(rows: &mut [Row]) {
    rows.sort_by(|left, right| {
        (left.group.as_deref(), left.name.as_str())
            .cmp(&(right.group.as_deref(), right.name.as_str()))
    });
}
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use piko_db::fixture::{BuiltScenario, PackageSpec, Scenario};

    use super::*;

    /// Runs a listing and returns its exit code with its lines, styling removed and columns
    /// collapsed to single spaces.
    ///
    /// A test harness captures `print!`, never file descriptor 1, and `console` decides on
    /// color by testing that descriptor — so a suite run from a terminal styles this output
    /// and a piped one does not. The subject here is which rows come out, in which order,
    /// under which group; the colors are [`crate::style`]'s to test.
    fn lines(run: impl FnOnce(&mut Vec<u8>) -> ExitCode) -> (ExitCode, Vec<String>) {
        let mut out = Vec::new();
        let code = run(&mut out);
        let text = String::from_utf8(out).unwrap();
        let lines = console::strip_ansi_codes(&text)
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        (code, lines)
    }

    /// Two installed groups, one of them shared with a repository, and one package in neither.
    fn scenario() -> BuiltScenario {
        Scenario::new()
            .installed(PackageSpec::new("editor", "1.0.0-1").groups(["tools"]))
            .installed(PackageSpec::new("linker", "2.0.0-1").groups(["tools", "build"]))
            .installed(PackageSpec::new("lonely", "1.0.0-1"))
            .repo("core", [PackageSpec::new("editor", "3.0.0-1").groups(["tools"])])
            .build()
    }

    #[test]
    fn no_name_lists_the_group_names() {
        let scenario = scenario();
        let (code, out) = lines(|out| groups(scenario.local(), &[], false, false, out));

        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(out, ["build", "tools", "", "2 group(s)"]);
    }

    /// `pacman -Qg`'s own form: every group with its members, ordered by group then package.
    #[test]
    fn with_members_lists_every_group_and_its_members() {
        let scenario = scenario();
        let (code, out) = lines(|out| groups(scenario.local(), &[], true, false, out));

        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(
            out,
            [
                "✓ build linker 2.0.0-1",
                "✓ tools editor 1.0.0-1",
                "✓ tools linker 2.0.0-1",
                "",
                "3 listed",
            ]
        );
    }

    #[test]
    fn a_named_group_lists_only_its_own_members() {
        let scenario = scenario();
        let names = ["build".to_owned()];
        let (code, out) = lines(|out| groups(scenario.local(), &names, false, false, out));

        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(out, ["✓ build linker 2.0.0-1", "", "1 listed"]);
    }

    /// pacman reports a group it cannot find and exits non-zero. The names that *were* found
    /// are still listed.
    #[test]
    fn a_group_nothing_belongs_to_fails_without_hiding_the_others() {
        let scenario = scenario();
        let names = ["build".to_owned(), "absent".to_owned()];
        let (code, out) = lines(|out| groups(scenario.local(), &names, false, false, out));

        assert_eq!(code, ExitCode::FAILURE);
        assert_eq!(out, ["✓ build linker 2.0.0-1", "", "1 listed"]);
    }

    /// `--quiet` is one bare package name per line in every form, including the one where
    /// `pacman -Qgq` prints pairs anyway.
    #[test]
    fn quiet_prints_bare_package_names_even_with_no_group_named() {
        let scenario = scenario();
        let (code, out) = lines(|out| groups(scenario.local(), &[], true, true, out));

        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(out, ["linker", "editor", "linker"]);
    }

    /// The repository side reads the same three forms, and draws no checkmark: it never asks
    /// what is installed.
    #[test]
    fn a_repository_listing_reads_the_same_forms() {
        let scenario = scenario();
        let repos: Vec<&RepoDatabase> = scenario.repos().iter().collect();

        let (code, names) = lines(|out| repo_groups(repos.iter().copied(), &[], false, false, out));
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(names, ["tools", "", "1 group(s)"]);

        let (code, members) =
            lines(|out| repo_groups(repos.iter().copied(), &[], true, false, out));
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(members, ["tools editor 3.0.0-1", "", "1 listed"]);

        let wanted = ["build".to_owned()];
        let (code, _) = lines(|out| repo_groups(repos.iter().copied(), &wanted, false, false, out));
        assert_eq!(code, ExitCode::FAILURE, "an installed-only group is not a repository group");
    }
}
