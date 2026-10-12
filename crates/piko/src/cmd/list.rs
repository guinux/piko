//! `piko list`: installed packages, a single repository's packages, configured repository
//! names, or the groups either side defines.
//!
//! Rendering follows the icon-column/aligned-columns/summary shape [`crate::cmd::search`]
//! establishes, with one addition. `--quiet` drops all of it down to one bare name per line,
//! for scripting. No color, no checkmark, no version column, no summary. This is the
//! `pacman -Qq`/`pacman -Sql` equivalent. It also opens no package's `desc`. Only the
//! directory-name-derived name and version are read.

use std::process::ExitCode;

use alpm_types::PackageInstallReason;
use piko_db::config::PacmanConfig;
use piko_db::groups::GroupIndex;
use piko_db::local::LocalDatabase;
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
/// In quiet mode, prints just `row.name`, one per line, and nothing else. That is also what
/// `pacman -Qgq`/`-Sgq` print for a group listing. Otherwise, it aligns rows into
/// group/name/version columns computed from the widest entry in `rows`. The group column is
/// left out entirely unless some row carries one. `with_icon` prefixes each line with
/// [`checkmark`]. That serves installed packages only, since a repository listing does not
/// check what is installed at all. A blank line and `"{rows.len()} {summary_word}"` follow.
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
/// (priority) order.
///
/// No database is opened.
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
/// Unlike [`installed`], this reads each installed package's `desc` to check `%REASON%`, so it
/// does not keep `list`'s directory-name-only laziness. It reads the eager tier
/// ([`piko_db::local::LocalPackage::eager`]), not the typed parse, so a `%LICENSE%` or `%PACKAGER%`
/// that does not convert cannot drop a package from the list. A package whose `desc` cannot be
/// read is reported to stderr and excluded. This is the same continue-past-a-miss convention
/// [`crate::cmd::files::files_installed`] uses. The exit code is a failure only once something
/// was unreadable.
pub fn explicit(db: &LocalDatabase, quiet: bool, out: &mut impl std::io::Write) -> ExitCode {
    let mut rows = Vec::new();
    let mut ok = true;

    for package in db.iter() {
        match package.eager() {
            Ok(eager) if eager.install_reason() == PackageInstallReason::Explicit => {
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

/// `piko list -o`/`--orphans`: every installed package pulled in only as a dependency that nothing
/// installed still requires via `%DEPENDS%`.
///
/// Matches `pacman -Qdttq`. `%OPTDEPENDS%` never counts; see [`piko_db::solve::orphans`].
///
/// Builds a [`Universe`] over the installed set alone, the same as `piko why`. No repository
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

/// `piko list -m`/`--foreign`: every installed package whose name is not found in any of `repos`,
/// `pacman -Qm`.
///
/// See [`piko_db::local::LocalDatabase::foreign`] for the exact rule.
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
fn print_group_names<'a>(
    names: impl Iterator<Item = &'a str>,
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut count = 0_usize;
    for name in names {
        emit!(out, "{}", piko_db::printable(name));
        count = count.saturating_add(1);
    }
    if !quiet {
        emit!(out, "");
        emit!(out, "{count} group(s)");
    }
    ExitCode::SUCCESS
}

/// Reports every name in `missing` the way pacman reports a group it cannot find. Returns
/// whether nothing was missing.
fn report_missing_groups(missing: &[&str]) -> bool {
    for name in missing {
        eprintln!("Error: group {name} was not found");
    }
    missing.is_empty()
}

/// Whether a group listing should emit a row per member, rather than the group names alone.
const fn lists_members(names: &[String], with_members: bool) -> bool {
    with_members || !names.is_empty()
}

/// Prints a group listing from `index`: the group names alone, or a row per member of each
/// group `names` asks for. `describe` gives a member's name and version.
fn print_groups<P>(
    index: &GroupIndex<'_, P>,
    names: &[String],
    with_members: bool,
    with_icon: bool,
    quiet: bool,
    describe: impl Fn(&P) -> (String, String),
    out: &mut impl std::io::Write,
) -> ExitCode {
    if !lists_members(names, with_members) {
        return print_group_names(index.names(), quiet, out);
    }

    let ok = report_missing_groups(&index.missing(names));
    let rows: Vec<Row> = index
        .members(names)
        .map(|(group, member)| {
            let (name, version) = describe(member);
            Row { group: Some(piko_db::printable(group)), name, version }
        })
        .collect();
    let code = print_rows(&rows, with_icon, quiet, "listed", out);
    if ok { code } else { ExitCode::FAILURE }
}

/// `piko list -g`/`--groups`: the groups installed packages belong to, `pacman -Qg`.
///
/// With `names` given, prints each named group's installed members. With none, prints every
/// group name at least one installed package belongs to. The exception is `with_members`,
/// which asks for each group's members as well, and is what `pacman -Qg` alone prints. A named
/// group nothing installed belongs to is reported to stderr, and makes the exit code a failure.
///
/// The index is [`piko_db::groups::local_group_index`]. It reads each installed package's eager
/// tier, the same caveat as [`explicit`]. A package whose `desc` cannot be read is reported to
/// stderr and excluded.
pub fn groups(
    db: &LocalDatabase,
    names: &[String],
    with_members: bool,
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let (index, unreadable) = piko_db::groups::local_group_index(db);
    for (_, error) in &unreadable {
        report(&**error);
    }
    let describe = |package: &piko_db::local::LocalPackage| {
        (package.name().to_string(), package.version().to_string())
    };
    let code = print_groups(&index, names, with_members, true, quiet, describe, out);
    if unreadable.is_empty() { code } else { ExitCode::FAILURE }
}

/// `piko list -g --repos`/`--repo <NAME>`: the groups `repos` define, `pacman -Sg`.
///
/// The repository counterpart of [`groups`], reading the same three forms. Those are named
/// groups' members, every group name, and, with `with_members`, every group and its members.
/// The last is `pacman -Sgg`. A named group no repository defines is reported to stderr, and
/// makes the exit code a failure.
pub fn repo_groups<'a>(
    repos: impl IntoIterator<Item = &'a RepoDatabase>,
    names: &[String],
    with_members: bool,
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let index = piko_db::groups::repo_group_index(repos);
    let describe = |package: &piko_db::repo::RepoPackage| {
        (package.name().to_string(), package.version().to_string())
    };
    print_groups(&index, names, with_members, false, quiet, describe, out)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use piko_db::fixture::{BuiltScenario, PackageSpec, Scenario};

    use super::*;

    /// Runs a listing and returns its exit code with its lines, styling removed and columns
    /// collapsed to single spaces.
    ///
    /// A test harness captures `print!`, never file descriptor 1. `console` decides on color
    /// by testing that descriptor. So a suite run from a terminal styles this output, and a
    /// piped one does not. The subject here is which rows come out, in which order and under
    /// which group. The colors are [`crate::style`]'s to test.
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

    /// An `%ARCH%` the typed parse refuses does not drop an explicit package from `-e`.
    #[test]
    fn explicit_lists_a_package_only_the_typed_parse_refuses() {
        let db = piko_db::fixture::DbFixture::new();
        let refused =
            piko_db::fixture::MINIMAL_DESC_V1.replacen("%ARCH%\nx86_64", "%ARCH%\nnot an arch", 1);
        db.package("foo-1.0.0-1").desc(&refused).files(piko_db::fixture::MINIMAL_FILES).build();
        let local = LocalDatabase::open(db.path()).unwrap();
        assert!(local.iter().next().unwrap().desc().is_err(), "the fixture must be refused");

        let (code, out) = lines(|out| explicit(&local, true, out));

        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(out, ["foo"]);
    }
}
