//! `piko list`: installed packages, a single repository's packages, or configured repository
//! names.
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
    name: String,
    version: String,
}

/// Prints every row.
///
/// In quiet mode, prints just `row.name`, one per line, nothing else. Otherwise, aligns rows
/// into name/version columns computed from the widest entry in `rows`. `with_icon` prefixes
/// each line with [`checkmark`], used only for installed packages, since a repository listing
/// does not check what is installed at all. A blank line and `"{rows.len()} {summary_word}"`
/// follow.
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

    let name_width = rows.iter().map(|row| row.name.len()).max().unwrap_or(0);
    let version_width = rows.iter().map(|row| row.version.len()).max().unwrap_or(0);

    for row in rows {
        let version =
            console::Style::new().cyan().apply_to(format!("{:<version_width$}", row.version));
        if with_icon {
            emit!(out, "{} {:<name_width$} {version}", checkmark(), row.name);
        } else {
            emit!(out, "{:<name_width$} {version}", row.name);
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
        .map(|package| Row {
            name: package.name().to_string(),
            version: package.version().to_string(),
        })
        .collect();
    print_rows(&rows, true, quiet, "installed", out)
}

/// `piko list --repo <name>`: every package in that repository.
pub fn repo(db: &RepoDatabase, quiet: bool, out: &mut impl std::io::Write) -> ExitCode {
    let rows: Vec<Row> = db
        .iter()
        .map(|package| Row {
            name: package.name().to_string(),
            version: package.version().to_string(),
        })
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
                rows.push(Row {
                    name: package.name().to_string(),
                    version: package.version().to_string(),
                });
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
        .map(|solvable| Row {
            name: solvable.name().to_string(),
            version: solvable.version().to_string(),
        })
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
        .map(|package| Row {
            name: package.name().to_string(),
            version: package.version().to_string(),
        })
        .collect();

    print_rows(&rows, true, quiet, "foreign", out)
}

/// `piko list -g`/`--groups`: installed packages belonging to one of `names`, `pacman -Qg
/// <name>...`. With `names` empty, this instead lists every group name at least one installed
/// package belongs to, `pacman -Qg` with no argument.
///
/// Forces a `desc` read per installed package, the same caveat as [`explicit`]. A package
/// whose `desc` cannot be read is reported to stderr and excluded. The exit code is a failure
/// only once something was unreadable.
pub fn groups(
    db: &LocalDatabase,
    names: &[String],
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut ok = true;

    if names.is_empty() {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for package in db.iter() {
            match package.desc() {
                Ok(desc) => seen.extend(desc.groups().iter().map(String::as_str)),
                Err(error) => {
                    report(&*error);
                    ok = false;
                }
            }
        }

        for name in &seen {
            emit!(out, "{name}");
        }
        if !quiet {
            emit!(out, "");
            emit!(out, "{} group(s)", seen.len());
        }
        return if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    }

    let mut rows = Vec::new();
    for package in db.iter() {
        match package.desc() {
            Ok(desc) => {
                if desc.groups().iter().any(|group| names.iter().any(|name| group == name)) {
                    rows.push(Row {
                        name: package.name().to_string(),
                        version: package.version().to_string(),
                    });
                }
            }
            Err(error) => {
                report(&*error);
                ok = false;
            }
        }
    }

    let code = print_rows(&rows, true, quiet, "listed", out);
    if ok { code } else { ExitCode::FAILURE }
}
