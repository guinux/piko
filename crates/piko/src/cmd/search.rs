//! `piko search`: installed packages, configured repositories, or both together.
//!
//! The three modes ([`installed`], [`repos_only`], [`merged`]) all rank hits identically
//! ([`piko_db::search::MatchKind`]). What differs is which database(s) are read, and, in
//! [`merged`], that a repository hit for an already-installed package is dropped rather than
//! shown twice. See [`piko_db::search::hide_installed`].
//!
//! Rendering follows the same visual language `cmd::plan` and `progress` already established
//! for the rest of the CLI: a colored icon, name/version columns aligned across the whole
//! listing, and a one-line summary at the end. See [`Row`] and [`print_rows`]. `--quiet` opts
//! out of all of it, down to one bare name per line, matching [`crate::cmd::list`]'s `--quiet`.

use std::process::ExitCode;

use piko_db::repo::RepoDatabase;
use piko_db::{LocalDatabase, search::hide_installed};

use crate::output::emit;
use crate::style::checkmark;

/// One result line, already reduced to exactly what [`print_rows`] needs to render it.
///
/// The three call sites ([`installed`], [`repos_only`], [`merged`]) differ only in how a
/// [`Row`] is built, never in how it is printed.
struct Row {
    /// `"{repo}/"` for a repository hit, empty for an installed one. Installed packages are
    /// not tied to any one repository, so they carry no prefix at all.
    prefix: String,
    name: String,
    version: String,
    description: String,
    installed: bool,
}

/// Prints every row.
///
/// In quiet mode, prints just `row.name`, one per line, nothing else: no icon, no repository
/// prefix, no version, no description, no summary. Otherwise, aligns rows into name/version
/// columns computed from the widest entry in `rows`, followed by a one-line summary:
/// `"N found"`, or `"N found · M installed"` once `installed_count` is `Some` and
/// distinguishes them. A search restricted to `--installed` passes `None`, since every row is
/// installed there and the clause would be redundant.
fn print_rows(
    rows: &[Row],
    installed_count: Option<usize>,
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    if rows.is_empty() {
        return ExitCode::SUCCESS;
    }

    if quiet {
        for row in rows {
            emit!(out, "{}", row.name);
        }
        return ExitCode::SUCCESS;
    }

    let name_width =
        rows.iter().map(|row| row.prefix.len().saturating_add(row.name.len())).max().unwrap_or(0);
    let version_width = rows.iter().map(|row| row.version.len()).max().unwrap_or(0);

    for row in rows {
        let icon = if row.installed { checkmark().to_string() } else { " ".to_owned() };
        // Padded as plain text first, then split back apart to color the prefix and name
        // differently. A `StyledObject`'s ANSI codes would otherwise throw off a `{:width$}`
        // padding built around the whole colored string. This is the same reason `plan.rs`
        // pads a version before, not after, applying its color.
        let padded = format!("{:<name_width$}", format!("{}{}", row.prefix, row.name));
        let (prefix_part, name_part) = padded.split_at(row.prefix.len());
        emit!(
            out,
            "{icon} {}{name_part} {}  {}",
            console::Style::new().dim().apply_to(prefix_part),
            console::Style::new().cyan().apply_to(format!("{:<version_width$}", row.version)),
            console::Style::new().dim().apply_to(&row.description),
        );
    }

    emit!(out, "");
    match installed_count {
        Some(installed) if installed > 0 => emit!(
            out,
            "{} found · {}",
            rows.len(),
            console::Style::new().green().apply_to(format!("{installed} installed"))
        ),
        _ => emit!(out, "{} found", rows.len()),
    }
    ExitCode::SUCCESS
}

/// Every installed package matching `terms`, as [`Row`]s.
///
/// `installed` is always `true`, and there is no repository prefix, since being installed has
/// nothing to do with any one repository.
fn local_rows(db: &LocalDatabase, terms: &[String]) -> Vec<Row> {
    db.search(terms.iter().map(String::as_str))
        .into_iter()
        .map(|(package, _)| Row {
            prefix: String::new(),
            name: package.name().to_string(),
            version: package.version().to_string(),
            description: package
                .desc()
                .map_or_else(|_| "(desc unavailable)".to_owned(), |d| d.description().to_string()),
            installed: true,
        })
        .collect()
}

/// A repository search hit as a [`Row`], prefixed with `db`'s own name.
///
/// This matches `pacman -Ss`/`yay`'s `repo/name` format. It is the only way a listing
/// spanning several repositories still says which one a result came from.
fn repo_row(db: &RepoDatabase, package: &piko_db::repo::RepoPackage) -> Row {
    Row {
        prefix: format!("{}/", db.name()),
        name: package.name().to_string(),
        version: package.version().to_string(),
        // A hit whose deferred `desc` will not parse still matched on name, provides, or
        // groups, so it is still a result. Saying so beats dropping it silently.
        description: package.desc().map_or_else(
            |_| "<desc could not be parsed>".to_owned(),
            |d| d.description().to_string(),
        ),
        installed: false,
    }
}

/// Every hit `db` produces for `terms`, as [`Row`]s.
fn repo_rows(db: &RepoDatabase, terms: &[String]) -> Vec<Row> {
    db.search(terms.iter().map(String::as_str))
        .into_iter()
        .map(|(package, _)| repo_row(db, package))
        .collect()
}

/// `piko search --installed`: installed packages only.
pub fn installed(
    db: &LocalDatabase,
    terms: &[String],
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    print_rows(&local_rows(db, terms), None, quiet, out)
}

/// `piko search --repos`: repository packages only, across every database in `dbs`, in
/// priority order. Mirrors `pacman -Ss` searching every configured sync database. No
/// installed status is shown: this mode never opens the local database at all.
pub fn repos_only(
    dbs: &[RepoDatabase],
    terms: &[String],
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let rows: Vec<Row> = dbs.iter().flat_map(|db| repo_rows(db, terms)).collect();
    print_rows(&rows, None, quiet, out)
}

/// `piko search` with neither `--installed` nor `--repos`: every matching installed package,
/// then every matching repository package that is not installed.
pub fn merged(
    local: &LocalDatabase,
    repos: &[RepoDatabase],
    terms: &[String],
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut rows = local_rows(local, terms);
    let installed_count = rows.len();
    for db in repos {
        let hits = hide_installed(db.search(terms.iter().map(String::as_str)), local);
        rows.extend(hits.into_iter().map(|(package, _)| repo_row(db, package)));
    }
    print_rows(&rows, Some(installed_count), quiet, out)
}
