//! `piko search`: installed packages, configured repositories, or both together.
//!
//! The three modes ([`installed`], [`repos_only`], [`merged`]) all rank hits identically
//! ([`piko_db::search::MatchKind`]). What differs is which database or databases are read.
//! [`merged`] also drops a repository hit for an already-installed package rather than showing
//! it twice. See [`piko_db::search::hide_installed`].
//!
//! Rendering follows the same visual language `cmd::plan` and `progress` already establish for
//! the rest of the CLI. That is a colored icon, name/version columns aligned across the whole
//! listing, and a one-line summary at the end. See [`Row`] and [`print_rows`]. `--quiet` opts
//! out of all of it, down to one bare name per line, matching [`crate::cmd::list`]'s `--quiet`.
//!
//! A search that finds nothing exits non-zero, as `pacman -Ss` and `-Qs` do, so a script can
//! test for a match by the exit code alone. A search whose every term is blank is refused
//! before any database is opened ([`all_blank`]).

use std::process::ExitCode;

use piko_db::repo::RepoDatabase;
use piko_db::{local::LocalDatabase, search::hide_installed};

use crate::output::{emit, escaped};
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
    /// `%DESC%`, escaped by [`escaped`]. A mirror or a package chose it.
    description: String,
    installed: bool,
}

/// Whether every term in `terms` is blank, which the search drops.
///
/// Such a search has no term left to match, and `piko_db`'s search answers nothing for it rather
/// than everything. Answering nothing would read as "no package matches", so the caller refuses
/// it instead. `pacman -Ss ''` lists every package; `piko search` never lists every package from
/// a term that says nothing.
pub fn all_blank(terms: &[String]) -> bool {
    terms.iter().all(|term| term.trim().is_empty())
}

/// Prints every row, and returns failure when there is none.
///
/// In quiet mode, prints just `row.name`, one per line, nothing else: no icon, no repository
/// prefix, no version, no description, no summary. Otherwise, aligns rows into name/version
/// columns computed from the widest entry in `rows`, followed by a one-line summary. That
/// summary reads `"N found"`, or `"N found · M installed"` once `installed_count` is `Some`
/// and distinguishes them. A search restricted to `--installed` passes `None`, since every row
/// is installed there and the clause would be redundant.
///
/// No row prints `0 found`, or nothing in quiet mode, and returns [`ExitCode::FAILURE`]: the
/// exit code `pacman -Ss` and `-Qs` give when nothing matches.
fn print_rows(
    rows: &[Row],
    installed_count: Option<usize>,
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    if rows.is_empty() {
        if !quiet {
            emit!(out, "{}", crate::i18n::tr!("search-found", count = 0usize));
        }
        return ExitCode::FAILURE;
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
            "{} · {}",
            crate::i18n::tr!("search-found", count = rows.len()),
            console::Style::new()
                .green()
                .apply_to(crate::i18n::tr!("search-installed", count = installed))
        ),
        _ => emit!(out, "{}", crate::i18n::tr!("search-found", count = rows.len())),
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
            description: package.desc().map_or_else(
                |_| crate::i18n::tr!("search-desc-unavailable"),
                |d| escaped(d.description()),
            ),
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
            |_| crate::i18n::tr!("search-desc-unparsed"),
            |d| escaped(d.description()),
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

/// `piko search --repos`: repository packages only, across every database in `dbs`, in priority
/// order.
///
/// Mirrors `pacman -Ss` searching every configured sync database. No installed status is shown:
/// this mode never opens the local database at all.
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    /// A search that finds nothing fails, as `pacman -Ss` does, and says so unless it is quiet.
    #[test]
    fn no_match_is_a_failure() {
        let mut out = Vec::new();
        assert_eq!(print_rows(&[], None, false, &mut out), ExitCode::FAILURE);
        assert_eq!(String::from_utf8(out).unwrap(), "0 found\n");

        let mut quiet = Vec::new();
        assert_eq!(print_rows(&[], None, true, &mut quiet), ExitCode::FAILURE);
        assert!(quiet.is_empty());
    }

    /// A match succeeds.
    #[test]
    fn a_match_is_a_success() {
        let row = Row {
            prefix: String::new(),
            name: "foo".to_owned(),
            version: "1.0-1".to_owned(),
            description: String::new(),
            installed: true,
        };
        let mut out = Vec::new();
        assert_eq!(print_rows(&[row], None, true, &mut out), ExitCode::SUCCESS);
        assert_eq!(String::from_utf8(out).unwrap(), "foo\n");
    }

    /// Only a search with no term left after the blank ones are dropped is refused.
    #[test]
    fn only_a_search_of_blank_terms_is_all_blank() {
        let terms = |list: &[&str]| list.iter().map(|term| (*term).to_owned()).collect::<Vec<_>>();
        assert!(all_blank(&terms(&[""])));
        assert!(all_blank(&terms(&["", " \t"])));
        assert!(!all_blank(&terms(&["", "foo"])));
    }
}
