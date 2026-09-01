//! `piko files`: the files one or more packages own.
//!
//! Uses its own `--quiet` convention, different from [`crate::cmd::list`]'s: `"{name} /{path}"`
//! normally, just `"/{path}"` in quiet mode. There is no name/version row to reduce to a bare
//! name here, so quiet instead drops the package prefix off each file line. It also uses a
//! best-effort, continue-past-a-miss style: report each missing or unreadable name to stderr,
//! keep going, and fail only at the end.

use std::process::ExitCode;

use piko_db::repo::{FileListEntry, RepoDatabase, RepoPackage};
use piko_db::{LocalDatabase, LocalOrRepo, resolve_installed_or_repo};

use crate::output::{emit, report};

/// Formats the line printed for one file: `"{name} /{path}"` with `name` dimmed, or just
/// `"/{path}"` in `--quiet` mode.
///
/// This is a pure formatter, not a printer. [`emit`] must be called directly from the function
/// that owns the loop, not from here, so a broken-pipe write error stops that loop rather than
/// only returning from this helper.
fn file_line(name: impl std::fmt::Display, path: impl std::fmt::Display, quiet: bool) -> String {
    if quiet {
        format!("/{path}")
    } else {
        format!("{} /{path}", console::Style::new().dim().apply_to(name))
    }
}

/// `piko files --installed <name>...`: the files each named installed package owns, from its
/// `files` file.
///
/// Continues past a name that is not installed, or whose `files` file cannot be read, instead
/// of stopping at the first one. Each is reported to stderr, and the exit code is a failure
/// only once something was missing or unreadable: `piko files` accepts more than one name, and
/// a typo in one of several should not hide the rest.
///
/// Unlike the repository case ([`files_repo`], [`files_installed_then_repos`]), there is no
/// batching win to be had here. [`piko_db::LocalPackage::file_list`] is a plain, cheap,
/// lazily-cached read of one package's own `files` file, not a shared archive walked once for
/// many packages the way a repository's `.files` archive is. A simple per-name loop is the
/// right amount of machinery.
pub fn files_installed(
    db: &LocalDatabase,
    names: &[String],
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut ok = true;

    for name in names {
        let Some(package) = db.get_str(name) else {
            eprintln!("piko: error: package {name} is not installed");
            ok = false;
            continue;
        };

        let paths = match package.file_list() {
            Ok(paths) => paths,
            Err(error) => {
                report(&*error);
                ok = false;
                continue;
            }
        };

        // `alpm-db` orders these as `PathBuf`s, comparing component by component. pacman
        // sorts the raw strings byte-wise, which puts `usr/share/makepkg-template` before
        // `usr/share/makepkg/...`. Re-sort so this output can be diffed against `pacman -Ql`.
        let mut sorted: Vec<_> = paths.iter().filter_map(|path| path.to_str()).collect();
        sorted.sort_unstable();

        if sorted.len() != paths.len() {
            eprintln!(
                "piko: warning: {} path(s) are not valid UTF-8 and were omitted",
                paths.len().saturating_sub(sorted.len())
            );
        }

        for path in sorted {
            emit!(out, "{}", file_line(package.name(), path, quiet));
        }
    }

    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// `piko files <name>... --repo <name>`: the files each named package owns.
///
/// Reads from a single repository database archive's `.files` sibling.
///
/// Looks every name up first, then asks for their file lists together via
/// [`RepoDatabase::file_lists`], so the `.files` archive is walked once for every package
/// found, not once per package.
pub fn files_repo(
    db: &RepoDatabase,
    names: &[String],
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut found = Vec::new();
    let mut ok = true;

    for name in names {
        match db.get_str(name) {
            Some(package) => found.push(package),
            None => {
                eprintln!("piko: error: package {name} is not in {}", db.path().display());
                ok = false;
            }
        }
    }

    for (name, result) in db.file_lists(found) {
        match result {
            Ok(paths) => {
                for path in paths {
                    emit!(out, "{}", file_line(&name, path.display(), quiet));
                }
            }
            Err(error) => {
                report(&*error);
                ok = false;
            }
        }
    }

    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// `piko files <name>...` (default source, neither `--installed` nor `--repo` given): the files
/// each named package owns.
///
/// Checks installed packages first. For any name not installed, checks `dbs`, the configured
/// repositories, in file (priority) order.
///
/// `dbs` need not hold every configured repository. The caller only opens as many as are
/// needed to resolve whichever names [`piko_db::resolve_installed_or_repo`] did not already
/// find locally, via [`crate::context::open_repos_for_packages`]. Names resolved against a
/// repository are grouped by which one, so each repository's `.files` archive is still walked
/// once for all of them, not once per package. This mirrors [`files_repo`]'s own batching. An
/// index kept alongside each name restores the overall order `names` was given in, once
/// installed and repository results are merged back together.
pub fn files_installed_then_repos(
    local: &LocalDatabase,
    dbs: &[RepoDatabase],
    names: &[String],
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut ok = true;
    let mut sources: Vec<Option<LocalOrRepo>> = Vec::with_capacity(names.len());

    for name in names {
        let source = resolve_installed_or_repo(local, dbs, name);
        if source.is_none() {
            eprintln!(
                "piko: error: package {name} is not installed and not in any configured \
                 repository"
            );
            ok = false;
        }
        sources.push(source);
    }

    let mut per_db: Vec<Vec<(usize, &RepoPackage)>> = dbs.iter().map(|_| Vec::new()).collect();
    for (index, source) in sources.iter().enumerate() {
        if let Some(LocalOrRepo::Repo(db_index, package)) = source
            && let Some(bucket) = per_db.get_mut(*db_index)
        {
            bucket.push((index, package));
        }
    }

    let mut repo_results: Vec<Option<FileListEntry>> = names.iter().map(|_| None).collect();
    for (db, bucket) in dbs.iter().zip(per_db) {
        if bucket.is_empty() {
            continue;
        }
        let (indices, packages): (Vec<usize>, Vec<&RepoPackage>) = bucket.into_iter().unzip();
        for (index, entry) in indices.into_iter().zip(db.file_lists(packages)) {
            if let Some(slot) = repo_results.get_mut(index) {
                *slot = Some(entry);
            }
        }
    }

    for (index, source) in sources.into_iter().enumerate() {
        match source {
            Some(LocalOrRepo::Local(package)) => match package.file_list() {
                Ok(paths) => {
                    // See `files_installed` for why this re-sorts.
                    let mut sorted: Vec<_> =
                        paths.iter().filter_map(|path| path.to_str()).collect();
                    sorted.sort_unstable();
                    if sorted.len() != paths.len() {
                        eprintln!(
                            "piko: warning: {} path(s) are not valid UTF-8 and were omitted",
                            paths.len().saturating_sub(sorted.len())
                        );
                    }
                    for path in sorted {
                        emit!(out, "{}", file_line(package.name(), path, quiet));
                    }
                }
                Err(error) => {
                    report(&*error);
                    ok = false;
                }
            },
            Some(LocalOrRepo::Repo(..)) => {
                let Some((name, result)) = repo_results.get_mut(index).and_then(Option::take)
                else {
                    continue;
                };
                match result {
                    Ok(paths) => {
                        for path in paths {
                            emit!(out, "{}", file_line(&name, path.display(), quiet));
                        }
                    }
                    Err(error) => {
                        report(&*error);
                        ok = false;
                    }
                }
            }
            None => {}
        }
    }

    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
