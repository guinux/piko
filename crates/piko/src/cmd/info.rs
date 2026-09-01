//! `piko info`: one or more packages' metadata, from the installed database, a single named
//! repository, or the installed database with a repository fallback.
//!
//! [`installed_then_repos`] resolves each name via [`piko_db::resolve_installed_or_repo`], the
//! same "installed first, then the configured repositories in file (priority) order" rule
//! [`crate::cmd::files::files_installed_then_repos`] uses. It skips that function's
//! per-repository batching, since an `info` lookup has no shared archive walk to batch, unlike
//! a `.files` read.
//!
//! More than one name prints each entry in turn, separated by a blank line. A name that
//! cannot be found, or whose `desc` cannot be read, is reported to stderr without stopping the
//! rest. This is the same continue-past-a-miss convention [`crate::cmd::files`] and
//! [`crate::cmd::check`] use for more than one name.

use std::process::ExitCode;

use piko_db::repo::RepoDatabase;
use piko_db::{LocalDatabase, LocalOrRepo, resolve_installed_or_repo};

use crate::cmd::local;
use crate::output::emit;

/// `piko info --installed <name>...`: each named package's metadata from the installed
/// database only.
pub fn installed(db: &LocalDatabase, names: &[String], out: &mut impl std::io::Write) -> ExitCode {
    let mut ok = true;

    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            emit!(out, "");
        }
        let Some(package) = db.get_str(name) else {
            eprintln!("piko: error: package {name} is not installed");
            ok = false;
            continue;
        };
        if local::info(db, package, out) != ExitCode::SUCCESS {
            ok = false;
        }
    }

    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// `piko info <name>... --repo <name>`: each named package's metadata from a single repository
/// database archive only.
pub fn repo(db: &RepoDatabase, names: &[String], out: &mut impl std::io::Write) -> ExitCode {
    let mut ok = true;

    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            emit!(out, "");
        }
        let Some(package) = db.get_str(name) else {
            eprintln!("piko: error: package {name} is not in {}", db.path().display());
            ok = false;
            continue;
        };
        if crate::cmd::repo::repo_info(db, package, out) != ExitCode::SUCCESS {
            ok = false;
        }
    }

    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// `piko info <name>...` (default source, neither `--installed` nor `--repo` given): each named
/// package's metadata.
///
/// Checks installed packages first. For any name not installed, checks `dbs`, the configured
/// repositories, in file (priority) order.
///
/// `dbs` need not hold every configured repository. The caller only opens as many as are
/// needed to resolve whichever names [`piko_db::LocalDatabase::get_str`] did not already find,
/// via [`crate::context::open_repos_for_packages`], the same as
/// [`crate::cmd::files::files_installed_then_repos`].
pub fn installed_then_repos(
    local: &LocalDatabase,
    dbs: &[RepoDatabase],
    names: &[String],
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut ok = true;

    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            emit!(out, "");
        }
        match resolve_installed_or_repo(local, dbs, name) {
            Some(LocalOrRepo::Local(package)) => {
                if self::local::info(local, package, out) != ExitCode::SUCCESS {
                    ok = false;
                }
            }
            Some(LocalOrRepo::Repo(index, package)) => {
                if let Some(db) = dbs.get(index)
                    && crate::cmd::repo::repo_info(db, package, out) != ExitCode::SUCCESS
                {
                    ok = false;
                }
            }
            None => {
                eprintln!(
                    "piko: error: package {name} is not installed and not in any configured \
                     repository"
                );
                ok = false;
            }
        }
    }

    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
