//! `piko owns`: the installed package that owns a file, pacman's `-Qo`.
//!
//! The inverse of [`crate::cmd::files`], and its visual hierarchy is the inverse too. There the
//! path is the payload and the owning package is context, so `files` dims the name. Here the
//! owning package is the answer and the path is an echo of the question, so this dims the path.
//!
//! It continues past a target nothing owns, the same as `files` does. Each miss goes to stderr,
//! the run keeps going, and the failure comes at the end.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use piko_db::LocalDatabase;
use piko_txn::owner::Owners;

use crate::output::{emit, report};

/// The `PATH` entries, in order, for a target that holds no `/`.
///
/// This function reads them rather than [`piko_txn::owner`], so the rule stays in the library
/// and the environment stays a front-end concern. An unset `PATH` gives an empty list, which is
/// the same answer as a `PATH` holding nothing useful.
fn search_path() -> Vec<PathBuf> {
    std::env::var_os("PATH").map(|path| std::env::split_paths(&path).collect()).unwrap_or_default()
}

/// Formats the line printed for one owner: `"{path} is owned by {name} {version}"` with `path`
/// dimmed, or just `"{name}"` in `--quiet` mode.
///
/// A pure formatter, not a printer, for the reason [`crate::cmd::files`] states: [`emit`] must be
/// called from the function that owns the loop, so a broken-pipe write stops that loop.
fn owner_line(path: &str, name: impl std::fmt::Display, version: &str, quiet: bool) -> String {
    if quiet {
        format!("{name}")
    } else {
        let dim = console::Style::new().dim();
        format!("{} is owned by {name} {version}", dim.apply_to(path))
    }
}

/// `piko owns <path>...`: the installed package that owns each path.
///
/// Builds one [`Owners`] index and asks it about every target. That index reads every installed
/// package's `files` file, so a second index would pay the same cost again.
pub fn owns(
    db: &LocalDatabase,
    root: &Path,
    targets: &[String],
    quiet: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut owners = Owners::new(db);
    let search_path = search_path();
    let mut ok = true;

    for target in targets {
        let answer = match owners.query(root, target, &search_path) {
            Ok(answer) => answer,
            Err(error) => {
                report(&error);
                ok = false;
                continue;
            }
        };

        if answer.owners.is_empty() {
            // The refused target is the one the resolution settled on, not the resolved path.
            // A refusal can be the resolution itself failing, and echoing a half-resolved path
            // would name something the user did not type.
            eprintln!("Error: No package owns {}", answer.query.named);
            ok = false;
            continue;
        }

        for name in &answer.owners {
            let version = db
                .get_str(name)
                .map_or_else(|| "?".to_owned(), |package| package.version().to_string());
            emit!(out, "{}", owner_line(&answer.query.resolved, name, &version, quiet));
        }
    }

    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
