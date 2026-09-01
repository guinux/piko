//! The `why` subcommand: what keeps a package installed.
//!
//! The graph walk itself lives in [`piko_db::solve::explain_why_installed`]. It is a pure
//! question over the installed set, with no terminal output of its own, so any frontend gets
//! the same answer `why` is verified against (`pacman -Qdttq`). This module only renders a
//! [`piko_db::solve::WhyResult`].

use std::process::ExitCode;

use piko_db::{
    LocalDatabase,
    solve::{SolvableId, Universe, UniverseOptions, WhyResult, explain_why_installed},
};

use crate::output::{emit, report};

/// Prints the shortest chain from an explicitly installed package to `target`.
pub fn why(local: &LocalDatabase, target: &str, out: &mut impl std::io::Write) -> ExitCode {
    // No repositories: this is a question about the installed set alone. Building the
    // universe over the sync databases too would cost 671 ms to answer it.
    let universe = match Universe::build(local, [], UniverseOptions::new()) {
        Ok(universe) => universe,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    let Some(result) = explain_why_installed(&universe, target) else {
        eprintln!("piko: error: package {target} is not installed");
        return ExitCode::FAILURE;
    };

    let show = |id: SolvableId| {
        universe
            .get(id)
            .map_or_else(|| "<unknown>".to_owned(), |s| format!("{} {}", s.name(), s.version()))
    };

    match result {
        WhyResult::Explicit(id) => {
            emit!(out, "{} was installed explicitly", show(id));
        }
        WhyResult::Orphan { target, direct } if direct.is_empty() => {
            emit!(
                out,
                "{} is installed as a dependency, and nothing installed requires it",
                show(target)
            );
            emit!(
                out,
                "(an orphan by hard dependencies; `piko plan -R -s` would sweep it. \
                 It may still be an optional dependency of something — `pacman -Qdt` counts \
                 those as required, `pacman -Qdtt` does not.)"
            );
        }
        WhyResult::Orphan { target, direct } => {
            emit!(out, "{} is installed as a dependency, required by:", show(target));
            for id in &direct {
                emit!(out, "  {}", show(*id));
            }
            emit!(
                out,
                "but no explicitly-installed package requires it, directly or indirectly \
                 — this whole group is orphaned"
            );
        }
        WhyResult::Chain(chain) => {
            for (depth, id) in chain.iter().enumerate() {
                let indent = "  ".repeat(depth);
                if depth == 0 {
                    emit!(out, "{}{} (explicitly installed)", indent, show(*id));
                } else {
                    emit!(out, "{}└─ requires {}", indent, show(*id));
                }
            }
        }
    }

    ExitCode::SUCCESS
}
