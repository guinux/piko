//! The `why` subcommand: what keeps a package installed.
//!
//! The graph walk itself lives in [`piko_db::solve::explain_why_installed`]. It is a pure
//! question over the installed set, with no terminal output of its own. So any frontend gets
//! the same answer `why` is verified against, which is `pacman -Qdttq`. This module only
//! renders a [`piko_db::solve::WhyResult`].

use std::process::ExitCode;

use piko_db::{
    local::LocalDatabase, solve::SolvableId, solve::Universe, solve::UniverseOptions,
    solve::WhyResult, solve::explain_why_installed,
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
        crate::i18n::print_error!("cli-not-installed", name = target.to_string());
        return ExitCode::FAILURE;
    };

    let show = |id: SolvableId| {
        universe.get(id).map_or_else(
            || crate::i18n::tr!("cli-unknown"),
            |s| format!("{} {}", s.name(), s.version()),
        )
    };

    match result {
        WhyResult::Explicit(id) => {
            emit!(out, "{}", crate::i18n::tr!("why-explicit", package = show(id)));
        }
        WhyResult::Orphan { target, direct } if direct.is_empty() => {
            emit!(out, "{}", crate::i18n::tr!("why-orphan", package = show(target)));
            emit!(out, "{}", crate::i18n::tr!("why-orphan-note"));
        }
        WhyResult::Orphan { target, direct } => {
            emit!(out, "{}", crate::i18n::tr!("why-required-by", package = show(target)));
            for id in &direct {
                emit!(out, "  {}", show(*id));
            }
            emit!(out, "{}", crate::i18n::tr!("why-group-orphaned"));
        }
        WhyResult::Chain(chain) => {
            for (depth, id) in chain.iter().enumerate() {
                let indent = "  ".repeat(depth);
                if depth == 0 {
                    emit!(
                        out,
                        "{indent}{}",
                        crate::i18n::tr!("why-chain-root", package = show(*id))
                    );
                } else {
                    emit!(
                        out,
                        "{indent}└─ {}",
                        crate::i18n::tr!("why-chain-requires", package = show(*id))
                    );
                }
            }
        }
    }

    ExitCode::SUCCESS
}
