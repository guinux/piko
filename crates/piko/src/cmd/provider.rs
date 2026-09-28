//! `ALPM_QUESTION_SELECT_PROVIDER`, the part of it a library cannot do.
//!
//! Which dependencies are ambiguous, which of them are asked, and what an answer does to a
//! plan, are [`piko_db::solve::plan_install`]'s. Any frontend gets those. What is left here is
//! the asking: rendering the candidates, and reading a number.

use std::io::Write;

use piko_db::solve::{Ambiguity, AmbiguityReport, SolvableId, Universe};

use crate::output;

/// The `%DEPENDS%` entry an ambiguity is about, verbatim.
fn relation_of(universe: &Universe<'_>, ambiguity: &Ambiguity) -> String {
    crate::cmd::plan::relation_of(universe, ambiguity.dependent, ambiguity.dependency)
}

/// Writes the numbered candidate list, grouped by the repository each came from.
///
/// The grouping is pacman's. The numbering runs across the whole list rather than restarting
/// per group, because the answer indexes the list, not the group.
fn print_providers(
    out: &mut impl Write,
    universe: &Universe<'_>,
    relation: &str,
    providers: &[SolvableId],
) -> std::io::Result<()> {
    writeln!(out, ":: There are {} providers available for {relation}:", providers.len())?;

    let mut current: Option<String> = None;
    for (index, id) in providers.iter().enumerate() {
        let origin = crate::cmd::origin_label(universe, *id);
        if current.as_deref() != Some(origin.as_str()) {
            writeln!(out, ":: {origin}")?;
            current = Some(origin);
        }
        let described = universe.get(*id).map_or_else(
            || "<unknown>".to_owned(),
            |solvable| format!("{} {}", solvable.name(), solvable.version()),
        );
        // `index` is bounded by `providers.len()`, and the list is what was just counted.
        writeln!(out, "   {}) {described}", index.saturating_add(1))?;
    }
    Ok(())
}

/// Asks which provider answers `question`, the `%DEPENDS%` entry `relation`.
///
/// Which questions reach this function, and which earlier answer settles a repeated one, is
/// [`piko_db::solve::plan_install`]'s decision. This only renders the list and reads a number.
/// Nothing can be asked down a broken pipe, so libalpm's own default stands there.
pub fn ask(
    universe: &Universe<'_>,
    question: &Ambiguity,
    relation: &str,
    out: &mut impl Write,
) -> SolvableId {
    let first = question.providers.first().copied().unwrap_or(question.dependent);
    if print_providers(out, universe, relation, &question.providers).is_err() {
        return first;
    }
    let prompt = "Enter a number (default=1): ";
    let index = output::select(out, prompt, question.providers.len(), 0);
    question.providers.get(index).copied().unwrap_or(first)
}

/// Reports the questions a non-interactive run answered with libalpm's default.
///
/// `piko plan` never asks, and neither does `--noconfirm`. A preview that blocks on stdin is
/// worse than one that states its assumption. Saying so keeps the plan honest. It is one of
/// several valid plans, and `piko install` is where the choice is made.
pub fn report_defaults(universe: &Universe<'_>, report: &AmbiguityReport) {
    if report.is_empty() {
        return;
    }
    let name_of =
        |id| universe.get(id).map_or_else(|| "<unknown>".to_owned(), |s| s.name().to_string());
    eprintln!(
        "Note: {} dependency requirement(s) have several providers; the first was taken \
         (an interactive `piko install` asks which one to use)",
        report.found().len()
    );
    for ambiguity in report.found() {
        // Named rather than counted, but not all of them. `tesseract requires tessdata` has
        // 128 providers on a real system, and a note is not the prompt. The prompt lists
        // every one, because there the list is what is being answered.
        const SHOWN: usize = 5;
        let listed: Vec<String> =
            ambiguity.providers.iter().take(SHOWN).map(|id| name_of(*id)).collect();
        let rest = ambiguity.providers.len().saturating_sub(listed.len());
        let among = if rest == 0 {
            listed.join(", ")
        } else {
            format!("{}, and {rest} more", listed.join(", "))
        };
        eprintln!(
            "  {} requires {}: took {}, among {among}",
            name_of(ambiguity.dependent),
            relation_of(universe, ambiguity),
            listed.first().map_or("?", String::as_str),
        );
    }
    if report.dropped() > 0 {
        eprintln!("  {} further requirement(s) not shown", report.dropped());
    }
}
