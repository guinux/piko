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

/// Writes the numbered provider list under its header.
fn print_providers(
    out: &mut impl Write,
    universe: &Universe<'_>,
    relation: &str,
    providers: &[SolvableId],
) -> std::io::Result<()> {
    let header = crate::i18n::tr!("provider-header", count = providers.len(), relation = relation);
    writeln!(out, ":: {header}")?;
    crate::cmd::write_candidates(out, universe, providers)
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
    let prompt = format!("{} ", crate::i18n::tr!("provider-prompt"));
    let index = output::select(out, &prompt, question.providers.len(), 0);
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
    crate::i18n::print_note!("provider-defaults", count = report.found().len());
    for ambiguity in report.found() {
        let taken = ambiguity
            .providers
            .first()
            .map_or_else(|| "?".to_owned(), |id| crate::cmd::candidate_name(universe, *id));
        let line = crate::i18n::tr!(
            "provider-default",
            package = crate::cmd::candidate_name(universe, ambiguity.dependent),
            relation = relation_of(universe, ambiguity),
            taken = taken,
            sample = crate::cmd::candidate_sample(universe, &ambiguity.providers)
        );
        eprintln!("  {line}");
    }
    if report.dropped() > 0 {
        eprintln!("  {}", crate::i18n::tr!("cli-requirements-not-shown", count = report.dropped()));
    }
}
