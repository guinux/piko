//! `ALPM_QUESTION_SELECT_PROVIDER`, the part of it a library cannot do.
//!
//! Which dependencies are ambiguous, and what an answer does to a plan, are
//! [`piko_db::solve::ambiguities`] and [`piko_db::solve::Request::choose_provider`]. Any
//! frontend gets those. What is left here is asking: rendering the candidates, reading a
//! number, and deciding that `--noconfirm` and a read-only preview do not ask at all.

use std::collections::HashMap;
use std::io::Write;

use piko_db::solve::{Ambiguity, AmbiguityReport, ProviderChoice, SolvableId, Universe};

use crate::output;

/// The `%DEPENDS%` entry an ambiguity is about, verbatim.
///
/// This doubles as the question's identity. Two packages requiring the same thing are one
/// question, not two: libalpm asks once and its accumulated package list answers the rest
/// (`deps.c:816`).
fn relation_of(universe: &Universe<'_>, ambiguity: &Ambiguity) -> String {
    universe
        .get(ambiguity.dependent)
        .and_then(|solvable| solvable.depends().ok())
        .and_then(|depends| depends.get(ambiguity.dependency).map(ToString::to_string))
        .unwrap_or_else(|| "?".to_owned())
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
        let origin = origin_label(universe, *id);
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

/// Where a candidate came from, as the group heading it is listed under.
fn origin_label(universe: &Universe<'_>, id: SolvableId) -> String {
    match universe.get(id).map(|solvable| solvable.origin()) {
        Some(piko_db::solve::Origin::Repository(index)) => universe
            .repository_name(index)
            .map_or_else(|| "Repository ?".to_owned(), |name| format!("Repository {name}")),
        // Reachable: a package file named on the command line is interned as a candidate, and
        // can provide a dependency like any other (`UniverseOptions::files`).
        Some(piko_db::solve::Origin::File(_)) => "Package file".to_owned(),
        // An installed provider suppresses the question, so `ambiguities` never yields one.
        Some(piko_db::solve::Origin::Installed) | None => "Installed".to_owned(),
    }
}

/// Asks which provider answers each question in `report`, returning one answer per question.
///
/// `answered` carries the answers already given this run, keyed by the dependency's text. A
/// question whose text was answered before is applied again without being asked, which is what
/// reproduces libalpm's accumulated package list answering later occurrences silently. It also
/// collapses two dependents raising the same dependency in one round into one question.
///
/// Every question gets an answer, including the ones taken at their default, so the caller's
/// next solve cannot raise them again.
pub fn answer(
    universe: &Universe<'_>,
    report: &AmbiguityReport,
    answered: &mut HashMap<String, SolvableId>,
    out: &mut impl Write,
) -> Vec<ProviderChoice> {
    let mut choices = Vec::new();
    for ambiguity in report.found() {
        // `ambiguities` yields at least two providers, so this never skips. Written as a
        // binding rather than an index, because the lint wall forbids proving it by panicking.
        let Some(first) = ambiguity.providers.first().copied() else { continue };
        let relation = relation_of(universe, ambiguity);
        let chosen = match answered.get(&relation) {
            // Only if it can still satisfy this requirement. The same text asked of a
            // different dependent can carry a different version constraint.
            Some(previous) if ambiguity.providers.contains(previous) => *previous,
            // Nothing can be asked down a broken pipe, so libalpm's own default stands.
            _ if print_providers(out, universe, &relation, &ambiguity.providers).is_err() => first,
            _ => {
                let prompt = "Enter a number (default=1): ";
                let index = output::select(out, prompt, ambiguity.providers.len(), 0);
                ambiguity.providers.get(index).copied().unwrap_or(first)
            }
        };
        answered.insert(relation, chosen);
        choices.push(ProviderChoice {
            dependent: ambiguity.dependent,
            dependency: ambiguity.dependency,
            chosen,
        });
    }
    choices
}

/// Reports the questions a non-interactive run answered with libalpm's default.
///
/// `piko plan` never asks — a preview that blocks on stdin is worse than one that states its
/// assumption — and neither does `--noconfirm`. Saying so keeps the plan honest: it is one of
/// several valid plans, and `piko install` is where the choice is made.
pub fn report_defaults(universe: &Universe<'_>, report: &AmbiguityReport) {
    if report.is_empty() {
        return;
    }
    let name_of =
        |id| universe.get(id).map_or_else(|| "<unknown>".to_owned(), |s| s.name().to_string());
    eprintln!(
        "note: {} dependency requirement(s) have several providers; the first was taken \
         (an interactive `piko install` asks which one to use)",
        report.found().len()
    );
    for ambiguity in report.found() {
        // Named rather than counted, but not all of them: `tesseract requires tessdata` has
        // 128 providers on a real system, and a note is not the prompt. The prompt lists every
        // one, because there the list is what is being answered.
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
