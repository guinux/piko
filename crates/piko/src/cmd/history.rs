//! `piko history`: what this system's transactions did.
//!
//! Rendering only. The merge of the two records, and every filter it applies, is
//! [`piko_txn::history::read`] — a second frontend gets the same history without re-deriving
//! it.

use std::{path::Path, process::ExitCode};

use piko_txn::history::{Action, Outcome, Query, Record};

use crate::output::{emit, report as report_error};
use crate::style::checkmark;

/// What `piko history` was asked to show.
#[derive(Clone, Debug)]
pub struct Options {
    /// `--last`, or `None` for `--all`.
    pub last: Option<usize>,
    /// `--package`, repeatable.
    pub packages: Vec<String>,
    /// `--since`, as the user spelled it.
    pub since: Option<String>,
    /// `--until`, as the user spelled it.
    pub until: Option<String>,
    /// `--quiet`: one line per transaction, no per-package detail.
    pub quiet: bool,
    /// The UTC offset timestamps are rendered in, captured in `main`.
    pub offset: piko_txn::LocalOffset,
}

/// Prints the transactions the two records describe, oldest first.
pub fn history(
    log_file: &Path,
    dbpath: &Path,
    options: Options,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let (since, until) =
        match (parse_when(options.since.as_deref()), parse_when(options.until.as_deref())) {
            (Ok(since), Ok(until)) => (since, until),
            (Err(bad), _) | (_, Err(bad)) => {
                eprintln!(
                    "piko: error: {bad} is not a time this understands; use YYYY-MM-DD or \
                 YYYY-MM-DDTHH:MM:SS+ZZZZ"
                );
                return ExitCode::FAILURE;
            }
        };

    let store = piko_txn::history::store::path(dbpath);
    let query = Query { last: options.last, packages: options.packages.clone(), since, until };
    let records = match piko_txn::history::read(Some(log_file), Some(&store), &query) {
        Ok(records) => records,
        Err(problem) => {
            report_error(&problem);
            return ExitCode::FAILURE;
        }
    };

    if records.is_empty() {
        emit!(out, "no transactions recorded");
        // An empty history and an unreadable one are different answers. Naming the files it
        // read is what lets a user tell "nothing has happened" from "piko looked in the wrong
        // place".
        emit!(
            out,
            "{}",
            console::Style::new().dim().apply_to(format!(
                "read {} and {}",
                log_file.display(),
                store.display()
            ))
        );
        return unfinished_note(dbpath, out);
    }

    for record in &records {
        let code = print_record(record, &options, out);
        if code != ExitCode::SUCCESS {
            return code;
        }
    }

    emit!(out, "");
    emit!(out, "{} transaction(s)", records.len());
    unfinished_note(dbpath, out)
}

/// Prints one transaction.
///
/// Returns an [`ExitCode`] rather than nothing, following the convention
/// [`crate::style::render_list_field`] sets: `emit!` returns from its enclosing function on a
/// write failure, so a helper that writes has to hand that decision back to its caller.
fn print_record(record: &Record, options: &Options, out: &mut impl std::io::Write) -> ExitCode {
    // The same spelling the log line carries, in the same time zone, so a line here can be
    // found in `pacman.log` by searching for it.
    let when = record.started.map_or_else(
        || "unknown date".to_owned(),
        |epoch| piko_txn::history::render_timestamp(epoch, options.offset),
    );
    let (summary, scale) = headline(record);

    emit!(
        out,
        "{} {} {} {}{}",
        outcome_mark(&record.outcome),
        console::Style::new().dim().apply_to(when),
        console::Style::new().cyan().apply_to(format!("[{}]", record.tool)),
        summary,
        console::Style::new().dim().apply_to(scale),
    );

    if options.quiet {
        return ExitCode::SUCCESS;
    }

    // `--package` names what the reader is asking about, so the detail is narrowed to it. The
    // transaction is still shown whole in its first line — a package upgraded as part of a
    // 400-package `-Syu` should not print the other 399 to say so.
    let shown: Vec<&Action> = record
        .actions
        .iter()
        .filter(|action| {
            options.packages.is_empty() || options.packages.iter().any(|name| name == action.name())
        })
        .collect();

    // Padded as plain text before being colored: a `StyledObject`'s ANSI codes throw off a
    // `{:width$}` built around the colored string. Same reason `plan.rs` and `search.rs` pad
    // first.
    let verb_width = shown.iter().map(|a| a.verb().len()).max().unwrap_or(0);
    let name_width = shown.iter().map(|a| a.name().len()).max().unwrap_or(0);
    for action in shown {
        emit!(
            out,
            "    {} {} {}",
            console::Style::new().dim().apply_to(format!("{:<verb_width$}", action.verb())),
            format!("{:<name_width$}", action.name()),
            console::Style::new().dim().apply_to(versions(action)),
        );
    }

    if let Outcome::Failed { reason } = &record.outcome {
        emit!(out, "    {}", console::Style::new().red().apply_to(reason));
    }
    for path in &record.pacnew {
        emit!(out, "    {} {}", console::Style::new().yellow().apply_to("pacnew"), path.display());
    }
    for path in &record.pacsave {
        emit!(out, "    {} {}", console::Style::new().yellow().apply_to("pacsave"), path.display());
    }
    ExitCode::SUCCESS
}

/// The version column: `1.0.0-1`, or `1.0.0-1 -> 1.1.0-1` where the version changed.
fn versions(action: &Action) -> String {
    match action.previous() {
        Some(from) => format!("{from} -> {}", action.version()),
        None => action.version().to_owned(),
    }
}

/// The leading mark: a green check for a completed transaction, a red cross otherwise.
fn outcome_mark(outcome: &Outcome) -> console::StyledObject<String> {
    match outcome {
        Outcome::Completed => console::Style::new().green().apply_to(checkmark().to_string()),
        Outcome::Failed { .. } => console::Style::new().red().apply_to("✗".to_owned()),
        Outcome::Interrupted => console::Style::new().yellow().apply_to("!".to_owned()),
    }
}

/// The first line's two halves: what the transaction was, and how big it was.
///
/// The scale is separate because it is dimmed, and because it must still show when
/// `--package` has narrowed the detail below it to one line. A package upgraded as part of a
/// 400-package `-Syu` reads very differently from one upgraded on its own.
fn headline(record: &Record) -> (String, String) {
    let scale = match record.actions.len() {
        0 | 1 => String::new(),
        count => format!("({count} packages)"),
    };
    let summary = match (&record.command, record.actions.as_slice()) {
        // The command line says most, when either record held one.
        (Some(command), _) => command.clone(),
        (None, [action]) => action.log_message(),
        (None, []) => "no packages".to_owned(),
        // Nothing to say that the scale does not already say.
        (None, _) => String::new(),
    };
    let scale = if summary.is_empty() { scale } else { prefix_space(scale) };
    (summary, scale)
}

/// `text` with a leading space, or an empty string unchanged.
fn prefix_space(text: String) -> String {
    if text.is_empty() { text } else { format!(" {text}") }
}

/// Reports an unfinished transaction, if the database still records one.
///
/// Read-only, and reusing what `piko report` already reads. A history that ends just before
/// the transaction that broke the system would be missing its most useful entry.
fn unfinished_note(dbpath: &Path, out: &mut impl std::io::Write) -> ExitCode {
    match piko_txn::journal::read(dbpath) {
        Ok(Some(_)) => {
            emit!(
                out,
                "{}",
                console::Style::new()
                    .yellow()
                    .apply_to("an unfinished transaction is recorded; run `piko report` to see it")
            );
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(error) => {
            report_error(&error);
            ExitCode::FAILURE
        }
    }
}

/// Parses `--since`/`--until`: a full timestamp, or a bare `YYYY-MM-DD` meaning its midnight.
///
/// A bare date is read in UTC rather than in the local zone. The alternative is to make a
/// filter's meaning depend on where the machine is, for a flag whose whole job is to cut a
/// list roughly in half.
fn parse_when(text: Option<&str>) -> Result<Option<i64>, String> {
    let Some(text) = text else {
        return Ok(None);
    };
    let full = if text.contains('T') { text.to_owned() } else { format!("{text}T00:00:00+0000") };
    piko_txn::history::parse_timestamp(&full).map(Some).ok_or_else(|| text.to_owned())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_date_is_read_as_its_utc_midnight() {
        assert_eq!(parse_when(Some("1970-01-01")).unwrap(), Some(0));
    }

    #[test]
    fn a_full_timestamp_is_read_as_written() {
        assert_eq!(parse_when(Some("1970-01-01T02:00:00+0200")).unwrap(), Some(0));
    }

    #[test]
    fn an_unparseable_time_names_itself() {
        assert_eq!(parse_when(Some("last tuesday")), Err("last tuesday".to_owned()));
    }

    #[test]
    fn no_filter_is_no_bound() {
        assert_eq!(parse_when(None).unwrap(), None);
    }

    fn record_with(command: Option<&str>, actions: Vec<Action>) -> Record {
        Record {
            id: None,
            tool: "PIKO".to_owned(),
            started: Some(0),
            finished: Some(0),
            command: command.map(ToOwned::to_owned),
            actions,
            hooks: Vec::new(),
            pacnew: Vec::new(),
            pacsave: Vec::new(),
            outcome: Outcome::Completed,
            detailed: true,
        }
    }

    fn installed(name: &str) -> Action {
        Action::Installed { name: name.to_owned(), version: "1.0.0-1".to_owned() }
    }

    /// A transaction with no recorded command line still has to describe itself.
    #[test]
    fn a_headline_describes_a_transaction_with_no_command() {
        assert_eq!(
            headline(&record_with(None, Vec::new())),
            ("no packages".to_owned(), String::new())
        );
        assert_eq!(
            headline(&record_with(None, vec![installed("foo")])),
            ("installed foo (1.0.0-1)".to_owned(), String::new())
        );
        // The count alone; repeating it as a summary as well says the same thing twice.
        assert_eq!(
            headline(&record_with(None, vec![installed("foo"), installed("bar")])),
            (String::new(), "(2 packages)".to_owned())
        );
    }

    /// The scale must survive `--package` narrowing the detail below it, which is the case it
    /// exists for.
    #[test]
    fn a_headline_keeps_the_scale_beside_a_command_line() {
        assert_eq!(
            headline(&record_with(Some("piko update"), vec![installed("foo"), installed("bar")])),
            ("piko update".to_owned(), " (2 packages)".to_owned())
        );
    }

    #[test]
    fn a_changed_version_shows_both_sides() {
        let action = Action::Upgraded {
            name: "foo".to_owned(),
            from: "1.0.0-1".to_owned(),
            to: "1.1.0-1".to_owned(),
        };
        assert_eq!(versions(&action), "1.0.0-1 -> 1.1.0-1");
    }
}
