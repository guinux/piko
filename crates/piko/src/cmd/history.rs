//! `piko history`: what this system's transactions did.
//!
//! Rendering only. The merge of the two records, and every filter it applies, is
//! [`piko_txn::history::read`] — a second frontend gets the same history without re-deriving
//! it.

use std::{path::Path, process::ExitCode};

use piko_txn::history::{Action, Outcome, Query, Record};

use crate::output::{emit, report as report_error};
use crate::style::{ChangeKind, checkmark};

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
    let (since, until) = match (
        parse_when(options.since.as_deref(), Bound::Start),
        parse_when(options.until.as_deref(), Bound::End),
    ) {
        (Ok(since), Ok(until)) => (since, until),
        (Err(bad), _) | (_, Err(bad)) => {
            eprintln!(
                "error: {bad} is not a time this understands; use YYYY-MM-DD or \
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

    // One pass over every action that will actually print, before the first line. Widths that
    // grew block by block would make an early transaction's columns wrong once a later, wider
    // one appeared — the rule `cmd::plan::column_widths` and `cmd::search` both follow.
    let widths = Widths::over(&records, &options);
    for (index, record) in records.iter().enumerate() {
        // A block is several lines now, so the blocks need separating. Not before the first.
        if index > 0 && !options.quiet {
            emit!(out, "");
        }
        let code = print_record(record, &options, widths, out);
        if code != ExitCode::SUCCESS {
            return code;
        }
    }

    emit!(out, "");
    emit!(out, "{} transaction(s)", records.len());
    unfinished_note(dbpath, out)
}

/// How wide the verb and name columns must be for every printed line to align.
///
/// Computed over the whole listing, not per transaction. See the call site.
#[derive(Clone, Copy, Debug, Default)]
struct Widths {
    verb: usize,
    name: usize,
}

impl Widths {
    /// Measures every action that [`print_record`] will actually print.
    fn over(records: &[Record], options: &Options) -> Self {
        let mut widths = Self::default();
        if options.quiet {
            return widths;
        }
        for action in records.iter().flat_map(|record| shown_actions(record, options)) {
            widths.verb = widths.verb.max(verb(action).len());
            widths.name = widths.name.max(action.name().len());
        }
        widths
    }
}

/// The actions of `record` that the listing will show.
///
/// `--package` names what the reader is asking about, so the detail is narrowed to it. The
/// transaction is still reported whole — a package upgraded as part of a 400-package `-Syu`
/// should not print the other 399 to say so, and the header's count says how big it was.
fn shown_actions<'a>(record: &'a Record, options: &'a Options) -> impl Iterator<Item = &'a Action> {
    record.actions.iter().filter(|action| {
        options.packages.is_empty() || options.packages.iter().any(|name| name == action.name())
    })
}

/// Prints one transaction.
///
/// Returns an [`ExitCode`] rather than nothing, following the convention
/// [`crate::style::render_list_field`] sets: `emit!` returns from its enclosing function on a
/// write failure, so a helper that writes has to hand that decision back to its caller.
fn print_record(
    record: &Record,
    options: &Options,
    widths: Widths,
    out: &mut impl std::io::Write,
) -> ExitCode {
    // The same spelling the log line carries, in the same time zone, so a line here can be
    // found in `pacman.log` by searching for it.
    let when = record.started.map_or_else(
        || "unknown date".to_owned(),
        |epoch| piko_txn::history::render_timestamp(epoch, options.offset),
    );

    // The count answers a question the detail below cannot: how big was the transaction this
    // line came from. So it shows only when there is no full detail to count — under
    // `--quiet`, and under `--package`, which narrows the detail to what was asked about.
    let hidden = options.quiet || !options.packages.is_empty();
    let count = match record.actions.len() {
        count if hidden && count > 1 => format!("  ({count} packages)"),
        _ => String::new(),
    };
    // `--quiet` is one line per transaction, so the command line stays on it: there is no
    // detail below for it to compete with. Otherwise it goes on its own line, below.
    //
    // A transaction whose records held no command line — most of pacman's — falls back to
    // naming its single action, which is what the detail lines would have said. That is not the
    // duplication this rendering exists to remove: under `--quiet` there are no detail lines,
    // and a row saying only "something happened at 16:30" is worth nothing.
    let inline = if options.quiet {
        match (&record.command, record.actions.as_slice()) {
            (Some(command), _) => format!("  {command}"),
            (None, [action]) => format!("  {}", action.log_message()),
            (None, _) => String::new(),
        }
    } else {
        String::new()
    };

    emit!(
        out,
        "{} {}  {}{inline}{}",
        outcome_mark(&record.outcome),
        console::Style::new().dim().apply_to(when),
        console::Style::new().cyan().apply_to(format!("[{}]", record.tool)),
        console::Style::new().dim().apply_to(count),
    );

    if options.quiet {
        return ExitCode::SUCCESS;
    }

    // Indented to where the verbs start, so it reads as a caption hanging under the header
    // rather than as one more action. Never truncated: it is the record of what was actually
    // typed, and a history that abbreviates that is a history that has to be double-checked.
    if let Some(command) = &record.command {
        emit!(out, "    {}", console::Style::new().dim().apply_to(command));
    }

    let Widths { verb: verb_width, name: name_width } = widths;
    for action in shown_actions(record, options) {
        let kind = kind_of(action);
        // Padded as plain text before being colored. A `StyledObject` writes its ANSI codes
        // straight through `write!` rather than `Formatter::pad`, so an outer `{:width$}`
        // around a styled value pads the escapes. Same reason as `plan.rs`.
        let prefix = kind.prefix(&format!("{:<verb_width$}", verb(action)));
        let name = action.name();
        emit!(out, "  {prefix} {name:name_width$} {}", versions(action, kind));
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

/// The shared icon-and-color vocabulary an action renders as.
const fn kind_of(action: &Action) -> ChangeKind {
    match action {
        Action::Installed { .. } => ChangeKind::Install,
        Action::Upgraded { .. } => ChangeKind::Upgrade,
        Action::Downgraded { .. } => ChangeKind::Downgrade,
        Action::Reinstalled { .. } => ChangeKind::Reinstall,
        Action::Removed { .. } => ChangeKind::Remove,
    }
}

/// The word, past tense — this command reports what already happened, where `piko plan`
/// previews what will. [`piko_txn::history::Action::verb`] is that word, and is what both
/// records write, so the screen and the files cannot disagree about it.
fn verb(action: &Action) -> &'static str {
    action.verb()
}

/// The version column: `1.0.0-1`, or `1.0.0-1 -> 1.1.0-1` where the version changed.
///
/// The version the package ended at carries the kind's color, and the one it came from is
/// dimmed — the same two-tone shape `cmd::plan` gives a `Step::Change`, so a line reads the
/// same whether piko is proposing the change or reporting it.
fn versions(action: &Action, kind: ChangeKind) -> String {
    let to = kind.style().apply_to(action.version());
    match action.previous() {
        Some(from) => format!("{} -> {to}", console::Style::new().dim().apply_to(from)),
        None => to.to_string(),
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

/// Which end of the range a `--since`/`--until` value bounds.
///
/// It decides what a bare date means, and only that. A full timestamp is taken as written
/// either way.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Bound {
    /// `--since`: the earliest transaction to keep.
    Start,
    /// `--until`: the latest transaction to keep.
    End,
}

/// The last second of a day, from its midnight.
const DAY_END: i64 = 24 * 60 * 60 - 1;

/// Parses `--since`/`--until`: a full timestamp, or a bare `YYYY-MM-DD` naming a whole day.
///
/// **A bare date names the day, not the instant it begins.** Both bounds are inclusive, so
/// `--since 2026-08-23` starts at that day's midnight and `--until 2026-08-23` runs to its
/// last second. Reading both ends as midnight would make `--until 2026-08-23` exclude every
/// transaction of the 23rd, and `--since D --until D` return nothing for any day — which is
/// the one range a reader is most likely to ask for.
///
/// A bare date is read in UTC rather than in the local zone. The alternative is to make a
/// filter's meaning depend on where the machine is, for a flag whose whole job is to cut a
/// list roughly in half.
fn parse_when(text: Option<&str>, bound: Bound) -> Result<Option<i64>, String> {
    let Some(text) = text else {
        return Ok(None);
    };
    // A spelled-out time is exact, and is used as it was written. Widening it to the end of
    // its day would ignore what the caller took the trouble to say.
    if text.contains('T') {
        return piko_txn::history::parse_timestamp(text).map(Some).ok_or_else(|| text.to_owned());
    }

    let midnight = piko_txn::history::parse_timestamp(&format!("{text}T00:00:00+0000"))
        .ok_or_else(|| text.to_owned())?;
    Ok(Some(match bound {
        Bound::Start => midnight,
        Bound::End => midnight.saturating_add(DAY_END),
    }))
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
    fn a_bare_date_starts_a_range_at_its_utc_midnight() {
        assert_eq!(parse_when(Some("1970-01-01"), Bound::Start).unwrap(), Some(0));
    }

    /// The bug this pins: `--until <date>` read as midnight excluded the whole day it named.
    #[test]
    fn a_bare_date_ends_a_range_at_its_last_second() {
        assert_eq!(parse_when(Some("1970-01-01"), Bound::End).unwrap(), Some(86_399));
    }

    /// `--since D --until D` is the range a reader asks for most often, and it has to contain
    /// the whole of day D.
    #[test]
    fn one_bare_date_on_both_bounds_covers_that_whole_day() {
        let start = parse_when(Some("2026-08-23"), Bound::Start).unwrap().unwrap();
        let end = parse_when(Some("2026-08-23"), Bound::End).unwrap().unwrap();
        // 16:29:28+0200 on that day — a real transaction from this machine's log.
        let inside = piko_txn::history::parse_timestamp("2026-08-23T16:29:28+0200").unwrap();
        assert!((start..=end).contains(&inside), "{start} ..= {end} misses {inside}");
        // And nothing from the neighbouring days.
        let before = piko_txn::history::parse_timestamp("2026-08-22T23:59:59+0000").unwrap();
        let after = piko_txn::history::parse_timestamp("2026-08-24T00:00:00+0000").unwrap();
        assert!(!(start..=end).contains(&before));
        assert!(!(start..=end).contains(&after));
    }

    /// A time the caller spelled out is exact at both bounds. Widening it to the end of its
    /// day would ignore what they took the trouble to say.
    #[test]
    fn a_full_timestamp_is_read_as_written_at_either_bound() {
        for bound in [Bound::Start, Bound::End] {
            assert_eq!(parse_when(Some("1970-01-01T02:00:00+0200"), bound).unwrap(), Some(0));
        }
    }

    #[test]
    fn an_unparseable_time_names_itself() {
        assert_eq!(parse_when(Some("last tuesday"), Bound::Start), Err("last tuesday".to_owned()));
        assert_eq!(parse_when(Some("last tuesday"), Bound::End), Err("last tuesday".to_owned()));
    }

    #[test]
    fn no_filter_is_no_bound() {
        assert_eq!(parse_when(None, Bound::Start).unwrap(), None);
        assert_eq!(parse_when(None, Bound::End).unwrap(), None);
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

    /// Every action maps to the icon and color its kind gets in `piko plan`. A reader who has
    /// seen a plan must not have to learn a second vocabulary to read a history.
    #[test]
    fn every_action_maps_to_its_kind() {
        let cases = [
            (installed("foo"), ChangeKind::Install),
            (
                Action::Upgraded {
                    name: "foo".to_owned(),
                    from: "1.0.0-1".to_owned(),
                    to: "1.1.0-1".to_owned(),
                },
                ChangeKind::Upgrade,
            ),
            (
                Action::Downgraded {
                    name: "foo".to_owned(),
                    from: "1.1.0-1".to_owned(),
                    to: "1.0.0-1".to_owned(),
                },
                ChangeKind::Downgrade,
            ),
            (
                Action::Reinstalled { name: "foo".to_owned(), version: "1.0.0-1".to_owned() },
                ChangeKind::Reinstall,
            ),
            (
                Action::Removed { name: "foo".to_owned(), version: "1.0.0-1".to_owned() },
                ChangeKind::Remove,
            ),
        ];
        for (action, expected) in cases {
            assert_eq!(kind_of(&action), expected, "{action:?}");
        }
    }

    /// The two directions are the pair most worth telling apart, and the pair a careless
    /// mapping would collapse. They must not share a glyph.
    #[test]
    fn an_upgrade_and_a_downgrade_do_not_share_a_glyph() {
        let up = Action::Upgraded {
            name: "foo".to_owned(),
            from: "1.0.0-1".to_owned(),
            to: "1.1.0-1".to_owned(),
        };
        let down = Action::Downgraded {
            name: "foo".to_owned(),
            from: "1.1.0-1".to_owned(),
            to: "1.0.0-1".to_owned(),
        };
        assert_ne!(kind_of(&up).icon(), kind_of(&down).icon());
    }

    /// The count answers what the detail cannot, so it must not appear beside the detail. The
    /// widths pass is the cheapest place to observe that the two modes differ.
    #[test]
    fn widths_are_measured_only_when_the_detail_prints() {
        let records = vec![record_with(None, vec![installed("a-very-long-package-name")])];
        let listing = Options {
            last: None,
            packages: Vec::new(),
            since: None,
            until: None,
            quiet: false,
            offset: piko_txn::LocalOffset::UTC,
        };
        assert!(Widths::over(&records, &listing).name > 0);
        assert_eq!(Widths::over(&records, &Options { quiet: true, ..listing }).name, 0);
    }

    /// `--package` narrows the detail, so the widths must be measured over what survives it,
    /// not over every action the transaction held.
    #[test]
    fn widths_follow_the_package_filter() {
        let records =
            vec![record_with(None, vec![installed("a-very-long-package-name"), installed("foo")])];
        let options = Options {
            last: None,
            packages: vec!["foo".to_owned()],
            since: None,
            until: None,
            quiet: false,
            offset: piko_txn::LocalOffset::UTC,
        };
        assert_eq!(Widths::over(&records, &options).name, "foo".len());
    }

    /// The text `versions` lays out, with any styling removed.
    ///
    /// A test harness captures `print!`, never file descriptor 1. So `console`, which decides
    /// on color by testing whether that descriptor is a terminal, styles its output here
    /// whenever the suite is run from one — and a styled version splits around an escape.
    /// The subject of these two tests is the text. Which color each kind carries is
    /// `ChangeKind`'s to test.
    fn plain(action: &Action, kind: ChangeKind) -> String {
        console::strip_ansi_codes(&versions(action, kind)).into_owned()
    }

    /// Both sides of a version change are shown.
    #[test]
    fn a_changed_version_shows_both_sides() {
        let action = Action::Upgraded {
            name: "foo".to_owned(),
            from: "1.0.0-1".to_owned(),
            to: "1.1.0-1".to_owned(),
        };
        assert_eq!(plain(&action, ChangeKind::Upgrade), "1.0.0-1 -> 1.1.0-1");
    }

    #[test]
    fn an_unchanged_version_shows_once() {
        assert_eq!(plain(&installed("foo"), ChangeKind::Install), "1.0.0-1");
    }
}
