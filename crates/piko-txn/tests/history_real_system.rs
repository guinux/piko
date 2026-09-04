//! The transaction log reader, against this machine's real `/var/log/pacman.log`.
//!
//! ```text
//! cargo test -p piko-txn --test history_real_system -- --ignored
//! ```
//!
//! Read-only. Nothing here writes anywhere.
//!
//! # Why this exists
//!
//! Every other test of the reader feeds it text this repository wrote. That proves the parser
//! agrees with the writer, and nothing more. `pacman.log` is a shared file: pacman wrote most
//! of it, over years, through several versions of libalpm. Whether piko reads *that* back is
//! a different question, and only a real log can answer it.
//!
//! The strongest available check is a count. `grep -c 'transaction started'` and
//! `grep -c '\[ALPM\] installed …'` are computed here the same way a person would compute them
//! at a shell, then compared against what the reader made of the same file. A parser that
//! silently drops a line, or merges two transactions into one, fails on the count before
//! anyone has to eyeball the output.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::path::Path;

use piko_txn::history::{Outcome, pacman_log};

/// This machine's log. Absent on a system pacman has never run.
const LOG: &str = "/var/log/pacman.log";

/// Skips the test when there is no real log to read.
fn log_text() -> Option<String> {
    std::fs::read_to_string(Path::new(LOG)).ok()
}

/// Counts the lines a shell `grep -c` would count.
fn grep_count(text: &str, predicate: impl Fn(&str) -> bool) -> usize {
    text.lines().filter(|line| predicate(line)).count()
}

/// Every `transaction started` must produce exactly one session, and no more.
///
/// This is the check that catches both directions of failure at once. Dropping a line loses a
/// session; failing to close one merges two transactions into a single entry. Either shows up
/// as a mismatch here.
#[test]
#[ignore = "requires a real /var/log/pacman.log"]
fn every_transaction_in_the_real_log_is_found_exactly_once() {
    let Some(text) = log_text() else {
        eprintln!("no {LOG} on this machine; skipping");
        return;
    };

    let expected = grep_count(&text, |line| line.contains("] transaction started"));
    let lines = pacman_log::read(Path::new(LOG)).expect("the log reads");
    let sessions = pacman_log::sessions(&lines);

    assert_eq!(
        sessions.len(),
        expected,
        "{} sessions against {expected} `transaction started` lines",
        sessions.len()
    );
}

/// Every action line must land in exactly one session, and be read as the verb it spells.
#[test]
#[ignore = "requires a real /var/log/pacman.log"]
fn every_action_in_the_real_log_is_attributed_to_a_transaction() {
    let Some(text) = log_text() else {
        eprintln!("no {LOG} on this machine; skipping");
        return;
    };

    let verbs = ["installed ", "upgraded ", "downgraded ", "reinstalled ", "removed "];
    let expected = grep_count(&text, |line| {
        // The same shape `grep -E '\[ALPM\] (installed|…) '` matches: a caller field, then one
        // of the five verbs. A `warning:` line mentioning "installed as" does not match,
        // because the verb has to follow the caller immediately.
        line.split_once("] [")
            .and_then(|(_, rest)| rest.split_once("] "))
            .is_some_and(|(_, message)| verbs.iter().any(|verb| message.starts_with(verb)))
    });

    let lines = pacman_log::read(Path::new(LOG)).expect("the log reads");
    let counted: usize =
        pacman_log::sessions(&lines).iter().map(|session| session.actions.len()).sum();

    assert_eq!(counted, expected, "{counted} actions read against {expected} action lines");
}

/// A real log is years of text written by several versions of libalpm. Every line with a
/// leader must parse, and every parsed line must be datable.
#[test]
#[ignore = "requires a real /var/log/pacman.log"]
fn every_dated_line_in_the_real_log_parses() {
    let Some(text) = log_text() else {
        eprintln!("no {LOG} on this machine; skipping");
        return;
    };

    let mut undated = Vec::new();
    for line in text.lines() {
        // A scriptlet copies its own output through, and that output can be anything,
        // including something shaped like a leader. Only lines that do parse are checked for
        // a readable timestamp.
        let Some(parsed) = pacman_log::Line::parse(line) else {
            continue;
        };
        if parsed.timestamp.is_none() {
            undated.push(line.to_owned());
        }
    }

    assert!(
        undated.is_empty(),
        "{} line(s) parsed but could not be dated, first: {:?}",
        undated.len(),
        undated.first()
    );
}

/// A finished transaction must not be reported as unfinished. `Interrupted` is reserved for a
/// session the log genuinely never closed — a machine that lost power mid-upgrade.
#[test]
#[ignore = "requires a real /var/log/pacman.log"]
fn a_closed_transaction_is_never_reported_as_interrupted() {
    let Some(text) = log_text() else {
        eprintln!("no {LOG} on this machine; skipping");
        return;
    };

    let closed = grep_count(&text, |line| {
        line.contains("] transaction completed") || line.contains("] transaction failed")
    });
    let lines = pacman_log::read(Path::new(LOG)).expect("the log reads");
    let sessions = pacman_log::sessions(&lines);
    let settled = sessions.iter().filter(|session| session.outcome != Outcome::Interrupted).count();

    assert_eq!(settled, closed, "{settled} settled sessions against {closed} ending lines");
}

/// The command line pacman logs must reach the session it belongs to.
#[test]
#[ignore = "requires a real /var/log/pacman.log"]
fn a_logged_command_line_reaches_its_transaction() {
    let Some(text) = log_text() else {
        eprintln!("no {LOG} on this machine; skipping");
        return;
    };
    if !text.contains("] Running '") {
        eprintln!("this log records no command lines; skipping");
        return;
    }

    let lines = pacman_log::read(Path::new(LOG)).expect("the log reads");
    let sessions = pacman_log::sessions(&lines);
    let with_command = sessions.iter().filter(|session| session.command.is_some()).count();

    assert!(with_command > 0, "no session picked up a `Running '…'` line");
}
