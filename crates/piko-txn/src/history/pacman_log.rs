//! `pacman.log`: the record piko shares with pacman.
//!
//! # Format
//!
//! One line per event, exactly as `_alpm_log_leader` builds it (`log.c`):
//!
//! ```text
//! [2026-09-04T10:11:12+0200] [PIKO] installed foo (1.0.0-1)
//! ```
//!
//! An ISO-8601 timestamp in the machine's own time zone, the writing tool in brackets, then
//! the message. libalpm writes `ALPM` there, and pacman's frontend writes `PACMAN`; piko
//! writes [`CALLER`] so a line always says which tool acted. A scriptlet's own output is
//! copied through under [`SCRIPTLET_CALLER`], one line at a time, as `util.c:527` does.
//!
//! # Reading
//!
//! [`read`] parses the file back, whoever wrote it, and [`sessions`] groups the lines into
//! transactions. That is what lets `piko history` show pacman's transactions beside piko's:
//! the file is the shared record, and neither tool owns it.

use std::{
    io::{BufRead as _, Read as _, Write as _},
    path::{Path, PathBuf},
};

use super::{Action, LocalOffset, Outcome, time_fmt};

/// The bracketed name piko writes its own lines under, where libalpm writes `ALPM`.
pub const CALLER: &str = "PIKO";

/// The bracketed name a scriptlet's copied output is written under.
pub const SCRIPTLET_CALLER: &str = "PIKO-SCRIPTLET";

/// Mode a log file is created with, matching `log.c`.
const LOG_MODE: u32 = 0o644;

/// Largest log a [`read`] will take in.
///
/// A `pacman.log` on a long-lived system runs to a few megabytes; this is generous without
/// being unbounded. Every read in piko is bounded, and a log is as attacker-influenced as any
/// other file on disk: it holds the output of every scriptlet that ever ran.
pub const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

/// An open log file, appended to for the duration of a transaction.
#[derive(Debug)]
pub struct PacmanLog {
    path: PathBuf,
    file: std::fs::File,
    offset: LocalOffset,
}

impl PacmanLog {
    /// Opens `path` for appending, creating it if it is absent.
    ///
    /// `O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC` at mode `0644`, the same flags `log.c`
    /// uses. The parent directory is **not** created: libalpm does not create it either, and a
    /// missing `/var/log` means the caller pointed at a root that is not set up yet, which is
    /// worth reporting rather than papering over.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] if the file cannot be opened.
    pub fn open(path: &Path, offset: LocalOffset) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = std::fs::OpenOptions::new();
        options.write(true).append(true).create(true).mode(LOG_MODE);
        options.custom_flags(libc::O_CLOEXEC);

        // libalpm retries only `EINTR` (`log.c`), and so does this. Every other failure is
        // the caller's to hear about.
        let file = loop {
            match options.open(path) {
                Ok(file) => break file,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        };
        Ok(Self { path: path.to_path_buf(), file, offset })
    }

    /// The file being written.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one line, stamped with the current time.
    ///
    /// A `\n` already ending `message` is not doubled, so a scriptlet line copied verbatim
    /// reads the same as one composed here.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] if the line cannot be written.
    pub fn line(&mut self, caller: &str, message: &str) -> std::io::Result<()> {
        self.line_at(super::now(), caller, message)
    }

    /// As [`PacmanLog::line`], at an explicit timestamp. Tests use this to pin the format.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] if the line cannot be written.
    pub fn line_at(&mut self, epoch: i64, caller: &str, message: &str) -> std::io::Result<()> {
        let stamp = time_fmt::render(epoch, self.offset);
        let message = message.strip_suffix('\n').unwrap_or(message);
        // One `write_all`, so a concurrent writer on the same `O_APPEND` file cannot land
        // between the leader and the message.
        self.file.write_all(format!("[{stamp}] [{caller}] {message}\n").as_bytes())?;
        // `fflush` per line, as `log.c` does. Not `fsync`: libalpm does not, and a log that
        // costs a disk barrier per line would dominate a transaction's cost.
        self.file.flush()
    }
}

/// One parsed line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Line {
    /// When it was written, when the leader could be dated.
    pub timestamp: Option<i64>,
    /// The bracketed caller: `PIKO`, `ALPM`, `PACMAN`, `ALPM-SCRIPTLET`, …
    pub caller: String,
    /// Everything after the leader.
    pub message: String,
}

impl Line {
    /// Parses one line of a log file.
    ///
    /// Returns `None` for a line with no `[stamp] [caller] ` leader. Such a line is a
    /// continuation of a multi-line message, or something else entirely; either way it names
    /// no event.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix('[')?;
        let (stamp, rest) = rest.split_once(']')?;
        let rest = rest.strip_prefix(" [")?;
        let (caller, message) = rest.split_once("] ")?;
        Some(Self {
            timestamp: time_fmt::parse(stamp),
            caller: caller.to_owned(),
            message: message.to_owned(),
        })
    }

    /// The action this line reports, if it reports one.
    ///
    /// Parses libalpm's four install verbs and its removal verb, in either tool's spelling —
    /// the message text is identical, only the caller differs.
    #[must_use]
    pub fn action(&self) -> Option<Action> {
        let (verb, rest) = self.message.split_once(' ')?;
        let (name, versions) = rest.split_once(" (")?;
        let versions = versions.strip_suffix(')')?;
        let name = name.to_owned();
        match (verb, versions.split_once(" -> ")) {
            ("installed", None) => Some(Action::Installed { name, version: versions.to_owned() }),
            ("reinstalled", None) => {
                Some(Action::Reinstalled { name, version: versions.to_owned() })
            }
            ("removed", None) => Some(Action::Removed { name, version: versions.to_owned() }),
            ("upgraded", Some((from, to))) => {
                Some(Action::Upgraded { name, from: from.to_owned(), to: to.to_owned() })
            }
            ("downgraded", Some((from, to))) => {
                Some(Action::Downgraded { name, from: from.to_owned(), to: to.to_owned() })
            }
            _ => None,
        }
    }
}

/// One transaction, as the log describes it.
///
/// This is what the log can say. It is less than [`super::Entry`] knows — no root, no dbpath,
/// no `.pacnew` list — and more than the store holds, because it covers pacman's transactions
/// too.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    /// The id piko stamped on the `transaction started` line, when piko wrote it.
    pub id: Option<String>,
    /// The tool that wrote the transaction's lines.
    pub caller: String,
    /// When it started.
    pub started: Option<i64>,
    /// When it ended, absent if the log has no ending for it.
    pub finished: Option<i64>,
    /// The command line, from a `Running '…'` line preceding it.
    pub command: Option<String>,
    /// What it did, in order.
    pub actions: Vec<Action>,
    /// The hooks it ran, in order.
    pub hooks: Vec<String>,
    /// How it ended, `Interrupted` when the log has no ending for it.
    pub outcome: Outcome,
}

/// Reads and parses a log file, bounded by [`MAX_LOG_BYTES`].
///
/// Unparseable lines are skipped rather than failing the read. A log file outlives the tools
/// that wrote it, and a reader that refuses the whole file over one odd line is a reader that
/// stops working on exactly the system whose history is worth looking at.
///
/// # Errors
///
/// [`std::io::Error`] if the file cannot be opened or read.
pub fn read(path: &Path) -> std::io::Result<Vec<Line>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file.take(MAX_LOG_BYTES));
    let mut lines = Vec::new();
    for line in reader.lines() {
        // A log holds scriptlet output, which is whatever a package printed. Invalid UTF-8 is
        // a reason to skip a line, never to fail the read.
        let Ok(line) = line else { continue };
        if let Some(parsed) = Line::parse(&line) {
            lines.push(parsed);
        }
    }
    Ok(lines)
}

/// Groups parsed lines into transactions, newest last.
///
/// A session runs from `transaction started` to `transaction completed`/`transaction failed`.
/// A `Running '…'` line seen before a session begins is attached to it as the command line,
/// which is how pacman's own `[PACMAN] Running '…'` reaches the same field piko records
/// explicitly. Lines outside any session are dropped: they describe no transaction.
#[must_use]
pub fn sessions(lines: &[Line]) -> Vec<Session> {
    let mut sessions: Vec<Session> = Vec::new();
    let mut open: Option<Session> = None;
    let mut pending_command: Option<String> = None;

    for line in lines {
        if let Some(command) = self::running_command(&line.message) {
            pending_command = Some(command);
            continue;
        }

        if let Some(id) = self::started_id(&line.message) {
            if let Some(session) = open.take() {
                // A start with no matching end: the previous transaction did not live to
                // write one.
                sessions.push(session);
            }
            open = Some(Session {
                id,
                caller: line.caller.clone(),
                started: line.timestamp,
                finished: None,
                command: pending_command.take(),
                actions: Vec::new(),
                hooks: Vec::new(),
                outcome: Outcome::Interrupted,
            });
            continue;
        }

        let Some(session) = open.as_mut() else { continue };

        if line.message == "transaction completed" || line.message == "transaction failed" {
            session.finished = line.timestamp;
            session.outcome = if line.message.ends_with("completed") {
                Outcome::Completed
            } else {
                Outcome::Failed { reason: "the log records a failed transaction".to_owned() }
            };
            sessions.extend(open.take());
            continue;
        }

        if let Some(hook) = self::hook_name(&line.message) {
            session.hooks.push(hook);
            continue;
        }

        if let Some(action) = line.action() {
            session.actions.push(action);
        }
    }

    sessions.extend(open);
    sessions
}

/// The command line a `Running '…'` message carries.
fn running_command(message: &str) -> Option<String> {
    let rest = message.strip_prefix("Running '")?;
    Some(rest.strip_suffix('\'')?.to_owned())
}

/// The id a `transaction started` message carries, or `None` for libalpm's un-suffixed form.
///
/// Returns `Some(None)` for a start with no id, and `None` for a line that is not a start at
/// all — the two answers a caller has to tell apart.
fn started_id(message: &str) -> Option<Option<String>> {
    let rest = message.strip_prefix("transaction started")?;
    let rest = rest.trim();
    let Some(rest) = rest.strip_prefix("(id ") else {
        return Some(None);
    };
    Some(rest.strip_suffix(')').map(ToOwned::to_owned))
}

/// The hook file a `running '…'...` message names.
fn hook_name(message: &str) -> Option<String> {
    let rest = message.strip_prefix("running '")?;
    Some(rest.strip_suffix("'...")?.to_owned())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().expect("a temporary directory")
    }

    #[test]
    fn a_line_matches_the_libalpm_leader() {
        let dir = temp();
        let path = dir.path().join("pacman.log");
        let mut log = PacmanLog::open(&path, LocalOffset::from_seconds(7200)).unwrap();
        log.line_at(0, CALLER, "installed foo (1.0.0-1)").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[1970-01-01T02:00:00+0200] [PIKO] installed foo (1.0.0-1)\n"
        );
    }

    /// A scriptlet's own line already ends with a newline in libalpm's format string. Doubling
    /// it would put a blank line between every two lines of output.
    #[test]
    fn a_trailing_newline_is_not_doubled() {
        let dir = temp();
        let path = dir.path().join("pacman.log");
        let mut log = PacmanLog::open(&path, LocalOffset::UTC).unwrap();
        log.line_at(0, SCRIPTLET_CALLER, "creating a user\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[1970-01-01T00:00:00+0000] [PIKO-SCRIPTLET] creating a user\n"
        );
    }

    #[test]
    fn opening_appends_rather_than_truncating() {
        let dir = temp();
        let path = dir.path().join("pacman.log");
        std::fs::write(&path, "[1970-01-01T00:00:00+0000] [ALPM] transaction started\n").unwrap();
        let mut log = PacmanLog::open(&path, LocalOffset::UTC).unwrap();
        log.line_at(1, CALLER, "installed foo (1.0.0-1)").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("[ALPM] transaction started"), "{text}");
        assert!(text.contains("[PIKO] installed foo"), "{text}");
    }

    /// libalpm does not create the directory either. A missing one means the caller named a
    /// root that is not set up, and saying so beats creating `/var/log` behind their back.
    #[test]
    fn a_missing_directory_is_reported_not_created() {
        let dir = temp();
        let path = dir.path().join("var/log/pacman.log");
        assert!(PacmanLog::open(&path, LocalOffset::UTC).is_err());
    }

    #[test]
    fn a_leader_parses_back() {
        let line = Line::parse("[2026-09-03T16:19:47+0200] [ALPM] installed foo (1.0.0-1)")
            .expect("a parseable line");
        assert_eq!(line.caller, "ALPM");
        assert_eq!(line.message, "installed foo (1.0.0-1)");
        assert!(line.timestamp.is_some());
    }

    #[test]
    fn a_line_with_no_leader_is_skipped() {
        assert_eq!(Line::parse(""), None);
        assert_eq!(Line::parse("installed foo (1.0.0-1)"), None);
        assert_eq!(Line::parse("[2026-09-03T16:19:47+0200] no caller"), None);
    }

    /// The message text is libalpm's, whoever wrote the line. Both callers must parse.
    #[test]
    fn every_verb_parses_from_a_message() {
        let cases = [
            ("installed foo (1.0.0-1)", "installed"),
            ("reinstalled foo (1.0.0-1)", "reinstalled"),
            ("removed foo (1.0.0-1)", "removed"),
            ("upgraded foo (1.0.0-1 -> 1.1.0-1)", "upgraded"),
            ("downgraded foo (1.1.0-1 -> 1.0.0-1)", "downgraded"),
        ];
        for (message, verb) in cases {
            let line =
                Line { timestamp: Some(0), caller: "ALPM".to_owned(), message: message.to_owned() };
            assert_eq!(line.action().expect(message).verb(), verb, "{message}");
        }
    }

    /// What a line reports and what the writer would write for it must agree, or a
    /// transaction read back says something the transaction did not do.
    #[test]
    fn an_action_round_trips_through_a_message() {
        let action = Action::Upgraded {
            name: "foo".to_owned(),
            from: "1.0.0-1".to_owned(),
            to: "1.1.0-1".to_owned(),
        };
        let line =
            Line { timestamp: Some(0), caller: CALLER.to_owned(), message: action.log_message() };
        assert_eq!(line.action(), Some(action));
    }

    #[test]
    fn a_warning_is_not_an_action() {
        let line = Line {
            timestamp: Some(0),
            caller: "ALPM".to_owned(),
            message: "warning: /etc/foo.conf installed as /etc/foo.conf.pacnew".to_owned(),
        };
        assert_eq!(line.action(), None);
    }

    fn parse_all(text: &str) -> Vec<Line> {
        text.lines().filter_map(Line::parse).collect()
    }

    #[test]
    fn a_pacman_transaction_groups_into_one_session() {
        let lines = parse_all(
            "[2026-09-03T16:19:47+0200] [PACMAN] Running 'pacman -Syu'\n\
             [2026-09-03T16:19:47+0200] [PACMAN] synchronizing package lists\n\
             [2026-09-03T16:19:48+0200] [ALPM] transaction started\n\
             [2026-09-03T16:19:49+0200] [ALPM] upgraded foo (1.0.0-1 -> 1.1.0-1)\n\
             [2026-09-03T16:19:50+0200] [ALPM] transaction completed\n\
             [2026-09-03T16:19:51+0200] [ALPM] running '35-systemd-update.hook'...\n",
        );
        let sessions = sessions(&lines);
        assert_eq!(sessions.len(), 1);
        let session = sessions.first().expect("one session");
        assert_eq!(session.caller, "ALPM");
        assert_eq!(session.command.as_deref(), Some("pacman -Syu"));
        assert_eq!(session.actions.len(), 1);
        assert_eq!(session.outcome, Outcome::Completed);
    }

    #[test]
    fn a_piko_transaction_carries_its_id() {
        let lines = parse_all(
            "[2026-09-03T16:19:47+0200] [PIKO] Running 'piko install foo'\n\
             [2026-09-03T16:19:48+0200] [PIKO] transaction started (id 1757000000-42)\n\
             [2026-09-03T16:19:49+0200] [PIKO] installed foo (1.0.0-1)\n\
             [2026-09-03T16:19:50+0200] [PIKO] transaction completed\n",
        );
        let sessions = sessions(&lines);
        let session = sessions.first().expect("one session");
        assert_eq!(session.id.as_deref(), Some("1757000000-42"));
        assert_eq!(session.caller, CALLER);
        assert_eq!(session.command.as_deref(), Some("piko install foo"));
    }

    /// A transaction whose process was killed writes no ending. It must still be reported,
    /// and reported as unfinished rather than as completed.
    #[test]
    fn a_session_with_no_ending_is_interrupted() {
        let lines = parse_all(
            "[2026-09-03T16:19:48+0200] [ALPM] transaction started\n\
             [2026-09-03T16:19:49+0200] [ALPM] installed foo (1.0.0-1)\n",
        );
        let sessions = sessions(&lines);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions.first().map(|s| s.outcome.clone()), Some(Outcome::Interrupted));
    }

    #[test]
    fn a_failed_session_is_reported_as_failed() {
        let lines = parse_all(
            "[2026-09-03T16:19:48+0200] [PIKO] transaction started (id 1-1)\n\
             [2026-09-03T16:19:50+0200] [PIKO] transaction failed\n",
        );
        let sessions = sessions(&lines);
        assert!(matches!(
            sessions.first().map(|s| s.outcome.clone()),
            Some(Outcome::Failed { .. })
        ));
    }

    #[test]
    fn hooks_inside_a_session_are_collected() {
        let lines = parse_all(
            "[2026-09-03T16:19:48+0200] [PIKO] transaction started (id 1-1)\n\
             [2026-09-03T16:19:49+0200] [PIKO] running '30-foo.hook'...\n\
             [2026-09-03T16:19:50+0200] [PIKO] transaction completed\n",
        );
        let sessions = sessions(&lines);
        assert_eq!(sessions.first().map(|s| s.hooks.clone()), Some(vec!["30-foo.hook".to_owned()]));
    }

    #[test]
    fn two_transactions_do_not_merge() {
        let lines = parse_all(
            "[2026-09-03T16:19:48+0200] [PIKO] transaction started (id 1-1)\n\
             [2026-09-03T16:19:49+0200] [PIKO] installed foo (1.0.0-1)\n\
             [2026-09-03T16:19:50+0200] [PIKO] transaction completed\n\
             [2026-09-03T16:20:48+0200] [PIKO] transaction started (id 2-1)\n\
             [2026-09-03T16:20:49+0200] [PIKO] removed foo (1.0.0-1)\n\
             [2026-09-03T16:20:50+0200] [PIKO] transaction completed\n",
        );
        assert_eq!(sessions(&lines).len(), 2);
    }

    #[test]
    fn reading_a_file_skips_what_it_cannot_parse() {
        let dir = temp();
        let path = dir.path().join("pacman.log");
        std::fs::write(
            &path,
            "not a log line\n\
             [2026-09-03T16:19:48+0200] [PIKO] transaction started (id 1-1)\n\
             \n",
        )
        .unwrap();
        assert_eq!(read(&path).unwrap().len(), 1);
    }
}
