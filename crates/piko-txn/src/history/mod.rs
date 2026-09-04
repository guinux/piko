//! A durable record of what transactions did.
//!
//! The [journal](crate::journal) is deliberately short-lived: it exists so an *interrupted*
//! transaction is detectable, and it is deleted the moment one finishes. Nothing else recorded
//! that a transaction happened at all. A package removed last month left no trace, and
//! `%INSTALLDATE%` answers only "when was what is here now put here".
//!
//! This module writes two records, because they answer different questions.
//!
//! # `pacman.log`, the shared record
//!
//! The `LogFile` directive was already parsed and already reported by `piko conf`; nothing
//! consumed it. So on a system driven by both tools, `/var/log/pacman.log` had a hole exactly
//! where piko acted. [`PacmanLog`] fills it, reproducing `_alpm_log_leader`'s format
//! (`log.c`) so one file holds both tools' lines and existing readers keep working.
//!
//! piko's lines are spelled `[PIKO]` where libalpm spells `[ALPM]`. Reading the file then
//! always says which tool acted. The cost is real and is the reason this is a choice rather
//! than an oversight: third-party tooling that greps for `[ALPM]` will not see piko's
//! transactions.
//!
//! # `piko-history`, the detailed record
//!
//! `pacman.log`'s line format cannot carry what piko knows — the exact command line, the
//! transaction's outcome as a value rather than a sentence, which `.pacnew` files it left.
//! [`store`] appends one self-delimiting block per transaction to `<dbpath>/piko-history`,
//! beside the journal and the lock.
//!
//! # Neither one can fail a transaction
//!
//! Both sinks are best-effort, and problems come back as [`Problem`] values on
//! [`crate::Report`] rather than as errors — principle 7, "diagnostics are returned, never
//! logged", applies to this module's own failures even though its whole job is writing a log.
//!
//! For `pacman.log` this diverges from libalpm, which raises `ALPM_ERR_BADPERMS`. Refusing a
//! transaction because `<root>/var/log/` does not exist would break bootstrapping a new root
//! and buy nothing. For the store the reasoning is different but lands in the same place: its
//! block is appended *after* every step succeeded, so failing there would report a completed
//! transaction as a failed one.

pub mod pacman_log;
pub mod store;
mod time_fmt;

use std::path::{Path, PathBuf};

use piko_db::EntryName;

pub use self::{
    pacman_log::{CALLER, PacmanLog, SCRIPTLET_CALLER},
    store::HISTORY_FILE,
    time_fmt::{LocalOffset, now, parse as parse_timestamp, render as render_timestamp},
};
use crate::progress::{Event, StepOutcome};

/// What one finished step did, in libalpm's own vocabulary.
///
/// The four install verbs are `add.c:641-655`'s, and the removal verb is `remove.c:722`'s.
/// Which one applies is decided **here and nowhere else**, so the two sinks cannot come to
/// different conclusions about the same step — the same reason `check_validity` is shared
/// between `piko install -w` and `Transaction::verify`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Nothing of this name was installed before.
    Installed {
        /// The package name.
        name: String,
        /// The version now installed.
        version: String,
    },
    /// A lower version was installed before.
    Upgraded {
        /// The package name.
        name: String,
        /// The version that was installed before.
        from: String,
        /// The version now installed.
        to: String,
    },
    /// A higher version was installed before.
    Downgraded {
        /// The package name.
        name: String,
        /// The version that was installed before.
        from: String,
        /// The version now installed.
        to: String,
    },
    /// The same version was installed before.
    Reinstalled {
        /// The package name.
        name: String,
        /// The version, unchanged.
        version: String,
    },
    /// The package is no longer installed.
    Removed {
        /// The package name.
        name: String,
        /// The version that was removed.
        version: String,
    },
}

impl Action {
    /// The action an install step performed, from the entry written and the entry replaced.
    ///
    /// The direction is decided by [`alpm_types::FullVersion`]'s `Ord`, which implements the
    /// same epoch/`pkgver`/`pkgrel` algorithm as `alpm_pkg_vercmp` (`version.c`). Comparing
    /// the rendered strings instead would call `1.10-1` a downgrade from `1.9-1`.
    #[must_use]
    pub fn installed(entry: &EntryName, replaced: Option<&EntryName>) -> Self {
        let name = entry.name_str().to_owned();
        let to = entry.version().to_string();
        let Some(previous) = replaced else {
            return Self::Installed { name, version: to };
        };
        let from = previous.version().to_string();
        match entry.version().cmp(previous.version()) {
            std::cmp::Ordering::Greater => Self::Upgraded { name, from, to },
            std::cmp::Ordering::Less => Self::Downgraded { name, from, to },
            std::cmp::Ordering::Equal => Self::Reinstalled { name, version: to },
        }
    }

    /// The action a removal step performed.
    #[must_use]
    pub fn removed(entry: &EntryName) -> Self {
        Self::Removed { name: entry.name_str().to_owned(), version: entry.version().to_string() }
    }

    /// The verb, as both records spell it.
    #[must_use]
    pub const fn verb(&self) -> &'static str {
        match self {
            Self::Installed { .. } => "installed",
            Self::Upgraded { .. } => "upgraded",
            Self::Downgraded { .. } => "downgraded",
            Self::Reinstalled { .. } => "reinstalled",
            Self::Removed { .. } => "removed",
        }
    }

    /// The package this action is about.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Installed { name, .. }
            | Self::Upgraded { name, .. }
            | Self::Downgraded { name, .. }
            | Self::Reinstalled { name, .. }
            | Self::Removed { name, .. } => name,
        }
    }

    /// The version the package is at after this action — the version removed, for a removal.
    #[must_use]
    pub fn version(&self) -> &str {
        match self {
            Self::Installed { version, .. }
            | Self::Reinstalled { version, .. }
            | Self::Removed { version, .. } => version,
            Self::Upgraded { to, .. } | Self::Downgraded { to, .. } => to,
        }
    }

    /// The version installed before this action, when it replaced one.
    #[must_use]
    pub fn previous(&self) -> Option<&str> {
        match self {
            Self::Upgraded { from, .. } | Self::Downgraded { from, .. } => Some(from),
            Self::Installed { .. } | Self::Reinstalled { .. } | Self::Removed { .. } => None,
        }
    }

    /// The `pacman.log` message, exactly as libalpm spells it.
    #[must_use]
    pub fn log_message(&self) -> String {
        match self.previous() {
            Some(from) => {
                format!("{} {} ({from} -> {})", self.verb(), self.name(), self.version())
            }
            None => format!("{} {} ({})", self.verb(), self.name(), self.version()),
        }
    }

    /// The history store's line for this action.
    #[must_use]
    pub fn store_line(&self) -> String {
        match self.previous() {
            Some(from) => {
                format!("{} {} {from} {}", self.verb(), self.name(), self.version())
            }
            None => format!("{} {} {}", self.verb(), self.name(), self.version()),
        }
    }

    /// Parses what [`Action::store_line`] wrote.
    #[must_use]
    pub fn parse_store_line(line: &str) -> Option<Self> {
        let mut fields = line.split_whitespace();
        let verb = fields.next()?;
        let name = fields.next()?.to_owned();
        let first = fields.next()?.to_owned();
        let second = fields.next().map(ToOwned::to_owned);
        match (verb, second) {
            ("installed", None) => Some(Self::Installed { name, version: first }),
            ("reinstalled", None) => Some(Self::Reinstalled { name, version: first }),
            ("removed", None) => Some(Self::Removed { name, version: first }),
            ("upgraded", Some(to)) => Some(Self::Upgraded { name, from: first, to }),
            ("downgraded", Some(to)) => Some(Self::Downgraded { name, from: first, to }),
            _ => None,
        }
    }
}

/// How a transaction ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Every step ran and the post-transaction hooks were given their turn.
    Completed,
    /// A step failed, or a `PreTransaction` hook with `AbortOnFail` refused the run.
    Failed {
        /// What went wrong, as the error described it.
        reason: String,
    },
    /// The record was found unfinished: the process did not live to write an ending.
    ///
    /// Never written by a transaction. This is what a reader reports for a block that has no
    /// `end` line, and what [`crate::journal::read`] finding a leftover journal means.
    Interrupted,
}

impl Outcome {
    /// The word the store writes for this outcome.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed { .. } => "failed",
            Self::Interrupted => "interrupted",
        }
    }
}

/// A problem writing one of the records.
///
/// Returned on [`crate::Report`] rather than raised, because neither record may fail a
/// transaction. See this module's documentation.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Problem {
    /// The `LogFile` could not be opened or written.
    #[error("cannot write the transaction log at {}: {reason}", path.display())]
    Log {
        /// The `LogFile` that was tried.
        path: PathBuf,
        /// The underlying failure.
        reason: String,
    },
    /// The history store could not be appended to.
    #[error("cannot write the transaction history at {}: {reason}", path.display())]
    Store {
        /// The history file that was tried.
        path: PathBuf,
        /// The underlying failure.
        reason: String,
    },
}

/// One transaction, as the history store records it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Identifies this transaction, and joins its store block to its `pacman.log` lines.
    pub id: String,
    /// When it started, in epoch seconds.
    pub started: i64,
    /// When it ended, in epoch seconds. Absent for an entry that never ended.
    pub finished: Option<i64>,
    /// The installation root it targeted.
    pub root: PathBuf,
    /// The database path it targeted.
    pub dbpath: PathBuf,
    /// The command line that asked for it, when the caller supplied one.
    pub command: Option<String>,
    /// What each step did, in the order the steps ran.
    pub actions: Vec<Action>,
    /// `.pacnew` files left behind.
    pub pacnew: Vec<PathBuf>,
    /// `.pacsave` files left behind.
    pub pacsave: Vec<PathBuf>,
    /// The hooks that ran, in order, both phases together.
    pub hooks: Vec<String>,
    /// How it ended.
    pub outcome: Outcome,
}

/// Where a transaction should record what it does.
///
/// Configuration only: nothing is opened until the transaction stages. Both paths are
/// optional, and the default records nothing — a library caller opts in, the same way it opts
/// in to scriptlets.
#[derive(Clone, Debug, Default)]
pub struct Recording {
    /// The `LogFile` to append `[PIKO]` lines to.
    pub log_file: Option<PathBuf>,
    /// The history store to append a block to. Conventionally `<dbpath>/piko-history`.
    pub store: Option<PathBuf>,
    /// The command line to record, as the user typed it.
    pub command: Option<String>,
    /// The offset timestamps are rendered in. See [`LocalOffset`].
    pub offset: LocalOffset,
}

impl Recording {
    /// Records into `<dbpath>/piko-history` and, when `log_file` names one, into that log.
    #[must_use]
    pub fn new(dbpath: &Path, log_file: Option<PathBuf>, offset: LocalOffset) -> Self {
        Self { log_file, store: Some(store::path(dbpath)), command: None, offset }
    }

    /// Records `command` as the command line that asked for the transaction.
    #[must_use]
    pub fn command(mut self, command: String) -> Self {
        self.command = Some(command);
        self
    }
}

/// One transaction as a reader sees it, from whichever records described it.
///
/// The log is the spine: it covers pacman's transactions as well as piko's, since both tools
/// write to the same file. The store fills in what the log's line format cannot hold, for the
/// transactions piko ran.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// The transaction's id, when whoever wrote it stamped one.
    pub id: Option<String>,
    /// The tool that ran it, as the log's caller field named it.
    pub tool: String,
    /// When it started.
    pub started: Option<i64>,
    /// When it ended.
    pub finished: Option<i64>,
    /// The command line, when either record held one.
    pub command: Option<String>,
    /// What it did, in order.
    pub actions: Vec<Action>,
    /// The hooks it ran, in order.
    pub hooks: Vec<String>,
    /// `.pacnew` files it left. Only the store records these.
    pub pacnew: Vec<PathBuf>,
    /// `.pacsave` files it left. Only the store records these.
    pub pacsave: Vec<PathBuf>,
    /// How it ended.
    pub outcome: Outcome,
    /// Whether the store described this transaction, as well as the log.
    pub detailed: bool,
}

impl Record {
    /// Whether this transaction touched a package named in `names`.
    #[must_use]
    pub fn touches(&self, names: &[String]) -> bool {
        names.is_empty()
            || self.actions.iter().any(|action| names.iter().any(|name| name == action.name()))
    }
}

/// Which transactions [`read`] should return.
#[derive(Clone, Debug, Default)]
pub struct Query {
    /// Keep at most this many, newest. `None` keeps every one.
    pub last: Option<usize>,
    /// Keep only transactions touching one of these packages. Empty keeps every one.
    pub packages: Vec<String>,
    /// Keep only transactions that started at or after this epoch second.
    pub since: Option<i64>,
    /// Keep only transactions that started at or before this epoch second.
    pub until: Option<i64>,
}

/// Reads both records and merges them into one history, oldest first.
///
/// A missing file is an empty record rather than an error: a system that has run no
/// transaction through a given tool has no file for it, which is not a failure to report.
///
/// # Errors
///
/// [`Problem`] if a file exists but cannot be read.
pub fn read(
    log: Option<&Path>,
    store: Option<&Path>,
    query: &Query,
) -> Result<Vec<Record>, Problem> {
    let sessions = match log {
        Some(path) => match pacman_log::read(path) {
            Ok(lines) => pacman_log::sessions(&lines),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                return Err(Problem::Log { path: path.to_path_buf(), reason: error.to_string() });
            }
        },
        None => Vec::new(),
    };

    let entries = match store {
        // The limit is applied after merging, so the store is read whole up to its own tail
        // bound. Trimming here would drop detail for a session the log still shows.
        Some(path) => {
            store::read_last(path, usize::MAX, store::DEFAULT_TAIL_BYTES).map_err(|error| {
                Problem::Store { path: path.to_path_buf(), reason: error.to_string() }
            })?
        }
        None => Vec::new(),
    };

    Ok(self::merge(sessions, entries, query))
}

/// Joins log sessions and store entries by id, then filters and trims.
#[must_use]
pub fn merge(
    sessions: Vec<pacman_log::Session>,
    entries: Vec<Entry>,
    query: &Query,
) -> Vec<Record> {
    let mut by_id: std::collections::HashMap<String, Entry> =
        entries.into_iter().map(|entry| (entry.id.clone(), entry)).collect();

    let mut records: Vec<Record> = Vec::new();
    for session in sessions {
        let detail = session.id.as_ref().and_then(|id| by_id.remove(id));
        records.push(self::joined(session, detail));
    }
    // A transaction the store knows and the log does not: the log was unwritable when it ran,
    // or it was written to a different `LogFile`. Dropping it would hide exactly the
    // transactions whose recording went wrong.
    records.extend(by_id.into_values().map(Record::from));

    records.sort_by_key(|record| record.started.unwrap_or(i64::MIN));
    records.retain(|record| {
        record.touches(&query.packages)
            && query.since.is_none_or(|since| record.started.is_none_or(|at| at >= since))
            && query.until.is_none_or(|until| record.started.is_none_or(|at| at <= until))
    });
    if let Some(last) = query.last
        && records.len() > last
    {
        records.drain(..records.len().saturating_sub(last));
    }
    records
}

/// One log session, with the store's detail folded in where there is any.
fn joined(session: pacman_log::Session, detail: Option<Entry>) -> Record {
    let Some(detail) = detail else {
        return Record {
            id: session.id,
            tool: session.caller,
            started: session.started,
            finished: session.finished,
            command: session.command,
            actions: session.actions,
            hooks: session.hooks,
            pacnew: Vec::new(),
            pacsave: Vec::new(),
            outcome: session.outcome,
            detailed: false,
        };
    };

    Record {
        id: Some(detail.id),
        tool: session.caller,
        started: session.started.or(Some(detail.started)),
        finished: session.finished.or(detail.finished),
        // The store's command line is the one piko recorded for itself; the log's was
        // reassembled from a line of text. Prefer the recorded one.
        command: detail.command.or(session.command),
        // Likewise the actions: the store holds them as values, where the log holds a rendering
        // of them. They describe the same steps, so taking one side wholesale keeps them
        // consistent rather than interleaving two orderings.
        actions: detail.actions,
        hooks: detail.hooks,
        pacnew: detail.pacnew,
        pacsave: detail.pacsave,
        // The store's outcome carries a reason where the log carries only a word.
        outcome: detail.outcome,
        detailed: true,
    }
}

impl From<Entry> for Record {
    fn from(entry: Entry) -> Self {
        Self {
            id: Some(entry.id),
            tool: CALLER.to_owned(),
            started: Some(entry.started),
            finished: entry.finished,
            command: entry.command,
            actions: entry.actions,
            hooks: entry.hooks,
            pacnew: entry.pacnew,
            pacsave: entry.pacsave,
            outcome: entry.outcome,
            detailed: true,
        }
    }
}

/// Appends one frontend line to the log `recording` names, if it names one.
///
/// pacman's frontend writes its own lines the same way, under the `PACMAN` caller: the command
/// it was invoked with, `synchronizing package lists`, `starting full system upgrade`. Those
/// happen outside any transaction, so they cannot come from a [`Recorder`], which exists only
/// between staging and committing.
///
/// # Errors
///
/// [`Problem::Log`] if the line cannot be written. Callers report it; nothing here may fail
/// what the user actually asked for.
pub fn note(recording: &Recording, message: &str) -> Result<(), Problem> {
    let Some(path) = recording.log_file.as_ref() else {
        return Ok(());
    };
    let mut log = PacmanLog::open(path, recording.offset)
        .map_err(|error| Problem::Log { path: path.clone(), reason: error.to_string() })?;
    log.line(CALLER, message)
        .map_err(|error| Problem::Log { path: path.clone(), reason: error.to_string() })
}

/// The open sinks, held for the duration of a transaction.
///
/// Driven by [`crate::progress::Event`] rather than by its own call sites. That is not a
/// shortcut: `StepFinished` is emitted only after the journal has durably recorded the step,
/// so feeding this from the event stream makes it structurally impossible for the log to
/// claim something the journal does not.
#[derive(Debug)]
pub(crate) struct Recorder {
    log: Option<PacmanLog>,
    log_path: Option<PathBuf>,
    store_path: Option<PathBuf>,
    offset: LocalOffset,
    entry: Entry,
    problems: Vec<Problem>,
}

impl Recorder {
    /// Opens both sinks and stamps the transaction's start.
    ///
    /// Never fails: a sink that cannot be opened is dropped, with a [`Problem`] recorded.
    pub(crate) fn open(recording: &Recording, root: &Path, dbpath: &Path, started: i64) -> Self {
        let mut problems = Vec::new();
        let log = recording.log_file.as_ref().and_then(|path| {
            match PacmanLog::open(path, recording.offset) {
                Ok(log) => Some(log),
                Err(error) => {
                    problems.push(Problem::Log { path: path.clone(), reason: error.to_string() });
                    None
                }
            }
        });

        Self {
            log,
            log_path: recording.log_file.clone(),
            store_path: recording.store.clone(),
            offset: recording.offset,
            entry: Entry {
                id: self::transaction_id(started),
                started,
                finished: None,
                root: root.to_path_buf(),
                dbpath: dbpath.to_path_buf(),
                command: recording.command.clone(),
                actions: Vec::new(),
                pacnew: Vec::new(),
                pacsave: Vec::new(),
                hooks: Vec::new(),
                outcome: Outcome::Interrupted,
            },
            problems,
        }
    }

    /// Writes `transaction started`, before the first mutation.
    pub(crate) fn started(&mut self) {
        let id = self.entry.id.clone();
        self.log(&format!("transaction started (id {id})"));
    }

    /// Records what one progress event says, if it says anything durable.
    pub(crate) fn observe(&mut self, event: &Event<'_>) {
        match *event {
            Event::StepFinished { step, outcome } => self.step(step, &outcome),
            Event::HookStarted { name, .. } => {
                self.entry.hooks.push(name.to_owned());
                self.log(&format!("running '{name}'..."));
            }
            Event::ScriptletOutputLine { line, .. } => self.scriptlet_line(line),
            _ => {}
        }
    }

    /// Records a finished step: what it left behind first, then what it did.
    ///
    /// The `.pacnew`/`.pacsave` warnings precede the verb, matching libalpm, which emits them
    /// from extraction and removal while the final `installed`/`removed` line is written after
    /// the database entry is updated (`add.c:641`).
    fn step(&mut self, step: &crate::Step, outcome: &StepOutcome<'_>) {
        let (action, pacsaves) = match *outcome {
            StepOutcome::Installed { entry, replaced, extraction, pacsaves } => {
                for path in self::pacnew_paths(extraction) {
                    self.log(&format!(
                        "warning: {} installed as {}",
                        self::strip_pacnew(&path).display(),
                        path.display()
                    ));
                    self.entry.pacnew.push(path);
                }
                (Action::installed(entry, replaced), pacsaves)
            }
            // What was removed is named by the step, not by the outcome: the entry is gone by
            // the time this fires, so the outcome carries only what the step left behind.
            StepOutcome::Removed { pacsaves } => match step {
                crate::Step::Remove { entry, .. } => (Action::removed(entry), pacsaves),
                crate::Step::Install { .. } => return,
            },
        };

        for path in pacsaves {
            self.log(&format!(
                "warning: {} saved as {}",
                self::strip_pacsave(path).display(),
                path.display()
            ));
            self.entry.pacsave.push(path.clone());
        }

        self.log(&action.log_message());
        self.entry.actions.push(action);
    }

    /// Copies one line of a scriptlet's output into the log, as libalpm does (`util.c:527`).
    fn scriptlet_line(&mut self, line: &str) {
        let Some(log) = self.log.as_mut() else {
            return;
        };
        if let Err(error) = log.line(SCRIPTLET_CALLER, line) {
            self.note_log_failure(&error);
        }
    }

    /// Writes one `[PIKO]` line, noting a failure rather than raising it.
    fn log(&mut self, message: &str) {
        let Some(log) = self.log.as_mut() else {
            return;
        };
        if let Err(error) = log.line(CALLER, message) {
            self.note_log_failure(&error);
        }
    }

    /// Drops the log after a write failure, so one broken file does not produce one problem
    /// per line for the rest of the transaction.
    fn note_log_failure(&mut self, error: &std::io::Error) {
        self.log = None;
        if let Some(path) = self.log_path.clone() {
            self.problems.push(Problem::Log { path, reason: error.to_string() });
        }
    }

    /// Writes the ending to both records, and returns whatever went wrong along the way.
    pub(crate) fn finish(mut self, outcome: Outcome, finished: i64) -> Vec<Problem> {
        self.log(match outcome {
            Outcome::Completed => "transaction completed",
            Outcome::Failed { .. } | Outcome::Interrupted => "transaction failed",
        });
        self.entry.outcome = outcome;
        self.entry.finished = Some(finished);

        if let Some(path) = self.store_path.clone()
            && let Err(error) = store::append(&path, &self.entry, self.offset)
        {
            self.problems.push(Problem::Store { path, reason: error.to_string() });
        }
        self.problems
    }

    /// Drops the recorder without writing an ending, for a transaction that never began.
    pub(crate) fn abandon(self) -> Vec<Problem> {
        self.problems
    }
}

/// Identifies one transaction: when it started, and which process ran it.
///
/// Unique in practice without a counter or any shared state. `db.lck` already serialises
/// transactions against one database, so a collision would need two processes with the same
/// pid starting in the same second against two different databases.
fn transaction_id(started: i64) -> String {
    format!("{started}-{}", std::process::id())
}

/// Every `.pacnew` an extraction left on disk.
fn pacnew_paths(extraction: &crate::install::Extraction) -> Vec<PathBuf> {
    extraction
        .outcomes
        .iter()
        .filter_map(|(_, outcome)| match outcome {
            crate::install::Outcome::Backup(crate::extract::BackupOutcome::KeptBoth { pacnew }) => {
                Some(pacnew.clone())
            }
            _ => None,
        })
        .collect()
}

/// The path a `.pacnew` was diverted from.
fn strip_pacnew(path: &Path) -> PathBuf {
    self::strip_suffix(path, ".pacnew")
}

/// The path a `.pacsave` was rotated from.
///
/// pacman numbers repeated saves `.pacsave.1`, `.pacsave.2`, … so the suffix is matched at the
/// last `.pacsave`, not only at the end of the string.
fn strip_pacsave(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    match text.rfind(".pacsave") {
        Some(index) => PathBuf::from(text.get(..index).unwrap_or_default()),
        None => path.to_path_buf(),
    }
}

/// `path` without `suffix`, or `path` unchanged if it does not end with it.
fn strip_suffix(path: &Path, suffix: &str) -> PathBuf {
    let text = path.to_string_lossy();
    text.strip_suffix(suffix).map_or_else(|| path.to_path_buf(), PathBuf::from)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn entry(raw: &str) -> EntryName {
        EntryName::parse(raw).unwrap()
    }

    #[test]
    fn a_fresh_install_is_installed() {
        let action = Action::installed(&entry("foo-1.0.0-1"), None);
        assert_eq!(
            action,
            Action::Installed { name: "foo".to_owned(), version: "1.0.0-1".to_owned() }
        );
        assert_eq!(action.log_message(), "installed foo (1.0.0-1)");
    }

    #[test]
    fn a_higher_version_is_an_upgrade() {
        let action = Action::installed(&entry("foo-1.1.0-1"), Some(&entry("foo-1.0.0-1")));
        assert_eq!(action.log_message(), "upgraded foo (1.0.0-1 -> 1.1.0-1)");
    }

    #[test]
    fn a_lower_version_is_a_downgrade() {
        let action = Action::installed(&entry("foo-1.0.0-1"), Some(&entry("foo-1.1.0-1")));
        assert_eq!(action.log_message(), "downgraded foo (1.1.0-1 -> 1.0.0-1)");
    }

    #[test]
    fn the_same_version_is_a_reinstall() {
        let action = Action::installed(&entry("foo-1.0.0-1"), Some(&entry("foo-1.0.0-1")));
        assert_eq!(action.log_message(), "reinstalled foo (1.0.0-1)");
    }

    /// The direction must come from `alpm_pkg_vercmp`'s algorithm, not from string order.
    /// Compared as text, `1.10-1` sorts below `1.9-1` and an upgrade is logged as a
    /// downgrade.
    #[test]
    fn the_direction_is_a_version_comparison_not_a_string_comparison() {
        let action = Action::installed(&entry("foo-1.10-1"), Some(&entry("foo-1.9-1")));
        assert_eq!(action.verb(), "upgraded");
    }

    /// An epoch outranks a numerically higher pkgver, the same way `piko_db::updates` treats
    /// it.
    #[test]
    fn an_epoch_bump_is_an_upgrade() {
        let action = Action::installed(&entry("foo-1:0.1-1"), Some(&entry("foo-9.9-1")));
        assert_eq!(action.verb(), "upgraded");
    }

    #[test]
    fn a_removal_names_what_went() {
        let action = Action::removed(&entry("foo-1.0.0-1"));
        assert_eq!(action.log_message(), "removed foo (1.0.0-1)");
    }

    #[test]
    fn store_lines_round_trip() {
        let actions = [
            Action::installed(&entry("foo-1.0.0-1"), None),
            Action::installed(&entry("foo-1.1.0-1"), Some(&entry("foo-1.0.0-1"))),
            Action::installed(&entry("foo-1.0.0-1"), Some(&entry("foo-1.1.0-1"))),
            Action::installed(&entry("foo-1.0.0-1"), Some(&entry("foo-1.0.0-1"))),
            Action::removed(&entry("bar-2.0-1")),
        ];
        for action in actions {
            let line = action.store_line();
            assert_eq!(Action::parse_store_line(&line), Some(action.clone()), "{line}");
        }
    }

    #[test]
    fn a_malformed_store_line_is_refused() {
        assert_eq!(Action::parse_store_line(""), None);
        assert_eq!(Action::parse_store_line("installed"), None);
        assert_eq!(Action::parse_store_line("exploded foo 1.0.0-1"), None);
        assert_eq!(Action::parse_store_line("installed foo 1.0.0-1 2.0.0-1"), None);
    }

    #[test]
    fn a_pacsave_names_the_file_it_came_from() {
        assert_eq!(strip_pacsave(Path::new("/etc/foo.conf.pacsave")), Path::new("/etc/foo.conf"));
        assert_eq!(strip_pacsave(Path::new("/etc/foo.conf.pacsave.3")), Path::new("/etc/foo.conf"));
        assert_eq!(strip_pacnew(Path::new("/etc/foo.conf.pacnew")), Path::new("/etc/foo.conf"));
    }

    /// Two transactions in the same second from different processes must not share an id.
    #[test]
    fn an_id_names_the_second_and_the_process() {
        let id = transaction_id(1_757_000_000);
        assert!(id.starts_with("1757000000-"), "{id}");
        assert_eq!(id, transaction_id(1_757_000_000));
    }
}
