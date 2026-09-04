//! `<dbpath>/piko-history`: the detailed record, in piko's own format.
//!
//! It sits beside `piko-journal` and `db.lck` rather than inside `local/`, for the reason the
//! journal gives for the same choice: the local database scan enumerates directories, so a
//! stray file next to them is skipped with no special case.
//!
//! # Format
//!
//! One self-delimiting block per transaction, appended. Line-oriented text, the same grammar
//! family as the journal, so a human reading a broken system reads both the same way:
//!
//! ```text
//! txn 1 1757000000-4211 2026-09-04T10:11:12+0200
//! root /
//! dbpath /var/lib/pacman
//! command piko install foo
//! installed foo 1.0.0-1
//! upgraded bar 2.0-1 3.0-1
//! pacnew /etc/foo.conf.pacnew
//! hook 30-foo.hook
//! end completed 2026-09-04T10:11:19+0200
//! ```
//!
//! There is no file header. A block carries its own format version, so a block written by a
//! future build is skipped without making the rest of the file unreadable, and a block cut
//! short by a full disk is skipped without taking a neighbour with it.
//!
//! # Growth
//!
//! Unbounded, exactly as `pacman.log` is. Rotating it is `logrotate`'s job, not piko's.
//! Reading is bounded regardless: [`read_last`] works from the end of the file and never takes
//! in more than it was asked for.

use std::{
    io::{Read as _, Seek as _, Write as _},
    path::{Path, PathBuf},
};

use super::{Action, Entry, LocalOffset, Outcome, time_fmt};

/// The history's file name, inside the database path.
pub const HISTORY_FILE: &str = "piko-history";

/// The block format version this build writes.
const VERSION: u32 = 1;

/// Mode the history file is created with. It is world-readable, like `pacman.log`: knowing
/// what was installed is not a privilege.
const FILE_MODE: u32 = 0o644;

/// How much of the file's tail [`read_last`] reads by default.
///
/// A block runs to a few hundred bytes, so this covers thousands of transactions while keeping
/// the read bounded the way every other read in piko is.
pub const DEFAULT_TAIL_BYTES: u64 = 8 * 1024 * 1024;

/// The history file inside `dbpath`.
#[must_use]
pub fn path(dbpath: &Path) -> PathBuf {
    dbpath.join(HISTORY_FILE)
}

/// Appends one transaction's block.
///
/// The whole block is built in memory and written with a single `write_all` onto an `O_APPEND`
/// file, so a concurrent writer cannot interleave with it. The write is followed by
/// `sync_data`: this is the record that outlives the journal, and a history that loses the
/// last transaction to a power cut is a history nobody can trust.
///
/// # Errors
///
/// [`std::io::Error`] if the file cannot be opened, written, or flushed.
pub fn append(path: &Path, entry: &Entry, offset: LocalOffset) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).append(true).create(true).mode(FILE_MODE);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);

    let mut file = loop {
        match options.open(path) {
            Ok(file) => break file,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    };
    file.write_all(self::render(entry, offset).as_bytes())?;
    file.sync_data()
}

/// Renders one block.
#[must_use]
pub fn render(entry: &Entry, offset: LocalOffset) -> String {
    let mut block = String::new();
    block.push_str(&format!(
        "txn {VERSION} {} {}\n",
        entry.id,
        time_fmt::render(entry.started, offset)
    ));
    block.push_str(&format!("root {}\n", entry.root.display()));
    block.push_str(&format!("dbpath {}\n", entry.dbpath.display()));
    if let Some(command) = &entry.command {
        // A command line is one line. A newline inside it would forge a block line, so it is
        // flattened rather than trusted — the same reason the journal writes one intent per
        // line and parses nothing else.
        block.push_str(&format!("command {}\n", self::one_line(command)));
    }
    for action in &entry.actions {
        block.push_str(&action.store_line());
        block.push('\n');
    }
    for pacnew in &entry.pacnew {
        block.push_str(&format!("pacnew {}\n", self::one_line(&pacnew.to_string_lossy())));
    }
    for pacsave in &entry.pacsave {
        block.push_str(&format!("pacsave {}\n", self::one_line(&pacsave.to_string_lossy())));
    }
    for hook in &entry.hooks {
        block.push_str(&format!("hook {}\n", self::one_line(hook)));
    }
    let finished = entry.finished.unwrap_or(entry.started);
    match &entry.outcome {
        Outcome::Failed { reason } => block.push_str(&format!(
            "end failed {} {}\n",
            time_fmt::render(finished, offset),
            self::one_line(reason)
        )),
        outcome => block.push_str(&format!(
            "end {} {}\n",
            outcome.as_str(),
            time_fmt::render(finished, offset)
        )),
    }
    block
}

/// Reads the last `limit` transactions, newest last.
///
/// Reads at most `tail_bytes` from the end of the file, then drops everything before the first
/// `txn` line found — which is what makes an arbitrary seek into the middle of a block safe.
/// So `limit` bounds what is returned and `tail_bytes` bounds what is read, and neither
/// depends on the file's total size.
///
/// A missing file is an empty history, not an error: nothing has been recorded yet.
///
/// # Errors
///
/// [`std::io::Error`] if the file exists but cannot be read.
pub fn read_last(path: &Path, limit: usize, tail_bytes: u64) -> std::io::Result<Vec<Entry>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };

    let length = file.metadata()?.len();
    let from = length.saturating_sub(tail_bytes);
    // A tail read can land mid-block and mid-character. Both are handled below: the partial
    // first block is dropped, and invalid UTF-8 is replaced rather than refused.
    let partial = from > 0;
    file.seek(std::io::SeekFrom::Start(from))?;
    let mut bytes = Vec::new();
    (&mut file).take(tail_bytes).read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);

    let mut entries = self::parse(&text, partial);
    if entries.len() > limit {
        entries.drain(..entries.len().saturating_sub(limit));
    }
    Ok(entries)
}

/// Parses every complete block in `text`, oldest first.
///
/// `skip_first` drops the leading block, for a read that began part-way through the file.
#[must_use]
pub fn parse(text: &str, skip_first: bool) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut current: Option<Entry> = None;
    let mut version_understood = false;
    let mut skipped = !skip_first;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("txn ") {
            // A `txn` line always starts a block, even if the previous one had no `end`. A
            // block cut short by a full disk must not swallow the one written after it.
            entries.extend(current.take().filter(|_| version_understood));
            if !skipped {
                skipped = true;
                version_understood = false;
                continue;
            }
            match self::parse_header(rest) {
                Some((id, started)) => {
                    version_understood = true;
                    current = Some(Entry {
                        id,
                        started,
                        finished: None,
                        root: PathBuf::new(),
                        dbpath: PathBuf::new(),
                        command: None,
                        actions: Vec::new(),
                        pacnew: Vec::new(),
                        pacsave: Vec::new(),
                        hooks: Vec::new(),
                        outcome: Outcome::Interrupted,
                    });
                }
                // A version this build does not understand, or a header it cannot read. The
                // block's own lines are then meaningless to it, so they are skipped until the
                // next `txn`.
                None => version_understood = false,
            }
            continue;
        }

        let Some(entry) = current.as_mut() else { continue };
        if !version_understood {
            continue;
        }
        self::apply(entry, line);
    }

    entries.extend(current.filter(|_| version_understood));
    entries
}

/// Reads `<version> <id> <timestamp>`.
fn parse_header(rest: &str) -> Option<(String, i64)> {
    let mut fields = rest.split_whitespace();
    let version: u32 = fields.next()?.parse().ok()?;
    if version != VERSION {
        return None;
    }
    let id = fields.next()?.to_owned();
    let started = time_fmt::parse(fields.next()?)?;
    Some((id, started))
}

/// Applies one line of a block to the entry it belongs to.
///
/// An unknown keyword is ignored, matching `journal::parse`. A history file written by a
/// future build carries lines this one has no field for, and the transaction it describes is
/// still worth reporting.
fn apply(entry: &mut Entry, line: &str) {
    let (keyword, value) = line.split_once(' ').unwrap_or((line, ""));
    match keyword {
        "root" => entry.root = PathBuf::from(value),
        "dbpath" => entry.dbpath = PathBuf::from(value),
        "command" => entry.command = Some(value.to_owned()),
        "pacnew" => entry.pacnew.push(PathBuf::from(value)),
        "pacsave" => entry.pacsave.push(PathBuf::from(value)),
        "hook" => entry.hooks.push(value.to_owned()),
        "end" => self::apply_end(entry, value),
        _ => {
            if let Some(action) = Action::parse_store_line(line) {
                entry.actions.push(action);
            }
        }
    }
}

/// Applies an `end <outcome> <timestamp> [reason]` line.
fn apply_end(entry: &mut Entry, value: &str) {
    let mut fields = value.splitn(3, ' ');
    let outcome = fields.next().unwrap_or_default();
    entry.finished = fields.next().and_then(time_fmt::parse);
    entry.outcome = match outcome {
        "completed" => Outcome::Completed,
        "failed" => {
            Outcome::Failed { reason: fields.next().unwrap_or("the transaction failed").to_owned() }
        }
        _ => Outcome::Interrupted,
    };
}

/// Flattens `text` to one line, so no value can forge a block line.
fn one_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ")
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

    fn sample() -> Entry {
        Entry {
            id: "1757000000-42".to_owned(),
            started: 1_757_000_000,
            finished: Some(1_757_000_007),
            root: PathBuf::from("/"),
            dbpath: PathBuf::from("/var/lib/pacman"),
            command: Some("piko install foo".to_owned()),
            actions: vec![
                Action::Installed { name: "foo".to_owned(), version: "1.0.0-1".to_owned() },
                Action::Upgraded {
                    name: "bar".to_owned(),
                    from: "2.0-1".to_owned(),
                    to: "3.0-1".to_owned(),
                },
                Action::Removed { name: "baz".to_owned(), version: "1.2-1".to_owned() },
            ],
            pacnew: vec![PathBuf::from("/etc/foo.conf.pacnew")],
            pacsave: vec![PathBuf::from("/etc/baz.conf.pacsave")],
            hooks: vec!["30-foo.hook".to_owned()],
            outcome: Outcome::Completed,
        }
    }

    #[test]
    fn an_entry_round_trips() {
        let entry = sample();
        let text = render(&entry, LocalOffset::UTC);
        assert_eq!(parse(&text, false), vec![entry]);
    }

    #[test]
    fn a_failed_entry_keeps_its_reason() {
        let entry = Entry {
            outcome: Outcome::Failed { reason: "the hook 30-foo.hook refused it".to_owned() },
            ..sample()
        };
        let text = render(&entry, LocalOffset::UTC);
        assert_eq!(parse(&text, false), vec![entry]);
    }

    /// A `command` holding a newline must not be able to forge an `end` line, or a failed
    /// transaction could be made to read as a completed one.
    #[test]
    fn a_value_cannot_forge_a_block_line() {
        let entry = Entry {
            command: Some("piko install foo\nend completed 1970-01-01T00:00:00+0000".to_owned()),
            outcome: Outcome::Failed { reason: "it failed".to_owned() },
            ..sample()
        };
        let parsed = parse(&render(&entry, LocalOffset::UTC), false);
        assert!(matches!(parsed.first().map(|e| e.outcome.clone()), Some(Outcome::Failed { .. })));
    }

    #[test]
    fn appending_keeps_every_block() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join(HISTORY_FILE);
        for index in 0..3_i64 {
            let entry = Entry { started: 1_757_000_000 + index, ..sample() };
            append(&path, &entry, LocalOffset::UTC).unwrap();
        }
        assert_eq!(read_last(&path, 10, DEFAULT_TAIL_BYTES).unwrap().len(), 3);
    }

    #[test]
    fn reading_a_missing_file_is_an_empty_history() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        assert!(
            read_last(&dir.path().join(HISTORY_FILE), 10, DEFAULT_TAIL_BYTES).unwrap().is_empty()
        );
    }

    /// The newest transactions are the ones worth showing, so a limit must drop the oldest.
    #[test]
    fn a_limit_keeps_the_newest() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join(HISTORY_FILE);
        for index in 0..5_i64 {
            let entry =
                Entry { id: format!("id-{index}"), started: 1_757_000_000 + index, ..sample() };
            append(&path, &entry, LocalOffset::UTC).unwrap();
        }
        let entries = read_last(&path, 2, DEFAULT_TAIL_BYTES).unwrap();
        assert_eq!(
            entries.iter().map(|e| e.id.clone()).collect::<Vec<_>>(),
            vec!["id-3".to_owned(), "id-4".to_owned()]
        );
    }

    /// A tail read lands wherever the byte count puts it. The block it lands inside is
    /// incomplete, and reporting half a transaction is worse than reporting one fewer.
    #[test]
    fn a_partial_leading_block_is_dropped() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join(HISTORY_FILE);
        for index in 0..4_i64 {
            let entry =
                Entry { id: format!("id-{index}"), started: 1_757_000_000 + index, ..sample() };
            append(&path, &entry, LocalOffset::UTC).unwrap();
        }
        let whole = std::fs::metadata(&path).unwrap().len();
        // Land part-way into the file, guaranteed to be inside a block rather than on a
        // boundary.
        let entries = read_last(&path, 10, whole / 2 + 7).unwrap();
        assert!(entries.len() < 4, "{} blocks", entries.len());
        for entry in &entries {
            assert_eq!(entry.root, PathBuf::from("/"), "a partial block reached the reader");
        }
    }

    /// A power cut mid-append leaves a block with no `end`. The next transaction appends after
    /// it, and both must be readable.
    #[test]
    fn a_truncated_block_does_not_swallow_the_next_one() {
        let text = format!(
            "txn 1 first 1970-01-01T00:00:00+0000\nroot /\ninstalled foo 1.0.0-1\n{}",
            render(&sample(), LocalOffset::UTC)
        );
        let entries = parse(&text, false);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.first().map(|e| e.outcome.clone()), Some(Outcome::Interrupted));
        assert_eq!(entries.get(1).map(|e| e.outcome.clone()), Some(Outcome::Completed));
    }

    /// A block from a future build is skipped whole. Its lines must not be attributed to the
    /// block before it, which would report actions that transaction never took.
    #[test]
    fn a_block_of_an_unknown_version_is_skipped_whole() {
        let text = format!(
            "{}txn 99 future 1970-01-01T00:00:00+0000\ninstalled ghost 9.9-9\nend completed \
             1970-01-01T00:00:00+0000\n",
            render(&sample(), LocalOffset::UTC)
        );
        let entries = parse(&text, false);
        assert_eq!(entries.len(), 1);
        let names: Vec<&str> =
            entries.first().expect("one entry").actions.iter().map(Action::name).collect();
        assert!(!names.contains(&"ghost"), "{names:?}");
    }

    #[test]
    fn an_unknown_keyword_is_ignored() {
        let text = "txn 1 x 1970-01-01T00:00:00+0000\nroot /\nsomething new\nend completed \
                    1970-01-01T00:00:00+0000\n";
        assert_eq!(parse(text, false).len(), 1);
    }
}
