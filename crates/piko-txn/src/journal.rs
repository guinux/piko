//! An intent log, so an interrupted transaction is detectable afterwards.
//!
//! libalpm has no equivalent. If pacman is killed part-way through a transaction, the system
//! is left partly changed and nothing records that it happened. The next run cannot tell a
//! half-applied upgrade from a healthy system, and neither can the user.
//!
//! piko writes what it is about to do, and fsyncs that, before it touches anything. A journal
//! present at startup means a previous run did not finish.
//!
//! # What this does not buy
//!
//! Not atomicity. This distinction matters enough to state plainly. There is no undo here:
//! files already replaced stay replaced. Without filesystem snapshots, rolling a transaction
//! back would mean keeping a copy of everything it overwrites — a different and much larger
//! feature. What the journal buys is that an interruption is detectable and describable rather
//! than silent. That is the difference between a user who knows to re-run and a user whose
//! system is subtly wrong.
//!
//! # Format
//!
//! Line-oriented text. It must be readable by a human staring at a broken system, and by a
//! piko build that may itself be a different version:
//!
//! ```text
//! piko-journal 1
//! root /
//! dbpath /var/lib/pacman
//! step 0 install foo-1.0.0-1-x86_64.pkg.tar.zst
//! step 1 remove bar-2.0-1
//! begin
//! done 0
//! ```
//!
//! Everything up to `begin` is written and fsynced in one atomic step, before the first
//! mutation. Each `done` line is appended and fsynced as that step completes. So the journal
//! also records how far the transaction got.

use std::{
    fmt::Write as _,
    io::Write as _,
    path::{Path, PathBuf},
};

use crate::error::{Error, IoAction, Result};

/// The journal's file name, inside the database path.
///
/// Placed beside `db.lck`, not inside `local/`, for the same reason: the local database scan
/// enumerates directories, so a stray file beside them is skipped without a special case.
pub const JOURNAL_FILE: &str = "piko-journal";

/// The format version this build writes and understands.
const VERSION: u32 = 1;

/// One thing a transaction intends to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Intent {
    /// Install the named package file.
    Install {
        /// The package file's name, as it appears in the cache.
        package: String,
    },
    /// Remove the named installed entry.
    Remove {
        /// The entry directory name, `<name>-<version>`.
        entry: String,
    },
}

impl Intent {
    /// The journal line for this intent, without its index.
    fn render(&self) -> String {
        match self {
            Self::Install { package } => format!("install {package}"),
            Self::Remove { entry } => format!("remove {entry}"),
        }
    }

    /// Parses a rendered intent.
    fn parse(text: &str) -> Option<Self> {
        let (verb, rest) = text.split_once(' ')?;
        match verb {
            "install" => Some(Self::Install { package: rest.to_owned() }),
            "remove" => Some(Self::Remove { entry: rest.to_owned() }),
            _ => None,
        }
    }
}

/// A transaction's recorded intent, as found on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// The installation root the transaction targeted.
    pub root: PathBuf,
    /// The database path it targeted.
    pub dbpath: PathBuf,
    /// Every step, in order.
    pub steps: Vec<Intent>,
    /// Whether the transaction had begun mutating when it stopped.
    ///
    /// `false` means it was interrupted before touching anything. The system is untouched, and
    /// the journal is merely litter.
    pub begun: bool,
    /// Indices of the steps that completed.
    pub completed: Vec<usize>,
}

impl Record {
    /// The steps that did not complete.
    #[must_use]
    pub fn outstanding(&self) -> Vec<&Intent> {
        self.steps
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.completed.contains(index))
            .map(|(_, intent)| intent)
            .collect()
    }
}

/// An open journal, held for the duration of a transaction.
#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: std::fs::File,
}

impl Journal {
    /// Writes the intent and fsyncs it, returning a journal that can record progress.
    ///
    /// This must complete before the first mutation. The write is atomic: a temporary file is
    /// written, fsynced, renamed over the target, and the directory is fsynced. So a crash
    /// during the write leaves either no journal or a complete one, never a half-written one
    /// that recovery would misread.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the journal cannot be written.
    pub fn begin(dbpath: &Path, root: &Path, steps: &[Intent]) -> Result<Self> {
        let path = dbpath.join(JOURNAL_FILE);

        let mut text = String::new();
        let _ = writeln!(text, "piko-journal {VERSION}");
        let _ = writeln!(text, "root {}", root.display());
        let _ = writeln!(text, "dbpath {}", dbpath.display());
        for (index, step) in steps.iter().enumerate() {
            let _ = writeln!(text, "step {index} {}", step.render());
        }
        let _ = writeln!(text, "begin");

        atomic_write(&path, text.as_bytes())?;

        // Reopened for appending: progress lines extend the file rather than rewriting it.
        // A crash mid-append then truncates at a line boundary at worst.
        let file = std::fs::File::options()
            .append(true)
            .open(&path)
            .map_err(|source| Error::io(&path, IoAction::Open, source))?;
        Ok(Self { path, file })
    }

    /// Records that step `index` completed, and fsyncs.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the append or the sync fails.
    pub fn completed(&mut self, index: usize) -> Result<()> {
        writeln!(self.file, "done {index}")
            .map_err(|source| Error::io(&self.path, IoAction::Write, source))?;
        self.file.sync_data().map_err(|source| Error::io(&self.path, IoAction::Sync, source))
    }

    /// Removes the journal, marking the transaction complete.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the file cannot be removed. Report this rather than ignore it: a
    /// journal left behind makes the next run believe a transaction was interrupted.
    pub fn finish(self) -> Result<()> {
        let path = self.path.clone();
        drop(self.file);
        match std::fs::remove_file(&path) {
            Ok(()) | Err(_) if !path.exists() => Ok(()),
            Ok(()) => Ok(()),
            Err(source) => Err(Error::io(&path, IoAction::Remove, source)),
        }
    }

    /// The journal file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Reads a journal left behind by a previous run, if there is one.
///
/// # Errors
///
/// [`Error::Io`] if the file exists but cannot be read.
pub fn read(dbpath: &Path) -> Result<Option<Record>> {
    let path = dbpath.join(JOURNAL_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(Error::io(&path, IoAction::Read, source)),
    };
    Ok(parse(&text))
}

/// Parses a journal's text.
///
/// Tolerant by design: a journal is read precisely when something went wrong. An unrecognised
/// or truncated line is skipped rather than failing the whole read. Reporting nine of ten
/// steps beats reporting nothing.
fn parse(text: &str) -> Option<Record> {
    let mut lines = text.lines();
    let version = lines.next()?.strip_prefix("piko-journal ")?;
    if version.trim() != VERSION.to_string() {
        return None;
    }

    let mut record = Record {
        root: PathBuf::new(),
        dbpath: PathBuf::new(),
        steps: Vec::new(),
        begun: false,
        completed: Vec::new(),
    };

    for line in lines {
        if let Some(value) = line.strip_prefix("root ") {
            record.root = PathBuf::from(value);
        } else if let Some(value) = line.strip_prefix("dbpath ") {
            record.dbpath = PathBuf::from(value);
        } else if let Some(value) = line.strip_prefix("step ") {
            if let Some((_, rest)) = value.split_once(' ')
                && let Some(intent) = Intent::parse(rest)
            {
                record.steps.push(intent);
            }
        } else if line == "begin" {
            record.begun = true;
        } else if let Some(value) = line.strip_prefix("done ")
            && let Ok(index) = value.parse::<usize>()
        {
            record.completed.push(index);
        }
    }
    Some(record)
}

/// Writes `contents` to `path` so that `path` is never observed partially written.
///
/// Uses the same sequence as `piko-db-write`'s writer, for the same reasons: `O_EXCL` on the
/// temporary rather than `O_TRUNC`, so a planted symlink there cannot be written through.
fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let directory = path.parent().unwrap_or(Path::new("."));
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".new");
    let temp = PathBuf::from(temp);

    let mut options = std::fs::File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o644).custom_flags(libc::O_NOFOLLOW);
    }

    let mut file = match options.open(&temp) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&temp)
                .map_err(|source| Error::io(&temp, IoAction::Remove, source))?;
            options.open(&temp).map_err(|source| Error::io(&temp, IoAction::Create, source))?
        }
        Err(source) => return Err(Error::io(&temp, IoAction::Create, source)),
    };

    let written = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|source| Error::io(&temp, IoAction::Write, source));
    if let Err(error) = written {
        drop(file);
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    drop(file);

    if let Err(source) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(Error::io(path, IoAction::Rename, source));
    }

    std::fs::File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(|source| Error::io(directory, IoAction::Sync, source))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn steps() -> Vec<Intent> {
        vec![
            Intent::Install { package: "foo-1.0.0-1-x86_64.pkg.tar.zst".to_owned() },
            Intent::Remove { entry: "bar-2.0-1".to_owned() },
        ]
    }

    #[test]
    fn a_finished_transaction_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::begin(dir.path(), Path::new("/"), &steps()).unwrap();
        assert!(dir.path().join(JOURNAL_FILE).exists());

        journal.finish().unwrap();
        assert!(!dir.path().join(JOURNAL_FILE).exists());
        assert!(read(dir.path()).unwrap().is_none());
    }

    /// The property the journal exists for: an interruption stays visible afterwards.
    #[test]
    fn an_interrupted_transaction_is_detectable_and_says_how_far_it_got() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::begin(dir.path(), Path::new("/"), &steps()).unwrap();
        journal.completed(0).unwrap();
        // Dropped without `finish`, the way a killed process would drop it.
        drop(journal);

        let record = read(dir.path()).unwrap().unwrap();
        assert!(record.begun);
        assert_eq!(record.steps, steps());
        assert_eq!(record.completed, [0]);
        assert_eq!(record.outstanding(), [&Intent::Remove { entry: "bar-2.0-1".to_owned() }]);
    }

    /// A journal written but not yet begun means the system stays untouched.
    #[test]
    fn the_recorded_root_and_dbpath_survive() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::begin(dir.path(), Path::new("/some/root"), &steps()).unwrap();
        std::mem::forget(journal);

        let record = read(dir.path()).unwrap().unwrap();
        assert_eq!(record.root, Path::new("/some/root"));
        assert_eq!(record.dbpath, dir.path());
    }

    /// A journal is read exactly when something has gone wrong. A truncated tail must not
    /// throw away the part that did survive.
    #[test]
    fn a_truncated_journal_still_reports_what_it_can() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::begin(dir.path(), Path::new("/"), &steps()).unwrap();
        drop(journal);

        let path = dir.path().join(JOURNAL_FILE);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("done 0\ndone ");
        std::fs::write(&path, text).unwrap();

        let record = read(dir.path()).unwrap().unwrap();
        assert_eq!(record.completed, [0], "the complete line survived, the partial one did not");
        assert_eq!(record.steps.len(), 2);
    }

    #[test]
    fn an_unknown_version_is_not_guessed_at() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(JOURNAL_FILE), "piko-journal 99\nbegin\n").unwrap();
        assert!(read(dir.path()).unwrap().is_none());
    }

    #[test]
    fn a_file_that_is_not_a_journal_is_not_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(JOURNAL_FILE), "hello\n").unwrap();
        assert!(read(dir.path()).unwrap().is_none());
    }

    #[test]
    fn intents_round_trip() {
        for intent in steps() {
            assert_eq!(Intent::parse(&intent.render()), Some(intent));
        }
    }

    /// Beginning a transaction twice must replace the journal, not append to a stale one.
    #[test]
    fn beginning_again_replaces_an_abandoned_journal() {
        let dir = tempfile::tempdir().unwrap();
        let first = Journal::begin(dir.path(), Path::new("/"), &steps()).unwrap();
        std::mem::forget(first);

        let second = Journal::begin(
            dir.path(),
            Path::new("/"),
            &[Intent::Remove { entry: "only-1-1".to_owned() }],
        )
        .unwrap();
        std::mem::forget(second);

        let record = read(dir.path()).unwrap().unwrap();
        assert_eq!(record.steps, [Intent::Remove { entry: "only-1-1".to_owned() }]);
    }
}
