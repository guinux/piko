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
//! reason 0 depend
//! step 1 remove bar-2.0-1
//! begin
//! done 0
//! ```
//!
//! Everything up to `begin` is written and fsynced in one atomic step, before the first
//! mutation. Each `done` line is appended and fsynced as that step completes. So the journal
//! also records how far the transaction got.
//!
//! A `reason` line gives an install step's install reason. It is a line of its own, not a
//! third field of the `step` line, so the format stays at version 1. A reader that does not
//! know the line skips it, and still sees the journal and refuses to run a transaction. A
//! journal that carries no `reason` line is still read. The reason is then unknown.
//!
//! # Recovery
//!
//! [`Record::recovery`] works out what finishes the transaction: the removals and installs
//! that did not complete, checked against the local database. The steps run in order, so the
//! first outstanding step is the only one that can be half-applied. An install step cut there
//! can leave some of its files on disk with no entry that owns them. So that package is
//! reinstalled on its own, with its files released from the conflict check.

use std::{
    fmt::Write as _,
    io::Write as _,
    path::{Path, PathBuf},
};

use alpm_types::{Name, PackageFileName, PackageInstallReason};
use piko_db::{EntryName, LocalDatabase};

use crate::error::{Error, IoAction, Result};

/// The journal's file name, inside the database path.
///
/// Placed beside `db.lck`, not inside `local/`, for the same reason. The local database scan
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
        /// Whether the user asked for the package or a dependency pulled it in.
        ///
        /// `None` when the journal does not record it.
        reason: Option<PackageInstallReason>,
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
            Self::Install { package, .. } => format!("install {package}"),
            Self::Remove { entry } => format!("remove {entry}"),
        }
    }

    /// Parses a rendered intent.
    fn parse(text: &str) -> Option<Self> {
        let (verb, rest) = text.split_once(' ')?;
        match verb {
            "install" => Some(Self::Install { package: rest.to_owned(), reason: None }),
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

    /// Works out what finishes the transaction.
    ///
    /// `local` is the local database the transaction changed, read now. A removal is still to
    /// do only if its entry is still recorded, at the same version. A removal the interruption
    /// cut can have removed the entry already, and then it is complete. An install is always
    /// still to do, because a step that wrote its entry and stopped before its `done` line
    /// looks complete in the database and is not.
    #[must_use]
    pub fn recovery(&self, local: &LocalDatabase) -> Recovery {
        let first = (0..self.steps.len()).find(|index| !self.completed.contains(index));
        let mut recovery = Recovery::default();
        for (index, intent) in self.steps.iter().enumerate() {
            if self.completed.contains(&index) {
                continue;
            }
            match intent {
                Intent::Remove { entry } => {
                    let Ok(parsed) = EntryName::parse(entry) else {
                        recovery.unreadable.push(entry.clone());
                        continue;
                    };
                    let recorded = local
                        .get_str(parsed.name_str())
                        .is_some_and(|package| package.entry().as_str() == entry);
                    if recorded && let Ok(name) = parsed.name_str().parse::<Name>() {
                        recovery.remove.push(name);
                    }
                }
                Intent::Install { package, reason } => {
                    let Ok(file) = package.parse::<PackageFileName>() else {
                        recovery.unreadable.push(package.clone());
                        continue;
                    };
                    let target = Reinstall { name: file.name().clone(), reason: *reason };
                    if Some(index) == first {
                        recovery.interrupted = Some(target);
                    } else {
                        recovery.install.push(target);
                    }
                }
            }
        }
        recovery
    }
}

/// What finishes an interrupted transaction.
///
/// These are the steps still to do, by package name. Turning them into commands is the
/// caller's task. The order to run them in is: [`Recovery::interrupted`], then
/// [`Recovery::remove`], then [`Recovery::install`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Recovery {
    /// The package whose install step the interruption cut, if it cut one.
    ///
    /// Its extraction can have stopped part-way. Some of its files can then be on disk with no
    /// entry that owns them, and a plain install refuses them as file conflicts. Reinstall it
    /// on its own, with its files released from that check.
    pub interrupted: Option<Reinstall>,
    /// Packages still to remove.
    ///
    /// The transaction checked its dependencies as a whole, and the installs that follow can
    /// be what satisfies them again. So remove these without a dependency check.
    pub remove: Vec<Name>,
    /// Packages still to install. None of them was started.
    pub install: Vec<Reinstall>,
    /// Steps whose package name cannot be read from the journal.
    ///
    /// piko writes these names from parsed values, so this is empty unless the journal was
    /// damaged. They are reported rather than dropped.
    pub unreadable: Vec<String>,
}

impl Recovery {
    /// Whether nothing is left to do but remove the journal.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.interrupted.is_none()
            && self.remove.is_empty()
            && self.install.is_empty()
            && self.unreadable.is_empty()
    }
}

/// A package to install again, and why it was installed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reinstall {
    /// The package's name.
    pub name: Name,
    /// The install reason the transaction gave it. `None` when the journal does not record it.
    pub reason: Option<PackageInstallReason>,
}

/// The journal's spelling of an install reason.
const fn reason_word(reason: PackageInstallReason) -> &'static str {
    match reason {
        PackageInstallReason::Explicit => "explicit",
        PackageInstallReason::Depend => "depend",
    }
}

/// Reads a `reason` line's value.
fn parse_reason(word: &str) -> Option<PackageInstallReason> {
    match word {
        "explicit" => Some(PackageInstallReason::Explicit),
        "depend" => Some(PackageInstallReason::Depend),
        _ => None,
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
            if let Intent::Install { reason: Some(reason), .. } = step {
                let _ = writeln!(text, "reason {index} {}", reason_word(*reason));
            }
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

/// Why a journal file that exists cannot be read as a journal.
///
/// [`read`] carries this in [`Error::JournalUnreadable`]. The file is there, so a previous
/// run did write something. What it records is unknown, and so is the state of the system.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Unreadable {
    /// The file is not UTF-8 text.
    NotText,
    /// The first line is not a `piko-journal <version>` header. The file is empty, damaged, or
    /// not a journal.
    NoHeader,
    /// The header names a format version this build does not know. A newer build can have
    /// written it.
    UnknownVersion(String),
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotText => f.write_str("it is not text"),
            Self::NoHeader => f.write_str("it has no `piko-journal` header"),
            Self::UnknownVersion(version) => {
                write!(f, "it uses format version {version:?}, and this build reads only {VERSION}")
            }
        }
    }
}

/// How many characters of an unknown version [`Unreadable::UnknownVersion`] keeps. The value
/// is printed, and a damaged header can be a line of any length.
const MAX_VERSION_CHARS: usize = 32;

/// Reads a journal left behind by a previous run, if there is one.
///
/// `Ok(None)` means only one thing: no journal file exists. A file that exists but is not a
/// journal this build can read is an error, not an absence. A caller that runs a transaction
/// when this returns `Ok(None)` must never run one over an interrupted transaction it failed
/// to understand.
///
/// # Errors
///
/// - [`Error::Io`] if the file exists but cannot be read.
/// - [`Error::JournalUnreadable`] if the file exists but is not a journal this build can read.
pub fn read(dbpath: &Path) -> Result<Option<Record>> {
    let path = dbpath.join(JOURNAL_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(Error::io(&path, IoAction::Read, source)),
    };
    let parsed =
        String::from_utf8(bytes).map_err(|_| Unreadable::NotText).and_then(|text| parse(&text));
    match parsed {
        Ok(record) => Ok(Some(record)),
        Err(reason) => Err(Error::JournalUnreadable { path, reason }),
    }
}

/// Parses a journal's text.
///
/// The header is strict, and the body is tolerant. The header says which format the rest is
/// in, so a body read under the wrong format is a guess. After the header, an unrecognised or
/// truncated line is skipped rather than failing the whole read. A journal is read precisely
/// when something went wrong, and reporting nine of ten steps beats reporting nothing.
fn parse(text: &str) -> std::result::Result<Record, Unreadable> {
    let mut lines = text.lines();
    let version = lines
        .next()
        .and_then(|line| line.strip_prefix("piko-journal "))
        .ok_or(Unreadable::NoHeader)?
        .trim();
    if version != VERSION.to_string() {
        return Err(Unreadable::UnknownVersion(version.chars().take(MAX_VERSION_CHARS).collect()));
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
        } else if let Some(value) = line.strip_prefix("reason ") {
            if let Some((index, word)) = value.split_once(' ')
                && let Ok(index) = index.parse::<usize>()
                && let Some(Intent::Install { reason, .. }) = record.steps.get_mut(index)
            {
                *reason = parse_reason(word);
            }
        } else if line == "begin" {
            record.begun = true;
        } else if let Some(value) = line.strip_prefix("done ")
            && let Ok(index) = value.parse::<usize>()
        {
            record.completed.push(index);
        }
    }
    Ok(record)
}

/// Writes `contents` to `path` so that `path` is never observed partially written.
///
/// Uses the same sequence as `piko-db-write`'s writer, for the same reasons. `O_EXCL` on the
/// temporary rather than `O_TRUNC` means a planted symlink there cannot be written through.
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
    use piko_db::fixture::DbFixture;

    use super::*;

    fn steps() -> Vec<Intent> {
        vec![
            Intent::Install {
                package: "foo-1.0.0-1-x86_64.pkg.tar.zst".to_owned(),
                reason: Some(PackageInstallReason::Depend),
            },
            Intent::Remove { entry: "bar-2.0-1".to_owned() },
        ]
    }

    fn install(package: &str, reason: PackageInstallReason) -> Intent {
        Intent::Install { package: package.to_owned(), reason: Some(reason) }
    }

    fn remove(entry: &str) -> Intent {
        Intent::Remove { entry: entry.to_owned() }
    }

    fn record(steps: Vec<Intent>, completed: Vec<usize>) -> Record {
        Record {
            root: PathBuf::from("/"),
            dbpath: PathBuf::from("/var/lib/pacman"),
            steps,
            begun: true,
            completed,
        }
    }

    /// A local database holding the entries named.
    fn local(entries: &[&str]) -> (DbFixture, LocalDatabase) {
        let fixture = DbFixture::new();
        for entry in entries {
            fixture.package(entry).with_defaults().build();
        }
        let local = LocalDatabase::open(fixture.path()).unwrap();
        (fixture, local)
    }

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    fn reinstall(text: &str, reason: PackageInstallReason) -> Reinstall {
        Reinstall { name: name(text), reason: Some(reason) }
    }

    /// The first outstanding install is the one the interruption can have cut. It is set apart
    /// from the installs that never started, which a plain install finishes.
    #[test]
    fn the_cut_install_is_set_apart_from_the_unstarted_ones() {
        let record = record(
            vec![
                remove("old-1.0-1"),
                install("foo-1.0.0-1-x86_64.pkg.tar.zst", PackageInstallReason::Explicit),
                install("bar-2.0-1-any.pkg.tar.zst", PackageInstallReason::Depend),
            ],
            vec![0],
        );
        let (_fixture, local) = local(&[]);

        let recovery = record.recovery(&local);
        assert_eq!(recovery.interrupted, Some(reinstall("foo", PackageInstallReason::Explicit)));
        assert!(recovery.remove.is_empty());
        assert_eq!(recovery.install, [reinstall("bar", PackageInstallReason::Depend)]);
        assert!(recovery.unreadable.is_empty());
    }

    /// A removal is still to do only while its entry is still recorded. The one the
    /// interruption cut can have removed the entry already.
    #[test]
    fn a_removal_whose_entry_is_gone_is_complete() {
        let record = record(vec![remove("gone-1.0-1"), remove("kept-2.0-1")], vec![]);
        let (_fixture, local) = local(&["kept-2.0-1"]);

        let recovery = record.recovery(&local);
        assert_eq!(recovery.remove, [name("kept")]);
        assert!(recovery.interrupted.is_none());
        assert!(recovery.install.is_empty());
    }

    /// An entry recorded at another version is not the one the transaction meant to remove.
    #[test]
    fn a_removal_matches_the_recorded_version_only() {
        let record = record(vec![remove("foo-1.0-1")], vec![]);
        let (_fixture, local) = local(&["foo-2.0-1"]);

        assert!(record.recovery(&local).remove.is_empty());
    }

    /// Every step completed: only the journal is left to remove.
    #[test]
    fn a_completed_transaction_needs_no_recovery() {
        let record = record(
            vec![install("foo-1.0.0-1-x86_64.pkg.tar.zst", PackageInstallReason::Explicit)],
            vec![0],
        );
        let (_fixture, local) = local(&["foo-1.0.0-1"]);

        assert!(record.recovery(&local).is_empty());
    }

    /// A damaged step is reported, never dropped.
    #[test]
    fn an_unreadable_step_is_reported() {
        let record = record(
            vec![
                Intent::Install { package: "not a package file".to_owned(), reason: None },
                remove("no-version"),
            ],
            vec![],
        );
        let (_fixture, local) = local(&[]);

        let recovery = record.recovery(&local);
        assert_eq!(recovery.unreadable, ["not a package file", "no-version"]);
        assert!(!recovery.is_empty());
    }

    /// The install reason survives the journal.
    #[test]
    fn the_install_reason_survives() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::begin(dir.path(), Path::new("/"), &steps()).unwrap();
        drop(journal);

        let record = read(dir.path()).unwrap().unwrap();
        assert_eq!(record.steps, steps());
    }

    /// A journal with no `reason` line is still read. Its install reasons are unknown.
    #[test]
    fn a_journal_without_reasons_is_still_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(JOURNAL_FILE),
            "piko-journal 1\nroot /\ndbpath /var/lib/pacman\n\
             step 0 install foo-1.0.0-1-x86_64.pkg.tar.zst\nbegin\n",
        )
        .unwrap();

        let record = read(dir.path()).unwrap().unwrap();
        assert_eq!(
            record.steps,
            [Intent::Install {
                package: "foo-1.0.0-1-x86_64.pkg.tar.zst".to_owned(),
                reason: None
            }]
        );
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

    /// A journal in a format this build does not know is not read as version 1. It is
    /// reported as present and unreadable, never as absent.
    #[test]
    fn an_unknown_version_is_not_guessed_at() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(JOURNAL_FILE), "piko-journal 99\nbegin\n").unwrap();
        match read(dir.path()) {
            Err(Error::JournalUnreadable { path, reason }) => {
                assert_eq!(path, dir.path().join(JOURNAL_FILE));
                assert_eq!(reason, Unreadable::UnknownVersion("99".to_owned()));
            }
            other => panic!("an unknown version was not refused: {other:?}"),
        }
    }

    #[test]
    fn a_file_that_is_not_a_journal_is_reported_as_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        for text in ["hello\n", "", "piko-journal\nbegin\n"] {
            std::fs::write(dir.path().join(JOURNAL_FILE), text).unwrap();
            assert!(
                matches!(
                    read(dir.path()),
                    Err(Error::JournalUnreadable { reason: Unreadable::NoHeader, .. })
                ),
                "{text:?} was not refused"
            );
        }
    }

    #[test]
    fn a_journal_that_is_not_text_is_reported_as_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(JOURNAL_FILE), b"piko-journal 1\n\xff\n").unwrap();
        assert!(matches!(
            read(dir.path()),
            Err(Error::JournalUnreadable { reason: Unreadable::NotText, .. })
        ));
    }

    /// A damaged header can be a line of any length. The error keeps a bounded prefix.
    #[test]
    fn an_unknown_version_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let header = format!("piko-journal {}\n", "9".repeat(10_000));
        std::fs::write(dir.path().join(JOURNAL_FILE), header).unwrap();
        match read(dir.path()) {
            Err(Error::JournalUnreadable {
                reason: Unreadable::UnknownVersion(version), ..
            }) => {
                assert_eq!(version.len(), MAX_VERSION_CHARS);
            }
            other => panic!("the header was not refused: {other:?}"),
        }
    }

    /// The `step` line carries no reason. The `reason` line does, and the test above pins it.
    #[test]
    fn intents_round_trip() {
        for intent in [
            install("foo-1.0.0-1-x86_64.pkg.tar.zst", PackageInstallReason::Explicit),
            remove("bar-2.0-1"),
        ] {
            let parsed = Intent::parse(&intent.render());
            match (&intent, parsed) {
                (
                    Intent::Install { package, .. },
                    Some(Intent::Install { package: read, reason }),
                ) => {
                    assert_eq!(&read, package);
                    assert_eq!(reason, None);
                }
                (intent, parsed) => assert_eq!(parsed.as_ref(), Some(intent)),
            }
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
