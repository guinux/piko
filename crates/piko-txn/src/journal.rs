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
//! group 1 3
//! ```
//!
//! Everything up to `begin` is written and fsynced in one atomic step, before the first
//! mutation. Each `done` line is appended and fsynced as that step completes. So the journal
//! also records how far the transaction got.
//!
//! A `group` line names the first and the last step of a group of installs, and is appended
//! and fsynced before the first of them starts. The steps of a group are extracted one after
//! the other, flushed together, then each gets its `done` line. A reader that does not know the
//! line skips it, as for `reason`.
//!
//! A `reason` line gives an install step's install reason. It is a line of its own, not a
//! third field of the `step` line, so the format stays at version 1. A reader that does not
//! know the line skips it, and still sees the journal and refuses to run a transaction. A
//! journal that carries no `reason` line is still read. The reason is then unknown.
//!
//! # Recovery
//!
//! [`Record::recovery`] works out what finishes the transaction: the removals and installs
//! that did not complete, checked against the local database. The steps run in order, so only
//! the first outstanding step, or the group it belongs to, can be half-applied. An install step
//! cut there can leave some of its files on disk with no entry that owns them. So those
//! packages are reinstalled apart from the others, with their files released from the conflict
//! check.

use std::{
    fmt::Write as _,
    io::Write as _,
    ops::RangeInclusive,
    path::{Path, PathBuf},
};

use alpm_types::{Name, PackageFileName, PackageInstallReason};
use piko_db::{EntryName, local::LocalDatabase};

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
#[non_exhaustive]
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
    /// The groups of install steps the transaction started, each from its first step to its
    /// last.
    pub groups: Vec<RangeInclusive<usize>>,
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
        // The steps the interruption can have cut: the first outstanding one, or the whole
        // group it belongs to. A group's steps are extracted before any of them is recorded.
        let cut = first.map(|first| {
            self.groups
                .iter()
                .rev()
                .find(|group| group.contains(&first))
                .map_or(first..=first, |group| first..=*group.end())
        });
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
                    if cut.as_ref().is_some_and(|cut| cut.contains(&index)) {
                        recovery.interrupted.push(target);
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
    /// The packages whose install steps the interruption cut: the first outstanding step, or
    /// every outstanding step of its group.
    ///
    /// Their extraction can have stopped part-way, or ended without its entry. Some of their
    /// files can then be on disk with no entry that owns them, and a plain install refuses them
    /// as file conflicts. Reinstall them apart from the others, with their files released from
    /// that check.
    pub interrupted: Vec<Reinstall>,
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
        self.interrupted.is_empty()
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
    /// written, fsynced, linked to the target, and the directory is fsynced. So a crash
    /// during the write leaves either no journal or a complete one, never a half-written one
    /// that recovery would misread.
    ///
    /// A journal already there is never replaced. The link fails when the target exists, so
    /// the refusal and the write are one step: no other writer can put a journal there between
    /// a check and the write.
    ///
    /// # Errors
    ///
    /// [`Error::UnfinishedTransaction`] if a journal is already there, readable or not.
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

        // The descriptor that wrote the journal keeps appending to it: progress lines extend the
        // file rather than rewriting it, and a crash mid-append truncates at a line boundary at
        // worst. The name is never opened again, so nothing put there after the link is
        // written through.
        let file = write_new(&path, text.as_bytes())?;
        Ok(Self { path, file })
    }

    /// Records that the steps `steps` are about to run as one group, and fsyncs.
    ///
    /// Written before the first of them starts, so a crash during the group leaves a journal
    /// that says which steps can hold files with no entry.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the append or the sync fails.
    pub fn group(&mut self, steps: RangeInclusive<usize>) -> Result<()> {
        writeln!(self.file, "group {} {}", steps.start(), steps.end())
            .map_err(|source| Error::io(&self.path, IoAction::Write, source))?;
        self.file.sync_data().map_err(|source| Error::io(&self.path, IoAction::Sync, source))
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
    /// Something other than a regular file sits at the journal's path: a directory, a FIFO, a
    /// device or a symbolic link.
    NotARegularFile,
    /// The file is larger than [`piko_db::Limits::journal_bytes`].
    TooLarge,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotText => f.write_str("it is not text"),
            Self::NoHeader => f.write_str("it has no `piko-journal` header"),
            Self::UnknownVersion(version) => {
                write!(f, "it uses format version {version:?}, and this build reads only {VERSION}")
            }
            Self::NotARegularFile => f.write_str("it is not a regular file"),
            Self::TooLarge => f.write_str("it is larger than a journal can be"),
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
    // The audited door: bounded, no final symlink followed, and a FIFO refused rather than
    // waited on. Each refusal is a journal that is there and cannot be read, which refuses a
    // transaction like any other unreadable journal.
    let max = piko_db::Limits::default().get(piko_db::Limit::Journal);
    let unreadable = |reason| Err(Error::JournalUnreadable { path: path.clone(), reason });
    let bytes = match piko_db::fs_util::read_capped(&path, piko_db::Limit::Journal, max) {
        Ok(bytes) => bytes,
        Err(piko_db::Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(piko_db::Error::Io { source, .. })
            if source.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) =>
        {
            return unreadable(Unreadable::NotARegularFile);
        }
        Err(piko_db::Error::NotARegularFile { .. }) => {
            return unreadable(Unreadable::NotARegularFile);
        }
        Err(piko_db::Error::LimitExceeded { .. }) => return unreadable(Unreadable::TooLarge),
        Err(piko_db::Error::Io { source, .. }) => {
            return Err(Error::io(&path, IoAction::Read, source));
        }
        Err(other) => {
            return Err(Error::io(&path, IoAction::Read, std::io::Error::other(other.to_string())));
        }
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
        groups: Vec::new(),
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
        } else if let Some(value) = line.strip_prefix("group ") {
            if let Some((first, last)) = value.split_once(' ')
                && let (Ok(first), Ok(last)) = (first.parse::<usize>(), last.parse::<usize>())
            {
                record.groups.push(first..=last);
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

/// Writes `contents` to `path`, which must not exist, so that `path` is never observed partially
/// written. Returns the descriptor that wrote it, open for appending.
///
/// The temporary is written and fsynced, then hard-linked to `path`. `link` fails with `EEXIST`
/// when `path` is there, which a rename would replace. `O_EXCL` on the temporary rather than
/// `O_TRUNC` means a planted symlink there cannot be written through. A temporary left by a
/// crash is removed and written again.
///
/// # Errors
///
/// [`Error::UnfinishedTransaction`] if `path` exists. [`Error::Io`] otherwise.
fn write_new(path: &Path, contents: &[u8]) -> Result<std::fs::File> {
    use rustix::fs::OFlags;
    use std::os::unix::fs::OpenOptionsExt as _;

    let directory = path.parent().unwrap_or(Path::new("."));
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".new");
    let temp = PathBuf::from(temp);

    let mut options = std::fs::File::options();
    // Append mode, because the caller keeps this descriptor for the progress lines.
    options
        .append(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(OFlags::NOFOLLOW.bits().cast_signed());

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

    // The temporary goes whether or not the link succeeded. A failed removal leaves a second
    // name for the same file, which the next write removes before it starts.
    let linked = std::fs::hard_link(&temp, path);
    let _ = std::fs::remove_file(&temp);
    match linked {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::UnfinishedTransaction { path: path.to_path_buf() });
        }
        Err(source) => return Err(Error::io(path, IoAction::Create, source)),
    }

    std::fs::File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(|source| Error::io(directory, IoAction::Sync, source))?;
    Ok(file)
}

/// Fails if `dbpath` holds a transaction journal, readable or not.
///
/// A journal is removed when its transaction finishes, so a journal that is there records a
/// transaction that did not. [`crate::Transaction::verify`] asks this first, so a run stops
/// before it downloads or reads anything. [`Journal::begin`] refuses again when it writes,
/// under `db.lck`, which is the refusal no race can pass.
///
/// # Errors
///
/// [`Error::UnfinishedTransaction`] if a readable journal is there, [`Error::JournalUnreadable`]
/// if one is there that this build cannot read, and [`Error::Io`] if the check itself fails.
pub(crate) fn refuse_if_present(dbpath: &Path) -> Result<()> {
    match read(dbpath)? {
        Some(_) => Err(Error::UnfinishedTransaction { path: dbpath.join(JOURNAL_FILE) }),
        None => Ok(()),
    }
}

#[cfg(test)]
#[expect(
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
            groups: Vec::new(),
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
        assert_eq!(recovery.interrupted, [reinstall("foo", PackageInstallReason::Explicit)]);
        assert!(recovery.remove.is_empty());
        assert_eq!(recovery.install, [reinstall("bar", PackageInstallReason::Depend)]);
        assert!(recovery.unreadable.is_empty());
    }

    /// A group's steps are extracted before any of them is recorded. So every outstanding step
    /// of the group the interruption cut can hold files with no entry, and none after it can.
    #[test]
    fn every_outstanding_step_of_the_cut_group_is_set_apart() {
        let mut record = record(
            vec![
                install("aaa-1.0-1-any.pkg.tar.zst", PackageInstallReason::Explicit),
                install("bbb-1.0-1-any.pkg.tar.zst", PackageInstallReason::Explicit),
                install("ccc-1.0-1-any.pkg.tar.zst", PackageInstallReason::Depend),
                install("ddd-1.0-1-any.pkg.tar.zst", PackageInstallReason::Explicit),
                remove("old-1.0-1"),
                install("eee-1.0-1-any.pkg.tar.zst", PackageInstallReason::Explicit),
            ],
            vec![0, 1],
        );
        record.groups = vec![0..=3];
        let (_fixture, local) = local(&["old-1.0-1"]);

        let recovery = record.recovery(&local);
        assert_eq!(
            recovery.interrupted,
            [
                reinstall("ccc", PackageInstallReason::Depend),
                reinstall("ddd", PackageInstallReason::Explicit)
            ]
        );
        assert_eq!(recovery.remove, [name("old")]);
        assert_eq!(recovery.install, [reinstall("eee", PackageInstallReason::Explicit)]);
    }

    /// A `group` line is read back as written, after the `done` lines before it.
    #[test]
    fn a_group_line_is_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::begin(dir.path(), Path::new("/"), &steps()).unwrap();
        journal.group(0..=1).unwrap();
        journal.completed(0).unwrap();
        drop(journal);

        let record = read(dir.path()).unwrap().unwrap();
        assert_eq!(record.groups, [0..=1]);
        assert_eq!(record.completed, [0]);
    }

    /// A removal is still to do only while its entry is still recorded. The one the
    /// interruption cut can have removed the entry already.
    #[test]
    fn a_removal_whose_entry_is_gone_is_complete() {
        let record = record(vec![remove("gone-1.0-1"), remove("kept-2.0-1")], vec![]);
        let (_fixture, local) = local(&["kept-2.0-1"]);

        let recovery = record.recovery(&local);
        assert_eq!(recovery.remove, [name("kept")]);
        assert!(recovery.interrupted.is_empty());
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

    /// The root and the database path a journal records are read back as written. The
    /// recovery commands `piko report` prints name them.
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

    /// A FIFO at the journal's path is refused without waiting for a writer, and so is a
    /// symbolic link. Either one still refuses a transaction: a journal is there.
    #[test]
    fn a_journal_that_is_not_a_regular_file_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join(JOURNAL_FILE);

        std::os::unix::fs::symlink("/etc/hostname", &journal).unwrap();
        assert!(
            matches!(
                read(dir.path()),
                Err(Error::JournalUnreadable { reason: Unreadable::NotARegularFile, .. })
            ),
            "a symbolic link was followed"
        );
        std::fs::remove_file(&journal).unwrap();

        // `mkfifo(3)` is `unsafe`, which this workspace forbids, so the utility makes it.
        let made = std::process::Command::new("mkfifo").arg(&journal).status();
        if !made.is_ok_and(|status| status.success()) {
            eprintln!("skipping the FIFO half: mkfifo is unavailable");
            return;
        }
        assert!(
            matches!(
                read(dir.path()),
                Err(Error::JournalUnreadable { reason: Unreadable::NotARegularFile, .. })
            ),
            "a FIFO was not refused"
        );
    }

    /// A journal past its bound is refused, never read short.
    #[test]
    fn an_oversized_journal_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let max = piko_db::Limits::default().get(piko_db::Limit::Journal);
        let file = std::fs::File::create(dir.path().join(JOURNAL_FILE)).unwrap();
        file.set_len(max + 1).unwrap();
        assert!(matches!(
            read(dir.path()),
            Err(Error::JournalUnreadable { reason: Unreadable::TooLarge, .. })
        ));
    }

    /// Progress lines go through the descriptor that wrote the journal. A file swapped in at
    /// the journal's name afterwards receives none of them.
    #[test]
    fn progress_lines_go_to_the_journal_that_was_written() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::begin(dir.path(), Path::new("/"), &steps()).unwrap();
        let path = dir.path().join(JOURNAL_FILE);
        let moved = dir.path().join("moved");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, b"planted\n").unwrap();

        journal.completed(0).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "planted\n");
        assert!(std::fs::read_to_string(&moved).unwrap().ends_with("done 0\n"));
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

    /// Beginning a transaction over an abandoned journal is refused, and the journal is left as
    /// it was. It is the only record of what the abandoned transaction did.
    #[test]
    fn beginning_again_refuses_and_keeps_an_abandoned_journal() {
        let dir = tempfile::tempdir().unwrap();
        let first = Journal::begin(dir.path(), Path::new("/"), &steps()).unwrap();
        std::mem::forget(first);
        let written = std::fs::read(dir.path().join(JOURNAL_FILE)).unwrap();

        let error = Journal::begin(
            dir.path(),
            Path::new("/"),
            &[Intent::Remove { entry: "only-1-1".to_owned() }],
        )
        .unwrap_err();

        assert!(matches!(error, Error::UnfinishedTransaction { .. }), "got {error:?}");
        assert_eq!(std::fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), written);
        assert!(!dir.path().join("piko-journal.new").exists(), "the temporary was left behind");
    }

    /// A journal this build cannot read is refused as well, and left as it was.
    #[test]
    fn beginning_over_an_unreadable_journal_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(JOURNAL_FILE), "piko-journal 99\n").unwrap();

        assert!(matches!(
            refuse_if_present(dir.path()).unwrap_err(),
            Error::JournalUnreadable { .. }
        ));
        let error = Journal::begin(dir.path(), Path::new("/"), &steps()).unwrap_err();
        assert!(matches!(error, Error::UnfinishedTransaction { .. }), "got {error:?}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(JOURNAL_FILE)).unwrap(),
            "piko-journal 99\n"
        );
    }
}
