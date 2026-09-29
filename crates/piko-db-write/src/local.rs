//! Creating, updating and removing entries in the local database.
//!
//! # Atomicity
//!
//! libalpm writes an entry's metadata with a plain `fopen(path, "w")`, streams into it, and
//! calls `fclose` without checking the result (`be_local.c:988-1108`). There is no temporary
//! file, no `rename`, and no `fsync`. The consequences are ordinary, not exotic. A power loss or
//! a full disk part-way through writing `desc` leaves a truncated `desc` that no longer parses.
//! The package it describes becomes unreadable to both pacman and piko. `fclose` going unchecked
//! means a write that failed at flush time is not even reported.
//!
//! piko writes to a temporary sibling, `fsync`s it, `rename`s it over the target, and `fsync`s
//! the directory. `rename(2)` within a directory is atomic. So at every instant the target is
//! either the complete old file or the complete new one. This is the clearest improvement
//! available over libalpm, and it costs nothing that matters. It is a handful of `fsync`s
//! against a transaction that is about to unpack megabytes.
//!
//! This does **not** make the whole transaction atomic, only each file. An interruption
//! between writing `desc` and writing `files` still leaves an entry that is internally
//! inconsistent, just not a corrupt one. Making the transaction atomic needs the journal
//! described for Phase C in the milestone plan. Without filesystem snapshots, even that buys
//! recoverability, not atomicity.

use std::{
    fs::File,
    io::Write as _,
    path::{Path, PathBuf},
    time::SystemTime,
};

use alpm_types::PackageInstallReason;

use piko_db::{
    EntryName, Limit, Limits, fs_util,
    local::schema_version::{ALPM_DB_VERSION, ALPM_DB_VERSION_FILE},
};

use crate::{
    error::{Error, IoAction, Result},
    lock::DbLock,
    record::{Record, RecordKind},
};

/// The directory inside a dbpath that holds the local database.
const LOCAL_DIR: &str = "local";

/// Mode for directories the writer creates, from `_alpm_local_db_prepare` (`be_local.c:941`).
const DIR_MODE: u32 = 0o755;

/// Mode for files the writer creates.
///
/// libalpm reaches this indirectly: it sets the process umask to `0022` around the write and
/// lets `fopen`'s `0666` get masked down (`be_local.c:984`). piko sets it explicitly instead.
/// See [`LocalDbWriter`]'s note on umask.
const FILE_MODE: u32 = 0o644;

/// The suffix used for the temporary file an atomic write goes through.
const TEMP_SUFFIX: &str = ".new";

/// Writes entries into a local database, holding the database lock.
///
/// Constructing one requires a [`DbLock`] **by reference**. A write cannot be attempted
/// without holding the lock, and the lock cannot be released while a writer is alive. That is
/// the one invariant worth spending the type system on here. libalpm enforces the same thing
/// with a runtime `ASSERT` on `handle->lockfd`.
///
/// # umask
///
/// libalpm calls `umask(0022)` before writing and restores it afterwards (`be_local.c:984`,
/// `be_local.c:1113`), and `umask(0000)` around `mkdir` (`be_local.c:940`). piko does not.
/// `umask` is process-global, so mutating it makes an unrelated thread's file creation depend
/// on when it happened to run. Modes are set explicitly after creation instead. That produces
/// the same `0755`/`0644` that libalpm produces, independent of the caller's umask and of what
/// any other thread is doing.
///
/// Each mode is set through an open descriptor (`fchmod`), never through a path. `chmod(2)`
/// follows a symbolic link. Anyone who can write into the directory could put one at the path
/// between the creation and the `chmod`, and a writer running as root would then change the
/// mode of any file on the system: `/etc/shadow` made readable, say.
#[derive(Debug)]
pub struct LocalDbWriter<'lock> {
    /// `<dbpath>/local`.
    root: PathBuf,
    limits: Limits,
    /// Proof that the database lock is held for as long as this writer exists.
    _lock: &'lock DbLock,
}

impl<'lock> LocalDbWriter<'lock> {
    /// Opens a writer for `<dbpath>/local`, creating the directory and its
    /// `ALPM_DB_VERSION` marker if they are absent.
    ///
    /// `lock` must be the lock for this same `dbpath`. Holding a lock on one database while
    /// writing another is a bug. The check here turns it into an error instead of a corrupted
    /// database.
    ///
    /// Creating `ALPM_DB_VERSION` is the writer's job precisely because
    /// [`piko_db::local::schema_version::check`] refuses to. Fabricating a version marker for a
    /// database whose layout is unknown papers over corruption. Writing one for a database this
    /// code just created states a fact instead. libalpm does the same, in `checkdbdir`
    /// (`be_local.c:370`) plus `_alpm_db_version` handling.
    ///
    /// # Errors
    ///
    /// - [`Error::WrongLock`] if `lock` does not belong to `dbpath`.
    /// - [`Error::Io`] if the directory or the version file cannot be created.
    /// - [`Error::Read`] wrapping [`piko_db::Error::SchemaVersion`] if a version file exists
    ///   and is not [`ALPM_DB_VERSION`].
    pub fn new(dbpath: &Path, lock: &'lock DbLock, limits: Limits) -> Result<Self> {
        let expected = lock.path().parent();
        if expected != Some(dbpath) {
            return Err(Error::WrongLock {
                lock: lock.path().to_path_buf(),
                dbpath: dbpath.to_path_buf(),
            });
        }

        let root = dbpath.join(LOCAL_DIR);
        create_dir(&root)?;

        let version = root.join(ALPM_DB_VERSION_FILE);
        if fs_util::exists_no_follow(&version) {
            // An existing database must already be a version this build understands.
            // Silently overwriting the marker would be exactly the corruption-papering the
            // reader refuses to do.
            piko_db::local::schema_version::check(&root, &limits)?;
        } else {
            atomic_write(&version, format!("{ALPM_DB_VERSION}\n").as_bytes())?;
        }

        Ok(Self { root, limits, _lock: lock })
    }

    /// `<dbpath>/local`.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory an entry lives in.
    #[must_use]
    pub fn entry_path(&self, entry: &EntryName) -> PathBuf {
        self.root.join(entry.as_str())
    }

    /// Creates an entry's directory.
    ///
    /// Fails if it already exists, matching `_alpm_local_db_prepare`'s bare `mkdir`
    /// (`be_local.c:941`). That is not an oversight in either implementation. An upgrade or a
    /// reinstall removes the old entry before creating the new one (`add.c`). So an entry that is
    /// already there means the caller has lost track of what it is doing. Silently writing into
    /// it would merge two packages' metadata.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the directory exists or cannot be created.
    pub fn create_entry(&self, entry: &EntryName) -> Result<()> {
        self.create_entry_unsynced(entry)?;
        sync_directory(&self.root)
    }

    /// Replaces an entry: removes `previous` and any entry already at `entry`, then creates
    /// `entry`, with **one** `fsync` of `local/` covering all three.
    ///
    /// This is the upgrade sequence, and doing it in one call is not merely tidier. Each of
    /// [`Self::create_entry`] and [`Self::remove_entry`] `fsync`s the root on its own. Called in
    /// sequence, they cost three root `fsync`s per package where one suffices. The directory's
    /// metadata covers every create and unlink within it, so syncing after the last one makes all
    /// of them durable. See `docs/perf-study.md` §4.2.
    ///
    /// The crash window is the same in kind as for three separate calls. Before the `fsync`, a
    /// crash may leave any prefix of the three operations visible. Re-running the same sequence
    /// recovers from any of them, because each removal is conditional on the path existing.
    ///
    /// `previous` is the entry installed under this package's name at its *old* version, if any.
    /// Passing `None` is a plain install.
    ///
    /// # Errors
    ///
    /// As [`Self::remove_entry`] and [`Self::create_entry`].
    pub fn replace_entry(&self, previous: Option<&EntryName>, entry: &EntryName) -> Result<()> {
        if let Some(previous) = previous.filter(|previous| self.entry_path(previous).exists()) {
            self.remove_entry_unsynced(previous)?;
        }
        if self.entry_path(entry).exists() {
            self.remove_entry_unsynced(entry)?;
        }
        self.create_entry_unsynced(entry)?;
        sync_directory(&self.root)
    }

    /// [`Self::create_entry`] without the root `fsync`, for [`Self::replace_entry`] to batch.
    fn create_entry_unsynced(&self, entry: &EntryName) -> Result<()> {
        let path = self.entry_path(entry);
        std::fs::create_dir(&path)
            .map_err(|source| Error::io(&path, IoAction::CreateDir, source))?;
        set_dir_mode(&path)
    }

    /// Begins a staged write of one entry's files, to be made durable together.
    ///
    /// This is the counterpart to calling [`Self::write_record`] and [`Self::write_raw`] in
    /// sequence. Prefer it when an entry gets more than one file. It pays one directory `fsync`
    /// for the whole entry instead of one per file, and it overlaps the data `fsync`s. See
    /// [`EntryWrite`] for the measurement, and for what the crash-safety property becomes.
    ///
    /// The entry directory must already exist. [`Self::create_entry`] makes it.
    pub fn entry_write(&self, entry: &EntryName) -> EntryWrite {
        EntryWrite { dir: self.entry_path(entry), staged: Vec::new() }
    }

    /// Writes a `desc` or `files` file into an existing entry, atomically.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the entry does not exist or the write fails at any stage.
    pub fn write_record(&self, entry: &EntryName, record: &Record) -> Result<()> {
        let path = self.entry_path(entry).join(file_name(record.kind()));
        atomic_write(&path, record.render().as_bytes())
    }

    /// Writes an arbitrary file into an existing entry, atomically.
    ///
    /// This is for members that are copied verbatim rather than built. Those are `mtree`,
    /// `install` and `changelog`, which libalpm likewise extracts into the entry rather than into
    /// the root (`add.c:194`). They have no `%SECTION%` structure, and `mtree` is gzipped binary.
    /// So [`Record`] does not apply, and the bytes are written as given.
    ///
    /// `modified` is the member's own modification time. Stamping it keeps the entry agreeing
    /// with the `ALPM-MTREE` data that describes it. This is the per-file counterpart of
    /// [`EntryWrite::raw`], which says more about why.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the entry does not exist or the write fails at any stage.
    pub fn write_raw(
        &self,
        entry: &EntryName,
        name: &str,
        contents: &[u8],
        modified: Option<SystemTime>,
    ) -> Result<()> {
        let path = self.entry_path(entry).join(name);
        atomic_write_at(&path, contents, modified)
    }

    /// Reads a `desc` or `files` file back out of an entry.
    ///
    /// Reading goes through [`piko_db::fs_util`] like every other read in the crate. So the
    /// symlink, file-type and size protections apply to the writer's read-modify-write path too.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the file cannot be read. [`Error::Read`] wrapping
    /// [`piko_db::Error::LimitExceeded`] or [`piko_db::Error::NotARegularFile`] if it is too large
    /// or is not a regular file. [`Error::Record`] if it is not a well-formed section list.
    pub fn read_record(&self, entry: &EntryName, kind: RecordKind) -> Result<Record> {
        let name = file_name(kind);
        let path = self.entry_path(entry).join(name);
        let limit = match kind {
            RecordKind::Desc => Limit::Desc,
            RecordKind::Files => Limit::Files,
        };
        let text = fs_util::read_capped_utf8_in(
            &self.entry_path(entry),
            name,
            limit,
            self.limits.get(limit),
        )?;
        Record::parse(kind, &text).map_err(|source| Error::Record { path, source })
    }

    /// Removes an entry's directory and everything in it.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] carrying [`std::io::ErrorKind::NotADirectory`] if the entry is a symlink
    /// rather than a real directory. Following it would delete something outside the database. Also
    /// [`Error::Io`] if the removal itself fails.
    pub fn remove_entry(&self, entry: &EntryName) -> Result<()> {
        self.remove_entry_unsynced(entry)?;
        sync_directory(&self.root)
    }

    /// [`Self::remove_entry`] without the root `fsync`, for [`Self::replace_entry`] to batch.
    fn remove_entry_unsynced(&self, entry: &EntryName) -> Result<()> {
        let path = self.entry_path(entry);
        if !fs_util::is_real_directory(&path)? {
            return Err(Error::io(
                &path,
                IoAction::Remove,
                std::io::Error::new(
                    std::io::ErrorKind::NotADirectory,
                    "entry is not a real directory",
                ),
            ));
        }
        std::fs::remove_dir_all(&path).map_err(|source| Error::io(&path, IoAction::Remove, source))
    }

    /// Changes an installed package's install reason, rewriting only that section.
    ///
    /// This is `pacman -D --asdeps` / `--asexplicit`. libalpm implements it the same way:
    /// `alpm_pkg_set_reason` re-writes the whole `desc` (`be_local.c:1196`). The one difference
    /// is that piko's rewrite is byte-identical everywhere else. It goes through [`Record`]
    /// rather than through a parse into typed fields and back.
    ///
    /// [`PackageInstallReason::Explicit`] *removes* the section rather than writing `0`. That is
    /// what libalpm does (`if(info->reason)` at `be_local.c:1029`), and what makes the result
    /// match a freshly installed explicit package.
    ///
    /// # Errors
    ///
    /// As [`LocalDbWriter::read_record`] and [`LocalDbWriter::write_record`].
    pub fn set_install_reason(
        &self,
        entry: &EntryName,
        reason: PackageInstallReason,
    ) -> Result<()> {
        let mut record = self.read_record(entry, RecordKind::Desc)?;
        match reason {
            PackageInstallReason::Explicit => {
                record.remove("REASON");
            }
            other => {
                record.set("REASON", vec![other.to_string()]).map_err(|source| Error::Record {
                    path: self.entry_path(entry).join(file_name(RecordKind::Desc)),
                    source,
                })?
            }
        }
        self.write_record(entry, &record)
    }
}

/// One entry's files, staged as temporaries and made durable together.
///
/// # Why this exists next to [`LocalDbWriter::write_record`]
///
/// [`LocalDbWriter::write_record`] is correct per *file*, and pays for that correctness per file
/// too. It costs an `fsync` of the data and an `fsync` of the directory, each one a filesystem
/// transaction commit. An entry is three or four files, so a 42-package upgrade issues 252
/// `fsync`s for 126 files. Measured on this machine's btrfs, that is **260 ms**. It is comparable
/// to the whole read side of `piko update`, and invisible in any command that only plans.
///
/// The directory `fsync`s are the easy half. A rename becomes durable when the directory is
/// synced. So syncing it once after the last rename makes *every* rename durable, not just the
/// last. Three become one.
///
/// The data `fsync`s cannot be removed, only overlapped. They are latency-bound rather than
/// CPU-bound, and a thread blocked in `fsync` costs nothing but a stack. Issuing an entry's three
/// together lets the filesystem merge them into fewer commits. That is why [`Self::commit`] uses
/// a scoped thread per staged file rather than a loop.
///
/// Measured, same corpus, `docs/perf-study.md` §4.2: **260 ms → 113 ms, 2.3x.**
///
/// # What this does not change
///
/// The crash-safety property is the one [`LocalDbWriter::write_record`] documents, and slightly
/// stronger. No `rename` happens until **every** staged file's data is durable. So an interruption
/// cannot leave an entry with a new `desc` beside an old `files`. It is still per-entry, not
/// per-transaction. See this module's header.
///
/// Dropping without [`Self::commit`] removes every temporary, so a failed step leaves the entry
/// exactly as it was.
#[derive(Debug)]
#[must_use = "staged files are discarded unless commit() is called"]
pub struct EntryWrite {
    /// The entry directory every staged file lands in.
    dir: PathBuf,
    staged: Vec<Temporary>,
}

impl EntryWrite {
    /// Stages a `desc` or `files` record.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the temporary cannot be created or written.
    pub fn record(&mut self, record: &Record) -> Result<()> {
        // A `desc` or `files` is built here rather than copied out of an archive. It has no
        // time of its own to carry, so it gets the time it was written.
        self.raw(file_name(record.kind()), record.render().as_bytes(), None)
    }

    /// Stages an arbitrary member — `mtree`, `install` or `changelog`, written verbatim.
    ///
    /// `modified` is the time the file should carry. For a member copied out of a package
    /// archive, that is the archive's own.
    ///
    /// Stamping it is not cosmetic. The `ALPM-MTREE` data records a time for `.INSTALL`, and
    /// `piko check` compares that record against this file. A member written with the time of
    /// the transaction reads as altered on every check from then on. libalpm reaches the same
    /// result through libarchive's `ARCHIVE_EXTRACT_TIME` (`add.c:194`).
    ///
    /// `None` leaves the time the write itself produced.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the temporary cannot be created or written.
    pub fn raw(&mut self, name: &str, contents: &[u8], modified: Option<SystemTime>) -> Result<()> {
        let mut temporary = Temporary::create(&self.dir.join(name))?;
        temporary.write_all(contents)?;
        // After the write, which would otherwise move the time forward again. Before
        // `commit`'s sync, which is what makes it durable. The rename does not touch the time:
        // it travels with the inode.
        if let Some(time) = modified {
            temporary.set_modified(time)?;
        }
        self.staged.push(temporary);
        Ok(())
    }

    /// Makes every staged file durable, then publishes them all.
    ///
    /// The order is the one [`LocalDbWriter::write_record`] documents, widened to the whole entry.
    /// Fsync every temporary, then rename every temporary, then fsync the directory once. A crash
    /// at any point leaves each destination either wholly absent, wholly the old file, or wholly
    /// the new one.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if any `fsync` or `rename` fails. Whatever has not been renamed yet is
    /// removed, so a partial failure does not leave temporaries behind.
    pub fn commit(mut self) -> Result<()> {
        // On an error, every temporary not yet renamed is dropped, which removes it.
        self.sync_all_staged()?;
        for temporary in std::mem::take(&mut self.staged) {
            temporary.publish()?;
        }

        // Every rename above becomes durable with this one directory sync. The directory's
        // metadata covers all of them, so syncing per rename would buy nothing.
        sync_directory(&self.dir)
    }

    /// `fsync`s every staged temporary, one scoped thread each.
    ///
    /// `File::sync_all` takes `&self` and `File` is `Sync`, so the threads borrow the staged
    /// files rather than owning them. An entry has three or four files, so this spawns three or
    /// four threads that are immediately blocked on the kernel. The point is overlap, not CPU
    /// parallelism.
    fn sync_all_staged(&self) -> Result<()> {
        std::thread::scope(|scope| {
            let handles: Vec<_> =
                self.staged.iter().map(|entry| scope.spawn(move || entry.sync())).collect();

            // Every handle is joined before the first failure is returned. So no thread is
            // left running against a `Temporary` this function is about to hand back.
            let mut first_error = None;
            for handle in handles {
                match handle.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => first_error = first_error.or(Some(error)),
                    // This crate cannot produce a panic inside `sync_all`, but swallowing one
                    // would turn a bug into a silently unsynced file.
                    Err(_) => {
                        first_error = first_error.or_else(|| {
                            Some(Error::io(
                                &self.dir,
                                IoAction::Sync,
                                std::io::Error::other("a sync thread panicked"),
                            ))
                        });
                    }
                }
            }
            first_error.map_or(Ok(()), Err)
        })
    }
}

/// The file name a record of this kind is stored under.
const fn file_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Desc => "desc",
        RecordKind::Files => "files",
    }
}

/// Creates a directory and its parents, then fixes its mode.
///
/// A symbolic link at `path` is refused, not followed: `set_dir_mode` opens it `O_NOFOLLOW`.
fn create_dir(path: &Path) -> Result<()> {
    if fs_util::is_real_directory(path)? {
        return Ok(());
    }
    std::fs::create_dir_all(path).map_err(|source| Error::io(path, IoAction::CreateDir, source))?;
    set_dir_mode(path)
}

/// Sets an open file to [`FILE_MODE`] through its descriptor (`fchmod`).
///
/// `path` names the file in an error. It is never used to reach the file, because a path can
/// name a symbolic link planted since the file was opened.
pub(crate) fn set_file_mode(file: &File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))
            .map_err(|source| Error::io(path, IoAction::Metadata, source))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path);
    }
    Ok(())
}

/// Sets a directory to [`DIR_MODE`] through a descriptor opened `O_DIRECTORY | O_NOFOLLOW`.
///
/// Something else can replace the directory between its creation and this call. A symbolic
/// link is refused by the open (`ELOOP`), so no mode lands on its target. A directory put there
/// by someone else gets the mode, which changes nothing outside the directory they could
/// already write into.
fn set_dir_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let directory = File::options()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|source| Error::io(path, IoAction::Open, source))?;
        directory
            .set_permissions(std::fs::Permissions::from_mode(DIR_MODE))
            .map_err(|source| Error::io(path, IoAction::Metadata, source))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Refuses to rename `temp` unless it still names the file this process wrote through `file`.
///
/// Anyone who can write into the directory can unlink the temporary and put a file or a
/// symbolic link of their own at its path, at any point while it is being written. `rename`
/// works on the name, so it would move theirs over the destination: content nobody verified,
/// or a link the next reader of the destination follows. The descriptor still holds the file
/// this process wrote. Its device and inode must match what `temp` names now.
///
/// This leaves a window between the comparison and the `rename`, which no call on a name can
/// close. It catches a replacement made while the file was written, which is the long window.
///
/// # Errors
///
/// - [`Error::TemporaryReplaced`] if `temp` names another file, or nothing.
/// - [`Error::Io`] if the descriptor cannot be stat'ed.
pub(crate) fn ensure_unreplaced(file: &File, temp: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let written =
            file.metadata().map_err(|source| Error::io(temp, IoAction::Metadata, source))?;
        let named = std::fs::symlink_metadata(temp).ok();
        let same =
            named.is_some_and(|named| named.dev() == written.dev() && named.ino() == written.ino());
        if !same {
            return Err(Error::TemporaryReplaced { path: temp.to_path_buf() });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (file, temp);
    }
    Ok(())
}

/// Writes `contents` to `path` so that `path` is never observed partially written.
///
/// The sequence is the standard one, and every step earns its place.
///
/// 1. Write to `path.new`. A crash here leaves the target untouched.
/// 2. `fsync` it. Without this the rename can be durable while the data is not. A crash then
///    yields an *empty* file rather than no file.
/// 3. `rename` over the target. This is atomic within a directory.
/// 4. `fsync` the directory. This makes the rename itself durable.
fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    atomic_write_at(path, contents, None)
}

/// [`atomic_write`], with `modified` stamped onto the file before it lands.
///
/// The time is set after the write, so the write cannot move it forward again. It is set before
/// the `fsync`, which makes it durable. See [`EntryWrite::raw`] for why a member copied out of an
/// archive needs one.
fn atomic_write_at(path: &Path, contents: &[u8], modified: Option<SystemTime>) -> Result<()> {
    let mut temporary = Temporary::create(path)?;
    temporary.write_all(contents)?;
    if let Some(time) = modified {
        temporary.set_modified(time)?;
    }
    temporary.sync()?;
    temporary.publish()?;
    sync_directory(path.parent().unwrap_or(Path::new(".")))
}

/// A file written beside its destination, which a rename publishes.
///
/// It is created `O_EXCL` (see [`create_temp`]) and set to [`FILE_MODE`] through its descriptor,
/// whatever the umask. Until [`Self::publish`], dropping it removes the temporary, so a failed
/// write never leaves one behind for some other code path to rename later.
#[derive(Debug)]
pub(crate) struct Temporary {
    file: File,
    temp: PathBuf,
    destination: PathBuf,
    /// Set once the rename is done, so `Drop` leaves the name alone.
    published: bool,
}

impl Temporary {
    /// Creates the temporary beside `destination`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the temporary cannot be created or its mode cannot be set.
    pub(crate) fn create(destination: &Path) -> Result<Self> {
        let temp = temp_path(destination);
        let file = create_temp(&temp)?;
        let temporary =
            Self { file, temp, destination: destination.to_path_buf(), published: false };
        // The mode on the open is masked by the caller's umask, so it is set explicitly. Set
        // before the data is synced, so the sync makes it durable too.
        set_file_mode(&temporary.file, &temporary.temp)?;
        Ok(temporary)
    }

    /// The temporary's path.
    pub(crate) fn path(&self) -> &Path {
        &self.temp
    }

    /// The path the temporary is published at.
    pub(crate) fn destination(&self) -> &Path {
        &self.destination
    }

    /// The open temporary, to write into.
    pub(crate) const fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Writes all of `bytes`.
    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.file.write_all(bytes).map_err(|source| Error::io(&self.temp, IoAction::Write, source))
    }

    /// Sets the modification time the published file carries. Call it after the last write.
    pub(crate) fn set_modified(&self, time: SystemTime) -> Result<()> {
        self.file
            .set_modified(time)
            .map_err(|source| Error::io(&self.temp, IoAction::Metadata, source))
    }

    /// Makes the contents, the mode and the time durable.
    pub(crate) fn sync(&self) -> Result<()> {
        self.file.sync_all().map_err(|source| Error::io(&self.temp, IoAction::Sync, source))
    }

    /// Renames the temporary over its destination, if it still names the file written.
    ///
    /// This does not sync the directory. The caller does, once, after its last rename.
    pub(crate) fn publish(mut self) -> Result<()> {
        ensure_unreplaced(&self.file, &self.temp)?;
        std::fs::rename(&self.temp, &self.destination)
            .map_err(|source| Error::io(&self.destination, IoAction::Rename, source))?;
        self.published = true;
        Ok(())
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

/// Creates the temporary file, refusing to write through anything that is already there.
///
/// The obvious spelling, `create(true).truncate(true)`, **follows a final symlink**. The
/// destination of an atomic write is safe from that by construction, because `rename` replaces a
/// symlink rather than resolving it. The temporary file is not safe. A `desc.new` planted as a
/// symlink to `/etc/passwd` would be truncated and filled with package metadata. The process doing
/// that is typically root.
///
/// `create_new` is `O_CREAT | O_EXCL`, which fails on *any* existing path, including a dangling
/// symlink. So the file this returns always did not exist a moment ago. `O_NOFOLLOW` is redundant
/// next to `O_EXCL` and is set anyway. That way the guarantee does not silently depend on which of
/// the two flags a future edit keeps.
///
/// A leftover temporary from an interrupted write must not wedge the database permanently. So
/// exactly one retry is made after removing it, with `remove_file`, which unlinks a symlink
/// rather than following it. One retry, not a loop: if the file reappears immediately,
/// something else is writing to this database, and stopping is correct.
pub(crate) fn create_temp(temp: &Path) -> Result<File> {
    let mut options = File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(FILE_MODE).custom_flags(libc::O_NOFOLLOW);
    }

    match options.open(temp) {
        Ok(file) => Ok(file),
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(temp)
                .map_err(|source| Error::io(temp, IoAction::Remove, source))?;
            options.open(temp).map_err(|source| Error::io(temp, IoAction::Create, source))
        }
        Err(source) => Err(Error::io(temp, IoAction::Create, source)),
    }
}

/// The temporary sibling an atomic write to `path` goes through.
///
/// The suffix is fixed, not random. The database lock already excludes a second writer. And a
/// predictable name means a leftover from a crashed write is recognizable as such, rather than
/// accumulating as unexplained litter.
pub(crate) fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(TEMP_SUFFIX);
    PathBuf::from(name)
}

/// Flushes a directory's own metadata, making a create or rename within it durable.
pub(crate) fn sync_directory(directory: &Path) -> Result<()> {
    let handle =
        File::open(directory).map_err(|source| Error::io(directory, IoAction::Open, source))?;
    handle.sync_all().map_err(|source| Error::io(directory, IoAction::Sync, source))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use piko_db::LocalDatabase;

    /// A dbpath with its lock held, plus the entry name used throughout.
    struct Harness {
        dir: tempfile::TempDir,
    }

    impl Harness {
        fn new() -> Self {
            Self { dir: tempfile::tempdir().unwrap() }
        }

        fn dbpath(&self) -> &Path {
            self.dir.path()
        }

        fn lock(&self) -> DbLock {
            DbLock::acquire(self.dbpath()).unwrap()
        }
    }

    fn entry(raw: &str) -> EntryName {
        EntryName::parse(raw).unwrap()
    }

    fn desc(name: &str, version: &str) -> Record {
        let text = format!("%NAME%\n{name}\n\n%VERSION%\n{version}\n\n");
        Record::parse(RecordKind::Desc, &text).unwrap()
    }

    #[test]
    fn a_staged_entry_write_publishes_every_member_at_once() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();

        let mut staged = writer.entry_write(&name);
        staged.record(&desc("foo", "1.0.0-1")).unwrap();
        staged.raw("mtree", b"gzipped bytes", None).unwrap();

        // Nothing is visible under its real name until `commit`. The temporaries are.
        let dir = writer.entry_path(&name);
        assert!(!dir.join("desc").exists(), "desc must not appear before commit");
        assert!(dir.join("desc.new").exists(), "the temporary should be staged");

        staged.commit().unwrap();
        assert!(dir.join("desc").exists());
        assert_eq!(std::fs::read(dir.join("mtree")).unwrap(), b"gzipped bytes");
        assert!(!dir.join("desc.new").exists(), "no temporary may survive a commit");
        assert!(!dir.join("mtree.new").exists());
    }

    /// A raw member keeps the time it was asked for, through both the staged path and the
    /// per-file one.
    ///
    /// The `fsync` and the `rename` sit between the request and the result. Neither may move
    /// the time. That is what keeps an entry's `install` agreeing with the `ALPM-MTREE` data
    /// that records a time for it.
    #[test]
    fn a_raw_member_keeps_the_time_it_was_given() {
        let stamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();
        let dir = writer.entry_path(&name);

        let mut staged = writer.entry_write(&name);
        staged.raw("install", b"post_install() { :; }", Some(stamp)).unwrap();
        staged.commit().unwrap();
        writer.write_raw(&name, "changelog", b"1.0.0-1 first release", Some(stamp)).unwrap();

        for member in ["install", "changelog"] {
            let seen = std::fs::metadata(dir.join(member)).unwrap().modified().unwrap();
            assert_eq!(seen, stamp, "{member} did not keep the requested time");
        }

        // A record has no time of its own to keep, so it gets the time of the write.
        let mut staged = writer.entry_write(&name);
        staged.record(&desc("foo", "1.0.0-1")).unwrap();
        staged.commit().unwrap();
        let written = std::fs::metadata(dir.join("desc")).unwrap().modified().unwrap();
        assert!(written > stamp, "a record must not inherit some other member's time");
    }

    /// Dropping without committing must leave the entry exactly as it was. Otherwise a failed
    /// step would litter the database with `.new` files. [`create_temp`]'s one retry would then
    /// have to clean them up on the next run.
    #[test]
    fn dropping_a_staged_entry_write_removes_every_temporary() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();
        let dir = writer.entry_path(&name);

        {
            let mut staged = writer.entry_write(&name);
            staged.record(&desc("foo", "1.0.0-1")).unwrap();
            staged.raw("install", b"post_install() { :; }", None).unwrap();
            assert!(dir.join("desc.new").exists());
        }

        assert!(!dir.join("desc.new").exists(), "the temporary must be removed on drop");
        assert!(!dir.join("install.new").exists());
        assert!(!dir.join("desc").exists(), "nothing may be published without a commit");
    }

    /// A staged write must produce the same bytes as the per-file path it replaces. Otherwise
    /// the batching would be a silent behavior change rather than a durability one.
    #[test]
    fn staged_and_per_file_writes_produce_identical_files() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();

        let staged_entry = entry("staged-1.0.0-1");
        writer.create_entry(&staged_entry).unwrap();
        let mut staged = writer.entry_write(&staged_entry);
        staged.record(&desc("staged", "1.0.0-1")).unwrap();
        staged.commit().unwrap();

        let direct_entry = entry("direct-1.0.0-1");
        writer.create_entry(&direct_entry).unwrap();
        writer.write_record(&direct_entry, &desc("direct", "1.0.0-1")).unwrap();

        let staged_bytes = std::fs::read(writer.entry_path(&staged_entry).join("desc")).unwrap();
        let direct_bytes = std::fs::read(writer.entry_path(&direct_entry).join("desc")).unwrap();
        assert_eq!(
            String::from_utf8(staged_bytes).unwrap().replace("staged", "X"),
            String::from_utf8(direct_bytes).unwrap().replace("direct", "X"),
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(writer.entry_path(&staged_entry).join("desc"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, FILE_MODE, "a staged file keeps the explicit mode");
        }
    }

    /// The upgrade sequence in one call, with one root `fsync`. The old entry must be gone,
    /// and the new one must exist and be empty.
    #[test]
    fn replace_entry_removes_the_old_entry_and_creates_the_new_one() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();

        let old = entry("foo-1.0.0-1");
        writer.create_entry(&old).unwrap();
        writer.write_record(&old, &desc("foo", "1.0.0-1")).unwrap();

        let new = entry("foo-2.0.0-1");
        writer.replace_entry(Some(&old), &new).unwrap();

        assert!(!writer.entry_path(&old).exists(), "the replaced entry must be gone");
        assert!(writer.entry_path(&new).is_dir());
        assert_eq!(std::fs::read_dir(writer.entry_path(&new)).unwrap().count(), 0);
    }

    /// A reinstall names the same entry as `previous` and as the new one. Removing it twice
    /// would fail on the second `remove_dir_all`, so the existence check has to guard both.
    #[test]
    fn replace_entry_handles_the_same_entry_named_twice() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();

        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();
        writer.write_record(&name, &desc("foo", "1.0.0-1")).unwrap();

        writer.replace_entry(Some(&name), &name).unwrap();

        assert!(writer.entry_path(&name).is_dir());
        assert_eq!(std::fs::read_dir(writer.entry_path(&name)).unwrap().count(), 0);
    }

    /// A plain install passes `None`, and an entry that is not there must not be an error.
    #[test]
    fn replace_entry_with_no_previous_is_a_plain_create() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();

        let name = entry("foo-1.0.0-1");
        writer.replace_entry(None, &name).unwrap();
        assert!(writer.entry_path(&name).is_dir());
    }

    #[test]
    fn creates_the_layout_and_the_version_marker() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();

        assert!(writer.root().is_dir());
        let version = writer.root().join(ALPM_DB_VERSION_FILE);
        assert_eq!(std::fs::read_to_string(&version).unwrap(), "9\n");
    }

    /// Opening an existing database must not rewrite its marker. It must refuse a version this
    /// build does not implement, rather than "upgrade" it in place.
    #[test]
    fn refuses_a_database_at_another_schema_version() {
        let harness = Harness::new();
        let root = harness.dbpath().join(LOCAL_DIR);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(ALPM_DB_VERSION_FILE), "8\n").unwrap();

        let lock = harness.lock();
        let err = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap_err();
        assert!(matches!(&err, Error::Read(piko_db::Error::SchemaVersion(_))), "got {err:?}");
        // And it left the marker alone.
        assert_eq!(std::fs::read_to_string(root.join(ALPM_DB_VERSION_FILE)).unwrap(), "8\n");
    }

    #[test]
    fn refuses_a_lock_belonging_to_another_dbpath() {
        let harness = Harness::new();
        let other = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(other.path()).unwrap();

        let err = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap_err();
        assert!(matches!(err, Error::WrongLock { .. }), "got {err:?}");
    }

    /// The end-to-end claim: what the writer produces, the reader reads.
    #[test]
    fn a_written_entry_is_readable_by_the_scanner() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();

        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();
        writer.write_record(&name, &desc("foo", "1.0.0-1")).unwrap();
        // Parent directories are listed because a real `files` lists them. `alpm-db`'s reader
        // rejects a path whose parent is absent.
        writer
            .write_record(
                &name,
                &Record::parse(RecordKind::Files, "%FILES%\nusr/\nusr/bin/\nusr/bin/foo\n\n")
                    .unwrap(),
            )
            .unwrap();

        let db = LocalDatabase::open(writer.root()).unwrap();
        assert_eq!(db.len(), 1);
        let package = db.get_str("foo").unwrap();
        assert_eq!(package.version().to_string(), "1.0.0-1");
        assert_eq!(
            package.file_list().unwrap(),
            [PathBuf::from("usr/"), PathBuf::from("usr/bin/"), PathBuf::from("usr/bin/foo")]
        );
    }

    #[test]
    fn entry_directories_and_files_get_pacmans_modes() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let harness = Harness::new();
            let lock = harness.lock();
            let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
            let name = entry("foo-1.0.0-1");
            writer.create_entry(&name).unwrap();
            writer.write_record(&name, &desc("foo", "1.0.0-1")).unwrap();

            let dir_mode =
                std::fs::metadata(writer.entry_path(&name)).unwrap().permissions().mode();
            let file_mode = std::fs::metadata(writer.entry_path(&name).join("desc"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, DIR_MODE, "{:o}", dir_mode & 0o777);
            assert_eq!(file_mode & 0o777, FILE_MODE, "{:o}", file_mode & 0o777);
        }
    }

    /// Silently writing into an existing entry would merge two packages' metadata.
    #[test]
    fn refuses_to_create_an_entry_twice() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();
        assert!(writer.create_entry(&name).is_err());
    }

    #[test]
    fn overwrites_an_existing_record_atomically() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();

        writer.write_record(&name, &desc("foo", "1.0.0-1")).unwrap();
        writer.write_record(&name, &desc("foo", "2.0.0-1")).unwrap();

        let text = std::fs::read_to_string(writer.entry_path(&name).join("desc")).unwrap();
        assert_eq!(text, "%NAME%\nfoo\n\n%VERSION%\n2.0.0-1\n\n");
        // The temporary file must not survive a successful write.
        assert!(!writer.entry_path(&name).join("desc.new").exists());
    }

    #[test]
    fn round_trips_a_record_through_disk() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();
        writer.write_record(&name, &desc("foo", "1.0.0-1")).unwrap();

        let read_back = writer.read_record(&name, RecordKind::Desc).unwrap();
        assert_eq!(read_back.render(), desc("foo", "1.0.0-1").render());
    }

    #[test]
    fn removes_an_entry() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();
        writer.write_record(&name, &desc("foo", "1.0.0-1")).unwrap();

        writer.remove_entry(&name).unwrap();
        assert!(!writer.entry_path(&name).exists());
        assert!(writer.remove_entry(&name).is_err(), "removing it twice must fail");
    }

    /// Following a symlinked entry would delete a directory outside the database.
    #[cfg(unix)]
    #[test]
    fn refuses_to_remove_a_symlinked_entry() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();

        let outside = harness.dbpath().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("precious"), b"x").unwrap();

        let name = entry("foo-1.0.0-1");
        std::os::unix::fs::symlink(&outside, writer.entry_path(&name)).unwrap();

        let err = writer.remove_entry(&name).unwrap_err();
        assert!(matches!(err, Error::Io { action: IoAction::Remove, .. }), "got {err:?}");
        assert!(outside.join("precious").exists(), "the symlink target was followed");
    }

    /// A symlink planted where the temporary file goes must not be written through. The
    /// naive `create(true).truncate(true)` open does exactly that, as root.
    #[cfg(unix)]
    #[test]
    fn never_writes_through_a_symlinked_temporary_file() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();

        let victim = harness.dbpath().join("victim");
        std::fs::write(&victim, b"do not overwrite me").unwrap();
        std::os::unix::fs::symlink(&victim, writer.entry_path(&name).join("desc.new")).unwrap();

        writer.write_record(&name, &desc("foo", "1.0.0-1")).unwrap();

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "do not overwrite me");
        assert_eq!(
            std::fs::read_to_string(writer.entry_path(&name).join("desc")).unwrap(),
            "%NAME%\nfoo\n\n%VERSION%\n1.0.0-1\n\n"
        );
    }

    /// The destination is safe for a different reason: `rename` replaces a symlink instead of
    /// resolving it. This is worth pinning down rather than relying on.
    #[cfg(unix)]
    #[test]
    fn never_writes_through_a_symlinked_destination() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();

        let victim = harness.dbpath().join("victim");
        std::fs::write(&victim, b"do not overwrite me").unwrap();
        std::os::unix::fs::symlink(&victim, writer.entry_path(&name).join("desc")).unwrap();

        writer.write_record(&name, &desc("foo", "1.0.0-1")).unwrap();

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "do not overwrite me");
        let written = writer.entry_path(&name).join("desc");
        assert!(!std::fs::symlink_metadata(&written).unwrap().is_symlink());
        assert_eq!(
            std::fs::read_to_string(&written).unwrap(),
            "%NAME%\nfoo\n\n%VERSION%\n1.0.0-1\n\n"
        );
    }

    /// A temporary left behind by an interrupted write must not wedge the database.
    #[test]
    fn recovers_from_a_leftover_temporary_file() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();
        std::fs::write(writer.entry_path(&name).join("desc.new"), b"half a file").unwrap();

        writer.write_record(&name, &desc("foo", "1.0.0-1")).unwrap();
        assert_eq!(
            std::fs::read_to_string(writer.entry_path(&name).join("desc")).unwrap(),
            "%NAME%\nfoo\n\n%VERSION%\n1.0.0-1\n\n"
        );
    }

    /// `pacman -D --asdeps`. One section changes, every other byte stays put.
    #[test]
    fn set_install_reason_changes_only_that_section() {
        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();

        // The record has a URL a URL parser would normalize, and a group, so both round-trip
        // hazards are live.
        let original = "%NAME%\nfoo\n\n%URL%\nhttps://archlinux.org\n\n%SIZE%\n10\n\n\
                        %GROUPS%\ng\n\n%DEPENDS%\nbar\n\n";
        writer.write_record(&name, &Record::parse(RecordKind::Desc, original).unwrap()).unwrap();

        writer.set_install_reason(&name, PackageInstallReason::Depend).unwrap();
        let text = std::fs::read_to_string(writer.entry_path(&name).join("desc")).unwrap();
        assert_eq!(
            text,
            "%NAME%\nfoo\n\n%URL%\nhttps://archlinux.org\n\n%SIZE%\n10\n\n\
             %REASON%\n1\n\n%GROUPS%\ng\n\n%DEPENDS%\nbar\n\n"
        );

        // And back: explicit removes the section and restores the original bytes exactly.
        writer.set_install_reason(&name, PackageInstallReason::Explicit).unwrap();
        let text = std::fs::read_to_string(writer.entry_path(&name).join("desc")).unwrap();
        assert_eq!(text, original);
    }

    /// A staged member's temporary swapped for a symbolic link is refused at commit. Its mode
    /// was set through the descriptor at staging, so it never reached the link's target.
    #[cfg(unix)]
    #[test]
    fn a_staged_temporary_swapped_for_a_symlink_is_neither_followed_nor_installed() {
        use std::os::unix::fs::PermissionsExt as _;

        let harness = Harness::new();
        let lock = harness.lock();
        let writer = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap();
        let name = entry("foo-1.0.0-1");
        writer.create_entry(&name).unwrap();

        let victim = harness.dbpath().join("secret");
        std::fs::write(&victim, b"private").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut staged = writer.entry_write(&name);
        staged.raw("install", b"post_install() { :; }", None).unwrap();
        let temp = temp_path(&writer.entry_path(&name).join("install"));
        std::fs::remove_file(&temp).unwrap();
        std::os::unix::fs::symlink(&victim, &temp).unwrap();

        let err = staged.commit().unwrap_err();
        assert!(matches!(err, Error::TemporaryReplaced { .. }), "got {err:?}");
        let mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the mode change followed the planted symlink");
        assert!(!writer.entry_path(&name).join("install").exists());
    }

    /// `<dbpath>/local` as a symbolic link is refused. Following it would give the link's target
    /// the database's `0755`, and write the database there.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_local_directory_is_refused_and_its_target_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let harness = Harness::new();
        let target = harness.dbpath().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&target, harness.dbpath().join(LOCAL_DIR)).unwrap();

        let lock = harness.lock();
        let err = LocalDbWriter::new(harness.dbpath(), &lock, Limits::default()).unwrap_err();
        assert!(matches!(err, Error::Io { action: IoAction::Open, .. }), "got {err:?}");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "the mode change followed the symlinked local directory");
        assert!(!target.join(ALPM_DB_VERSION_FILE).exists());
    }
}
