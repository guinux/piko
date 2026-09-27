//! The audited filesystem core.
//!
//! Every byte this crate reads off disk passes through `read_capped`. The hardening lives in one
//! place, so it can be reviewed on its own. The `MetadataFile` convenience constructors from
//! `alpm-common` (`from_file`) are deliberately never used. They call `read_to_string` on a
//! path with no bound and no file-type check.
//!
//! Three properties are enforced here:
//!
//! 1. **No symlink traversal.** A metadata file is opened with `O_NOFOLLOW`. A symlink
//!    planted in an entry directory cannot redirect a read outside the database. A file inside
//!    an entry is read through [`read_capped_in`], which opens the entry directory and then the
//!    file by descriptor, each `O_NOFOLLOW`: an entry directory swapped for a symlink after the
//!    scan cannot redirect the read either.
//! 2. **No blocking on non-files.** The open uses `O_NONBLOCK`, and the descriptor is
//!    `fstat`ed before any read. Without this, opening a FIFO blocks until a writer
//!    appears, and reading `/dev/zero` never terminates.
//! 3. **No unbounded reads.** Reads stop one byte past the configured limit and report
//!    [`Error::LimitExceeded`] instead of returning truncated data.
//!
//! # Public surface
//!
//! Most of this module is crate-private. A small, deliberate part is public: `piko-db-write`
//! lives in another crate and must not reimplement the audited door. A second, unaudited path
//! to the filesystem is exactly what this module exists to prevent. Export only what a caller
//! outside the crate has a demonstrated need for. Extend it when a real need appears, not in
//! advance.

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, IoAction, Result},
    limits::Limit,
};

/// Opens `path` for reading without following a final symlink and without blocking.
fn open_no_follow(path: &Path) -> Result<File> {
    let mut options = File::options();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    options.open(path).map_err(|source| Error::io(path, IoAction::Open, source))
}

/// Fails unless `file` is a regular file.
///
/// An `fstat` catches a FIFO, socket, device node or directory before an unbounded read
/// would.
pub(crate) fn ensure_regular_file(file: &File, path: &Path) -> Result<std::fs::Metadata> {
    let metadata = file.metadata().map_err(|source| Error::io(path, IoAction::Metadata, source))?;
    if !metadata.is_file() {
        return Err(Error::NotARegularFile { path: path.to_path_buf() });
    }
    Ok(metadata)
}

/// Opens `path` for reading, following a final symlink but never blocking.
///
/// Unlike `open_no_follow`, this **does** follow a symlink. It exists for repository
/// archives. The path is a single file the caller names explicitly (e.g. `core.db`), not one
/// of many enumerated directory entries. The [alpm-repo-db] spec itself documents
/// `repo.db -> repo.db.tar.gz` as the normal server-side layout. Refusing to follow it would
/// break the documented access path for no security benefit. The `O_NONBLOCK` plus `fstat`
/// check still applies. A FIFO or device node named like an archive still cannot hang the
/// process, or be read as if it were one.
///
/// It is public for a caller that must stream a file rather than read it into memory:
/// `piko-sig` hands the open descriptor to GPGME, which hashes a package archive of any size
/// in bounded memory. No bound on the length applies here; the caller reads in chunks.
///
/// [alpm-repo-db]: https://alpm.archlinux.page/specifications/alpm-repo-db.7.html
///
/// # Errors
///
/// - [`Error::Io`] if the path cannot be opened or stat'ed.
/// - [`Error::NotARegularFile`] if it is a directory, FIFO, socket or device node.
pub fn open_following_symlinks(path: &Path) -> Result<File> {
    let mut options = File::options();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }

    let file = options.open(path).map_err(|source| Error::io(path, IoAction::Open, source))?;
    ensure_regular_file(&file, path)?;
    Ok(file)
}

/// Reads `path` in full, refusing anything that is not a regular file and anything larger
/// than `max` bytes.
///
/// `limit` names the bound in the resulting error; it carries no behaviour.
///
/// A final symlink is not followed. Public for a file a caller keeps beside the database it
/// reads, such as `piko-txn`'s journal, so that read takes this door too.
///
/// # Errors
///
/// - [`Error::Io`] if the path cannot be opened, stat'ed or read. A final symlink is an
///   [`Error::Io`] carrying `ELOOP`.
/// - [`Error::NotARegularFile`] if it is a directory, FIFO, socket or device node.
/// - [`Error::LimitExceeded`] if the contents exceed `max` bytes.
pub fn read_capped(path: &Path, limit: Limit, max: u64) -> Result<Vec<u8>> {
    let file = open_no_follow(path)?;
    let metadata = ensure_regular_file(&file, path)?;
    read_open(file, &metadata, path, limit, max)
}

/// Reads the already-checked `file` in full, refusing more than `max` bytes.
fn read_open(
    file: File,
    metadata: &std::fs::Metadata,
    path: &Path,
    limit: Limit,
    max: u64,
) -> Result<Vec<u8>> {
    // Reading one byte past the limit distinguishes "exactly at the limit" from "truncated".
    // An oversized file is reported, never silently accepted short.
    let ceiling = max.saturating_add(1);
    let mut buffer = Vec::with_capacity(hint_capacity(metadata.len(), max));
    file.take(ceiling)
        .read_to_end(&mut buffer)
        .map_err(|source| Error::io(path, IoAction::Read, source))?;

    if buffer.len() as u64 > max {
        return Err(Error::LimitExceeded { path: path.to_path_buf(), limit, max });
    }

    Ok(buffer)
}

/// Why a file or a directory is not trusted: a user other than root and this process's
/// effective user could change it.
///
/// The rule is `sshd`'s `StrictModes` for one level. The owner is root or the effective user,
/// and neither the group nor others may write. A sticky bit does not pass: in a sticky,
/// world-writable directory, anyone can still create a file under a name before it is written.
/// libalpm checks none of this.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Distrust {
    /// Owned by a user that is neither root nor this process's effective user.
    ForeignOwner {
        /// The owner's user ID.
        uid: u32,
    },
    /// The group or others may write it.
    GroupOrOtherWritable {
        /// The permission bits.
        mode: u32,
    },
}

impl std::fmt::Display for Distrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignOwner { uid } => write!(f, "owned by user {uid}"),
            Self::GroupOrOtherWritable { mode } => {
                write!(f, "writable by its group or others (mode {mode:04o})")
            }
        }
    }
}

/// Whether `metadata` describes a file or a directory another user could change. See
/// [`Distrust`].
#[must_use]
pub fn distrust(metadata: &std::fs::Metadata) -> Option<Distrust> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let uid = metadata.uid();
        if uid != 0 && uid != rustix::process::geteuid().as_raw() {
            return Some(Distrust::ForeignOwner { uid });
        }
        let mode = metadata.mode() & 0o7777;
        if mode & 0o022 != 0 {
            return Some(Distrust::GroupOrOtherWritable { mode });
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    None
}

/// How many symbolic links [`ensure_trusted_directory`] follows before it gives up: Linux's
/// own limit for one path resolution.
const MAX_SYMLINK_HOPS: usize = 40;

/// Fails unless no user other than root and this process's effective user could change what
/// `directory` names.
///
/// Testing `directory` alone is not enough. A user who can write any directory above it can
/// rename it away between this test and the read, and put another in its place. So the path
/// is resolved one component at a time, from `/`, following each symbolic link by hand, and
/// every directory the resolution passes through is tested: each ancestor, and each directory
/// a link leads through.
///
/// A directory on the way may be writable by others only if it is sticky, as `/tmp` is. In a
/// sticky directory only the owner of an entry can rename or remove it, and the entry that
/// comes next is tested for its owner: a directory by [`distrust`], and a symbolic link by the
/// owner of the link itself, since its owner can point it elsewhere at any time. `directory`
/// itself gets no such exemption: in it, anyone could create a file under a name before it is
/// written.
///
/// A relative path is resolved against the current directory.
///
/// # Errors
///
/// [`Error::Untrusted`] naming the first directory, or symbolic link, that fails. [`Error::Io`]
/// if a component cannot be stat'ed or read, is not a directory, or the resolution follows more
/// than 40 links.
pub fn ensure_trusted_directory(directory: &Path) -> Result<()> {
    use std::collections::VecDeque;
    use std::path::Component;

    /// One step of a resolution still to come.
    enum Step {
        Parent,
        Name(std::ffi::OsString),
    }

    fn steps(path: &Path) -> impl Iterator<Item = Step> + '_ {
        path.components().filter_map(|component| match component {
            Component::ParentDir => Some(Step::Parent),
            Component::Normal(name) => Some(Step::Name(name.to_os_string())),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
    }

    let stat = |path: &Path| {
        std::fs::metadata(path).map_err(|source| Error::io(path, IoAction::Metadata, source))
    };
    let untrusted = |path: &Path, distrust| Error::Untrusted { path: path.to_path_buf(), distrust };
    // Whether a directory on the way is acceptable, and if so whether it is open to others
    // (sticky), in which case the next entry's owner is tested too.
    let on_the_way = |path: &Path, metadata: &std::fs::Metadata| -> Result<bool> {
        match distrust(metadata) {
            None => Ok(false),
            Some(Distrust::GroupOrOtherWritable { mode }) if mode & 0o1000 != 0 => Ok(true),
            Some(distrust) => Err(untrusted(path, distrust)),
        }
    };

    let absolute = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| Error::io(directory, IoAction::Metadata, source))?
            .join(directory)
    };
    let mut pending: VecDeque<Step> = steps(&absolute).collect();
    let mut current = PathBuf::from("/");
    let mut open = on_the_way(&current, &stat(&current)?)?;
    let mut hops = 0_usize;

    while let Some(step) = pending.pop_front() {
        let name = match step {
            Step::Parent => {
                current.pop();
                open = on_the_way(&current, &stat(&current)?)?;
                continue;
            }
            Step::Name(name) => name,
        };
        let next = current.join(&name);
        let metadata = std::fs::symlink_metadata(&next)
            .map_err(|source| Error::io(&next, IoAction::Metadata, source))?;
        if open && let Some(foreign @ Distrust::ForeignOwner { .. }) = distrust(&metadata) {
            return Err(untrusted(&next, foreign));
        }
        if metadata.file_type().is_symlink() {
            hops = hops.saturating_add(1);
            if hops > MAX_SYMLINK_HOPS {
                let source = std::io::Error::other("too many levels of symbolic links");
                return Err(Error::io(&next, IoAction::Metadata, source));
            }
            let target = std::fs::read_link(&next)
                .map_err(|source| Error::io(&next, IoAction::Read, source))?;
            if target.has_root() {
                current = PathBuf::from("/");
                open = on_the_way(&current, &stat(&current)?)?;
            }
            let mut ahead: VecDeque<Step> = steps(&target).collect();
            ahead.append(&mut pending);
            pending = ahead;
        } else if metadata.is_dir() {
            open = on_the_way(&next, &metadata)?;
            current = next;
        } else {
            let source = std::io::Error::from(std::io::ErrorKind::NotADirectory);
            return Err(Error::io(&next, IoAction::Metadata, source));
        }
    }

    match distrust(&stat(&current)?) {
        Some(distrust) => Err(untrusted(&current, distrust)),
        None => Ok(()),
    }
}

/// Fails if the file `metadata` describes, or the directory holding `path`, is one another
/// user could change.
///
/// The directory is the one the path names, not the one a followed link resolves into: a
/// user who can write it can replace the link.
fn ensure_trusted(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if let Some(distrust) = self::distrust(metadata) {
        return Err(Error::Untrusted { path: path.to_path_buf(), distrust });
    }
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    ensure_trusted_directory(parent)
}

/// Reads configuration at `path` in full as UTF-8, as [`read_capped_utf8`] does, and refuses a
/// file another user could change, or one in a directory another user could write.
///
/// For a file root reads as instructions: `pacman.conf` and every file it `Include`s. A user
/// who can change one can name a hook directory, a keyring, or a server.
///
/// # Errors
///
/// As [`read_capped_utf8`], plus [`Error::Untrusted`] naming the file or the directory that
/// failed [`distrust`].
pub fn read_trusted_utf8(path: &Path, limit: Limit, max: u64) -> Result<String> {
    let file = open_no_follow(path)?;
    let metadata = ensure_regular_file(&file, path)?;
    ensure_trusted(path, &metadata)?;
    decode(path, read_open(file, &metadata, path, limit, max)?)
}

/// Reads `path` in full as UTF-8, **following a final symlink**, as
/// [`read_capped_utf8_following`] does, and refuses a file another user could change.
///
/// Only the file is tested, on its descriptor: the one the link resolves to. The directory
/// holding the link is the caller's to test, with [`ensure_trusted_directory`], once for every
/// file it reads there. A directory that passed that test stays trusted: only root and the
/// effective user can change it or any directory above it. So one test covers every file read
/// from it afterwards, and repeating it per file adds nothing.
///
/// A link to something that is not a regular file is still [`Error::NotARegularFile`], tested
/// first, so a hook masked by a link to `/dev/null` stays masked.
///
/// # Errors
///
/// As [`read_capped_utf8_following`], plus [`Error::Untrusted`] naming the file if it fails
/// [`distrust`].
pub fn read_trusted_file_utf8_following(path: &Path, limit: Limit, max: u64) -> Result<String> {
    let file = open_following_symlinks(path)?;
    let metadata = ensure_regular_file(&file, path)?;
    if let Some(distrust) = distrust(&metadata) {
        return Err(Error::Untrusted { path: path.to_path_buf(), distrust });
    }
    decode(path, read_open(file, &metadata, path, limit, max)?)
}

/// Reads `path` in full and decodes it as UTF-8.
///
/// # Errors
///
/// As `read_capped`, plus [`Error::NotUtf8`] if the contents are not valid UTF-8.
pub fn read_capped_utf8(path: &Path, limit: Limit, max: u64) -> Result<String> {
    let bytes = read_capped(path, limit, max)?;
    decode(path, bytes)
}

/// Reads `path` in full and decodes it as UTF-8, **following a final symlink**.
///
/// Exposes the `open_following_symlinks` door for alpm `.hook` files. `alpm-hooks(5)` documents
/// disabling a hook by shadowing it with a symlink to `/dev/null`. Refusing to follow that
/// symlink would break the feature instead of protecting anything. A hook directory is host
/// configuration named by `pacman.conf`, not a package-controlled entry directory. And the file
/// is one of an enumerated set whose whole population is trusted the same way.
///
/// The rest of the door is unchanged: `O_NONBLOCK`, an `fstat` that refuses anything but a
/// regular file, and a bounded read. A FIFO planted in a hook directory still cannot hang the
/// process. The caller distinguishes [`Error::NotARegularFile`] and decides what a non-file
/// means for it. For hooks it means "no content", exactly what `/dev/null` would have
/// yielded.
///
/// # Errors
///
/// As `read_capped`, except that a final symlink is resolved rather than refused.
pub fn read_capped_utf8_following(path: &Path, limit: Limit, max: u64) -> Result<String> {
    let bytes = read_capped_following(path, limit, max)?;
    decode(path, bytes)
}

/// Reads `path` in full as bytes, **following a final symlink**.
///
/// The bytes counterpart of [`read_capped_utf8_following`], for a file whose contents are
/// paths rather than text. The kernel's mount table is that case. `/etc/mtab` is a symlink to
/// `/proc/self/mounts`, and a mount directory is a byte string the filesystem never promised
/// would decode as UTF-8. Refusing the whole table over one such directory would disable the
/// disk-space check on the system that needs it.
///
/// The rest of the door is unchanged: `O_NONBLOCK`, an `fstat` that refuses anything but a
/// regular file, and a bounded read. A procfs file reports a size of zero. That only means the
/// read starts with no capacity hint. The bound still applies to what actually arrives.
///
/// # Errors
///
/// As `read_capped`, except that a final symlink is resolved rather than refused.
pub fn read_capped_following(path: &Path, limit: Limit, max: u64) -> Result<Vec<u8>> {
    let file = open_following_symlinks(path)?;
    let metadata = ensure_regular_file(&file, path)?;
    read_open(file, &metadata, path, limit, max)
}

/// Reads the file `name` inside the entry directory `dir`, in full, following no symbolic link
/// at either level, refusing anything that is not a regular file and anything larger than
/// `max` bytes.
///
/// `O_NOFOLLOW` on `dir.join(name)` covers only the last component. The scan checked that `dir`
/// is a real directory, but a lazy read comes later, and by then `dir` can be a symbolic link
/// to anywhere. So `dir`'s parent is opened (following links: the caller named that path), then
/// `dir` from it with `O_DIRECTORY | O_NOFOLLOW`, then `name` from that with
/// `O_NOFOLLOW | O_NONBLOCK`. `name` is a single component, such as `desc`.
///
/// # Errors
///
/// As `read_capped`, plus [`Error::Io`] with [`IoAction::Open`] if `dir` is a symbolic link.
pub fn read_capped_in(dir: &Path, name: &str, limit: Limit, max: u64) -> Result<Vec<u8>> {
    let path = join(dir, name);
    let file = open_in(dir, name).map_err(|source| Error::io(&path, IoAction::Open, source))?;
    let metadata = ensure_regular_file(&file, &path)?;

    let ceiling = max.saturating_add(1);
    let mut buffer = Vec::with_capacity(hint_capacity(metadata.len(), max));
    file.take(ceiling)
        .read_to_end(&mut buffer)
        .map_err(|source| Error::io(&path, IoAction::Read, source))?;
    if buffer.len() as u64 > max {
        return Err(Error::LimitExceeded { path, limit, max });
    }

    Ok(buffer)
}

/// [`read_capped_in`], decoded as UTF-8.
///
/// # Errors
///
/// As [`read_capped_in`], plus [`Error::NotUtf8`] if the contents are not valid UTF-8.
pub fn read_capped_utf8_in(dir: &Path, name: &str, limit: Limit, max: u64) -> Result<String> {
    let bytes = read_capped_in(dir, name, limit, max)?;
    decode(&join(dir, name), bytes)
}

/// Returns `true` if `name` exists inside the entry directory `dir`, following no symbolic link
/// at either level. A symbolic link named `name` exists; one in place of `dir` does not.
pub fn exists_in(dir: &Path, name: &str) -> bool {
    #[cfg(unix)]
    {
        use rustix::fs::{AtFlags, CWD, Mode};
        let Some((parent, entry)) = split_dir(dir) else { return false };
        let Ok(parent) = rustix::fs::openat(CWD, parent, parent_flags(), Mode::empty()) else {
            return false;
        };
        let Ok(entry) = rustix::fs::openat(&parent, entry, entry_flags(), Mode::empty()) else {
            return false;
        };
        rustix::fs::statat(&entry, name, AtFlags::SYMLINK_NOFOLLOW).is_ok()
    }
    #[cfg(not(unix))]
    {
        exists_no_follow(&join(dir, name))
    }
}

/// Opens `name` inside `dir` as [`read_capped_in`] describes.
fn open_in(dir: &Path, name: &str) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        let (parent, entry) = split_dir(dir).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent directory")
        })?;
        let parent = rustix::fs::openat(rustix::fs::CWD, parent, parent_flags(), Mode::empty())?;
        let entry = rustix::fs::openat(&parent, entry, entry_flags(), Mode::empty())?;
        let file = rustix::fs::openat(
            &entry,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(File::from(file))
    }
    #[cfg(not(unix))]
    {
        File::open(join(dir, name))
    }
}

/// Splits an entry directory into its parent and its own name. A bare name has the current
/// directory as its parent.
#[cfg(unix)]
fn split_dir(dir: &Path) -> Option<(&Path, &std::ffi::OsStr)> {
    let entry = dir.file_name()?;
    let parent = dir.parent().filter(|parent| !parent.as_os_str().is_empty());
    Some((parent.unwrap_or(Path::new(".")), entry))
}

/// The flags the parent of an entry directory is opened with. It follows symbolic links,
/// because the caller named it.
#[cfg(unix)]
fn parent_flags() -> rustix::fs::OFlags {
    use rustix::fs::OFlags;
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC
}

/// The flags an entry directory is opened with: never through a symbolic link.
#[cfg(unix)]
fn entry_flags() -> rustix::fs::OFlags {
    use rustix::fs::OFlags;
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Decodes bytes read from `path` as UTF-8.
fn decode(path: &Path, bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes)
        .map_err(|error| Error::NotUtf8 { path: path.to_path_buf(), source: error.utf8_error() })
}

/// Chooses a starting allocation from the stat'ed size.
///
/// The stat'ed size is untrusted, so it only ever shrinks the allocation. It never grows it
/// past the limit. A file claiming to be huge must not make piko allocate that much up front.
fn hint_capacity(reported: u64, max: u64) -> usize {
    let bounded = reported.min(max).min(1024 * 1024);
    usize::try_from(bounded).unwrap_or(0)
}

/// Returns `true` if `path` is a directory and not a symlink to one.
///
/// libalpm's equivalent (`is_dir` in `be_local.c`) uses a following `stat`. A symlink
/// pointing at a directory is accepted there as a database entry. piko does not follow it: an
/// entry directory that is a symlink is a redirection primitive with no legitimate use.
///
/// # Errors
///
/// [`Error::Io`] if the path cannot be stat'ed for a reason other than not existing.
pub fn is_real_directory(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(Error::io(path, IoAction::Metadata, source)),
    }
}

/// Returns `true` if `path` exists, without following a final symlink.
pub fn exists_no_follow(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Joins `directory` and `component`, where `component` is a single path component.
pub(crate) fn join(directory: &Path, component: &str) -> PathBuf {
    directory.join(component)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn write(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        path
    }

    #[test]
    fn reads_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "desc", b"%NAME%\nfoo\n");
        let contents = read_capped(&path, Limit::Desc, 1024).unwrap();
        assert_eq!(contents, b"%NAME%\nfoo\n");
    }

    #[test]
    fn accepts_an_empty_file() {
        // Seven packages on a real system ship a zero-byte `files` file.
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "files", b"");
        assert!(read_capped(&path, Limit::Files, 1024).unwrap().is_empty());
    }

    #[test]
    fn accepts_a_file_exactly_at_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "desc", &[b'x'; 16]);
        assert_eq!(read_capped(&path, Limit::Desc, 16).unwrap().len(), 16);
    }

    /// Truncating would misreport a package's contents. The read must fail instead.
    #[test]
    fn refuses_a_file_one_byte_over_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "desc", &[b'x'; 17]);
        let err = read_capped(&path, Limit::Desc, 16).unwrap_err();
        assert!(
            matches!(err, Error::LimitExceeded { limit: Limit::Desc, max: 16, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn refuses_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir");
        std::fs::create_dir(&path).unwrap();
        let err = read_capped(&path, Limit::Desc, 1024).unwrap_err();
        // A directory fails at `open` on Linux (EISDIR) rather than at the stat check.
        // Either rejection is acceptable; silently succeeding is not.
        assert!(matches!(err, Error::Io { .. } | Error::NotARegularFile { .. }), "got {err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = write(dir.path(), "target", b"secret");
        let link = dir.path().join("desc");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = read_capped(&link, Limit::Desc, 1024).unwrap_err();
        assert!(matches!(err, Error::Io { action: IoAction::Open, .. }), "got {err:?}");
    }

    #[test]
    fn reports_invalid_utf8_with_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "desc", &[0xff, 0xfe]);
        let err = read_capped_utf8(&path, Limit::Desc, 1024).unwrap_err();
        assert!(matches!(err, Error::NotUtf8 { .. }), "got {err:?}");
        assert!(err.to_string().contains("desc"));
    }

    #[cfg(unix)]
    #[test]
    fn open_following_symlinks_follows_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = write(dir.path(), "core.db.tar.gz", b"archive bytes");
        let link = dir.path().join("core.db");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut file = open_following_symlinks(&link).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"archive bytes");
    }

    #[test]
    fn open_following_symlinks_refuses_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = open_following_symlinks(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Io { .. } | Error::NotARegularFile { .. }), "got {err:?}");
    }

    #[test]
    fn missing_files_report_their_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent");
        let err = read_capped(&path, Limit::Desc, 1024).unwrap_err();
        assert!(matches!(err, Error::Io { action: IoAction::Open, .. }), "got {err:?}");
        assert!(err.to_string().contains("absent"));
    }

    #[cfg(unix)]
    #[test]
    fn is_real_directory_rejects_a_symlink_to_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(is_real_directory(&real).unwrap());
        assert!(!is_real_directory(&link).unwrap(), "a symlinked entry must not be followed");
    }

    #[test]
    fn is_real_directory_reports_false_for_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_real_directory(&dir.path().join("absent")).unwrap());
    }

    /// A capacity hint is a performance detail. It must never be driven by an untrusted
    /// size, or a sparse file claiming to be terabytes would abort the process.
    #[test]
    fn capacity_hint_never_exceeds_the_limit() {
        assert_eq!(hint_capacity(u64::MAX, 16), 16);
        assert_eq!(hint_capacity(8, 1024), 8);
        assert_eq!(hint_capacity(u64::MAX, u64::MAX), 1024 * 1024);
    }
}
