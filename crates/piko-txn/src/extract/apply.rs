//! Writes one archive member into the installation root.
//!
//! Every path here goes through [`crate::rootfs`]. As a result, this module cannot address a
//! location outside the root, even when an archive asks for one. [`super::decision`] makes the
//! decisions; this module only carries them out.
//!
//! # Unlink, then create exclusively
//!
//! libalpm passes `ARCHIVE_EXTRACT_UNLINK` (`add.c:121`). This makes libarchive remove an
//! existing object before creating the new one. This is not a convenience. It stops the write
//! from following a symlink already sitting at the destination. piko does the same thing
//! explicitly: `unlinkat` removes a symlink rather than following it, then `openat` runs with
//! `O_CREAT | O_EXCL | O_NOFOLLOW`. `O_EXCL` means the create fails if anything reappears at
//! the path between the two calls, rather than writing through it.
//!
//! # Ownership before mode, never the reverse
//!
//! `chown(2)` clears `S_ISUID` and `S_ISGID` on a regular file. On Linux this happens even for
//! root, and even when the owner does not change: `chown_common` adds
//! `ATTR_KILL_SUID | ATTR_KILL_SGID` for anything that is not a directory, before
//! `notify_change` compares the ids. So `fchmod` followed by `fchown` silently strips the
//! setuid bit off every setuid binary a package ships — `sudo`, `mount`, `su`, `passwd`.
//!
//! piko applies ownership first and the mode second, for this reason. libarchive does the
//! same: `archive_write_disk_posix.c` calls `set_ownership` before `set_perm`.
use std::{
    io::{Read, Write as _},
    os::fd::AsFd,
    path::Path,
};

use rustix::fs::{AtFlags, Gid, Mode, OFlags, Timestamps, Uid};

use crate::{
    error::{Error, IoAction, Result},
    extract::{
        archive::{Link, LinkKind, Member},
        decision::{Disposition, EntryKind, PacnewReason},
    },
    rootfs::{Resolved, RootDir},
};

/// The suffix an entry diverted by [`Disposition::ExtractAsPacnew`] is written under.
pub const PACNEW_SUFFIX: &str = ".pacnew";

/// What happened to a member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Applied {
    /// Written to its intended path.
    Written,
    /// Written alongside the existing file, as `<path>.pacnew`.
    WrittenAsPacnew {
        /// Why it was diverted.
        reason: PacnewReason,
        /// Whether this extraction created the `.pacnew`, as opposed to replacing one that
        /// was already there.
        ///
        /// [`super::decision::resolve_backup`] uses this to decide whether removing the
        /// `.pacnew` is safe. A `.pacnew` the user is already merging from must not be
        /// deleted.
        is_new: bool,
    },
    /// Nothing was done.
    Skipped,
}

/// Whether to apply the ownership recorded in the archive.
///
/// Setting ownership requires privilege. An unprivileged extraction (a test, or `--root` into
/// a user-owned tree) must be able to skip it instead of failing. libalpm has no equivalent
/// switch: it always passes `ARCHIVE_EXTRACT_OWNER` and fails when not root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ownership {
    /// Apply the archive's uid and gid.
    FromArchive,
    /// Leave ownership to the creating process.
    Inherit,
}

/// Carries out `disposition` for `member`.
///
/// `contents` is read only for a regular file, and only when something is actually written.
///
/// # Errors
///
/// [`Error::UnsafeArchivePath`] or [`Error::PathEscapesRoot`] if the member's path cannot be
/// resolved inside the root, or [`Error::Io`] if a filesystem operation fails.
pub fn apply(
    root: &RootDir,
    member: &Member,
    contents: &mut dyn Read,
    disposition: &Disposition,
    ownership: Ownership,
) -> Result<Applied> {
    match disposition {
        Disposition::Skip(_) => Ok(Applied::Skipped),
        Disposition::Refuse(reason) => {
            Err(Error::ExtractionRefused { path: member.path.clone(), reason: *reason })
        }
        Disposition::Extract => {
            let resolved = root.resolve_parent(&member.path)?;
            write_member(root, &resolved, resolved.name(), member, contents, ownership)?;
            Ok(Applied::Written)
        }
        Disposition::ExtractAsPacnew(reason) => {
            let resolved = root.resolve_parent(&member.path)?;
            let mut name = resolved.name().to_os_string();
            name.push(PACNEW_SUFFIX);

            // Whether the `.pacnew` already existed decides later whether removal is safe.
            // This check runs before writing, because writing creates the file either way.
            let is_new =
                rustix::fs::statat(resolved.dir(), name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .is_err();

            write_member(root, &resolved, name.as_os_str(), member, contents, ownership)?;
            Ok(Applied::WrittenAsPacnew { reason: reason.clone(), is_new })
        }
    }
}

/// Writes `member` as `name` inside `resolved`'s directory.
fn write_member(
    root: &RootDir,
    resolved: &Resolved,
    name: &std::ffi::OsStr,
    member: &Member,
    contents: &mut dyn Read,
    ownership: Ownership,
) -> Result<()> {
    match member.link.as_ref() {
        Some(Link { kind: LinkKind::Symbolic, target }) => {
            write_symlink(resolved, name, target, member, ownership)
        }
        Some(Link { kind: LinkKind::Hard, target }) => {
            write_hard_link(root, resolved, name, target)
        }
        None => match member.entry {
            EntryKind::Directory => write_directory(resolved, name, member, ownership),
            EntryKind::Other => write_file(resolved, name, member, contents, ownership),
        },
    }
}

/// Creates a hard link to another member of the same package.
///
/// The target is a path relative to the installation root, so [`RootDir`] resolves it like any
/// other path. A hard link is the one archive construct that can reach an *existing* file by
/// name, so confining it matters as much as confining the destination. This uses
/// `AtFlags::empty()` rather than `SYMLINK_FOLLOW`: linking to the symlink itself, rather than
/// to whatever it points at, keeps the result inside the root.
///
/// Mode, ownership, and times are not set here. A hard link is a second name for one inode, so
/// it has no metadata of its own. Applying the archive's metadata would silently rewrite the
/// target's.
fn write_hard_link(
    root: &RootDir,
    resolved: &Resolved,
    name: &std::ffi::OsStr,
    target: &Path,
) -> Result<()> {
    let source = root.resolve_parent(target)?;
    remove_existing(resolved, name)?;
    rustix::fs::linkat(source.dir(), source.name(), resolved.dir(), name, AtFlags::empty())
        .map_err(|error| io(name, IoAction::Create, error))
}

/// Creates a regular file, replacing whatever is there.
fn write_file(
    resolved: &Resolved,
    name: &std::ffi::OsStr,
    member: &Member,
    contents: &mut dyn Read,
    ownership: Ownership,
) -> Result<()> {
    remove_existing(resolved, name)?;

    let mode = Mode::from_raw_mode(member.mode & 0o7777);
    let fd = rustix::fs::openat(
        resolved.dir(),
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode,
    )
    .map_err(|source| io(name, IoAction::Create, source))?;

    let mut file = std::fs::File::from(fd);
    copy(contents, &mut file, name)?;

    // Ownership is applied first, then the mode. This order is load-bearing — see the module
    // note above.
    apply_ownership_fd(&file, member, ownership, name)?;
    // The process umask masks the mode passed to `openat`, so this sets the mode again.
    rustix::fs::fchmod(&file, mode).map_err(|source| io(name, IoAction::Metadata, source))?;
    set_times(resolved, name, member)?;
    Ok(())
}

/// Creates a directory, or leaves an existing one alone.
///
/// An existing directory keeps its mode. libalpm warns when the modes differ but changes
/// nothing (`add.c:258`), because the directory may be shared with another package or
/// adjusted deliberately.
fn write_directory(
    resolved: &Resolved,
    name: &std::ffi::OsStr,
    member: &Member,
    ownership: Ownership,
) -> Result<()> {
    let mode = Mode::from_raw_mode(member.mode & 0o7777);
    match rustix::fs::mkdirat(resolved.dir(), name, mode) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => return Ok(()),
        Err(source) => return Err(io(name, IoAction::CreateDir, source)),
    }

    // Ownership is applied before the mode, as for a file. A directory is actually exempt
    // from the setgid-clearing rule — measured: `chown_common` sets `ATTR_KILL_SUID` only for
    // `!S_ISDIR` — so this order changes nothing today. This keeps the two functions from
    // drifting apart, and keeps a setgid directory from depending on that exemption.
    apply_ownership_at(resolved, name, member, ownership)?;
    // As for files, `mkdirat`'s mode is umask-masked.
    rustix::fs::chmodat(resolved.dir(), name, mode, AtFlags::empty())
        .map_err(|source| io(name, IoAction::Metadata, source))?;
    set_times(resolved, name, member)?;
    Ok(())
}

/// Creates a symlink, replacing whatever is there.
fn write_symlink(
    resolved: &Resolved,
    name: &std::ffi::OsStr,
    target: &Path,
    member: &Member,
    ownership: Ownership,
) -> Result<()> {
    remove_existing(resolved, name)?;
    rustix::fs::symlinkat(target, resolved.dir(), name)
        .map_err(|source| io(name, IoAction::Create, source))?;
    // A symlink's own mode is meaningless on Linux, so only ownership and times apply. Both
    // operations must avoid following the symlink.
    apply_ownership_at(resolved, name, member, ownership)?;
    set_times(resolved, name, member)
}

/// Removes whatever is at `name`, so the create that follows cannot write through it.
///
/// A directory is left alone. [`Disposition::Refuse`] already prevents replacing a directory
/// with a file, and `unlinkat` without `AT_REMOVEDIR` would fail on a directory anyway.
fn remove_existing(resolved: &Resolved, name: &std::ffi::OsStr) -> Result<()> {
    match rustix::fs::unlinkat(resolved.dir(), name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(source) => Err(io(name, IoAction::Remove, source)),
    }
}

/// Copies a member's contents into `file`.
fn copy(contents: &mut dyn Read, file: &mut std::fs::File, name: &std::ffi::OsStr) -> Result<()> {
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = match contents.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(source) => return Err(Error::io(name, IoAction::Read, source)),
        };
        let chunk = buffer.get(..read).unwrap_or_default();
        file.write_all(chunk).map_err(|source| Error::io(name, IoAction::Write, source))?;
    }
    Ok(())
}

/// Applies the archive's ownership to an open file.
fn apply_ownership_fd(
    file: &impl AsFd,
    member: &Member,
    ownership: Ownership,
    name: &std::ffi::OsStr,
) -> Result<()> {
    if ownership == Ownership::Inherit {
        return Ok(());
    }
    let (uid, gid) = ids(member);
    rustix::fs::fchown(file, Some(uid), Some(gid))
        .map_err(|source| io(name, IoAction::Chown, source))
}

/// Applies the archive's ownership to a path, without following a symlink.
fn apply_ownership_at(
    resolved: &Resolved,
    name: &std::ffi::OsStr,
    member: &Member,
    ownership: Ownership,
) -> Result<()> {
    if ownership == Ownership::Inherit {
        return Ok(());
    }
    let (uid, gid) = ids(member);
    rustix::fs::chownat(resolved.dir(), name, Some(uid), Some(gid), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io(name, IoAction::Chown, source))
}

/// The archive's uid and gid, narrowed to what the kernel accepts.
fn ids(member: &Member) -> (Uid, Gid) {
    let uid = u32::try_from(member.uid).unwrap_or(0);
    let gid = u32::try_from(member.gid).unwrap_or(0);
    (Uid::from_raw(uid), Gid::from_raw(gid))
}

/// Applies the archive's modification time, without following a symlink.
///
/// libalpm passes `ARCHIVE_EXTRACT_TIME` (`add.c:120`). This sets both timestamps to the
/// member's `mtime`. tar records no access time, and leaving atime alone would let the
/// extraction itself define it.
fn set_times(resolved: &Resolved, name: &std::ffi::OsStr, member: &Member) -> Result<()> {
    let seconds = i64::try_from(member.mtime).unwrap_or(0);
    let stamp = rustix::fs::Timespec { tv_sec: seconds, tv_nsec: 0 };
    let times = Timestamps { last_access: stamp, last_modification: stamp };

    rustix::fs::utimensat(resolved.dir(), name, &times, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io(name, IoAction::Metadata, source))
}

/// Wraps a `rustix` error, naming the member rather than a full path.
///
/// The directory here is only a descriptor, so there is no path to report. This is exactly
/// what makes the write safe. The caller already knows the archive path.
fn io(name: &std::ffi::OsStr, action: IoAction, source: rustix::io::Errno) -> Error {
    Error::io(Path::new(name), action, source.into())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::extract::archive::MemberKind;

    fn member(path: &str, entry: EntryKind, mode: u32) -> Member {
        Member {
            path: PathBuf::from(path),
            kind: MemberKind::Payload,
            entry,
            link: None,
            mode,
            uid: 0,
            gid: 0,
            mtime: 1_600_000_000,
            size: 0,
        }
    }

    fn root() -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = RootDir::open(dir.path()).unwrap();
        (dir, root)
    }

    fn write(root: &RootDir, member: &Member, contents: &[u8]) -> Applied {
        apply(root, member, &mut &contents[..], &Disposition::Extract, Ownership::Inherit).unwrap()
    }

    #[test]
    fn writes_a_file_with_its_mode_and_time() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let (dir, root) = root();
        std::fs::create_dir(dir.path().join("usr")).unwrap();

        let entry = member("usr/foo", EntryKind::Other, 0o755);
        assert_eq!(write(&root, &entry, b"payload"), Applied::Written);

        let path = dir.path().join("usr/foo");
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
        assert_eq!(metadata.mtime(), 1_600_000_000);
    }

    /// A setuid binary must arrive setuid.
    ///
    /// Every other test here extracts under `Ownership::Inherit`, which performs no `chown`
    /// and never triggers the clearing. So this bug was invisible to them. Only
    /// `Ownership::FromArchive`, the mode a real root install uses, hit it.
    ///
    /// This test still runs unprivileged: `fchown` to the caller's own uid and gid needs no
    /// privilege and still clears the bit. Linux kills setuid on any `chown` of a
    /// non-directory, not only on one that changes something. Recording the ids from the
    /// running user is what makes the real sequence reachable from an ordinary test.
    ///
    /// Verified against the real `sudo` package before the fix: the archive says `4755`, but
    /// `Ownership::FromArchive` produced `0755`.
    #[test]
    fn a_setuid_file_keeps_its_setuid_bit_when_ownership_is_applied() {
        use std::os::unix::fs::PermissionsExt as _;

        let (dir, root) = root();
        let mut entry = member("suid", EntryKind::Other, 0o4755);
        entry.uid = u64::from(rustix::process::getuid().as_raw());
        entry.gid = u64::from(rustix::process::getgid().as_raw());

        let applied = apply(
            &root,
            &entry,
            &mut &b"payload"[..],
            &Disposition::Extract,
            Ownership::FromArchive,
        )
        .unwrap();
        assert_eq!(applied, Applied::Written);

        let mode = std::fs::metadata(dir.path().join("suid")).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o4755, "chown stripped the setuid bit");
    }

    /// The setgid half of the same rule, on a file rather than a directory.
    #[test]
    fn a_setgid_file_keeps_its_setgid_bit_when_ownership_is_applied() {
        use std::os::unix::fs::PermissionsExt as _;

        let (dir, root) = root();
        let mut entry = member("sgid", EntryKind::Other, 0o2755);
        entry.uid = u64::from(rustix::process::getuid().as_raw());
        entry.gid = u64::from(rustix::process::getgid().as_raw());

        apply(&root, &entry, &mut &b"payload"[..], &Disposition::Extract, Ownership::FromArchive)
            .unwrap();

        let mode = std::fs::metadata(dir.path().join("sgid")).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o2755, "chown stripped the setgid bit");
    }

    #[test]
    fn creates_a_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let (dir, root) = root();
        let entry = member("usr", EntryKind::Directory, 0o755);
        write(&root, &entry, b"");

        let metadata = std::fs::metadata(dir.path().join("usr")).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
    }

    /// An existing directory keeps its mode, matching libalpm's warn-and-continue.
    #[test]
    fn an_existing_directory_is_left_as_it_is() {
        use std::os::unix::fs::PermissionsExt as _;

        let (dir, root) = root();
        std::fs::create_dir(dir.path().join("usr")).unwrap();
        std::fs::set_permissions(dir.path().join("usr"), std::fs::Permissions::from_mode(0o700))
            .unwrap();

        write(&root, &member("usr", EntryKind::Directory, 0o755), b"");
        let mode = std::fs::metadata(dir.path().join("usr")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "an existing directory was re-moded");
    }

    #[test]
    fn creates_a_symlink() {
        let (dir, root) = root();
        let mut entry = member("link", EntryKind::Other, 0o777);
        entry.link = Some(Link { kind: LinkKind::Symbolic, target: PathBuf::from("target") });
        write(&root, &entry, b"");

        let link = dir.path().join("link");
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("target"));
    }

    /// The reason `ARCHIVE_EXTRACT_UNLINK` exists: a symlink at the destination must be
    /// replaced, never written through.
    #[test]
    fn replaces_a_symlink_instead_of_writing_through_it() {
        let (dir, root) = root();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, b"do not overwrite me").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("foo")).unwrap();

        write(&root, &member("foo", EntryKind::Other, 0o644), b"new contents");

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "do not overwrite me");
        let written = dir.path().join("foo");
        assert!(!std::fs::symlink_metadata(&written).unwrap().is_symlink());
        assert_eq!(std::fs::read(&written).unwrap(), b"new contents");
    }

    /// A hard link must become a second name for the same inode, not a symlink. `glibc`
    /// ships three of them, so getting this wrong corrupts a package that nothing else can
    /// fix.
    #[test]
    fn creates_a_hard_link_not_a_symlink() {
        use std::os::unix::fs::MetadataExt as _;

        let (dir, root) = root();
        write(&root, &member("real", EntryKind::Other, 0o644), b"shared");

        let mut entry = member("alias", EntryKind::Other, 0o644);
        entry.link = Some(Link { kind: LinkKind::Hard, target: PathBuf::from("real") });
        write(&root, &entry, b"");

        let alias = dir.path().join("alias");
        assert!(!std::fs::symlink_metadata(&alias).unwrap().is_symlink(), "made a symlink");
        assert_eq!(std::fs::read(&alias).unwrap(), b"shared");
        assert_eq!(
            std::fs::metadata(&alias).unwrap().ino(),
            std::fs::metadata(dir.path().join("real")).unwrap().ino(),
            "not the same inode"
        );
    }

    /// A hard link's target is a path too, so it must be confined like any other.
    #[test]
    fn refuses_a_hard_link_pointing_outside_the_root() {
        let (_dir, root) = root();
        let mut entry = member("alias", EntryKind::Other, 0o644);
        entry.link = Some(Link { kind: LinkKind::Hard, target: PathBuf::from("../../etc/passwd") });

        let err = apply(&root, &entry, &mut &b""[..], &Disposition::Extract, Ownership::Inherit)
            .unwrap_err();
        assert!(matches!(err, Error::UnsafeArchivePath { .. }), "got {err:?}");
    }

    #[test]
    fn replaces_an_existing_regular_file() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("foo"), b"old").unwrap();
        write(&root, &member("foo", EntryKind::Other, 0o644), b"new");
        assert_eq!(std::fs::read(dir.path().join("foo")).unwrap(), b"new");
    }

    #[test]
    fn writes_a_pacnew_beside_the_existing_file() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("conf"), b"user edited").unwrap();

        let entry = member("conf", EntryKind::Other, 0o644);
        let applied = apply(
            &root,
            &entry,
            &mut &b"packaged"[..],
            &Disposition::ExtractAsPacnew(PacnewReason::NoUpgrade),
            Ownership::Inherit,
        )
        .unwrap();

        assert_eq!(
            applied,
            Applied::WrittenAsPacnew { reason: PacnewReason::NoUpgrade, is_new: true }
        );
        assert_eq!(std::fs::read(dir.path().join("conf")).unwrap(), b"user edited");
        assert_eq!(std::fs::read(dir.path().join("conf.pacnew")).unwrap(), b"packaged");
    }

    /// A `.pacnew` the user is already merging from must be reported as pre-existing, so
    /// nothing later deletes it.
    #[test]
    fn an_existing_pacnew_is_reported_as_not_new() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("conf"), b"user edited").unwrap();
        std::fs::write(dir.path().join("conf.pacnew"), b"from last time").unwrap();

        let applied = apply(
            &root,
            &member("conf", EntryKind::Other, 0o644),
            &mut &b"packaged"[..],
            &Disposition::ExtractAsPacnew(PacnewReason::NoUpgrade),
            Ownership::Inherit,
        )
        .unwrap();

        assert!(matches!(applied, Applied::WrittenAsPacnew { is_new: false, .. }));
    }

    #[test]
    fn a_skip_writes_nothing() {
        let (dir, root) = root();
        let applied = apply(
            &root,
            &member("foo", EntryKind::Other, 0o644),
            &mut &b"x"[..],
            &Disposition::Skip(crate::extract::decision::SkipReason::NoExtract),
            Ownership::Inherit,
        )
        .unwrap();
        assert_eq!(applied, Applied::Skipped);
        assert!(!dir.path().join("foo").exists());
    }

    #[test]
    fn a_refusal_is_an_error() {
        let (_dir, root) = root();
        let err = apply(
            &root,
            &member("foo", EntryKind::Other, 0o644),
            &mut &b"x"[..],
            &Disposition::Refuse(crate::extract::decision::RefuseReason::DirectoryInTheWay),
            Ownership::Inherit,
        )
        .unwrap_err();
        assert!(matches!(err, Error::ExtractionRefused { .. }), "got {err:?}");
    }

    /// Confinement still applies at the writing layer, not only at resolution.
    #[test]
    fn refuses_to_write_outside_the_root() {
        let (_dir, root) = root();
        let err = apply(
            &root,
            &member("../escape", EntryKind::Other, 0o644),
            &mut &b"x"[..],
            &Disposition::Extract,
            Ownership::Inherit,
        )
        .unwrap_err();
        assert!(matches!(err, Error::UnsafeArchivePath { .. }), "got {err:?}");
    }
}
