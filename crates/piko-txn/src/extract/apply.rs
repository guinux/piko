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
//! explicitly. `unlinkat` removes a symlink rather than following it. Then `openat` runs with
//! `O_CREAT | O_EXCL | O_NOFOLLOW`. `O_EXCL` means the create fails if anything reappears at
//! the path between the two calls, rather than writing through it.
//!
//! # Ownership before mode, never the reverse
//!
//! `chown(2)` clears `S_ISUID` and `S_ISGID` on a regular file. On Linux this happens even for
//! root, and even when the owner does not change. `chown_common` adds
//! `ATTR_KILL_SUID | ATTR_KILL_SGID` for anything that is not a directory. It does so before
//! `notify_change` compares the ids. So `fchmod` followed by `fchown` silently strips the
//! setuid bit off every setuid binary a package ships: `sudo`, `mount`, `su`, `passwd`.
//!
//! piko applies ownership first and the mode second, for this reason. libarchive does the
//! same. `archive_write_disk_posix.c` calls `set_ownership` before `set_perm`.
//!
//! # Extended attributes come after both
//!
//! The same `chown` also removes `security.capability`: the kernel drops it on any change of
//! owner, as it drops the setuid bit. A write to the file drops it too. So the attributes are
//! set once the contents, the owner and the mode are final, and only the times follow. This is
//! libarchive's order when it runs as root: ownership, then mode, then `set_xattrs`, then
//! times. A mode change does not touch an attribute.
//!
//! Two namespaces are restored: `user.*` and `security.capability`. Every other one is
//! reported and left off. `security.capability` is how `newuidmap` gets `cap_setuid` without
//! a setuid bit. It grants no more than the setuid bit this module already restores. The other
//! `security.*` names are labels for an LSM policy to assign, not for a package to choose.
//! `trusted.*` holds state that kernel subsystems read, such as overlayfs whiteouts. `system.*`
//! is ACLs, which libalpm does not restore either. No package measured carries any of them.
//!
//! An attribute that cannot be set is reported and does not fail the install. libalpm treats
//! libarchive's `ARCHIVE_WARN` the same way. The package's files are already on disk by then,
//! and a filesystem without extended attributes, such as a FAT `/boot`, must not stop it.
use std::{
    ffi::OsString,
    io::{Read, Write as _},
    os::fd::AsFd,
    path::{Path, PathBuf},
};

use rustix::fs::{AtFlags, Gid, Mode, OFlags, Timestamps, Uid};

use crate::{
    error::{Error, IoAction, Result},
    extract::{
        archive::{Link, LinkKind, Member, Xattr},
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

/// An extended attribute the archive recorded and the disk does not have.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrProblem {
    /// The member's path, as the archive spells it.
    pub path: PathBuf,
    /// The attribute's full name.
    pub name: OsString,
    /// Why it was not set.
    pub reason: XattrRefusal,
}

/// Why an extended attribute was not set.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum XattrRefusal {
    /// Its namespace is not one piko restores. See the module documentation.
    Namespace,
    /// The member is a symbolic link. Linux refuses `user.*` on a link, and a capability on
    /// one means nothing.
    Symlink,
    /// The kernel refused it, with this error.
    Failed(String),
}

impl std::fmt::Display for XattrProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Both come from the archive, and this line is printed on a terminal.
        let name = piko_db::printable(&self.name.to_string_lossy());
        let path = piko_db::printable_path(&self.path);
        match &self.reason {
            XattrRefusal::Namespace => {
                write!(f, "{path}: extended attribute {name} is not restored (namespace refused)")
            }
            XattrRefusal::Symlink => {
                write!(f, "{path}: extended attribute {name} is not set on a symbolic link")
            }
            XattrRefusal::Failed(error) => {
                let error = piko_db::printable(error);
                write!(f, "{path}: could not set extended attribute {name}: {error}")
            }
        }
    }
}

/// Whether piko restores an attribute of this name.
fn accepted(name: &std::ffi::OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let name = name.as_bytes();
    name == b"security.capability" || name.starts_with(b"user.")
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
/// Every extended attribute `member` records that was not set is appended to `xattrs`.
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
    xattrs: &mut Vec<XattrProblem>,
) -> Result<Applied> {
    // Before anything is written, so a refused owner leaves no file behind.
    if ownership == Ownership::FromArchive {
        owner_ids(member)?;
    }
    match disposition {
        Disposition::Skip(_) => Ok(Applied::Skipped),
        Disposition::Refuse(reason) => {
            Err(Error::ExtractionRefused { path: member.path.clone(), reason: *reason })
        }
        Disposition::Extract => {
            let resolved = root.resolve_parent(&member.path)?;
            write_member(root, &resolved, resolved.name(), member, contents, ownership, xattrs)?;
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

            write_member(root, &resolved, name.as_os_str(), member, contents, ownership, xattrs)?;
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
    xattrs: &mut Vec<XattrProblem>,
) -> Result<()> {
    match member.link.as_ref() {
        Some(Link { kind: LinkKind::Symbolic, target }) => {
            refuse_all(member, XattrRefusal::Symlink, xattrs);
            write_symlink(resolved, name, target, member, ownership)
        }
        // A hard link's attributes are its target's, set when the target was written.
        Some(Link { kind: LinkKind::Hard, target }) => {
            write_hard_link(root, resolved, name, target)
        }
        None => match member.entry {
            EntryKind::Directory => write_directory(resolved, name, member, ownership, xattrs),
            EntryKind::Other => write_file(resolved, name, member, contents, ownership, xattrs),
        },
    }
}

/// Reports every attribute `member` records as not set, for `reason`.
fn refuse_all(member: &Member, reason: XattrRefusal, problems: &mut Vec<XattrProblem>) {
    problems.extend(member.xattrs.iter().map(|xattr| XattrProblem {
        path: member.path.clone(),
        name: xattr.name.clone(),
        reason: reason.clone(),
    }));
}

/// Sets `member`'s extended attributes on the open file `fd`, reporting what was not set.
///
/// Through the descriptor, so the attributes land on the object that was just written, never
/// on whatever a path resolves to now.
fn set_xattrs(fd: &impl AsFd, member: &Member, problems: &mut Vec<XattrProblem>) {
    for Xattr { name, value } in &member.xattrs {
        let reason = if accepted(name) {
            match rustix::fs::fsetxattr(
                fd,
                name.as_os_str(),
                value,
                rustix::fs::XattrFlags::empty(),
            ) {
                Ok(()) => continue,
                Err(error) => XattrRefusal::Failed(std::io::Error::from(error).to_string()),
            }
        } else {
            XattrRefusal::Namespace
        };
        problems.push(XattrProblem { path: member.path.clone(), name: name.clone(), reason });
    }
}

/// Creates a hard link to another member of the same package.
///
/// The target is a path relative to the installation root, so [`RootDir`] resolves it like any
/// other path. A hard link is the one archive construct that can reach an *existing* file by
/// name. Confining it matters as much as confining the destination. This uses
/// `AtFlags::empty()` rather than `SYMLINK_FOLLOW`. Linking to the symlink itself, rather than
/// to whatever it points at, keeps the result inside the root.
///
/// Mode, ownership and times are not set here. A hard link is a second name for one inode, so
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
    xattrs: &mut Vec<XattrProblem>,
) -> Result<()> {
    remove_existing(resolved, name)?;

    // Created private, and given its own mode only once its contents, owner and attributes are
    // final. Created at the archive's mode, a setuid binary would sit executable and setuid,
    // under the extracting user's id, while its contents were still being written. libarchive
    // creates restrictively and sets the mode last for the same reason.
    let fd = rustix::fs::openat(
        resolved.dir(),
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|source| io(name, IoAction::Create, source))?;

    let mut file = std::fs::File::from(fd);
    copy(contents, &mut file, name)?;
    set_metadata_fd(&file, name, member, ownership, xattrs)
}

/// Applies `member`'s owner, mode, extended attributes and times to the open object `fd`.
///
/// Through the descriptor, never through the name. A name can be swapped for a symbolic link
/// between the create and these calls by anyone who can write the directory, and `chmod` on a
/// name follows a link: root would then give the archive's mode to whatever the link points at.
///
/// Ownership is applied first, then the mode. This order is load-bearing — see the module
/// note above. The attributes come after both, and the times last.
fn set_metadata_fd(
    fd: &impl AsFd,
    name: &std::ffi::OsStr,
    member: &Member,
    ownership: Ownership,
    xattrs: &mut Vec<XattrProblem>,
) -> Result<()> {
    apply_ownership_fd(fd, member, ownership, name)?;
    // The process umask masks the mode passed to `openat` or `mkdirat`, so this sets it again.
    let mode = Mode::from_raw_mode(member.mode & 0o7777);
    rustix::fs::fchmod(fd, mode).map_err(|source| io(name, IoAction::Metadata, source))?;
    set_xattrs(fd, member, xattrs);
    rustix::fs::futimens(fd, &timestamps(member))
        .map_err(|source| io(name, IoAction::Metadata, source))
}

/// Creates a directory, or leaves an existing one alone.
///
/// An existing directory keeps its mode. libalpm warns when the modes differ but changes
/// nothing (`add.c:258`), because the directory may be shared with another package or
/// adjusted deliberately.
///
/// The new directory is opened `O_NOFOLLOW | O_DIRECTORY` straight after the create, and its
/// metadata is set through that descriptor. A user who can write the parent can replace the
/// directory with a symbolic link in between. The open then fails rather than reaching the
/// link's target.
///
/// A directory is exempt from the setgid-clearing rule the module note describes. Measured:
/// `chown_common` sets `ATTR_KILL_SUID` only for `!S_ISDIR`. Ownership still comes before the
/// mode, so a setgid directory does not depend on that exemption.
fn write_directory(
    resolved: &Resolved,
    name: &std::ffi::OsStr,
    member: &Member,
    ownership: Ownership,
    xattrs: &mut Vec<XattrProblem>,
) -> Result<()> {
    let mode = Mode::from_raw_mode(member.mode & 0o7777);
    match rustix::fs::mkdirat(resolved.dir(), name, mode) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => return Ok(()),
        Err(source) => return Err(io(name, IoAction::CreateDir, source)),
    }

    let fd = rustix::fs::openat(
        resolved.dir(),
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| io(name, IoAction::Open, source))?;
    set_metadata_fd(&fd, name, member, ownership, xattrs)
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
    let (uid, gid) = owner_ids(member)?;
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
    let (uid, gid) = owner_ids(member)?;
    rustix::fs::chownat(resolved.dir(), name, Some(uid), Some(gid), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io(name, IoAction::Chown, source))
}

/// The archive's uid and gid, as ids the kernel accepts.
///
/// `archive::walk` refuses a member this refuses, so extraction never meets one. The check is
/// repeated here because [`apply`] is public and takes any [`Member`].
///
/// # Errors
///
/// [`Error::UnusableMemberOwner`] if either id does not fit 32 bits, or is `u32::MAX`, which
/// `chown` reads as "leave unchanged".
pub(crate) fn owner_ids(member: &Member) -> Result<(Uid, Gid)> {
    let usable = |id: u64| u32::try_from(id).ok().filter(|id| *id != u32::MAX);
    match (usable(member.uid), usable(member.gid)) {
        (Some(uid), Some(gid)) => Ok((Uid::from_raw(uid), Gid::from_raw(gid))),
        _ => Err(Error::UnusableMemberOwner {
            member: member.path.clone(),
            uid: member.uid,
            gid: member.gid,
        }),
    }
}

/// Applies the archive's modification time, without following a symlink.
///
/// libalpm passes `ARCHIVE_EXTRACT_TIME` (`add.c:120`). This sets both timestamps to the
/// member's `mtime`. tar records no access time, and leaving atime alone would let the
/// extraction itself define it.
fn set_times(resolved: &Resolved, name: &std::ffi::OsStr, member: &Member) -> Result<()> {
    rustix::fs::utimensat(resolved.dir(), name, &timestamps(member), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| io(name, IoAction::Metadata, source))
}

/// The member's modification time, as both timestamps.
fn timestamps(member: &Member) -> Timestamps {
    let seconds = i64::try_from(member.mtime).unwrap_or(0);
    let stamp = rustix::fs::Timespec { tv_sec: seconds, tv_nsec: 0 };
    Timestamps { last_access: stamp, last_modification: stamp }
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
            xattrs: Vec::new(),
        }
    }

    fn root() -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = RootDir::open(dir.path()).unwrap();
        (dir, root)
    }

    fn write(root: &RootDir, member: &Member, contents: &[u8]) -> Applied {
        apply(
            root,
            member,
            &mut &contents[..],
            &Disposition::Extract,
            Ownership::Inherit,
            &mut Vec::new(),
        )
        .unwrap()
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
            &mut Vec::new(),
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

        apply(
            &root,
            &entry,
            &mut &b"payload"[..],
            &Disposition::Extract,
            Ownership::FromArchive,
            &mut Vec::new(),
        )
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

        let err = apply(
            &root,
            &entry,
            &mut &b""[..],
            &Disposition::Extract,
            Ownership::Inherit,
            &mut Vec::new(),
        )
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
            &mut Vec::new(),
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
            &mut Vec::new(),
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
            &mut Vec::new(),
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
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::ExtractionRefused { .. }), "got {err:?}");
    }

    fn xattr(name: &str, value: &[u8]) -> Xattr {
        Xattr { name: name.into(), value: value.to_vec() }
    }

    fn get_xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
        let mut buffer = vec![0_u8; 256];
        let length = rustix::fs::lgetxattr(path, name, &mut buffer[..]).ok()?;
        buffer.truncate(length);
        Some(buffer)
    }

    fn apply_reporting(root: &RootDir, member: &Member, ownership: Ownership) -> Vec<XattrProblem> {
        let mut problems = Vec::new();
        apply(root, member, &mut &b"payload"[..], &Disposition::Extract, ownership, &mut problems)
            .unwrap();
        problems
    }

    /// A `user.*` attribute lands on the file, and survives the `chown` that ownership applies.
    #[test]
    fn restores_a_user_attribute_on_a_file_and_a_directory() {
        let (dir, root) = root();
        let mut directory = member("share", EntryKind::Directory, 0o755);
        directory.xattrs = vec![xattr("user.kind", b"dir")];
        let mut file = member("share/f", EntryKind::Other, 0o644);
        file.uid = u64::from(rustix::process::getuid().as_raw());
        file.gid = u64::from(rustix::process::getgid().as_raw());
        file.xattrs = vec![xattr("user.kind", b"file")];

        assert_eq!(apply_reporting(&root, &directory, Ownership::Inherit), []);
        assert_eq!(apply_reporting(&root, &file, Ownership::FromArchive), []);

        assert_eq!(get_xattr(&dir.path().join("share"), "user.kind").unwrap(), b"dir");
        assert_eq!(get_xattr(&dir.path().join("share/f"), "user.kind").unwrap(), b"file");
    }

    /// Only `user.*` and `security.capability` are restored. The rest is reported, not set.
    #[test]
    fn an_attribute_outside_the_accepted_namespaces_is_reported_and_not_set() {
        let (dir, root) = root();
        let mut file = member("f", EntryKind::Other, 0o644);
        file.xattrs = vec![
            xattr("trusted.overlay.opaque", b"y"),
            xattr("security.selinux", b"system_u:object_r:shadow_t:s0"),
            xattr("user.ok", b"1"),
        ];

        let problems = apply_reporting(&root, &file, Ownership::Inherit);
        let refused: Vec<_> = problems.iter().map(|p| (p.name.clone(), p.reason.clone())).collect();
        assert_eq!(
            refused,
            [
                ("trusted.overlay.opaque".into(), XattrRefusal::Namespace),
                ("security.selinux".into(), XattrRefusal::Namespace),
            ]
        );
        assert_eq!(get_xattr(&dir.path().join("f"), "user.ok").unwrap(), b"1");
    }

    /// The attribute's name and the member's path are the archive's, and the report is printed.
    #[test]
    fn a_reported_attribute_escapes_what_could_drive_a_terminal() {
        let problem = XattrProblem {
            path: PathBuf::from("usr/bin/\u{1b}[2J"),
            name: "trusted.\u{1b}]0;title\u{7}".into(),
            reason: XattrRefusal::Namespace,
        };
        let line = problem.to_string();
        assert!(!line.contains('\u{1b}') && !line.contains('\u{7}'), "{line:?}");
    }

    #[test]
    fn an_attribute_on_a_symlink_is_reported_and_the_link_is_still_made() {
        let (dir, root) = root();
        let mut link = member("link", EntryKind::Other, 0o777);
        link.link = Some(Link { kind: LinkKind::Symbolic, target: PathBuf::from("target") });
        link.xattrs = vec![xattr("user.x", b"1")];

        let problems = apply_reporting(&root, &link, Ownership::Inherit);
        assert_eq!(problems.first().map(|p| &p.reason), Some(&XattrRefusal::Symlink));
        assert!(std::fs::symlink_metadata(dir.path().join("link")).unwrap().is_symlink());
    }

    /// A capability the kernel refuses is reported, and the file is still written. Unprivileged,
    /// `CAP_SETFCAP` is missing, which is the refusal this reaches. As root the attribute is set,
    /// which `extract_real_system.rs` checks against a real package.
    #[test]
    fn a_capability_the_kernel_refuses_is_reported_and_does_not_fail_the_file() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let (dir, root) = root();
        let mut file = member("newuidmap", EntryKind::Other, 0o755);
        file.xattrs = vec![xattr(
            "security.capability",
            b"\x01\x00\x00\x02\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )];

        let problems = apply_reporting(&root, &file, Ownership::Inherit);
        assert!(
            matches!(problems.as_slice(), [XattrProblem { reason: XattrRefusal::Failed(_), .. }]),
            "got {problems:?}"
        );
        assert_eq!(std::fs::read(dir.path().join("newuidmap")).unwrap(), b"payload");
    }

    /// While a file's contents are written, it is private: no setuid bit, no group or other
    /// access. The archive's mode arrives only once the file is complete.
    #[test]
    fn a_file_is_private_while_its_contents_are_written() {
        use std::os::unix::fs::PermissionsExt as _;

        /// A reader that records the destination's mode the first time it is read from.
        struct Spy {
            path: PathBuf,
            seen: Option<u32>,
            data: &'static [u8],
        }
        impl Read for Spy {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.seen.is_none() {
                    self.seen = Some(std::fs::metadata(&self.path)?.permissions().mode() & 0o7777);
                }
                self.data.read(buffer)
            }
        }

        let (dir, root) = root();
        let mut entry = member("suid", EntryKind::Other, 0o4755);
        entry.uid = u64::from(rustix::process::getuid().as_raw());
        entry.gid = u64::from(rustix::process::getgid().as_raw());
        let mut spy = Spy { path: dir.path().join("suid"), seen: None, data: b"payload" };

        apply(
            &root,
            &entry,
            &mut spy,
            &Disposition::Extract,
            Ownership::FromArchive,
            &mut Vec::new(),
        )
        .unwrap();

        let during = spy.seen.unwrap();
        assert_eq!(during & 0o7077, 0, "the file was {during:o} while it was written");
        let after = std::fs::metadata(dir.path().join("suid")).unwrap().permissions().mode();
        assert_eq!(after & 0o7777, 0o4755);
    }

    /// A new directory swapped for a symbolic link before its mode is set must not lend that
    /// mode to the link's target.
    ///
    /// A second thread replaces each directory `apply` creates with a link to a file outside
    /// the root, as a user who can write the parent could. A mode set by name reaches that file
    /// within a few hundred attempts. A mode set through the descriptor cannot, so no number of
    /// attempts makes this test fail.
    #[test]
    fn a_directory_swapped_for_a_symlink_does_not_lend_its_mode_to_the_target() {
        use std::{
            os::unix::fs::PermissionsExt as _,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
        };

        let (dir, root) = root();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, b"secret").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut entry = member("d", EntryKind::Directory, 0o777);
        entry.uid = u64::from(rustix::process::getuid().as_raw());
        entry.gid = u64::from(rustix::process::getgid().as_raw());

        let slot = dir.path().join("d");
        let parked = dir.path().join("parked");
        let stop = Arc::new(AtomicBool::new(false));
        let racer = {
            let (slot, parked, victim, stop) =
                (slot.clone(), parked.clone(), victim.clone(), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if std::fs::symlink_metadata(&slot).is_ok_and(|m| m.is_dir())
                        && std::fs::rename(&slot, &parked).is_ok()
                    {
                        let _ = std::os::unix::fs::symlink(&victim, &slot);
                    }
                }
            })
        };

        for _ in 0..5_000 {
            let _ = std::fs::remove_file(&slot);
            let _ = std::fs::remove_dir(&slot);
            let _ = std::fs::remove_dir(&parked);
            // Either outcome of the race is acceptable: written, or refused. Only the victim's
            // mode is asserted.
            let _ = apply(
                &root,
                &entry,
                &mut &b""[..],
                &Disposition::Extract,
                Ownership::FromArchive,
                &mut Vec::new(),
            );
            let mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o7777;
            if mode != 0o600 {
                stop.store(true, Ordering::Relaxed);
                racer.join().unwrap();
                panic!("a file outside the root was re-moded to {mode:o}");
            }
        }
        stop.store(true, Ordering::Relaxed);
        racer.join().unwrap();
    }

    /// `apply` takes any `Member`, so it refuses an owner the walk would have refused, rather
    /// than narrowing it to root.
    #[test]
    fn an_owner_the_kernel_cannot_set_is_refused_rather_than_narrowed() {
        let (dir, root) = root();
        let mut entry = member("f", EntryKind::Other, 0o644);
        entry.uid = 1 << 32;
        let err = apply(
            &root,
            &entry,
            &mut &b"x"[..],
            &Disposition::Extract,
            Ownership::FromArchive,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::UnusableMemberOwner { .. }), "got {err:?}");
        assert!(!dir.path().join("f").exists(), "the file was written anyway");
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
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::UnsafeArchivePath { .. }), "got {err:?}");
    }
}
