//! Carrying out a decision about one pending file.
//!
//! Every write goes through a [`Resolved`]. So the directory written in is the object that was
//! checked, never a path that resolves to it by the time the write runs. A joined path is for
//! display only.
//!
//! # The two ways a file is replaced are not the same, on purpose
//!
//! [`Action::Overwrite`] renames the pending file over the target. The target's inode is
//! replaced, so it takes the package's mode and owner. That is what the package says its
//! configuration file should be, and it is what `mv` does in `pacdiff`.
//!
//! [`Action::UseMerged`] truncates the target in place. The inode survives, so the mode, the
//! owner, the ACLs, the hard links and any open descriptor all survive with it. A merged file
//! is the user's file with changes folded in, so it keeps the user's file's identity. Writing a
//! temporary and renaming it would reset the mode to the temporary's and break hard links; `cp`
//! in `pacdiff` truncates for the same reason. The cost is that a crash mid-write leaves a
//! partial file, which is the trade `cp` makes too.

use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Mode, OFlags};

use crate::{
    error::{Error, IoAction, Result},
    hash,
    merge::Pending,
    rootfs::{Resolved, RootDir},
};

/// What to do with one pending file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action<'a> {
    /// Leave both files where they are.
    Skip,
    /// Delete the pending file.
    Remove,
    /// Rename the pending file over the target.
    Overwrite,
    /// Write `contents` into the target, then delete the pending file.
    UseMerged {
        /// The merged bytes, as the merge program produced them.
        contents: &'a [u8],
    },
}

/// What applying an [`Action`] did.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Outcome {
    /// Nothing was touched.
    Skipped,
    /// The pending file was deleted.
    Removed {
        /// The file that is gone.
        pacfile: PathBuf,
    },
    /// The pending file is now the target.
    Overwritten {
        /// The file that now holds the package's version.
        target: PathBuf,
        /// The pending file that is gone.
        pacfile: PathBuf,
    },
    /// The target was rewritten and the pending file deleted.
    Merged {
        /// The file that now holds the merged bytes.
        target: PathBuf,
        /// The pending file that is gone.
        pacfile: PathBuf,
    },
}

/// Carries out `action` on `pending`.
///
/// # Errors
///
/// [`Error::UnsafeArchivePath`] or [`Error::PathEscapesRoot`] if a path does not resolve inside
/// the root, and [`Error::Io`] if a rename, a removal or a write fails.
pub fn apply(root: &RootDir, pending: &Pending, action: Action<'_>) -> Result<Outcome> {
    match action {
        Action::Skip => Ok(Outcome::Skipped),
        Action::Remove => {
            let resolved = root.resolve_parent(&pending.target)?;
            let pacname = self::pacname(pending)?;
            rustix::fs::unlinkat(resolved.dir(), &pacname, AtFlags::empty())
                .map_err(|source| Error::io(&pending.pacfile, IoAction::Remove, source.into()))?;
            Ok(Outcome::Removed { pacfile: pending.pacfile.clone() })
        }
        Action::Overwrite => {
            let resolved = root.resolve_parent(&pending.target)?;
            let pacname = self::pacname(pending)?;
            rustix::fs::renameat(resolved.dir(), &pacname, resolved.dir(), resolved.name())
                .map_err(|source| Error::io(&pending.pacfile, IoAction::Rename, source.into()))?;
            Ok(Outcome::Overwritten {
                target: pending.target.clone(),
                pacfile: pending.pacfile.clone(),
            })
        }
        Action::UseMerged { contents } => {
            let resolved = root.resolve_parent(&pending.target)?;
            self::truncate_and_write(&resolved, &pending.target, contents)?;
            let pacname = self::pacname(pending)?;
            rustix::fs::unlinkat(resolved.dir(), &pacname, AtFlags::empty())
                .map_err(|source| Error::io(&pending.pacfile, IoAction::Remove, source.into()))?;
            Ok(Outcome::Merged { target: pending.target.clone(), pacfile: pending.pacfile.clone() })
        }
    }
}

/// Deletes the pending file, and only if it still holds the target's bytes.
///
/// [`apply`] does what it is told. This asks the question and acts on the answer through one
/// descriptor, so nothing changes between the two. It is the one act a caller performs without
/// asking the user, which is why it re-reads rather than trusting a scan's verdict.
///
/// The outcome is [`Outcome::Skipped`] when the two differ, or when either is gone.
///
/// # Errors
///
/// As [`apply`], plus whatever [`hash::same_contents_at`] refuses.
pub fn remove_if_identical(root: &RootDir, pending: &Pending, max: u64) -> Result<Outcome> {
    let resolved = root.resolve_parent(&pending.target)?;
    let pacname = self::pacname(pending)?;
    let same = hash::same_contents_at(resolved.dir(), resolved.name(), &pacname, max)?;
    if same != Some(true) {
        return Ok(Outcome::Skipped);
    }
    rustix::fs::unlinkat(resolved.dir(), &pacname, AtFlags::empty())
        .map_err(|source| Error::io(&pending.pacfile, IoAction::Remove, source.into()))?;
    Ok(Outcome::Removed { pacfile: pending.pacfile.clone() })
}

/// Writes `contents` over the file `resolved` names, keeping its inode.
///
/// `O_NOFOLLOW` is the protection: a target that has become a symlink fails here rather than
/// being followed out of the root. `O_NONBLOCK` keeps a FIFO from blocking the open.
fn truncate_and_write(resolved: &Resolved, path: &Path, contents: &[u8]) -> Result<()> {
    let fd = rustix::fs::openat(
        resolved.dir(),
        resolved.name(),
        OFlags::WRONLY | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| Error::io(path, IoAction::Open, source.into()))?;

    let stat = rustix::fs::fstat(&fd)
        .map_err(|source| Error::io(path, IoAction::Metadata, source.into()))?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(Error::UnusableSource {
            path: path.to_path_buf(),
            reason: "not a regular file".to_owned(),
        });
    }

    use std::io::Write as _;
    let mut file = std::fs::File::from(fd);
    file.write_all(contents).map_err(|source| Error::io(path, IoAction::Write, source))?;
    file.sync_all().map_err(|source| Error::io(path, IoAction::Write, source))
}

/// The pending file's own name, beside its target in the same directory.
///
/// Built from the target's final component rather than from [`Pending::pacfile`]. Every action
/// resolves the target's parent, so deriving the name here is what keeps the name and the
/// descriptor naming one directory. It also means a target that does not resolve inside the
/// root refuses every action, including the removal of the file beside it.
fn pacname(pending: &Pending) -> Result<std::ffi::OsString> {
    let name = pending.target.file_name().ok_or_else(|| Error::UnsafeArchivePath {
        path: pending.target.clone(),
        reason: crate::rootfs::UnsafePath::Empty,
    })?;
    let mut pacname = name.to_os_string();
    pacname.push(pending.kind.suffix());
    Ok(pacname)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::merge::{PendingKind, Verdict};

    /// A root holding `etc/foo.conf` and `etc/foo.conf.pacnew` with the contents given.
    fn root(target: &[u8], pacfile: &[u8]) -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/foo.conf"), target).unwrap();
        std::fs::write(dir.path().join("etc/foo.conf.pacnew"), pacfile).unwrap();
        let root = RootDir::open(dir.path()).unwrap();
        (dir, root)
    }

    fn pending() -> Pending {
        Pending {
            pacfile: PathBuf::from("etc/foo.conf.pacnew"),
            target: PathBuf::from("etc/foo.conf"),
            kind: PendingKind::Pacnew,
            package: "foo".parse().unwrap(),
            installed_version: "1.0.0-1".parse().unwrap(),
            verdict: Verdict::Differs,
        }
    }

    #[test]
    fn skip_touches_nothing() {
        let (dir, root) = root(b"mine", b"theirs");
        assert_eq!(apply(&root, &pending(), Action::Skip).unwrap(), Outcome::Skipped);
        assert!(dir.path().join("etc/foo.conf").exists());
        assert!(dir.path().join("etc/foo.conf.pacnew").exists());
    }

    #[test]
    fn remove_deletes_only_the_pending_file() {
        let (dir, root) = root(b"mine", b"theirs");
        let outcome = apply(&root, &pending(), Action::Remove).unwrap();

        assert!(matches!(outcome, Outcome::Removed { .. }), "got {outcome:?}");
        assert!(!dir.path().join("etc/foo.conf.pacnew").exists());
        assert_eq!(std::fs::read(dir.path().join("etc/foo.conf")).unwrap(), b"mine");
    }

    #[test]
    fn overwrite_moves_the_pending_file_into_place() {
        let (dir, root) = root(b"mine", b"theirs");
        let outcome = apply(&root, &pending(), Action::Overwrite).unwrap();

        assert!(matches!(outcome, Outcome::Overwritten { .. }), "got {outcome:?}");
        assert!(!dir.path().join("etc/foo.conf.pacnew").exists());
        assert_eq!(std::fs::read(dir.path().join("etc/foo.conf")).unwrap(), b"theirs");
    }

    /// The merged file is the user's file with changes folded in, so it keeps the user's
    /// file's identity: the same inode, and with it the mode, the owner and any hard link.
    #[cfg(unix)]
    #[test]
    fn use_merged_rewrites_the_target_in_place() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let (dir, root) = root(b"mine", b"theirs");
        let target = dir.path().join("etc/foo.conf");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::metadata(&target).unwrap();

        let outcome = apply(&root, &pending(), Action::UseMerged { contents: b"merged" }).unwrap();

        assert!(matches!(outcome, Outcome::Merged { .. }), "got {outcome:?}");
        assert_eq!(std::fs::read(&target).unwrap(), b"merged");
        assert!(!dir.path().join("etc/foo.conf.pacnew").exists());
        let after = std::fs::metadata(&target).unwrap();
        assert_eq!(after.ino(), before.ino(), "the inode must survive");
        assert_eq!(after.permissions().mode() & 0o777, 0o600);
    }

    /// A target that has become a symlink must fail rather than be followed out of the root.
    #[cfg(unix)]
    #[test]
    fn use_merged_refuses_a_symlinked_target() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret");
        std::fs::write(&secret, b"secret").unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("etc/foo.conf")).unwrap();
        std::fs::write(dir.path().join("etc/foo.conf.pacnew"), b"theirs").unwrap();
        let root = RootDir::open(dir.path()).unwrap();

        assert!(apply(&root, &pending(), Action::UseMerged { contents: b"merged" }).is_err());
        assert_eq!(std::fs::read(&secret).unwrap(), b"secret");
    }

    #[test]
    fn a_path_that_escapes_the_root_is_refused() {
        let (_dir, root) = root(b"mine", b"theirs");
        let escaping = Pending { target: PathBuf::from("../outside.conf"), ..pending() };
        assert!(apply(&root, &escaping, Action::Remove).is_err());
        assert!(apply(&root, &escaping, Action::Overwrite).is_err());
    }

    #[test]
    fn removes_a_pending_file_that_still_matches() {
        let (dir, root) = root(b"same", b"same");
        let outcome =
            remove_if_identical(&root, &pending(), crate::hash::MAX_BACKUP_BYTES).unwrap();

        assert!(matches!(outcome, Outcome::Removed { .. }), "got {outcome:?}");
        assert!(!dir.path().join("etc/foo.conf.pacnew").exists());
    }

    /// A scan's verdict is a snapshot. This is the one act taken without asking the user, so
    /// it asks the question again through the descriptor it acts on.
    #[test]
    fn keeps_a_pending_file_that_changed_since_the_scan() {
        let (dir, root) = root(b"same", b"changed after the scan");
        let outcome =
            remove_if_identical(&root, &pending(), crate::hash::MAX_BACKUP_BYTES).unwrap();

        assert_eq!(outcome, Outcome::Skipped);
        assert!(dir.path().join("etc/foo.conf.pacnew").exists());
    }

    #[test]
    fn keeps_a_pending_file_whose_target_is_gone() {
        let (dir, root) = root(b"same", b"same");
        std::fs::remove_file(dir.path().join("etc/foo.conf")).unwrap();

        let outcome =
            remove_if_identical(&root, &pending(), crate::hash::MAX_BACKUP_BYTES).unwrap();
        assert_eq!(outcome, Outcome::Skipped);
        assert!(dir.path().join("etc/foo.conf.pacnew").exists());
    }
}
