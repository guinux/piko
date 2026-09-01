//! Resolves a backup file after its `.pacnew` has been written.
//!
//! [`super::apply`] writes the packaged version to `<path>.pacnew` and stops there. This
//! module decides what happens next: whether the user's file is replaced, kept, or left beside
//! the new one for them to merge.
//!
//! The rule itself is [`super::decision::resolve_backup`], which is pure. This module only
//! supplies its three hashes and carries out its answer.

use std::path::{Path, PathBuf};

use alpm_types::Md5Checksum;

use crate::{
    error::{Error, IoAction, Result},
    extract::{
        apply::PACNEW_SUFFIX,
        decision::{BackupAction, resolve_backup},
    },
    hash::{self, MAX_BACKUP_BYTES},
    rootfs::RootDir,
};

/// What happened to a backup file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupOutcome {
    /// The packaged version was moved into place.
    InstalledNew,
    /// The user's file was kept.
    KeptExisting {
        /// Whether the `.pacnew` was removed as redundant.
        pacnew_removed: bool,
    },
    /// Both remain; the user has to merge them.
    KeptBoth {
        /// The `.pacnew` left on disk, for reporting.
        pacnew: PathBuf,
    },
}

/// The result of resolving one backup file.
#[derive(Clone, Debug)]
pub struct Resolution {
    /// What happened.
    pub outcome: BackupOutcome,
    /// The hash to record in `%BACKUP%`.
    ///
    /// This is always the hash of what the *package* shipped, even when the user's file was
    /// kept. That is what libalpm records (`add.c:335` hashes the just-extracted file), and it
    /// has to be: the next upgrade reads it back as "what the previous package shipped", the
    /// only baseline that can tell an edited file from an untouched one.
    pub recorded_hash: Option<Md5Checksum>,
    /// Whether a hash could not be computed.
    ///
    /// This is reported rather than swallowed, per principle 7. An unreadable file is
    /// *unknown*, and [`resolve_backup`] deliberately keeps the user's copy when a hash is
    /// unknown. The caller should still be able to say so.
    pub unreadable: bool,
}

/// Resolves the backup file at `path`, whose `.pacnew` has just been written.
///
/// `original_hash` is what the currently installed package recorded for this path, or `None`
/// if it did not have one.
///
/// # Errors
///
/// [`Error::UnsafeArchivePath`] or [`Error::PathEscapesRoot`] if `path` cannot be resolved
/// inside the root, or [`Error::Io`] if a rename or removal fails.
pub fn resolve(
    root: &RootDir,
    path: &Path,
    original_hash: Option<&str>,
    pacnew_is_new: bool,
) -> Result<Resolution> {
    let resolved = root.resolve_parent(path)?;
    let mut pacnew_name = resolved.name().to_os_string();
    pacnew_name.push(PACNEW_SUFFIX);

    // A hash that cannot be computed is *unknown*, not *absent* and not *equal*. Both map to
    // `None` here, the input `resolve_backup` treats conservatively.
    let mut unreadable = false;
    let mut hash = |name: &std::ffi::OsStr| -> Option<Md5Checksum> {
        match hash::file_md5_at(resolved.dir(), name, MAX_BACKUP_BYTES) {
            Ok(value) => value,
            Err(_) => {
                unreadable = true;
                None
            }
        }
    };

    let local = hash(resolved.name());
    let packaged = hash(pacnew_name.as_os_str());

    let action = resolve_backup(
        local.as_ref().map(ToString::to_string).as_deref(),
        packaged.as_ref().map(ToString::to_string).as_deref(),
        original_hash,
        pacnew_is_new,
    );

    let outcome = match action {
        BackupAction::InstallNew => {
            rustix::fs::renameat(
                resolved.dir(),
                pacnew_name.as_os_str(),
                resolved.dir(),
                resolved.name(),
            )
            .map_err(|source| Error::io(path, IoAction::Rename, std::io::Error::from(source)))?;
            BackupOutcome::InstalledNew
        }
        BackupAction::KeepExisting { remove_pacnew } => {
            if remove_pacnew {
                match rustix::fs::unlinkat(
                    resolved.dir(),
                    pacnew_name.as_os_str(),
                    rustix::fs::AtFlags::empty(),
                ) {
                    Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                    Err(source) => {
                        return Err(Error::io(
                            path,
                            IoAction::Remove,
                            std::io::Error::from(source),
                        ));
                    }
                }
            }
            BackupOutcome::KeptExisting { pacnew_removed: remove_pacnew }
        }
        BackupAction::KeepBoth => BackupOutcome::KeptBoth {
            pacnew: PathBuf::from(format!("{}{PACNEW_SUFFIX}", path.display())),
        },
    };

    Ok(Resolution { outcome, recorded_hash: packaged, unreadable })
}

/// The `%BACKUP%` hash of a file that had no `.pacnew` to be resolved against.
///
/// [`resolve`] handles the case with three hashes to compare. This is the commoner one.
/// Leaving it out once made `%BACKUP%` look like an upgrade-only concept: libalpm records a
/// hash for **every** backup file it extracted, whatever cell of the matrix it landed in. The
/// `if(backup)` at `add.c:333` sits *outside* the `notouch || needbackup` branch. So a backup
/// file that simply was not on the system before — the whole of a fresh install — gets
/// recorded too.
///
/// `None` means the file could not be hashed. The caller reports that through
/// [`crate::Extraction::unreadable`], exactly as [`resolve`] does.
#[must_use]
pub fn hash_of(root: &RootDir, path: &Path) -> Option<Md5Checksum> {
    let resolved = root.resolve_parent(path).ok()?;
    hash::file_md5_at(resolved.dir(), resolved.name(), MAX_BACKUP_BYTES).ok().flatten()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// Sets up a root holding `conf` and `conf.pacnew` with the given contents.
    fn scenario(local: Option<&str>, packaged: Option<&str>) -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().unwrap();
        if let Some(local) = local {
            std::fs::write(dir.path().join("conf"), local).unwrap();
        }
        if let Some(packaged) = packaged {
            std::fs::write(dir.path().join("conf.pacnew"), packaged).unwrap();
        }
        let root = RootDir::open(dir.path()).unwrap();
        (dir, root)
    }

    fn md5(text: &str) -> String {
        Md5Checksum::calculate_from(text.as_bytes()).to_string()
    }

    #[test]
    fn installs_when_the_user_already_has_the_packaged_content() {
        let (dir, root) = scenario(Some("same"), Some("same"));
        let resolution = resolve(&root, Path::new("conf"), Some(&md5("old")), true).unwrap();

        assert_eq!(resolution.outcome, BackupOutcome::InstalledNew);
        assert_eq!(std::fs::read_to_string(dir.path().join("conf")).unwrap(), "same");
        assert!(!dir.path().join("conf.pacnew").exists(), "the .pacnew was not consumed");
    }

    #[test]
    fn keeps_the_users_file_when_the_package_did_not_change_it() {
        let (dir, root) = scenario(Some("edited"), Some("shipped"));
        let resolution = resolve(&root, Path::new("conf"), Some(&md5("shipped")), true).unwrap();

        assert_eq!(resolution.outcome, BackupOutcome::KeptExisting { pacnew_removed: true });
        assert_eq!(std::fs::read_to_string(dir.path().join("conf")).unwrap(), "edited");
        assert!(!dir.path().join("conf.pacnew").exists());
    }

    /// A `.pacnew` that predates this transaction is the user's, possibly half-merged.
    #[test]
    fn does_not_remove_a_pacnew_it_did_not_create() {
        let (dir, root) = scenario(Some("edited"), Some("shipped"));
        let resolution = resolve(&root, Path::new("conf"), Some(&md5("shipped")), false).unwrap();

        assert_eq!(resolution.outcome, BackupOutcome::KeptExisting { pacnew_removed: false });
        assert!(dir.path().join("conf.pacnew").exists());
    }

    #[test]
    fn upgrades_a_file_the_user_never_touched() {
        let (dir, root) = scenario(Some("original"), Some("new"));
        let resolution = resolve(&root, Path::new("conf"), Some(&md5("original")), true).unwrap();

        assert_eq!(resolution.outcome, BackupOutcome::InstalledNew);
        assert_eq!(std::fs::read_to_string(dir.path().join("conf")).unwrap(), "new");
    }

    /// The case the whole mechanism exists for.
    #[test]
    fn keeps_both_when_the_user_and_the_package_both_changed_it() {
        let (dir, root) = scenario(Some("edited"), Some("new"));
        let resolution = resolve(&root, Path::new("conf"), Some(&md5("original")), true).unwrap();

        assert!(matches!(resolution.outcome, BackupOutcome::KeptBoth { .. }));
        assert_eq!(std::fs::read_to_string(dir.path().join("conf")).unwrap(), "edited");
        assert_eq!(std::fs::read_to_string(dir.path().join("conf.pacnew")).unwrap(), "new");
    }

    /// The recorded hash is the package's, even when the user's file was kept. It is the
    /// baseline the *next* upgrade compares against.
    #[test]
    fn records_the_packaged_hash_even_when_keeping_the_users_file() {
        let (_dir, root) = scenario(Some("edited"), Some("new"));
        let resolution = resolve(&root, Path::new("conf"), Some(&md5("original")), true).unwrap();

        assert!(matches!(resolution.outcome, BackupOutcome::KeptBoth { .. }));
        assert_eq!(resolution.recorded_hash.unwrap().to_string(), md5("new"));
    }

    /// Without a baseline, only an exact match may overwrite. Piko cannot tell an edited
    /// file from an unedited one.
    #[test]
    fn a_newly_declared_backup_file_keeps_both_unless_identical() {
        let (dir, root) = scenario(Some("edited"), Some("new"));
        let resolution = resolve(&root, Path::new("conf"), None, true).unwrap();
        assert!(matches!(resolution.outcome, BackupOutcome::KeptBoth { .. }));
        assert_eq!(std::fs::read_to_string(dir.path().join("conf")).unwrap(), "edited");

        let (dir, root) = scenario(Some("same"), Some("same"));
        let resolution = resolve(&root, Path::new("conf"), None, true).unwrap();
        assert_eq!(resolution.outcome, BackupOutcome::InstalledNew);
        assert!(!dir.path().join("conf.pacnew").exists());
    }

    /// A config file the user deleted has no local hash, so nothing may be assumed about it.
    #[test]
    fn a_missing_local_file_keeps_both() {
        let (_dir, root) = scenario(None, Some("new"));
        let resolution = resolve(&root, Path::new("conf"), Some(&md5("original")), true).unwrap();
        assert!(matches!(resolution.outcome, BackupOutcome::KeptBoth { .. }));
        assert!(!resolution.unreadable, "absence is not unreadability");
    }

    /// An unreadable file is unknown, and unknown keeps the user's copy, and says so.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_local_file_is_reported_and_keeps_both() {
        let (dir, root) = scenario(None, Some("new"));
        // A symlink at the backup path cannot be hashed (`O_NOFOLLOW`). This is the
        // unreadable case, not the absent one.
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join("conf")).unwrap();

        let resolution = resolve(&root, Path::new("conf"), Some(&md5("original")), true).unwrap();
        assert!(matches!(resolution.outcome, BackupOutcome::KeptBoth { .. }));
        assert!(resolution.unreadable, "an unreadable file was not reported");
        // And it was not followed and overwritten.
        assert!(std::fs::symlink_metadata(dir.path().join("conf")).unwrap().is_symlink());
    }

    #[test]
    fn refuses_a_path_outside_the_root() {
        let (_dir, root) = scenario(Some("x"), Some("y"));
        assert!(resolve(&root, Path::new("../escape"), None, true).is_err());
    }
}
