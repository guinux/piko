//! Writes a file atomically, in a form that can be inspected before it lands.
//!
//! [`crate::LocalDbWriter`] already writes database entries atomically, but only from a `&[u8]`
//! held in memory. That fits a `desc`. It does not fit a downloaded repository database:
//! `extra.files` is about 50 MB on this machine. A downloaded file must also be **verified before
//! it replaces the live one**. This requires the file to exist on disk, under a name the verifier
//! can check, while the destination stays untouched.
//!
//! [`AtomicFile`] provides this. It streams into a temporary beside the destination, and
//! exposes that path through [`AtomicFile::path`] for inspection. It renames the temporary
//! over the target only when [`AtomicFile::commit`] runs. Dropping it without committing
//! removes the temporary, so
//! a failed or rejected download leaves nothing behind.
//!
//! The durability sequence matches [`crate::LocalDbWriter`]'s, for the same reason. It fsyncs
//! the data before the rename. Otherwise a crash can make the rename durable while the
//! contents are not, leaving an empty file where a good one belongs.

use std::{io::Write, path::Path, time::SystemTime};

use crate::{
    error::{Error, IoAction, Result},
    local::Temporary,
};

/// A file that becomes visible at its destination only when [`Self::commit`] is called.
///
/// # Why the temporary is never written through
///
/// The destination resists symlink games by construction: `rename` replaces a symlink rather
/// than resolving it. The *temporary* does not get this protection for free. The obvious
/// `create(true).truncate(true)` follows a final symlink. A `core.db.new` planted as a symlink
/// to `/etc/passwd` would then be truncated and filled by a process that typically runs as
/// root.
///
/// This type reuses `local`'s `create_temp`, which opens `O_CREAT | O_EXCL | O_NOFOLLOW`. When
/// it finds something already there, it **unlinks it and retries exactly once**. It uses
/// `remove_file`, which removes a symlink rather than resolving it. A planted temporary is
/// discarded rather than followed, and a leftover from a crashed write does not wedge the path
/// permanently.
#[derive(Debug)]
pub struct AtomicFile {
    temporary: Temporary,
    /// The mtime the committed file should carry, if the caller asked for one.
    modified: Option<SystemTime>,
}

impl AtomicFile {
    /// Creates a temporary beside `destination`, ready for writing.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the temporary cannot be created. This includes the case where
    /// something already exists at its path; the write is refused rather than overwriting it.
    pub fn create(destination: &Path) -> Result<Self> {
        Ok(Self { temporary: Temporary::create(destination)?, modified: None })
    }

    /// The temporary's path.
    ///
    /// This is what makes "verify before installing" possible. A caller hands this path to a
    /// signature check while the destination still holds the previous, known-good file.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.temporary.path()
    }

    /// Sets the modification time the committed file will carry.
    ///
    /// [`Self::commit`] applies this, not this call, because writing to the file would
    /// overwrite the timestamp again. A caller downloading a file uses this to stamp the
    /// server's `Last-Modified` onto it. That stamp is what lets the *next* conditional
    /// request send a value the server recognizes. See `piko_net`'s refresh path.
    pub const fn set_modified(&mut self, time: SystemTime) {
        self.modified = Some(time);
    }

    /// Flushes, fsyncs and renames the temporary over its destination.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if any step fails. The temporary is removed on failure, so a partial
    /// write is never left where a later run could rename it into place.
    pub fn commit(mut self) -> Result<()> {
        self.temporary
            .file_mut()
            .flush()
            .map_err(|source| Error::io(self.temporary.path(), IoAction::Write, source))?;
        // After the last write, which would otherwise move the mtime forward again, and before
        // the sync, which makes it durable with the contents. The rename does not touch the
        // mtime; it travels with the inode.
        if let Some(time) = self.modified {
            self.temporary.set_modified(time)?;
        }
        self.temporary.sync()?;
        let directory =
            self.temporary.destination().parent().unwrap_or(Path::new(".")).to_path_buf();
        self.temporary.publish()?;
        crate::local::sync_directory(&directory)
    }
}

impl Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.temporary.file_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.temporary.file_mut().flush()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn a_committed_file_replaces_its_destination() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("core.db");
        std::fs::write(&dest, b"old").unwrap();

        let mut file = AtomicFile::create(&dest).unwrap();
        file.write_all(b"new").unwrap();
        file.commit().unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    }

    /// This is the property the download path depends on. Until `commit`, the destination
    /// holds the old file, and the new bytes are inspectable at a separate path.
    #[test]
    fn the_destination_is_untouched_until_commit() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("core.db");
        std::fs::write(&dest, b"old").unwrap();

        let mut file = AtomicFile::create(&dest).unwrap();
        file.write_all(b"new").unwrap();
        file.flush().unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"old", "the live file changed too early");
        assert_eq!(std::fs::read(file.path()).unwrap(), b"new", "the temp is not readable");
        drop(file);
    }

    /// A rejected download costs nothing.
    #[test]
    fn dropping_without_committing_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("core.db");
        std::fs::write(&dest, b"old").unwrap();

        let temp = {
            let mut file = AtomicFile::create(&dest).unwrap();
            file.write_all(b"new").unwrap();
            file.path().to_path_buf()
        };

        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
        assert!(!temp.exists(), "the temporary survived the drop");
    }

    /// The stamped mtime survives the commit. That is the whole point: the next conditional
    /// request reads it back off the installed file.
    #[test]
    fn a_requested_modification_time_survives_the_commit() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("core.db");
        let stamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_787_000_000);

        let mut file = AtomicFile::create(&dest).unwrap();
        file.write_all(b"downloaded").unwrap();
        file.set_modified(stamp);
        file.commit().unwrap();

        let seen = std::fs::metadata(&dest).unwrap().modified().unwrap();
        assert_eq!(seen.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(), 1_787_000_000);
    }

    /// Writing with no destination yet present is the first-refresh case.
    #[test]
    fn a_missing_destination_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("core.db");

        let mut file = AtomicFile::create(&dest).unwrap();
        file.write_all(b"fresh").unwrap();
        file.commit().unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"fresh");
    }

    /// A planted temporary is discarded, never written through.
    ///
    /// This does not assert that `create` fails. `create_temp` deliberately unlinks a
    /// leftover and retries once, so a crashed write does not wedge the path forever. The
    /// property that matters is the one asserted here: the symlink's target stays untouched,
    /// so nothing was followed.
    #[test]
    fn a_planted_temporary_is_discarded_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("core.db");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"do not touch").unwrap();

        // This is the same name `AtomicFile` tries to create.
        let planted = crate::local::temp_path(&dest);
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        let mut file = AtomicFile::create(&dest).unwrap();
        file.write_all(b"downloaded").unwrap();
        file.commit().unwrap();

        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"do not touch",
            "the write followed a planted symlink"
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"downloaded");
    }

    /// A file this process must never touch, with a mode it must keep.
    #[cfg(unix)]
    fn victim(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let victim = dir.join("secret");
        std::fs::write(&victim, b"private").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        victim
    }

    /// Anyone who can write into the directory can swap the temporary for a symbolic link while
    /// it is written. The mode change must not reach the link's target, which would make a root
    /// process `chmod 644` any file it names. And the link must not be renamed over the
    /// destination.
    #[cfg(unix)]
    #[test]
    fn a_temporary_swapped_for_a_symlink_is_neither_followed_nor_installed() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let victim = victim(dir.path());
        let dest = dir.path().join("core.db");
        std::fs::write(&dest, b"old").unwrap();

        let mut file = AtomicFile::create(&dest).unwrap();
        file.write_all(b"downloaded").unwrap();
        let temp = file.path().to_path_buf();
        std::fs::remove_file(&temp).unwrap();
        std::os::unix::fs::symlink(&victim, &temp).unwrap();

        let err = file.commit().unwrap_err();
        assert!(matches!(err, Error::TemporaryReplaced { .. }), "got {err:?}");

        let mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the mode change followed the planted symlink");
        assert_eq!(std::fs::read(&victim).unwrap(), b"private");
        assert!(!std::fs::symlink_metadata(&dest).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&dest).unwrap(), b"old", "the destination must stay as it was");
    }

    /// A regular file swapped in is refused too. The caller verified the file at `path()`, and
    /// only that file may reach the destination.
    #[test]
    fn a_temporary_swapped_for_another_file_is_not_installed() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("core.db");
        std::fs::write(&dest, b"old").unwrap();

        let mut file = AtomicFile::create(&dest).unwrap();
        file.write_all(b"verified").unwrap();
        let temp = file.path().to_path_buf();
        std::fs::remove_file(&temp).unwrap();
        std::fs::write(&temp, b"forged").unwrap();

        let err = file.commit().unwrap_err();
        assert!(matches!(err, Error::TemporaryReplaced { .. }), "got {err:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
    }
}
