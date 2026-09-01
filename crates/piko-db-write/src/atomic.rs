//! Writes a file atomically, in a form that can be inspected before it lands.
//!
//! [`crate::local`] already writes database entries atomically, but only from a `&[u8]` held
//! in memory. That fits a `desc`. It does not fit a downloaded repository database:
//! `extra.files` is about 50 MB on this machine. A downloaded file must also be **verified
//! before it replaces the live one**. This requires the file to exist on disk, under a name
//! the verifier can check, while the destination stays untouched.
//!
//! [`AtomicFile`] provides this. It streams into a temporary beside the destination, exposes
//! that path through [`AtomicFile::path`] for inspection, and renames it over the target only
//! when [`AtomicFile::commit`] runs. Dropping it without committing removes the temporary, so
//! a failed or rejected download leaves nothing behind.
//!
//! The durability sequence matches [`crate::local`]'s, for the same reason: fsync the data
//! before the rename. Otherwise a crash can make the rename durable while the contents are
//! not, leaving an empty file where a good one used to be.

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::error::{Error, IoAction, Result};

/// A file that becomes visible at its destination only when [`Self::commit`] is called.
///
/// # Why the temporary is never written through
///
/// The destination resists symlink games by construction: `rename` replaces a symlink rather
/// than resolving it. The *temporary* does not get this protection for free. The obvious
/// `create(true).truncate(true)` follows a final symlink, so a `core.db.new` planted as a
/// symlink to `/etc/passwd` would be truncated and filled by a process that typically runs
/// as root.
///
/// This type reuses `local`'s `create_temp`, which opens `O_CREAT | O_EXCL | O_NOFOLLOW`. When
/// it finds something already there, it **unlinks it and retries exactly once**, using
/// `remove_file`, which removes a symlink rather than resolving it. A planted temporary is
/// discarded rather than followed, and a leftover from a crashed write does not wedge the path
/// permanently.
#[derive(Debug)]
pub struct AtomicFile {
    temp: PathBuf,
    destination: PathBuf,
    /// `None` once committed, so `Drop` knows not to clean up.
    file: Option<File>,
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
        let temp = crate::local::temp_path(destination);
        let file = crate::local::create_temp(&temp)?;
        Ok(Self { temp, destination: destination.to_path_buf(), file: Some(file), modified: None })
    }

    /// The temporary's path.
    ///
    /// This is what makes "verify before installing" possible. A caller hands this path to a
    /// signature check while the destination still holds the previous, known-good file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.temp
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
        let Some(mut file) = self.file.take() else {
            // Unreachable: only this call takes `file`, and `self` is consumed here.
            return Ok(());
        };

        if let Err(source) = file.flush().and_then(|()| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(&self.temp);
            return Err(Error::io(&self.temp, IoAction::Sync, source));
        }
        // This runs after the write and the fsync. Setting the mtime earlier would let a
        // later write move it forward again. The chmod and rename below do not touch mtime;
        // it travels with the inode.
        if let Some(source) = self.modified.and_then(|time| file.set_modified(time).err()) {
            drop(file);
            let _ = std::fs::remove_file(&self.temp);
            return Err(Error::io(&self.temp, IoAction::Metadata, source));
        }
        drop(file);

        // The caller's umask masks the mode set at open time, so this sets it explicitly.
        if let Err(error) = crate::local::set_file_mode(&self.temp) {
            let _ = std::fs::remove_file(&self.temp);
            return Err(error);
        }

        if let Err(source) = std::fs::rename(&self.temp, &self.destination) {
            let _ = std::fs::remove_file(&self.temp);
            return Err(Error::io(&self.destination, IoAction::Rename, source));
        }

        let directory = self.destination.parent().unwrap_or(Path::new("."));
        crate::local::sync_directory(directory)
    }
}

impl Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.file.as_mut() {
            Some(file) => file.write(buf),
            None => Err(std::io::Error::other("the atomic file has already been committed")),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl Drop for AtomicFile {
    /// Removes the temporary unless it was committed.
    ///
    /// This makes a rejected download cost nothing. The caller returns an error, the value
    /// drops, and the destination stays exactly as it was.
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
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
    /// An earlier version of this test asserted that `create` fails. That assertion was wrong:
    /// `create_temp` deliberately unlinks a leftover and retries once, so a crashed write does
    /// not wedge the path forever. The property that actually matters is the one asserted
    /// here: the symlink's target stays untouched, so nothing was followed.
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
}
