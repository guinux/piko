//! The root check a command makes before it changes the running system.
//!
//! pacman refuses every write operation to a user that is not root (`needs_root`, `util.c:123`,
//! checked in `main` at `pacman.c:1226`). pacman-key does the same for each keyring change. piko
//! refuses only when the command writes to a system path. A command that writes only to paths
//! named on the command line runs without root, because piko supports a transaction into a
//! user-owned `--root` (see `piko_txn::extract::Ownership`).
//!
//! This check is for the user, not for security. The kernel refuses the writes either way. The
//! check stops the command before it opens anything, with one message that says what to do.
//! Without it, the first write fails with a permission error, partway through the command.

use std::path::Path;

use crate::cli::KeyCommand;
use crate::error::Error;

/// What a command writes to, and whether the command line named it.
///
/// A path the command line did not name comes from pacman.conf or from a built-in default. Both
/// are the system's.
#[derive(Debug)]
pub enum Target<'a> {
    /// A transaction: files under `root`, and the local database under `dbpath`.
    Transaction {
        /// The resolved installation root.
        root: &'a Path,
        /// The resolved database path.
        dbpath: &'a Path,
        /// Whether `--dbpath` gave `dbpath`.
        dbpath_named: bool,
    },
    /// A refresh: the sync databases under `dbpath`.
    Databases {
        /// The resolved database path.
        dbpath: &'a Path,
        /// Whether `--dbpath` gave `dbpath`.
        named: bool,
    },
    /// A keyring change: the keyring at `gpgdir`.
    Keyring {
        /// The resolved keyring directory.
        gpgdir: &'a Path,
        /// Whether `--gpgdir` gave `gpgdir`.
        named: bool,
    },
}

impl<'a> Target<'a> {
    /// The system path this target writes to, or `None` when it writes to none.
    ///
    /// A root is the system's when it resolves to `/`, whatever the command line said. A root
    /// that does not resolve cannot be `/`, and the transaction reports that failure itself.
    fn system_path(&self) -> Option<&'a Path> {
        match *self {
            Target::Transaction { root, dbpath, dbpath_named } => {
                if std::fs::canonicalize(root).is_ok_and(|resolved| resolved == Path::new("/")) {
                    Some(root)
                } else if dbpath_named {
                    None
                } else {
                    Some(dbpath)
                }
            }
            Target::Databases { dbpath: path, named } | Target::Keyring { gpgdir: path, named } => {
                (!named).then_some(path)
            }
        }
    }

    /// The flags that name paths the user can own instead.
    const fn flags(&self) -> &'static str {
        match self {
            Target::Transaction { .. } => "--root and --dbpath",
            Target::Databases { .. } => "--dbpath",
            Target::Keyring { .. } => "--gpgdir",
        }
    }
}

/// Refuses `command` unless this process is root, or `target` writes to no system path.
///
/// The effective user ID decides. pacman-key and the kernel's own permission checks read the
/// same one.
///
/// # Errors
///
/// [`Error::NotRoot`] if the effective user ID is not 0 and `target` writes to a system path.
pub fn require_root(command: &'static str, target: &Target<'_>) -> Result<(), Error> {
    if rustix::process::geteuid().is_root() {
        return Ok(());
    }
    match target.system_path() {
        Some(path) => {
            Err(Error::NotRoot { command, path: path.to_path_buf(), flags: target.flags() })
        }
        None => Ok(()),
    }
}

/// Whether a `piko key` subcommand changes the keyring.
///
/// The same split as pacman-key: listing keys and verifying a signature only read.
pub const fn changes_keyring(command: &KeyCommand) -> bool {
    match command {
        KeyCommand::Init
        | KeyCommand::Populate { .. }
        | KeyCommand::Add { .. }
        | KeyCommand::LsignKey { .. }
        | KeyCommand::Delete { .. }
        | KeyCommand::Updatedb => true,
        KeyCommand::ListKeys { .. } | KeyCommand::Verify { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_that_resolves_to_slash_is_the_system_even_with_dbpath_named() {
        let target = Target::Transaction {
            root: Path::new("//"),
            dbpath: Path::new("/x"),
            dbpath_named: true,
        };
        assert_eq!(target.system_path(), Some(Path::new("//")));
    }

    #[test]
    fn a_transaction_into_named_paths_writes_to_no_system_path() {
        let dir = std::env::temp_dir();
        let target = Target::Transaction { root: &dir, dbpath: &dir, dbpath_named: true };
        assert_eq!(target.system_path(), None);
    }

    #[test]
    fn a_configured_dbpath_is_the_system_even_under_another_root() {
        let dir = std::env::temp_dir();
        let dbpath = Path::new("/var/lib/pacman");
        let target = Target::Transaction { root: &dir, dbpath, dbpath_named: false };
        assert_eq!(target.system_path(), Some(dbpath));
    }

    #[test]
    fn a_refresh_or_a_keyring_change_is_the_system_unless_named() {
        let path = Path::new("/p");
        assert_eq!(Target::Databases { dbpath: path, named: false }.system_path(), Some(path));
        assert_eq!(Target::Databases { dbpath: path, named: true }.system_path(), None);
        assert_eq!(Target::Keyring { gpgdir: path, named: false }.system_path(), Some(path));
        assert_eq!(Target::Keyring { gpgdir: path, named: true }.system_path(), None);
    }

    #[test]
    fn only_listing_and_verifying_leave_the_keyring_unchanged() {
        assert!(changes_keyring(&KeyCommand::Init));
        assert!(changes_keyring(&KeyCommand::Updatedb));
        assert!(!changes_keyring(&KeyCommand::ListKeys { keyids: Vec::new() }));
    }
}
