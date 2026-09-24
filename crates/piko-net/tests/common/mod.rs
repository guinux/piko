//! A sync directory inside a database path of its own.
//!
//! A refresh takes `<dbpath>/db.lck` for the `<dbpath>` that holds its `sync` directory. So a
//! test cannot use a bare `TempDir` as the sync directory: its lock would sit in the shared
//! temporary directory, and two tests running at once would refuse each other.

use std::path::{Path, PathBuf};

use piko_db_write::DbLock;

/// `<tempdir>/sync`, created, removed with the `TempDir`.
#[derive(Debug)]
pub struct SyncDir {
    _dbpath: tempfile::TempDir,
    sync: PathBuf,
}

impl SyncDir {
    /// Creates a fresh database path and its empty `sync` directory.
    pub fn new() -> Self {
        let dbpath = tempfile::tempdir().unwrap();
        let sync = dbpath.path().join("sync");
        std::fs::create_dir(&sync).unwrap();
        Self { _dbpath: dbpath, sync }
    }

    /// The sync directory.
    pub fn path(&self) -> &Path {
        &self.sync
    }
}

/// Takes the lock of the database path that holds `sync`.
pub fn lock(sync: &Path) -> DbLock {
    DbLock::acquire(sync.parent().unwrap()).unwrap()
}
