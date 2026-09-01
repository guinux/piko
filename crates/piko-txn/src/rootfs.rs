//! Resolves an archive path inside an installation root, without ever leaving it.
//!
//! This is the security core of the commit engine. A package archive is attacker-controlled
//! wherever its files go: a repository can be compromised, a signature can be absent, and a
//! `.pkg.tar.zst` handed to `piko -U` came from wherever the user found it. Two classic escapes
//! must be closed. Checking the path as a *string* does not close either one:
//!
//! 1. **`..` traversal.** An entry named `../../etc/passwd` writes outside the root.
//! 2. **Symlinked path components.** If `usr/bin` is a symlink to `/etc`, an entry named
//!    `usr/bin/foo` writes to `/etc/foo` even though the path itself looks harmless.
//!
//! Inspecting the path and then using it cannot prevent the second case. Whatever
//! `symlink_metadata` reported a moment ago, the component can be replaced with a symlink before
//! the write lands. That race is why this module opens each component with `openat` and
//! `O_NOFOLLOW`, and keeps the resulting descriptor. The directory a file is created in is then
//! *the same object* that was checked, not a path that resolves to it.
//!
//! # Against pacman
//!
//! libalpm extracts with libarchive's `archive_write_disk` under
//! `ARCHIVE_EXTRACT_SECURE_SYMLINKS` (`add.c:118`), which refuses an entry whose final
//! location would be changed by a symlink. piko matches that.
//!
//! It does **not** set `ARCHIVE_EXTRACT_SECURE_NODOTDOT`, so a `..` component is permitted.
//! piko refuses it instead, so it is deliberately stricter than pacman.

use std::{
    ffi::{OsStr, OsString},
    os::fd::OwnedFd,
    path::{Component, Path, PathBuf},
};

use rustix::fs::{Mode, OFlags};

use crate::error::{Error, Result};

/// Why an archive path was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UnsafePath {
    /// The path is absolute, so it does not name a location inside the root at all.
    Absolute,
    /// The path contains a `..` component.
    ParentTraversal,
    /// The path contains a `.` component, or a repeated separator that yields one.
    ///
    /// piko refuses this rather than normalizing it away. A well-formed package never contains
    /// one, so its presence means the producer is doing something unusual. Silently rewriting
    /// an attacker-influenced path is how a check gets bypassed by a spelling it did not
    /// consider.
    CurrentDirectory,
    /// The path is empty, or is nothing but separators.
    Empty,
    /// A component contains a byte the kernel cannot accept in a file name.
    InvalidComponent,
}

impl std::fmt::Display for UnsafePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Absolute => "the path is absolute",
            Self::ParentTraversal => "the path contains a '..' component",
            Self::CurrentDirectory => "the path contains a '.' component",
            Self::Empty => "the path is empty",
            Self::InvalidComponent => "a component is not a usable file name",
        })
    }
}

/// Splits a package-relative path into components, refusing anything that could escape.
///
/// This function is pure and filesystem-free, so the rules can be tested exhaustively without
/// a root to resolve against. That matters: these rules decide whether a hostile archive can
/// write to `/etc`.
///
/// # Errors
///
/// [`Error::UnsafeArchivePath`] if the path is absolute, empty, or contains a `.` or `..`
/// component.
pub fn components(relative: &Path) -> Result<Vec<&OsStr>> {
    let refuse = |reason| Err(Error::UnsafeArchivePath { path: relative.to_path_buf(), reason });

    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                // A NUL cannot reach the kernel. An embedded separator means the component was
                // never really one component.
                if part.is_empty() || as_bytes(part).contains(&0) {
                    return refuse(UnsafePath::InvalidComponent);
                }
                parts.push(part);
            }
            Component::ParentDir => return refuse(UnsafePath::ParentTraversal),
            Component::CurDir => return refuse(UnsafePath::CurrentDirectory),
            Component::RootDir | Component::Prefix(_) => return refuse(UnsafePath::Absolute),
        }
    }

    if parts.is_empty() {
        return refuse(UnsafePath::Empty);
    }
    Ok(parts)
}

/// The bytes of a path component.
fn as_bytes(part: &OsStr) -> &[u8] {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        part.as_bytes()
    }
    #[cfg(not(unix))]
    {
        // Non-unix is not a supported target for extraction. This branch only keeps the module
        // building.
        let _ = part;
        &[]
    }
}

/// A directory that resolution is confined to.
///
/// Holds an open descriptor for the root, so the root itself cannot be swapped underneath a
/// running transaction. Every resolution starts from this descriptor, not from the path it
/// was opened by.
#[derive(Debug)]
pub struct RootDir {
    fd: OwnedFd,
    /// Only for error messages. Resolution never uses it.
    display: PathBuf,
}

impl RootDir {
    /// Opens `path` as an installation root.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if it cannot be opened, or is not a directory.
    pub fn open(path: &Path) -> Result<Self> {
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| Error::io(path, crate::error::IoAction::Open, source.into()))?;

        Ok(Self { fd, display: path.to_path_buf() })
    }

    /// The path this root was opened by, for messages.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.display
    }

    /// Walks to the directory that will contain `relative`, without following any symlink.
    ///
    /// Returns a descriptor for that directory together with the final component. This is
    /// exactly what `openat`/`mkdirat`/`symlinkat` need. The caller does the creating; this
    /// function only guarantees *where*.
    ///
    /// Intermediate directories are **not** created here — see [`RootDir::create_dir_all`]. A
    /// missing one is an error. During extraction it means the archive listed a file before
    /// the directory containing it, and inventing the directory would mean inventing its
    /// ownership and mode too.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsafeArchivePath`] if `relative` is not a safe relative path.
    /// - [`Error::PathEscapesRoot`] if a component is a symlink, or is not a directory.
    /// - [`Error::Io`] if a component cannot be opened.
    pub fn resolve_parent(&self, relative: &Path) -> Result<Resolved> {
        let parts = components(relative)?;
        // `components` guarantees at least one part, so the split always succeeds.
        let Some((last, leading)) = parts.split_last() else {
            return Err(Error::UnsafeArchivePath {
                path: relative.to_path_buf(),
                reason: UnsafePath::Empty,
            });
        };

        let mut current = self.duplicate()?;
        let mut walked = PathBuf::new();
        for part in leading {
            walked.push(part);
            current = self.descend(&current, part, &walked, relative)?;
        }

        Ok(Resolved { dir: current, name: (*last).to_os_string() })
    }

    /// Creates every directory in `relative`, then resolves it.
    ///
    /// Used for the destination of a file whose parent directories the archive did not list.
    /// Directories created this way get mode `0755`. An archive that cares about the mode
    /// lists the directory itself, and then this function never runs for it.
    ///
    /// # Errors
    ///
    /// As [`RootDir::resolve_parent`], plus [`Error::Io`] if a directory cannot be created.
    pub fn create_dir_all(&self, relative: &Path) -> Result<Resolved> {
        let parts = components(relative)?;
        let Some((last, leading)) = parts.split_last() else {
            return Err(Error::UnsafeArchivePath {
                path: relative.to_path_buf(),
                reason: UnsafePath::Empty,
            });
        };

        let mut current = self.duplicate()?;
        let mut walked = PathBuf::new();
        for part in leading {
            walked.push(part);
            // `EEXIST` is the ordinary case here, not an error. Anything else is.
            match rustix::fs::mkdirat(&current, *part, Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(source) => {
                    return Err(Error::io(
                        self.display.join(&walked),
                        crate::error::IoAction::CreateDir,
                        source.into(),
                    ));
                }
            }
            current = self.descend(&current, part, &walked, relative)?;
        }

        Ok(Resolved { dir: current, name: (*last).to_os_string() })
    }

    /// Opens `part` inside `current`, refusing to follow a symlink.
    ///
    /// `O_NOFOLLOW` closes the hole: on a symlink, the open fails instead of resolving it.
    /// `O_DIRECTORY` additionally rejects a component that is not a directory.
    ///
    /// This function then establishes the *reason* with an `lstat`, not from the errno. The
    /// two flags interact: POSIX specifies `ELOOP` for `O_NOFOLLOW` on a symlink, but Linux
    /// returns `ENOTDIR` when `O_DIRECTORY` is also set. So a symlink and a regular file are
    /// indistinguishable by errno alone. Getting the reason wrong only produces a wrong
    /// message — the refusal itself is already correct — but "it is not a directory" pointing
    /// at a symlink sends someone debugging in the wrong direction.
    fn descend(
        &self,
        current: &OwnedFd,
        part: &OsStr,
        walked: &Path,
        relative: &Path,
    ) -> Result<OwnedFd> {
        match rustix::fs::openat(
            current,
            part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => Ok(fd),
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                Err(Error::PathEscapesRoot {
                    path: relative.to_path_buf(),
                    component: walked.to_path_buf(),
                    reason: self.describe_blocker(current, part),
                })
            }
            Err(source) => Err(Error::io(
                self.display.join(walked),
                crate::error::IoAction::Open,
                source.into(),
            )),
        }
    }

    /// What `part` actually is, for the refusal message.
    ///
    /// This is best-effort. If the `lstat` itself fails, the component changed underneath the
    /// caller. That is worth saying rather than papering over with a guess.
    fn describe_blocker(&self, current: &OwnedFd, part: &OsStr) -> &'static str {
        match rustix::fs::statat(current, part, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
                rustix::fs::FileType::Symlink => "it is a symlink",
                _ => "it is not a directory",
            },
            Err(_) => "it could not be examined",
        }
    }

    /// A second descriptor for the root. A walk of zero components still yields an owned
    /// directory this way, rather than a borrow of `self`.
    fn duplicate(&self) -> Result<OwnedFd> {
        rustix::fs::openat(
            &self.fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| Error::io(&self.display, crate::error::IoAction::Open, source.into()))
    }
}

/// A resolved destination: the directory to act in, and the name to act on.
#[derive(Debug)]
pub struct Resolved {
    dir: OwnedFd,
    name: OsString,
}

impl Resolved {
    /// The directory the final component lives in.
    ///
    /// This is a descriptor rather than a path on purpose. Acting through it makes the result
    /// immune to the directory being replaced after it was checked.
    #[must_use]
    pub fn dir(&self) -> &OwnedFd {
        &self.dir
    }

    /// The final path component.
    #[must_use]
    pub fn name(&self) -> &OsStr {
        &self.name
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

    fn refused(path: &str) -> UnsafePath {
        match components(Path::new(path)) {
            Err(Error::UnsafeArchivePath { reason, .. }) => reason,
            other => panic!("{path:?} was not refused: {other:?}"),
        }
    }

    #[test]
    fn accepts_ordinary_package_paths() {
        assert_eq!(components(Path::new("usr/bin/foo")).unwrap(), ["usr", "bin", "foo"]);
        assert_eq!(components(Path::new("etc/passwd")).unwrap(), ["etc", "passwd"]);
        // tar spells a directory entry with a trailing slash.
        assert_eq!(components(Path::new("usr/bin/")).unwrap(), ["usr", "bin"]);
        assert_eq!(components(Path::new("foo")).unwrap(), ["foo"]);
    }

    /// The escape pacman's own flags permit.
    #[test]
    fn refuses_parent_traversal_anywhere_in_the_path() {
        for path in ["../etc/passwd", "usr/../../etc/passwd", "usr/bin/..", ".."] {
            assert_eq!(refused(path), UnsafePath::ParentTraversal, "{path:?}");
        }
    }

    #[test]
    fn refuses_absolute_paths() {
        for path in ["/etc/passwd", "/"] {
            assert_eq!(refused(path), UnsafePath::Absolute, "{path:?}");
        }
    }

    /// `Path::components` normalizes `a//b` and a trailing `/.`. The check must not depend
    /// on which spellings it happens to collapse.
    #[test]
    fn refuses_current_directory_components() {
        assert_eq!(refused("./usr/bin"), UnsafePath::CurrentDirectory);
        assert_eq!(refused("."), UnsafePath::CurrentDirectory);
    }

    #[test]
    fn refuses_an_empty_path() {
        assert_eq!(refused(""), UnsafePath::Empty);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_component_containing_nul() {
        use std::os::unix::ffi::OsStrExt as _;

        let path = PathBuf::from(OsStr::from_bytes(b"usr/b\0in/foo"));
        assert!(matches!(
            components(&path),
            Err(Error::UnsafeArchivePath { reason: UnsafePath::InvalidComponent, .. })
        ));
    }

    fn root() -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = RootDir::open(dir.path()).unwrap();
        (dir, root)
    }

    #[test]
    fn resolves_inside_an_existing_tree() {
        let (dir, root) = root();
        std::fs::create_dir_all(dir.path().join("usr/bin")).unwrap();

        let resolved = root.resolve_parent(Path::new("usr/bin/foo")).unwrap();
        assert_eq!(resolved.name(), "foo");

        // Proof the descriptor really is `usr/bin`: create through it and check the file
        // lands where it should.
        rustix::fs::openat(
            resolved.dir(),
            resolved.name(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o644),
        )
        .unwrap();
        assert!(dir.path().join("usr/bin/foo").is_file());
    }

    #[test]
    fn resolves_a_single_component_against_the_root() {
        let (dir, root) = root();
        let resolved = root.resolve_parent(Path::new("foo")).unwrap();
        assert_eq!(resolved.name(), "foo");

        rustix::fs::openat(
            resolved.dir(),
            resolved.name(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o644),
        )
        .unwrap();
        assert!(dir.path().join("foo").is_file());
    }

    /// The escape a string check cannot catch. The path is entirely innocent; the filesystem
    /// is what redirects it.
    #[cfg(unix)]
    #[test]
    fn refuses_to_descend_through_a_symlinked_directory() {
        let (dir, root) = root();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("passwd"), b"root:x:0:0").unwrap();
        std::fs::create_dir(dir.path().join("usr")).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("usr/bin")).unwrap();

        let err = root.resolve_parent(Path::new("usr/bin/passwd")).unwrap_err();
        assert!(matches!(err, Error::PathEscapesRoot { .. }), "got {err:?}");
        assert!(err.to_string().contains("symlink"), "{err}");
        assert_eq!(std::fs::read_to_string(outside.path().join("passwd")).unwrap(), "root:x:0:0");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_descend_through_a_symlink_to_a_directory_inside_the_root() {
        // Even an *internal* symlink is refused. `SECURE_SYMLINKS` cares whether the final
        // location is altered at all, not where it lands.
        let (dir, root) = root();
        std::fs::create_dir_all(dir.path().join("usr/lib")).unwrap();
        std::os::unix::fs::symlink("usr/lib", dir.path().join("lib")).unwrap();

        let err = root.resolve_parent(Path::new("lib/libfoo.so")).unwrap_err();
        assert!(matches!(err, Error::PathEscapesRoot { .. }), "got {err:?}");
    }

    #[test]
    fn refuses_to_descend_through_a_regular_file() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("usr"), b"not a directory").unwrap();

        let err = root.resolve_parent(Path::new("usr/bin/foo")).unwrap_err();
        assert!(matches!(err, Error::PathEscapesRoot { .. }), "got {err:?}");
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    #[test]
    fn a_missing_intermediate_directory_is_an_error_not_an_invention() {
        let (_dir, root) = root();
        let err = root.resolve_parent(Path::new("usr/bin/foo")).unwrap_err();
        assert!(matches!(err, Error::Io { .. }), "got {err:?}");
    }

    #[test]
    fn create_dir_all_makes_the_intermediate_directories() {
        let (dir, root) = root();
        let resolved = root.create_dir_all(Path::new("usr/share/doc/foo")).unwrap();
        assert_eq!(resolved.name(), "foo");
        assert!(dir.path().join("usr/share/doc").is_dir());
        // The leaf is the caller's to create.
        assert!(!dir.path().join("usr/share/doc/foo").exists());
    }

    #[test]
    fn create_dir_all_is_idempotent() {
        let (dir, root) = root();
        root.create_dir_all(Path::new("usr/share/foo")).unwrap();
        root.create_dir_all(Path::new("usr/share/bar")).unwrap();
        assert!(dir.path().join("usr/share").is_dir());
    }

    /// Creating directories must not become a way around the symlink rule.
    #[cfg(unix)]
    #[test]
    fn create_dir_all_still_refuses_a_symlinked_component() {
        let (dir, root) = root();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("usr")).unwrap();

        let err = root.create_dir_all(Path::new("usr/share/foo")).unwrap_err();
        assert!(matches!(err, Error::PathEscapesRoot { .. }), "got {err:?}");
        assert!(!outside.path().join("share").exists(), "it created a directory outside the root");
    }

    #[test]
    fn create_dir_all_refuses_an_unsafe_path() {
        let (_dir, root) = root();
        assert!(root.create_dir_all(Path::new("../escape/foo")).is_err());
    }

    #[test]
    fn opening_a_non_directory_root_fails() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(RootDir::open(&file).is_err());
    }
}
