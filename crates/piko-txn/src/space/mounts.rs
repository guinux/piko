//! The kernel's mount table, and the rule that maps a path to one of its entries.
//!
//! Nothing in the `alpm-*` crates reads a mount table, and `getmntent` is unavailable because
//! the workspace forbids `unsafe_code`. So the table is parsed here, in the shape glibc's
//! `getmntent` produces. The fields are whitespace-separated, and the second is the mount
//! directory. Four octal escapes apply.
//!
//! Two properties of this module carry the whole matching rule, and both come from libalpm's
//! `mount_point_list`/`match_mount_point` (`diskspace.c`):
//!
//! - The list is sorted **descending** by bytes. That puts every child before its parent, and
//!   `/` last. So the first match a linear scan finds is the most specific one.
//! - A prefix match is not enough. `/e` must not swallow `/etc/myconfig`, so the byte after the
//!   prefix has to be a separator or the end of the path.
//!
//! Directories are compared as bytes, never as text. A mount directory is whatever the kernel
//! reports, and a `%FILES%` entry is a `PathBuf`. Neither promises UTF-8.

use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt as _, OsStringExt as _},
    path::{Path, PathBuf},
};

use piko_db::Limit;

use crate::error::{Error, Result};

/// The table glibc's `getmntent` reads, and the file `/etc/mtab` points at on a modern system.
const MTAB: &str = "/etc/mtab";

/// Where the kernel publishes the table for this mount namespace.
///
/// libalpm has no fallback and fails outright when `/etc/mtab` is missing. A container image
/// that ships no `/etc/mtab` is not a system piko should refuse to check.
const PROC_MOUNTS: &str = "/proc/self/mounts";

/// Every mount point this namespace has, ordered so the deepest match comes first.
#[derive(Clone, Debug)]
pub struct MountTable {
    /// Mount directories, sorted descending by bytes and deduplicated.
    dirs: Vec<PathBuf>,
}

impl MountTable {
    /// Reads and parses the kernel's mount table.
    ///
    /// # Errors
    ///
    /// [`Error::MountTableUnreadable`] if neither `/etc/mtab` nor `/proc/self/mounts` can be
    /// read. libalpm raises no error code at all in this case, which leaves the caller unable
    /// to say what went wrong. The path and the reason are named here instead.
    pub fn load() -> Result<Self> {
        Self::load_from(Path::new(MTAB), Path::new(PROC_MOUNTS))
    }

    /// As [`MountTable::load`], over two named files. Parameterized so a test can supply a
    /// table it built rather than the one this machine is running on.
    fn load_from(primary: &Path, fallback: &Path) -> Result<Self> {
        let max = piko_db::Limits::default().get(Limit::MountTable);
        // `/etc/mtab` is a symlink to `/proc/self/mounts` on a modern system. So the door
        // that follows a final symlink is the one that opens either spelling. This is the
        // bytes door rather than the UTF-8 one, since a mount directory may not decode.
        let read =
            |path: &Path| piko_db::fs_util::read_capped_following(path, Limit::MountTable, max);
        let bytes = match read(primary) {
            Ok(bytes) => bytes,
            // The fallback answers an absent `/etc/mtab`, which a container image may well
            // not ship. It does not stand in for a table that *is* there and is unusable. An
            // oversized or non-regular primary is reported with its own reason. Reading a
            // second table after refusing the first would hide the refusal.
            Err(piko_db::Error::Io { .. }) => {
                read(fallback).map_err(|second| Error::MountTableUnreadable {
                    path: fallback.to_path_buf(),
                    reason: second.to_string(),
                })?
            }
            Err(first) => {
                return Err(Error::MountTableUnreadable {
                    path: primary.to_path_buf(),
                    reason: first.to_string(),
                });
            }
        };
        Ok(Self::parse(&bytes))
    }

    /// Parses a mount table's bytes, in the format `getmntent` reads.
    ///
    /// [`MountTable::load`] is what a transaction calls. This is for a caller that already
    /// holds the bytes. A test uses it to weigh a transaction against a table it wrote, rather
    /// than against whatever the machine running it mounts.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Self {
        let mut seen = HashSet::new();
        let mut dirs = Vec::new();
        for line in bytes.split(|byte| *byte == b'\n') {
            let Some(dir) = mount_dir(line) else { continue };
            // A bind mount, an overmount, or an autofs placeholder shadowed by the real
            // filesystem leaves two records with the same directory. libalpm keeps both, and
            // its stable sort means the scan always answers with the first. The second stays
            // untouched and is never checked. Dropping it is the same answer for one `statvfs`
            // less.
            if seen.insert(dir.clone()) {
                dirs.push(PathBuf::from(dir));
            }
        }
        // Descending, so a child sorts before its parent and `/` lands last. libalpm spells
        // this as `-strcmp` inside its comparator.
        dirs.sort_by(|left, right| right.as_os_str().as_bytes().cmp(left.as_os_str().as_bytes()));
        Self { dirs }
    }

    /// How many mount points the table holds.
    pub fn count(&self) -> usize {
        self.dirs.len()
    }

    /// The directory of the mount point at `index`.
    pub fn dir(&self, index: usize) -> Option<&Path> {
        self.dirs.get(index).map(PathBuf::as_path)
    }

    /// Every mount directory, deepest first.
    pub fn dirs(&self) -> impl Iterator<Item = &Path> {
        self.dirs.iter().map(PathBuf::as_path)
    }

    /// The index of the most specific mount point `path` lives under.
    ///
    /// `path` must be absolute as the kernel spells it. A relative path matches nothing, which
    /// is why the caller canonicalizes the root once before asking.
    pub fn match_point(&self, path: &Path) -> Option<usize> {
        let path = path.as_os_str().as_bytes();
        self.dirs.iter().position(|dir| {
            let dir = dir.as_os_str().as_bytes();
            let Some(rest) = path.strip_prefix(dir) else { return false };
            // A mount directory ending in `/` is already at a boundary — that is how `/`
            // itself matches everything. Otherwise the next byte decides, so that `/e` does
            // not claim `/etc/myconfig`. An empty remainder means the path *is* the mount
            // directory, which matches.
            dir.last() == Some(&b'/') || matches!(rest.first(), None | Some(&b'/'))
        })
    }
}

/// The mount directory a table line names, unescaped.
///
/// `None` for a blank line, a comment, or a line with no second field.
fn mount_dir(line: &[u8]) -> Option<OsString> {
    let mut fields = line.split(|byte| *byte == b' ' || *byte == b'\t').filter(|f| !f.is_empty());
    let device = fields.next()?;
    if device.first() == Some(&b'#') {
        return None;
    }
    let dir = fields.next()?;
    Some(unescape(dir))
}

/// Decodes the four octal escapes `getmntent` writes.
///
/// glibc escapes exactly space, tab, newline and backslash when it writes a table, and decodes
/// exactly those four when it reads one. A backslash in any other position is a literal
/// backslash in the directory name, so it is kept.
fn unescape(field: &[u8]) -> OsString {
    if !field.contains(&b'\\') {
        return OsStr::from_bytes(field).to_owned();
    }
    let mut out = Vec::with_capacity(field.len());
    let mut rest = field;
    while let Some((first, tail)) = rest.split_first() {
        let decoded = if *first == b'\\' {
            match tail {
                [b'0', b'4', b'0', ..] => Some(b' '),
                [b'0', b'1', b'1', ..] => Some(b'\t'),
                [b'0', b'1', b'2', ..] => Some(b'\n'),
                [b'1', b'3', b'4', ..] => Some(b'\\'),
                _ => None,
            }
        } else {
            None
        };
        match decoded {
            Some(byte) => {
                out.push(byte);
                rest = tail.get(3..).unwrap_or_default();
            }
            None => {
                out.push(*first);
                rest = tail;
            }
        }
    }
    OsString::from_vec(out)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// A real excerpt, including this machine's duplicated `/boot`.
    const SAMPLE: &[u8] = b"\
/dev/nvme0n1p3 / btrfs rw,noatime 0 0
devtmpfs /dev devtmpfs rw,nosuid 0 0
systemd-1 /boot autofs rw,relatime 0 0
/dev/nvme0n1p1 /boot vfat rw,relatime 0 0
tmpfs /var/cache tmpfs rw 0 0
";

    fn table() -> MountTable {
        MountTable::parse(SAMPLE)
    }

    #[test]
    fn children_sort_before_their_parent_and_the_root_sorts_last() {
        let table = table();
        let order: Vec<&Path> = table.dirs().collect();
        assert_eq!(
            order,
            vec![Path::new("/var/cache"), Path::new("/dev"), Path::new("/boot"), Path::new("/"),]
        );
    }

    #[test]
    fn a_repeated_mount_directory_is_kept_once() {
        // `/boot` appears twice in `SAMPLE`: the autofs placeholder and the vfat filesystem
        // that shadows it. libalpm's stable sort always answers with the first, so the second
        // record is never consulted.
        let table = table();
        assert_eq!(table.dirs().filter(|dir| *dir == Path::new("/boot")).count(), 1);
    }

    #[test]
    fn a_prefix_that_is_not_a_path_component_does_not_match() {
        // libalpm names this case in `match_mount_point`'s own comment: `/etc/myconfig` must
        // not map to a mount point `/e`.
        let table = MountTable::parse(b"x /e ext4 rw 0 0\nx / ext4 rw 0 0\n");
        let index = table.match_point(Path::new("/etc/myconfig")).unwrap();
        assert_eq!(table.dir(index).unwrap(), Path::new("/"));
    }

    #[test]
    fn a_path_equal_to_its_mount_directory_matches_it() {
        let table = table();
        let index = table.match_point(Path::new("/boot")).unwrap();
        assert_eq!(table.dir(index).unwrap(), Path::new("/boot"));
    }

    #[test]
    fn the_deepest_mount_point_wins() {
        let table = table();
        let index = table.match_point(Path::new("/var/cache/pacman/pkg/foo.zst")).unwrap();
        assert_eq!(table.dir(index).unwrap(), Path::new("/var/cache"));
    }

    #[test]
    fn the_root_is_the_catch_all() {
        let table = table();
        let index = table.match_point(Path::new("/usr/bin/ls")).unwrap();
        assert_eq!(table.dir(index).unwrap(), Path::new("/"));
    }

    #[test]
    fn a_path_shorter_than_every_mount_directory_matches_nothing() {
        let table = MountTable::parse(b"x /mnt/disk ext4 rw 0 0\n");
        assert_eq!(table.match_point(Path::new("/mnt")), None);
    }

    #[test]
    fn an_empty_table_matches_nothing() {
        let table = MountTable::parse(b"");
        assert_eq!(table.count(), 0);
        assert_eq!(table.match_point(Path::new("/")), None);
    }

    #[test]
    fn the_four_octal_escapes_are_decoded_and_any_other_backslash_is_literal() {
        assert_eq!(unescape(b"/mnt/my\\040disk"), OsString::from("/mnt/my disk"));
        assert_eq!(unescape(b"/mnt/a\\011b"), OsString::from("/mnt/a\tb"));
        assert_eq!(unescape(b"/mnt/a\\012b"), OsString::from("/mnt/a\nb"));
        assert_eq!(unescape(b"/mnt/a\\134b"), OsString::from("/mnt/a\\b"));
        // Not one of the four glibc writes, so it stays exactly as it is.
        assert_eq!(unescape(b"/mnt/a\\999b"), OsString::from("/mnt/a\\999b"));
        assert_eq!(unescape(b"/mnt/trailing\\"), OsString::from("/mnt/trailing\\"));
    }

    #[test]
    fn an_escaped_mount_directory_is_matched_by_its_decoded_spelling() {
        let table = MountTable::parse(b"x /mnt/my\\040disk ext4 rw 0 0\n");
        let index = table.match_point(Path::new("/mnt/my disk/file")).unwrap();
        assert_eq!(table.dir(index).unwrap(), Path::new("/mnt/my disk"));
    }

    #[test]
    fn a_missing_primary_table_falls_back_to_the_kernels() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("mtab");
        let fallback = dir.path().join("mounts");
        std::fs::write(&fallback, b"x / ext4 rw 0 0\n").unwrap();
        let table = MountTable::load_from(&absent, &fallback).unwrap();
        assert_eq!(table.dir(0).unwrap(), Path::new("/"));
    }

    #[test]
    fn an_oversized_table_is_refused_rather_than_allocated_for() {
        let dir = tempfile::tempdir().unwrap();
        let huge = dir.path().join("mtab");
        let max = piko_db::Limits::default().get(Limit::MountTable);
        let line = b"device /mnt/x ext4 rw 0 0\n";
        let repeats = usize::try_from(max).unwrap() / line.len() + 2;
        std::fs::write(&huge, line.repeat(repeats)).unwrap();
        // The fallback must not rescue it: a table that is there and is refused is a refusal,
        // not an absence.
        let error = MountTable::load_from(&huge, Path::new(PROC_MOUNTS)).unwrap_err();
        assert!(matches!(error, Error::MountTableUnreadable { .. }), "got {error:?}");
    }

    #[test]
    fn a_table_that_is_not_a_regular_file_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("mtab");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        // Nothing will ever write to this FIFO. The `O_NONBLOCK` + `fstat` door is what stops
        // the open from hanging here forever. Without it the test would time out.
        let error = MountTable::load_from(&fifo, Path::new(PROC_MOUNTS)).unwrap_err();
        assert!(matches!(error, Error::MountTableUnreadable { .. }), "got {error:?}");
    }

    #[test]
    fn a_table_that_is_absent_everywhere_names_the_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let error =
            MountTable::load_from(&dir.path().join("a"), &dir.path().join("b")).unwrap_err();
        match error {
            Error::MountTableUnreadable { path, .. } => assert_eq!(path, dir.path().join("b")),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn blank_and_short_lines_are_skipped() {
        let table = MountTable::parse(b"\n\nx\n# comment /nope ext4 rw 0 0\nx / ext4 rw 0 0\n");
        assert_eq!(table.count(), 1);
        assert_eq!(table.dir(0).unwrap(), Path::new("/"));
    }
}
