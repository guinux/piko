//! Hashing installed files, for the backup comparison.
//!
//! pacman records a backup file's MD5 in the local database. It compares that hash against the
//! file on disk to decide whether the user edited it. piko must compute the same digest to
//! interoperate: the recorded hashes come from pacman, and piko compares its own hashes against
//! them. So "MD5 is weak" is not a reason to choose a different algorithm here. MD5 is not a
//! security primitive in this context — it only answers "did these bytes change" against a
//! value pacman wrote.
//!
//! The digest comes from `alpm_types::Md5Checksum`, not from `md-5` directly. The official
//! crate already exposes it and is already in the dependency graph.

use std::{ffi::OsStr, os::fd::AsFd, path::Path};

use alpm_types::Md5Checksum;
use rustix::fs::{AtFlags, Mode, OFlags};

use crate::error::{Error, IoAction, Result};

/// Largest file that will be hashed for a backup comparison.
///
/// `Checksum::calculate_from` takes the whole input as a slice, so the read must be capped
/// somewhere. 64 MiB is far beyond any real configuration file. The bound exists so a package
/// declaring `usr/lib/firmware.bin` as a `%BACKUP%` entry cannot make piko read it into memory.
/// It does not constrain legitimate use.
pub const MAX_BACKUP_BYTES: u64 = 64 * 1024 * 1024;

/// How much of each file [`same_contents_at`] holds in memory at a time.
///
/// The comparison walks both files together, so nothing larger than two of these blocks is ever
/// allocated, whatever [`MAX_BACKUP_BYTES`] allows.
const COMPARE_BLOCK_BYTES: usize = 64 * 1024;

/// Computes the MD5 of `name` inside `dir`.
///
/// Returns `Ok(None)` when the file is simply not there. That is an ordinary state, not a
/// failure — for example a backup file the user deleted.
///
/// # Errors
///
/// [`Error::Io`] if the file exists but cannot be read, or
/// [`Error::PackageLimitExceeded`] if it is larger than `max`.
///
/// # Treat a failure as *unknown*, never as *unchanged*
///
/// Both an `Err` and an `Ok(None)` mean piko does not know what the file contains. A caller
/// must map both to `None` when feeding [`crate::extract::decision::resolve_backup`] or
/// [`crate::remove::decide_removal`]. Never map either to a hash that happens to be convenient.
/// Those functions rely on an unknown hash keeping the user's file, and that safety depends on
/// the unknown actually arriving as unknown. libalpm gets this wrong in `remove.c:536`: there,
/// an uncomputable hash compares equal to the recorded one, and the file gets deleted.
pub fn file_md5_at(dir: &impl AsFd, name: &OsStr, max: u64) -> Result<Option<Md5Checksum>> {
    let Some((mut file, size)) = self::open_regular_at(dir, name, max)? else {
        return Ok(None);
    };

    let mut contents = Vec::with_capacity(usize::try_from(size.min(max)).unwrap_or(0));
    // Reading one byte past the cap distinguishes "exactly at the limit" from "truncated". This
    // is the same idiom as piko-db's `fs_util::read_capped`. A file that grew between the stat
    // and the read must not be silently hashed short.
    {
        use std::io::Read as _;
        file.by_ref()
            .take(max.saturating_add(1))
            .read_to_end(&mut contents)
            .map_err(|source| Error::io(Path::new(name), IoAction::Read, source))?;
    }
    if contents.len() as u64 > max {
        return Err(self::too_large(name, max));
    }

    Ok(Some(Md5Checksum::calculate_from(&contents)))
}

/// Reports whether `left` and `right` inside `dir` hold exactly the same bytes.
///
/// Returns `Ok(None)` when either file is not there. That is an ordinary state: the caller
/// asked about a pair, and a pair needs two files.
///
/// # Errors
///
/// [`Error::Io`] if a file exists but cannot be read, [`Error::UnusableSource`] if it is not a
/// regular file, or [`Error::PackageLimitExceeded`] if it is larger than `max`.
///
/// # A pair that cannot be read is never "the same"
///
/// This answers the question that deletes a file without asking the user. So a failure arrives
/// as an `Err`, and a caller must keep both files. This is the rule [`file_md5_at`] states, in
/// the one place where getting it wrong costs the user's own copy.
///
/// # Bytes, not digests
///
/// Two calls to [`file_md5_at`] would answer the same question in one line. They would also
/// trade an exact comparison for an MD5 one, on this branch. MD5 has constructible
/// chosen-prefix collisions, and a package author picks one side of this pair. Comparing in
/// blocks also costs no allocation, where two digests cost two buffers of up to `max` bytes.
pub fn same_contents_at(
    dir: &impl AsFd,
    left: &OsStr,
    right: &OsStr,
    max: u64,
) -> Result<Option<bool>> {
    let Some((left_file, left_size)) = self::open_regular_at(dir, left, max)? else {
        return Ok(None);
    };
    let Some((right_file, right_size)) = self::open_regular_at(dir, right, max)? else {
        return Ok(None);
    };
    if left_size != right_size {
        return Ok(Some(false));
    }

    let mut left_reader = std::io::BufReader::new(left_file);
    let mut right_reader = std::io::BufReader::new(right_file);
    let mut left_block = [0_u8; COMPARE_BLOCK_BYTES];
    let mut right_block = [0_u8; COMPARE_BLOCK_BYTES];
    let mut compared = 0_u64;
    loop {
        let read = self::fill(&mut left_reader, &mut left_block)
            .map_err(|source| Error::io(Path::new(left), IoAction::Read, source))?;
        let other = self::fill(&mut right_reader, &mut right_block)
            .map_err(|source| Error::io(Path::new(right), IoAction::Read, source))?;
        if read != other {
            return Ok(Some(false));
        }
        if read == 0 {
            return Ok(Some(true));
        }
        if left_block.get(..read) != right_block.get(..read) {
            return Ok(Some(false));
        }
        compared = compared.saturating_add(read as u64);
        // A file that grew after its size was read must not be compared short. The stat said
        // both files fit under `max`, so passing it means one of them is being written now.
        if compared > max {
            return Err(self::too_large(left, max));
        }
    }
}

/// Reads until `block` is full or the file ends, and reports how many bytes landed.
///
/// `Read::read` may return fewer bytes than asked for at any point. Comparing two short reads
/// against each other would report two identical files as different, because the two sides can
/// stop at different offsets.
fn fill(reader: &mut impl std::io::Read, block: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while let Some(rest) = block.get_mut(filled..) {
        if rest.is_empty() {
            break;
        }
        match reader.read(rest) {
            Ok(0) => break,
            Ok(read) => filled = filled.saturating_add(read),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Opens `name` inside `dir` for reading, and reports its size.
///
/// Returns `Ok(None)` when the file is not there.
///
/// # Errors
///
/// [`Error::Io`] if the open or the `fstat` fails, [`Error::UnusableSource`] if the file is not
/// a regular file, or [`Error::PackageLimitExceeded`] if it is larger than `max`.
fn open_regular_at(
    dir: &impl AsFd,
    name: &OsStr,
    max: u64,
) -> Result<Option<(std::fs::File, u64)>> {
    // `O_NOFOLLOW`: a backup path that has become a symlink must not be followed out of the
    // root to read something else.
    //
    // `O_NONBLOCK`: opening a FIFO for reading blocks until a writer appears. Without this
    // flag, a backup path that is a FIFO hangs the package manager forever. The file-type
    // check below runs after the open, far too late to help. This is the same reasoning as
    // `piko_db::fs_util::open_no_follow`.
    let fd = match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(source) => return Err(self::io(name, IoAction::Open, source)),
    };

    let stat =
        rustix::fs::fstat(&fd).map_err(|source| self::io(name, IoAction::Metadata, source))?;
    // Only a regular file has contents worth comparing. `O_NOFOLLOW` rules out a symlink
    // here. A FIFO or device node could still reach this point, and reading one would block
    // or never end.
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(Error::UnusableSource {
            path: Path::new(name).to_path_buf(),
            reason: "not a regular file".to_owned(),
        });
    }

    let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
    if size > max {
        return Err(self::too_large(name, max));
    }

    Ok(Some((std::fs::File::from(fd), size)))
}

/// The refusal a file over the cap earns.
fn too_large(name: &OsStr, max: u64) -> Error {
    Error::PackageLimitExceeded {
        path: Path::new(name).to_path_buf(),
        limit: "backup file size",
        max,
    }
}

/// Reports whether `name` exists inside `dir`, without following a symlink.
pub fn exists_at(dir: &impl AsFd, name: &OsStr) -> bool {
    rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).is_ok()
}

/// Wraps a `rustix` error against a bare name.
fn io(name: &OsStr, action: IoAction, source: rustix::io::Errno) -> Error {
    Error::io(Path::new(name), action, source.into())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::rootfs::RootDir;

    fn root() -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = RootDir::open(dir.path()).unwrap();
        (dir, root)
    }

    fn hash_of(root: &RootDir, name: &str) -> Result<Option<Md5Checksum>> {
        let resolved = root.resolve_parent(Path::new(name)).unwrap();
        file_md5_at(resolved.dir(), resolved.name(), MAX_BACKUP_BYTES)
    }

    /// The digest must be the one pacman would have recorded. Pin it against a known MD5,
    /// not only against itself.
    #[test]
    fn computes_the_standard_md5() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("f"), b"abc").unwrap();
        assert_eq!(
            hash_of(&root, "f").unwrap().unwrap().to_string(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn hashes_an_empty_file() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("f"), b"").unwrap();
        assert_eq!(
            hash_of(&root, "f").unwrap().unwrap().to_string(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    /// Absence is an ordinary state, not a failure.
    #[test]
    fn a_missing_file_is_none_not_an_error() {
        let (_dir, root) = root();
        assert!(hash_of(&root, "absent").unwrap().is_none());
    }

    #[test]
    fn refuses_a_file_over_the_limit() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("f"), vec![b'x'; 100]).unwrap();

        let resolved = root.resolve_parent(Path::new("f")).unwrap();
        let err = file_md5_at(resolved.dir(), resolved.name(), 10).unwrap_err();
        assert!(
            matches!(err, Error::PackageLimitExceeded { limit: "backup file size", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn accepts_a_file_exactly_at_the_limit() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("f"), vec![b'x'; 10]).unwrap();
        let resolved = root.resolve_parent(Path::new("f")).unwrap();
        assert!(file_md5_at(resolved.dir(), resolved.name(), 10).unwrap().is_some());
    }

    /// A backup path replaced by a symlink must not be followed to hash something else.
    #[cfg(unix)]
    #[test]
    fn refuses_to_follow_a_symlink() {
        let (dir, root) = root();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret");
        std::fs::write(&secret, b"secret").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("f")).unwrap();

        assert!(hash_of(&root, "f").is_err());
    }

    /// Reading a FIFO would block forever.
    #[cfg(unix)]
    #[test]
    fn refuses_a_non_regular_file() {
        let (dir, root) = root();
        let fifo = dir.path().join("f");
        let path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // `mkfifo` via rustix keeps `unsafe_code = forbid` intact.
        rustix::fs::mknodat(
            rustix::fs::CWD,
            path.as_c_str(),
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();

        let err = hash_of(&root, "f").unwrap_err();
        assert!(matches!(err, Error::UnusableSource { .. }), "got {err:?}");
    }

    fn same(root: &RootDir, left: &str, right: &str) -> Result<Option<bool>> {
        let resolved = root.resolve_parent(Path::new(left)).unwrap();
        let other = root.resolve_parent(Path::new(right)).unwrap();
        same_contents_at(resolved.dir(), resolved.name(), other.name(), MAX_BACKUP_BYTES)
    }

    #[test]
    fn two_files_with_the_same_bytes_are_the_same() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("a"), b"hello").unwrap();
        std::fs::write(dir.path().join("b"), b"hello").unwrap();
        assert_eq!(same(&root, "a", "b").unwrap(), Some(true));
    }

    #[test]
    fn two_empty_files_are_the_same() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("a"), b"").unwrap();
        std::fs::write(dir.path().join("b"), b"").unwrap();
        assert_eq!(same(&root, "a", "b").unwrap(), Some(true));
    }

    #[test]
    fn two_files_of_one_size_that_differ_are_not_the_same() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("a"), b"hello").unwrap();
        std::fs::write(dir.path().join("b"), b"world").unwrap();
        assert_eq!(same(&root, "a", "b").unwrap(), Some(false));
    }

    #[test]
    fn two_files_of_different_sizes_are_not_the_same() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("a"), b"hello").unwrap();
        std::fs::write(dir.path().join("b"), b"hello there").unwrap();
        assert_eq!(same(&root, "a", "b").unwrap(), Some(false));
    }

    /// One block is 64 KiB, so a pair that spans several of them exercises the loop rather
    /// than its first iteration.
    #[test]
    fn compares_a_pair_larger_than_one_block() {
        let (dir, root) = root();
        let mut left = vec![b'x'; 200 * 1024];
        std::fs::write(dir.path().join("a"), &left).unwrap();
        std::fs::write(dir.path().join("b"), &left).unwrap();
        assert_eq!(same(&root, "a", "b").unwrap(), Some(true));

        // A single byte in the last block is enough to tell them apart.
        let last = left.len().saturating_sub(1);
        *left.get_mut(last).unwrap() = b'y';
        std::fs::write(dir.path().join("b"), &left).unwrap();
        assert_eq!(same(&root, "a", "b").unwrap(), Some(false));
    }

    #[test]
    fn a_missing_side_is_none_not_an_error() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("a"), b"hello").unwrap();
        assert!(same(&root, "a", "absent").unwrap().is_none());
        assert!(same(&root, "absent", "a").unwrap().is_none());
    }

    /// The answer that would delete the user's file must never come from a file piko could
    /// not read.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_side_is_an_error_not_a_match() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("a"), b"hello").unwrap();
        std::os::unix::fs::symlink(dir.path().join("a"), dir.path().join("b")).unwrap();
        assert!(same(&root, "a", "b").is_err());
    }

    #[test]
    fn refuses_a_pair_over_the_limit() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("a"), vec![b'x'; 100]).unwrap();
        std::fs::write(dir.path().join("b"), vec![b'x'; 100]).unwrap();

        let resolved = root.resolve_parent(Path::new("a")).unwrap();
        let other = root.resolve_parent(Path::new("b")).unwrap();
        let err = same_contents_at(resolved.dir(), resolved.name(), other.name(), 10).unwrap_err();
        assert!(
            matches!(err, Error::PackageLimitExceeded { limit: "backup file size", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn exists_reports_presence_without_following() {
        let (dir, root) = root();
        std::fs::write(dir.path().join("here"), b"x").unwrap();
        let resolved = root.resolve_parent(Path::new("here")).unwrap();
        assert!(exists_at(resolved.dir(), resolved.name()));

        let absent = root.resolve_parent(Path::new("gone")).unwrap();
        assert!(!exists_at(absent.dir(), absent.name()));
    }
}
