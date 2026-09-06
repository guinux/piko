//! Reading a `.pkg.tar.*` archive, member by member.
//!
//! This reader follows the same three rules as `piko-db`'s repository-archive reader, for the
//! same reasons.
//!
//! 1. **Magic-byte sniffing, not extension detection.** A package is usually named
//!    `.pkg.tar.zst`. But the name is not a guarantee, and `alpm-compress`'s own
//!    `TryFrom<&Path>` trusts it anyway.
//! 2. **Bounded decompression.** `alpm-compress` caps nothing anywhere. A [`BoundedReader`]
//!    wraps the decoder and trips a shared flag on overrun. This flag is what tells a bound
//!    violation apart from a corrupt archive, after `tar` fails.
//! 3. **`tar::Archive` driven directly**, because `TarballReader` is concretely
//!    `Archive<CompressionDecoder>` and cannot take a bounding wrapper.
//!
//! Nothing here writes. [`super::decision`] makes the decisions; the caller writes, through
//! [`crate::rootfs`].

use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use alpm_compress::decompression::{CompressionDecoder, DecompressionSettings};

use crate::{
    error::{Error, IoAction, Result},
    extract::decision::EntryKind,
};

/// Bounds on what a single package may cost to read.
///
/// Generous rather than tight. The purpose is that a hostile archive costs a *bounded* amount
/// of work, not that a legitimate one is squeezed — real packages reach hundreds of megabytes
/// inflated (`libreoffice-fresh` unpacks to roughly 700 MB), so a limit tuned to the typical
/// case would reject them.
#[derive(Clone, Copy, Debug)]
pub struct PackageLimits {
    /// Largest package file that will be opened.
    pub compressed_bytes: u64,
    /// Largest total inflated size that will be read out of one package.
    pub inflated_bytes: u64,
    /// Largest number of members a package may contain.
    pub max_members: usize,
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self {
            // The largest package in Arch's repositories is a few hundred MB compressed.
            compressed_bytes: 8 * 1024 * 1024 * 1024,
            inflated_bytes: 32 * 1024 * 1024 * 1024,
            // `linux-firmware` and the texlive packages run to tens of thousands of files.
            max_members: 2_000_000,
        }
    }
}

/// Which half of a package a member belongs to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberKind {
    /// A metadata member: a name beginning with `.`, such as `.PKGINFO` or `.MTREE`.
    ///
    /// libalpm reserves the whole `.`-prefixed namespace (`add.c:266`) and extracts only
    /// `.INSTALL`, `.CHANGELOG` and `.MTREE`, into the local database entry rather than into
    /// the installation root. Everything else beginning with `.` is skipped.
    Metadata,
    /// A payload member, destined for the installation root.
    Payload,
}

/// Which kind of link a member is.
///
/// Keeping these apart is not pedantry. `tar` reports a target for both through
/// `link_name()`, so conflating them creates a *symlink* where the archive asked for a hard
/// link — and real packages contain hard links: `glibc` ships three.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkKind {
    /// A symbolic link. The target is stored verbatim and may point anywhere.
    Symbolic,
    /// A hard link to another member of the same package, named relative to the root.
    Hard,
}

/// A link member's kind and target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    /// Symbolic or hard.
    pub kind: LinkKind,
    /// What it points at.
    pub target: PathBuf,
}

/// One member of a package archive, without its contents.
#[derive(Clone, Debug)]
pub struct Member {
    /// The member's path as the archive spells it.
    pub path: PathBuf,
    /// Whether it is metadata or payload.
    pub kind: MemberKind,
    /// Whether the archive says it is a directory.
    pub entry: EntryKind,
    /// The link this member is, if it is one.
    pub link: Option<Link>,
    /// The permission bits.
    pub mode: u32,
    /// The owning user id recorded in the archive.
    pub uid: u64,
    /// The owning group id recorded in the archive.
    pub gid: u64,
    /// The modification time recorded in the archive.
    pub mtime: u64,
    /// The member's size in bytes.
    pub size: u64,
}

impl Member {
    /// Whether this member is a symbolic link.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        matches!(&self.link, Some(Link { kind: LinkKind::Symbolic, .. }))
    }

    /// Whether this member is a hard link.
    #[must_use]
    pub fn is_hard_link(&self) -> bool {
        matches!(&self.link, Some(Link { kind: LinkKind::Hard, .. }))
    }
}

/// Walks every member of the package at `path`.
///
/// `on_member` is given the header and a reader over that member's contents. The reader is
/// valid only for the duration of the call, because the underlying stream is a decompressor
/// that cannot seek backwards — contents must be consumed then, or not at all. Not reading
/// them is fine; `tar` skips to the next member either way.
///
/// # Errors
///
/// - [`Error::Io`] if the file cannot be opened or read.
/// - [`Error::UnsupportedCompression`] if the magic bytes match no supported format.
/// - [`Error::PackageLimitExceeded`] if a bound is exceeded.
/// - Whatever `on_member` returns.
pub fn walk(
    path: &Path,
    limits: &PackageLimits,
    mut on_member: impl FnMut(&Member, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    walk_until(path, limits, |member, contents| {
        on_member(member, contents)?;
        Ok(Flow::Continue)
    })
}

/// Whether [`walk_until`] should read the next member or stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Flow {
    /// Read the next member.
    Continue,
    /// Stop, without an error.
    Stop,
}

/// [`walk`], for a caller that can answer its question before the archive ends.
///
/// Stopping early skips the decompression of everything after the member that answered. A
/// `.PKGINFO` sits at the front of a package makepkg built, so a reader that only wants the
/// metadata pays for a few kilobytes rather than for the whole archive. Every bound
/// [`walk`] enforces still applies to what was read.
///
/// # Errors
///
/// As [`walk`].
pub fn walk_until(
    path: &Path,
    limits: &PackageLimits,
    mut on_member: impl FnMut(&Member, &mut dyn Read) -> Result<Flow>,
) -> Result<()> {
    let mut file =
        std::fs::File::open(path).map_err(|source| Error::io(path, IoAction::Open, source))?;

    let metadata = file.metadata().map_err(|source| Error::io(path, IoAction::Metadata, source))?;
    if !metadata.is_file() {
        return Err(Error::UnusableSource {
            path: path.to_path_buf(),
            reason: "not a regular file".to_owned(),
        });
    }
    if metadata.len() > limits.compressed_bytes {
        return Err(Error::PackageLimitExceeded {
            path: path.to_path_buf(),
            limit: "compressed size",
            max: limits.compressed_bytes,
        });
    }

    let settings = sniff_file(&mut file, path)?;
    let decoder = CompressionDecoder::new(file, settings)
        .map_err(|source| Error::io(path, IoAction::Decompress, std::io::Error::other(source)))?;

    let tripped = Arc::new(AtomicBool::new(false));
    let bounded = BoundedReader {
        inner: decoder,
        limit: limits.inflated_bytes,
        read_so_far: 0,
        tripped: Arc::clone(&tripped),
    };
    let mut archive = tar::Archive::new(bounded);

    let classify = |source: std::io::Error| classify_io_error(path, source, &tripped, limits);
    let entries = archive.entries().map_err(classify)?;

    let mut seen = 0_usize;
    for entry in entries {
        let mut entry = entry.map_err(classify)?;

        seen = seen.saturating_add(1);
        if seen > limits.max_members {
            return Err(Error::PackageLimitExceeded {
                path: path.to_path_buf(),
                limit: "member count",
                max: u64::try_from(limits.max_members).unwrap_or(u64::MAX),
            });
        }

        let member = describe(&entry).map_err(classify)?;
        if on_member(&member, &mut entry)? == Flow::Stop {
            break;
        }
    }

    Ok(())
}

/// Builds a [`Member`] from a tar header.
fn describe<R: Read>(entry: &tar::Entry<'_, R>) -> std::io::Result<Member> {
    let header = entry.header();
    let path = entry.path()?.into_owned();

    // A member whose first component begins with `.` is metadata. Checking the first
    // component rather than the whole path is what stops a payload file legitimately named
    // `usr/share/foo/.keep` being mistaken for one.
    let kind = match path.components().next() {
        Some(std::path::Component::Normal(first)) if first.to_string_lossy().starts_with('.') => {
            MemberKind::Metadata
        }
        _ => MemberKind::Payload,
    };

    let entry_kind =
        if header.entry_type().is_dir() { EntryKind::Directory } else { EntryKind::Other };

    // `link_name` is populated for both kinds, so the entry type is what tells them apart.
    let link_kind = if header.entry_type().is_symlink() {
        Some(LinkKind::Symbolic)
    } else if header.entry_type().is_hard_link() {
        Some(LinkKind::Hard)
    } else {
        None
    };
    let link = match (link_kind, entry.link_name()?) {
        (Some(kind), Some(target)) => Some(Link { kind, target: target.into_owned() }),
        _ => None,
    };

    Ok(Member {
        path,
        kind,
        entry: entry_kind,
        link,
        mode: header.mode()?,
        uid: header.uid()?,
        gid: header.gid()?,
        mtime: header.mtime()?,
        size: header.size()?,
    })
}

/// Identifies a compression format from the file's magic bytes.
fn sniff_file(file: &mut std::fs::File, path: &Path) -> Result<DecompressionSettings> {
    use std::io::Seek as _;

    // Long enough for every magic below, plus the "ustar" tag at offset 257 that marks an
    // uncompressed tar.
    let mut header = [0_u8; 262];
    let read = file.read(&mut header).map_err(|source| Error::io(path, IoAction::Read, source))?;
    file.rewind().map_err(|source| Error::io(path, IoAction::Read, source))?;

    header
        .get(..read)
        .and_then(sniff)
        .ok_or_else(|| Error::UnsupportedCompression { path: path.to_path_buf() })
}

/// Identifies a compression format from its magic bytes.
fn sniff(header: &[u8]) -> Option<DecompressionSettings> {
    if header.starts_with(&[0x1f, 0x8b]) {
        Some(DecompressionSettings::Gzip)
    } else if header.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some(DecompressionSettings::Zstd)
    } else if header.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        Some(DecompressionSettings::Xz)
    } else if header.starts_with(&[0x42, 0x5a, 0x68]) {
        Some(DecompressionSettings::Bzip2)
    } else if header.get(257..262) == Some(b"ustar".as_slice()) {
        Some(DecompressionSettings::None)
    } else {
        None
    }
}

/// Tells a genuine bound violation apart from an unrelated I/O or tar-format failure.
///
/// `tar` surfaces [`BoundedReader`]'s error as an opaque [`std::io::Error`], so the shared
/// flag — set only when the limit was actually exceeded — is what distinguishes the two.
fn classify_io_error(
    path: &Path,
    source: std::io::Error,
    tripped: &Arc<AtomicBool>,
    limits: &PackageLimits,
) -> Error {
    if tripped.load(Ordering::Relaxed) {
        return Error::PackageLimitExceeded {
            path: path.to_path_buf(),
            limit: "inflated size",
            max: limits.inflated_bytes,
        };
    }
    Error::io(path, IoAction::Read, source)
}

/// A reader that refuses to yield more than `limit` bytes in total.
///
/// A compressed archive can inflate to arbitrarily more than its own size, so without this a
/// few kilobytes on disk can exhaust memory or fill a filesystem.
#[derive(Debug)]
struct BoundedReader<R> {
    inner: R,
    limit: u64,
    read_so_far: u64,
    tripped: Arc<AtomicBool>,
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.read_so_far = self.read_so_far.saturating_add(read as u64);
        if self.read_so_far > self.limit {
            self.tripped.store(true, Ordering::Relaxed);
            return Err(std::io::Error::other("decompressed size limit exceeded"));
        }
        Ok(read)
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

    /// Builds an uncompressed tar so the tests exercise the walk without depending on a
    /// compressor's output.
    fn tarball(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> PathBuf {
        let mut builder = tar::Builder::new(Vec::new());
        build(&mut builder);
        let bytes = builder.into_inner().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pkg.tar");
        std::fs::write(&path, bytes).unwrap();
        // Leak the TempDir so the file outlives this helper; tests are short-lived.
        std::mem::forget(dir);
        path
    }

    /// A header with every numeric field populated.
    ///
    /// `Header::new_gnu` leaves uid/gid/mtime as blanks, which are not parseable numbers —
    /// real packages always carry them.
    fn header(mode: u32) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(0);
        header
    }

    fn file_entry(builder: &mut tar::Builder<Vec<u8>>, name: &str, contents: &[u8], mode: u32) {
        let mut header = header(mode);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, name, contents).unwrap();
    }

    fn collect(path: &Path) -> Vec<(Member, Vec<u8>)> {
        let mut found = Vec::new();
        walk(path, &PackageLimits::default(), |member, reader| {
            let mut contents = Vec::new();
            reader.read_to_end(&mut contents).unwrap();
            found.push((member.clone(), contents));
            Ok(())
        })
        .unwrap();
        found
    }

    #[test]
    fn reads_members_and_their_contents() {
        let path = tarball(|builder| {
            file_entry(builder, "usr/bin/foo", b"binary", 0o755);
        });
        let members = collect(&path);
        assert_eq!(members.len(), 1);
        let (member, contents) = members.first().unwrap();
        assert_eq!(member.path, Path::new("usr/bin/foo"));
        assert_eq!(member.kind, MemberKind::Payload);
        assert_eq!(member.entry, EntryKind::Other);
        assert_eq!(member.mode, 0o755);
        assert_eq!(contents, b"binary");
    }

    #[test]
    fn classifies_metadata_members() {
        let path = tarball(|builder| {
            file_entry(builder, ".PKGINFO", b"pkgname = foo", 0o644);
            file_entry(builder, "usr/bin/foo", b"x", 0o755);
        });
        let members = collect(&path);
        assert_eq!(members.first().unwrap().0.kind, MemberKind::Metadata);
        assert_eq!(members.get(1).unwrap().0.kind, MemberKind::Payload);
    }

    /// A dotfile inside the payload is payload. Testing the first component rather than the
    /// whole path is what makes that true.
    #[test]
    fn a_dotfile_deeper_in_the_tree_is_payload() {
        let path = tarball(|builder| {
            file_entry(builder, "usr/share/foo/.keep", b"", 0o644);
        });
        assert_eq!(collect(&path).first().unwrap().0.kind, MemberKind::Payload);
    }

    #[test]
    fn recognises_directories_and_symlinks() {
        let path = tarball(|builder| {
            let mut directory = header(0o755);
            directory.set_entry_type(tar::EntryType::Directory);
            directory.set_cksum();
            builder.append_data(&mut directory, "usr/bin/", &[][..]).unwrap();

            let mut link = header(0o777);
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_cksum();
            builder.append_link(&mut link, "usr/bin/bar", "foo").unwrap();
        });

        let members = collect(&path);
        assert_eq!(members.first().unwrap().0.entry, EntryKind::Directory);
        let symlink = &members.get(1).unwrap().0;
        assert!(symlink.is_symlink());
        assert!(!symlink.is_hard_link());
        assert_eq!(symlink.link.as_ref().map(|link| link.target.as_path()), Some(Path::new("foo")));
    }

    /// `tar` reports a target for a hard link through the same `link_name()` as a symlink,
    /// so conflating them would create a symlink where the package asked for a hard link.
    /// `glibc` really ships three of these.
    #[test]
    fn a_hard_link_is_not_mistaken_for_a_symlink() {
        let path = tarball(|builder| {
            file_entry(builder, "usr/bin/real", b"x", 0o755);
            let mut link = header(0o755);
            link.set_entry_type(tar::EntryType::Link);
            link.set_cksum();
            builder.append_link(&mut link, "usr/bin/alias", "usr/bin/real").unwrap();
        });

        let members = collect(&path);
        let hard = &members.get(1).unwrap().0;
        assert!(hard.is_hard_link(), "{hard:?}");
        assert!(!hard.is_symlink());
        assert_eq!(
            hard.link.as_ref().map(|link| link.target.as_path()),
            Some(Path::new("usr/bin/real"))
        );
    }

    /// The name is not a guarantee; the bytes are.
    #[test]
    fn refuses_a_file_that_is_not_an_archive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not.pkg.tar.zst");
        std::fs::write(&path, b"this is not a package").unwrap();

        let err = walk(&path, &PackageLimits::default(), |_, _| Ok(())).unwrap_err();
        assert!(matches!(err, Error::UnsupportedCompression { .. }), "got {err:?}");
    }

    #[test]
    fn refuses_a_package_over_the_compressed_limit() {
        let path = tarball(|builder| file_entry(builder, "usr/bin/foo", b"x", 0o755));
        let limits = PackageLimits { compressed_bytes: 4, ..PackageLimits::default() };

        let err = walk(&path, &limits, |_, _| Ok(())).unwrap_err();
        assert!(
            matches!(err, Error::PackageLimitExceeded { limit: "compressed size", .. }),
            "got {err:?}"
        );
    }

    /// A bound violation must be reported as one, not as a corrupt archive — which is what
    /// the shared flag exists for.
    #[test]
    fn refuses_a_package_over_the_inflated_limit() {
        let path = tarball(|builder| {
            file_entry(builder, "usr/share/big", &vec![b'x'; 64 * 1024], 0o644);
        });
        let limits = PackageLimits { inflated_bytes: 1024, ..PackageLimits::default() };

        let err = walk(&path, &limits, |_, reader| {
            let mut sink = Vec::new();
            let _ = reader.read_to_end(&mut sink);
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(err, Error::PackageLimitExceeded { limit: "inflated size", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn refuses_a_package_with_too_many_members() {
        let path = tarball(|builder| {
            for index in 0..10 {
                file_entry(builder, &format!("usr/share/f{index}"), b"x", 0o644);
            }
        });
        let limits = PackageLimits { max_members: 3, ..PackageLimits::default() };

        let err = walk(&path, &limits, |_, _| Ok(())).unwrap_err();
        assert!(
            matches!(err, Error::PackageLimitExceeded { limit: "member count", .. }),
            "got {err:?}"
        );
    }

    /// An error from the callback stops the walk rather than being swallowed.
    #[test]
    fn propagates_a_callback_error() {
        let path = tarball(|builder| {
            file_entry(builder, "usr/bin/foo", b"x", 0o755);
            file_entry(builder, "usr/bin/bar", b"x", 0o755);
        });

        let mut seen = 0_usize;
        let err = walk(&path, &PackageLimits::default(), |_, _| {
            seen += 1;
            Err(Error::UnusableSource { path: PathBuf::from("x"), reason: "stop".to_owned() })
        })
        .unwrap_err();
        assert!(matches!(err, Error::UnusableSource { .. }), "got {err:?}");
        assert_eq!(seen, 1, "the walk continued past a failing callback");
    }

    /// Skipping a member's contents must not desynchronise the stream.
    #[test]
    fn a_member_whose_contents_are_not_read_is_skipped_cleanly() {
        let path = tarball(|builder| {
            file_entry(builder, "usr/share/a", &vec![b'a'; 5000], 0o644);
            file_entry(builder, "usr/share/b", b"second", 0o644);
        });

        let mut names = Vec::new();
        walk(&path, &PackageLimits::default(), |member, _| {
            names.push(member.path.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(names, [PathBuf::from("usr/share/a"), PathBuf::from("usr/share/b")]);
    }

    #[test]
    fn sniffs_every_supported_format() {
        assert!(matches!(sniff(&[0x1f, 0x8b, 0, 0]), Some(DecompressionSettings::Gzip)));
        assert!(matches!(sniff(&[0x28, 0xb5, 0x2f, 0xfd]), Some(DecompressionSettings::Zstd)));
        assert!(matches!(
            sniff(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]),
            Some(DecompressionSettings::Xz)
        ));
        assert!(matches!(sniff(b"BZh9"), Some(DecompressionSettings::Bzip2)));
        assert!(sniff(b"nonsense").is_none());
    }
}
