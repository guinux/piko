//! The audited archive core: everything that touches a repository archive's raw bytes.
//!
//! Everything that reads a repository archive goes through [`walk`], exactly as
//! [`crate::fs_util`] is the single audited door for the local database. This module enforces
//! three properties:
//!
//! 1. **Magic-byte sniffing, not extension detection.** `alpm-compress`'s own
//!    `TryFrom<&Path>` reads the file *extension*. The real files are named `core.db` —
//!    extension `"db"`, which is not a compression suffix at all. Sniffing the header is both
//!    necessary and stronger than trusting the name.
//! 2. **Bounded decompression.** `alpm-compress` has no size cap anywhere. Inspection of
//!    `CompressionDecoder` and every `DecompressionSettings` variant confirms this.
//!    [`BoundedReader`] wraps the decoder and trips a shared flag on overrun. That flag is
//!    what tells a limit violation apart from a genuinely corrupt archive after `tar` fails.
//! 3. **`tar::Archive` driven directly, not through `alpm-compress::TarballReader`.**
//!    `TarballReader`'s field is concretely `Archive<CompressionDecoder>`, not generic over
//!    `Read`, so a bounding wrapper cannot be inserted into it. Its `read_entry` also re-calls
//!    `entries()` on every invocation, and `tar` refuses that once the stream has moved past
//!    position 0 — impossible to satisfy against a decompressor. So `entries()` is called
//!    exactly once here.

use std::{
    collections::HashSet,
    io::Read as _,
    path::{Component, Path},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use alpm_compress::decompression::{CompressionDecoder, DecompressionSettings};
use alpm_types::Name;

use crate::{
    entry_name::{EntryName, EntryNameError},
    error::{Error, IoAction, Result},
    fs_util,
    limits::{Limit, Limits},
};

/// One parsed `desc` or `files` member from a repository archive.
pub(crate) enum ArchiveItem {
    /// A `<name>-<version>/desc` member, with its UTF-8 text.
    Desc { entry: EntryName, text: String },
    /// A `<name>-<version>/files` member, with its UTF-8 text.
    Files { entry: EntryName, text: String },
}

/// Why a tar member was not turned into an [`ArchiveItem`].
pub(crate) enum SkipReason {
    /// The member's path is not valid UTF-8.
    NonUtf8Path,
    /// The path is not `<name>-<version>/desc` or `<name>-<version>/files`.
    UnexpectedShape,
    /// The first path component is not a valid entry name.
    InvalidEntryName(EntryNameError),
    /// The member is a symlink, hard link, device node or FIFO, not a regular file.
    NotARegularFile,
    /// The same member path appeared more than once in the archive.
    Duplicate,
}

/// A tar member that was not turned into an [`ArchiveItem`], for diagnostic reporting.
pub(crate) struct Skipped {
    /// The member's path as it appeared in the archive, or a placeholder if it was not
    /// valid UTF-8.
    pub(crate) path: String,
    /// Why it was skipped.
    pub(crate) reason: SkipReason,
}

/// Opens, decompresses and walks a repository archive exactly once.
///
/// `on_item` is called for every valid `desc` or `files` member. `on_skip` is called for
/// every member that was not one, with the reason. Directory members (the
/// `<name>-<version>/` entries themselves) are skipped with no callback at all — the same
/// silent skip the local database applies to `ALPM_DB_VERSION`.
///
/// `on_item` returns a `Result`, unlike `on_skip`, because a caller-side resource limit (the
/// files arena's byte cap, say) can fire there. Such a failure must abort the whole open, the
/// same way [`Error::TooManyEntries`] aborts the local database's scan. It must not be
/// downgraded to a diagnostic that lets the walk continue.
///
/// # Errors
///
/// - [`Error::UnsupportedCompression`] if the archive's header does not match gzip, zstd, xz,
///   bzip2 or an uncompressed tar.
/// - [`Error::LimitExceeded`] if the archive's compressed size, its total inflated size, or a
///   single member's size exceeds the configured [`Limits`].
/// - [`Error::Io`] for any other read failure, including a malformed tar stream.
/// - Whatever `on_item` returns, on the first failure.
pub(crate) fn walk(
    path: &Path,
    limits: &Limits,
    mut on_item: impl FnMut(ArchiveItem) -> Result<()>,
    mut on_skip: impl FnMut(Skipped),
) -> Result<()> {
    let mut file = fs_util::open_following_symlinks(path)?;

    let compressed_len =
        file.metadata().map_err(|source| Error::io(path, IoAction::Metadata, source))?.len();
    if compressed_len > limits.repo_compressed_bytes {
        return Err(Error::LimitExceeded {
            path: path.to_path_buf(),
            limit: Limit::RepoCompressed,
            max: limits.repo_compressed_bytes,
        });
    }

    let settings = sniff_file(&mut file, path)?;
    let decoder = CompressionDecoder::new(file, settings)
        .map_err(|source| Error::io(path, IoAction::Decompress, std::io::Error::other(source)))?;

    let tripped = Arc::new(AtomicBool::new(false));
    let bounded = BoundedReader {
        inner: decoder,
        limit: limits.repo_inflated_bytes,
        read_so_far: 0,
        tripped: Arc::clone(&tripped),
    };
    let mut archive = tar::Archive::new(bounded);

    let classify = |source: std::io::Error| classify_io_error(path, source, &tripped, limits);

    let entries = archive.entries().map_err(classify)?;
    // Keyed on the *parsed* identity — the entry directory name plus which member it is —
    // rather than on the raw path string. A path spelled differently but denoting the same
    // member (an interior `.` component, say) would slip past a raw-string key. The
    // duplicate check would then disagree with the identity everything downstream uses.
    let mut seen: HashSet<(Box<str>, Member)> = HashSet::new();

    for entry in entries {
        let mut entry = entry.map_err(classify)?;

        // The header is consulted before the path is materialised. So the directory member
        // every package contributes costs no allocation at all: one skipped allocation per
        // package across the whole archive.
        if entry.header().entry_type() == tar::EntryType::Directory {
            continue;
        }
        let is_regular = entry.header().entry_type() == tar::EntryType::Regular;

        // Classified while the borrow on `entry` is live. The outcome is owned, which ends
        // that borrow so the member can be read below. The full path string is built only
        // for a member that is about to be reported — an accepted one never allocates it.
        let classified = match entry.path() {
            Err(_) => Classified::NonUtf8,
            Ok(raw) => classify_member(&raw, is_regular),
        };

        let (entry_name, member) = match classified {
            Classified::Accepted { entry_name, member } => (entry_name, member),
            Classified::NonUtf8 => {
                on_skip(Skipped {
                    path: "<non-utf8 path>".to_owned(),
                    reason: SkipReason::NonUtf8Path,
                });
                continue;
            }
            Classified::Rejected { path: raw_path, reason } => {
                on_skip(Skipped { path: raw_path, reason });
                continue;
            }
        };

        if !seen.insert((entry_name.as_str().into(), member)) {
            on_skip(Skipped {
                path: format!("{}/{}", entry_name.as_str(), member.as_str()),
                reason: SkipReason::Duplicate,
            });
            continue;
        }

        let declared_size = entry.header().size().map_err(classify)?;
        if declared_size > limits.repo_entry_bytes {
            return Err(Error::LimitExceeded {
                path: path.to_path_buf(),
                limit: Limit::RepoEntry,
                max: limits.repo_entry_bytes,
            });
        }

        let ceiling = limits.repo_entry_bytes.saturating_add(1);
        let mut buf = Vec::new();
        (&mut entry).take(ceiling).read_to_end(&mut buf).map_err(classify)?;
        if buf.len() as u64 > limits.repo_entry_bytes {
            return Err(Error::LimitExceeded {
                path: path.to_path_buf(),
                limit: Limit::RepoEntry,
                max: limits.repo_entry_bytes,
            });
        }

        let text = String::from_utf8(buf).map_err(|error| Error::NotUtf8 {
            path: path.to_path_buf(),
            source: error.utf8_error(),
        })?;

        on_item(match member {
            Member::Desc => ArchiveItem::Desc { entry: entry_name, text },
            Member::Files => ArchiveItem::Files { entry: entry_name, text },
        })?;
    }

    Ok(())
}

/// Which of an entry directory's two metadata members a tar member is.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Member {
    /// The `desc` member.
    Desc,
    /// The `files` member.
    Files,
}

impl Member {
    /// Recognises a member file name. Anything else is not part of the format.
    fn parse(name: &str) -> Option<Self> {
        match name {
            "desc" => Some(Self::Desc),
            "files" => Some(Self::Files),
            _ => None,
        }
    }

    /// The member's file name, for rebuilding a path in a diagnostic.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Desc => "desc",
            Self::Files => "files",
        }
    }
}

/// What [`classify_member`] made of one tar member's path.
enum Classified {
    /// A well-formed `<name>-<version>/desc` or `/files` member of a regular file.
    Accepted {
        /// The parsed entry directory name.
        entry_name: EntryName,
        /// Which member it is.
        member: Member,
    },
    /// The path was not valid UTF-8, so there is no path to report.
    NonUtf8,
    /// The member is not one this format defines, and is reported with its path.
    Rejected {
        /// The member's path as it appeared in the archive.
        path: String,
        /// Why it was rejected.
        reason: SkipReason,
    },
}

/// Decides what a tar member is from its path alone.
///
/// Allocating the path as a `String` is deferred to the branches that actually report it: an
/// accepted member never needs one, and it is by far the common case.
fn classify_member(raw: &Path, is_regular: bool) -> Classified {
    let rejected = |reason: SkipReason| Classified::Rejected {
        path: raw.to_string_lossy().into_owned(),
        reason,
    };

    if !is_regular {
        return rejected(SkipReason::NotARegularFile);
    }

    let Some((dir_str, member_str)) = two_components_of(raw) else {
        return rejected(SkipReason::UnexpectedShape);
    };
    let Some(member) = Member::parse(member_str) else {
        return rejected(SkipReason::UnexpectedShape);
    };
    match EntryName::parse(dir_str) {
        Ok(entry_name) => Classified::Accepted { entry_name, member },
        Err(source) => rejected(SkipReason::InvalidEntryName(source)),
    }
}

/// Walks a `.files` archive looking only for `wanted`'s `files` members, stopping as soon as
/// every one of them has been seen.
///
/// Unlike [`walk`], this is not a general-purpose primitive: it never looks at `desc`
/// members, skips any entry whose directory does not name one of `wanted` without buffering
/// or parsing it, and returns without reading the rest of the archive once `wanted` is
/// exhausted. It exists for `FilesSource::file_lists_for`, where a caller wants file lists
/// for a handful of packages out of a repository that may hold thousands.
///
/// Skipping a non-matching entry only saves the allocation and UTF-8 validation it would
/// otherwise cost — the underlying gzip stream is still sequential, so every byte up to the
/// last matched entry is still decompressed regardless. Stopping early is what actually saves
/// work, and it is only possible once every wanted name has been *seen* — not resolved: a
/// package present at a different version than expected still counts as seen here (its
/// `files` member is handed to `on_item`), and any version mismatch is reported later by
/// `FilesArena::file_list` at lookup time, exactly as it is for a full walk. Only a package
/// genuinely absent from the whole archive forces a full walk, with no way to know that
/// short of reaching the end.
///
/// There is no `on_skip`: diagnostics from this walk are not collected, matching
/// `FilesSource::load`'s existing lazy `.files` walk, which already discards them.
///
/// # Errors
///
/// As [`walk`], for the entries actually read.
pub(crate) fn walk_matching(
    path: &Path,
    limits: &Limits,
    wanted: &HashSet<&Name>,
    mut on_item: impl FnMut(EntryName, String) -> Result<()>,
) -> Result<()> {
    if wanted.is_empty() {
        return Ok(());
    }

    let mut file = fs_util::open_following_symlinks(path)?;

    let compressed_len =
        file.metadata().map_err(|source| Error::io(path, IoAction::Metadata, source))?.len();
    if compressed_len > limits.repo_compressed_bytes {
        return Err(Error::LimitExceeded {
            path: path.to_path_buf(),
            limit: Limit::RepoCompressed,
            max: limits.repo_compressed_bytes,
        });
    }

    let settings = sniff_file(&mut file, path)?;
    let decoder = CompressionDecoder::new(file, settings)
        .map_err(|source| Error::io(path, IoAction::Decompress, std::io::Error::other(source)))?;

    let tripped = Arc::new(AtomicBool::new(false));
    let bounded = BoundedReader {
        inner: decoder,
        limit: limits.repo_inflated_bytes,
        read_so_far: 0,
        tripped: Arc::clone(&tripped),
    };
    let mut archive = tar::Archive::new(bounded);

    let classify = |source: std::io::Error| classify_io_error(path, source, &tripped, limits);

    let entries = archive.entries().map_err(classify)?;
    let mut still_wanted: HashSet<&Name> = wanted.clone();

    for entry in entries {
        let mut entry = entry.map_err(classify)?;

        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }

        // Nothing is reported from this walk, so no member's path is ever materialised as a
        // `String` — the identity is parsed straight out of the borrowed path and the entry
        // is skipped without allocating if it is not one of `wanted`.
        let entry_name = match entry.path() {
            Ok(raw) => match two_components_of(&raw) {
                Some((dir_str, "files")) => match EntryName::parse(dir_str) {
                    Ok(parsed) => parsed,
                    Err(_) => continue,
                },
                _ => continue,
            },
            Err(_) => continue,
        };

        if !still_wanted.remove(entry_name.name()) {
            continue;
        }

        let declared_size = entry.header().size().map_err(classify)?;
        if declared_size > limits.repo_entry_bytes {
            return Err(Error::LimitExceeded {
                path: path.to_path_buf(),
                limit: Limit::RepoEntry,
                max: limits.repo_entry_bytes,
            });
        }

        let ceiling = limits.repo_entry_bytes.saturating_add(1);
        let mut buf = Vec::new();
        (&mut entry).take(ceiling).read_to_end(&mut buf).map_err(classify)?;
        if buf.len() as u64 > limits.repo_entry_bytes {
            return Err(Error::LimitExceeded {
                path: path.to_path_buf(),
                limit: Limit::RepoEntry,
                max: limits.repo_entry_bytes,
            });
        }

        let text = String::from_utf8(buf).map_err(|error| Error::NotUtf8 {
            path: path.to_path_buf(),
            source: error.utf8_error(),
        })?;

        on_item(entry_name, text)?;

        if still_wanted.is_empty() {
            break;
        }
    }

    Ok(())
}

/// Splits `raw_path` into `(directory, member)` if it has exactly two normal components.
///
/// Anything else — extra nesting, a leading `..` or `/`, a single component — is rejected by
/// returning `None`, which the caller turns into [`SkipReason::UnexpectedShape`]. There is no
/// filesystem write anywhere in this crate, so this is about refusing a malformed shape, not
/// preventing extraction — but a `..` component still cannot reach `Component::Normal`, so it
/// is rejected the same way regardless.
///
/// Note that [`Path::components`] normalises away interior `.` components, so
/// `foo-1.0.0-1/./desc` splits exactly as `foo-1.0.0-1/desc` does. That is why [`walk`]'s
/// duplicate check is keyed on this function's output rather than on the raw path: the two
/// spellings denote the same member and must be treated as such.
fn two_components_of(raw_path: &Path) -> Option<(&str, &str)> {
    let mut components = raw_path.components();
    let (Some(Component::Normal(dir)), Some(Component::Normal(member)), None) =
        (components.next(), components.next(), components.next())
    else {
        return None;
    };
    Some((dir.to_str()?, member.to_str()?))
}

/// Reads enough of `file` to identify its compression, then rewinds it.
fn sniff_file(file: &mut std::fs::File, path: &Path) -> Result<DecompressionSettings> {
    use std::io::Seek as _;

    // Long enough to see every magic below, plus the "ustar" tag at offset 257 that
    // identifies an uncompressed tar.
    let mut header = [0_u8; 262];
    let read = file.read(&mut header).map_err(|source| Error::io(path, IoAction::Read, source))?;
    file.rewind().map_err(|source| Error::io(path, IoAction::Read, source))?;

    header
        .get(..read)
        .and_then(sniff)
        .ok_or_else(|| Error::UnsupportedCompression { path: path.to_path_buf() })
}

/// Identifies a compression format from its magic bytes.
///
/// The [alpm-repo-db] spec also allows `.Z`, `.lrz`, `.lz`, `.lz4` and `.lzo` suffixes;
/// `alpm-compress` implements none of them (confirmed: its `DecompressionSettings` has no
/// variant for any of the five), so archives using them are read by nothing in this crate.
///
/// [alpm-repo-db]: https://alpm.archlinux.page/specifications/alpm-repo-db.7.html
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
/// `tar` propagates [`BoundedReader`]'s error as an opaque [`std::io::Error`], so the shared
/// `tripped` flag — set only when the configured limit was actually exceeded — is what lets
/// this be reported as [`Error::LimitExceeded`] rather than a generic parse failure.
fn classify_io_error(
    path: &Path,
    source: std::io::Error,
    tripped: &AtomicBool,
    limits: &Limits,
) -> Error {
    if tripped.load(Ordering::Relaxed) {
        Error::LimitExceeded {
            path: path.to_path_buf(),
            limit: Limit::RepoInflated,
            max: limits.repo_inflated_bytes,
        }
    } else {
        Error::io(path, IoAction::Read, source)
    }
}

/// Wraps a [`Read`](std::io::Read) and fails once more than `limit` bytes have passed
/// through it.
///
/// `alpm-compress::tarball::TarballReader` cannot be bounded this way: its field is
/// concretely `Archive<CompressionDecoder>`, not generic over `Read`. Driving `tar::Archive`
/// directly over this wrapper is why this module exists instead of using that type.
struct BoundedReader<R> {
    inner: R,
    limit: u64,
    read_so_far: u64,
    tripped: Arc<AtomicBool>,
}

impl<R: std::io::Read> std::io::Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read_so_far = self.read_so_far.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if self.read_so_far > self.limit {
            self.tripped.store(true, Ordering::Relaxed);
            return Err(std::io::Error::other("decompressed size exceeded the configured limit"));
        }
        Ok(n)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::{io::Write as _, path::PathBuf};

    use super::*;

    fn gzip_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *content).unwrap();
        }
        let tar_bytes = builder.into_inner().unwrap();

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn write_archive(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// As [`gzip_tar`], but writes each member's name into the header field verbatim.
    ///
    /// `tar::Builder::append_data` normalises the path it is given, so it cannot produce a
    /// member named `foo-1.0.0-1/./desc` — which is exactly the shape the duplicate check
    /// needs to be tested against. Writing the name bytes directly is the only way to build
    /// one, and mirrors what a non-Rust archiver could legitimately emit.
    fn gzip_tar_raw(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();

        for (name, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            let name_bytes = name.as_bytes();
            let field = &mut header.as_gnu_mut().unwrap().name;
            field.get_mut(..name_bytes.len()).unwrap().copy_from_slice(name_bytes);
            header.set_cksum();

            tar_bytes.extend_from_slice(header.as_bytes().as_slice());
            tar_bytes.extend_from_slice(content);
            // Every member's data is padded out to a 512-byte block boundary.
            let remainder = content.len() % 512;
            let padding = if remainder == 0 { 0 } else { 512_usize.saturating_sub(remainder) };
            tar_bytes.extend(std::iter::repeat_n(0_u8, padding));
        }
        // Two zero blocks terminate the archive.
        tar_bytes.extend(std::iter::repeat_n(0_u8, 1024));

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn sniffs_gzip() {
        assert!(matches!(sniff(&[0x1f, 0x8b, 0, 0]), Some(DecompressionSettings::Gzip)));
    }

    #[test]
    fn sniffs_zstd() {
        assert!(matches!(sniff(&[0x28, 0xb5, 0x2f, 0xfd]), Some(DecompressionSettings::Zstd)));
    }

    #[test]
    fn sniffs_xz() {
        assert!(matches!(
            sniff(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]),
            Some(DecompressionSettings::Xz)
        ));
    }

    #[test]
    fn sniffs_bzip2() {
        assert!(matches!(sniff(&[0x42, 0x5a, 0x68]), Some(DecompressionSettings::Bzip2)));
    }

    #[test]
    fn sniffs_an_uncompressed_tar_by_the_ustar_magic_at_offset_257() {
        let mut header = vec![0_u8; 262];
        if let Some(slot) = header.get_mut(257..262) {
            slot.copy_from_slice(b"ustar");
        }
        assert!(matches!(sniff(&header), Some(DecompressionSettings::None)));
    }

    #[test]
    fn rejects_unrecognised_headers() {
        assert!(sniff(&[0, 0, 0, 0]).is_none());
        assert!(sniff(&[]).is_none());
    }

    #[test]
    fn walks_desc_and_files_members() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = gzip_tar(&[
            ("foo-1.0.0-1/desc", b"%NAME%\nfoo\n"),
            ("foo-1.0.0-1/files", b"%FILES%\nusr/bin/foo\n"),
        ]);
        let path = write_archive(dir.path(), "core.db", &bytes);

        let mut items = Vec::new();
        walk(
            &path,
            &Limits::default(),
            |item| {
                items.push(item);
                Ok(())
            },
            |_| {},
        )
        .unwrap();

        assert_eq!(items.len(), 2);
        assert!(items.iter().any(
            |i| matches!(i, ArchiveItem::Desc { entry, .. } if entry.as_str() == "foo-1.0.0-1")
        ));
        assert!(items.iter().any(
            |i| matches!(i, ArchiveItem::Files { entry, .. } if entry.as_str() == "foo-1.0.0-1")
        ));
    }

    #[test]
    fn skips_a_member_with_the_wrong_shape() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = gzip_tar(&[("foo-1.0.0-1/nested/desc", b"x"), ("stray-file", b"x")]);
        let path = write_archive(dir.path(), "core.db", &bytes);

        let mut skips = Vec::new();
        walk(&path, &Limits::default(), |_| Ok(()), |s| skips.push(s.path)).unwrap();

        assert_eq!(skips.len(), 2, "{skips:?}");
    }

    #[test]
    fn skips_an_entry_with_an_invalid_name() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = gzip_tar(&[("not-a-valid-name/desc", b"x")]);
        let path = write_archive(dir.path(), "core.db", &bytes);

        let mut reasons = Vec::new();
        walk(
            &path,
            &Limits::default(),
            |_| Ok(()),
            |s| reasons.push(matches!(s.reason, SkipReason::InvalidEntryName(_))),
        )
        .unwrap();

        assert_eq!(reasons, [true]);
    }

    /// The reason `TarballReader` cannot be used: this must fail as `LimitExceeded`, not as a
    /// truncated-archive parse error.
    #[test]
    fn refuses_an_archive_exceeding_the_inflated_limit() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = gzip_tar(&[("foo-1.0.0-1/desc", &vec![b'x'; 10_000])]);
        let path = write_archive(dir.path(), "core.db", &bytes);

        let limits = Limits { repo_inflated_bytes: 1024, ..Limits::default() };
        let err = walk(&path, &limits, |_| Ok(()), |_| {}).unwrap_err();

        assert!(
            matches!(&err, Error::LimitExceeded { limit: Limit::RepoInflated, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn refuses_an_oversized_compressed_archive() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = gzip_tar(&[("foo-1.0.0-1/desc", b"hello")]);
        let path = write_archive(dir.path(), "core.db", &bytes);

        let limits = Limits { repo_compressed_bytes: 4, ..Limits::default() };
        let err = walk(&path, &limits, |_| Ok(()), |_| {}).unwrap_err();

        assert!(
            matches!(&err, Error::LimitExceeded { limit: Limit::RepoCompressed, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn refuses_an_oversized_member() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = gzip_tar(&[("foo-1.0.0-1/desc", &vec![b'x'; 1024])]);
        let path = write_archive(dir.path(), "core.db", &bytes);

        let limits = Limits { repo_entry_bytes: 16, ..Limits::default() };
        let err = walk(&path, &limits, |_| Ok(()), |_| {}).unwrap_err();

        assert!(
            matches!(&err, Error::LimitExceeded { limit: Limit::RepoEntry, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_a_file_with_an_unrecognised_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_archive(dir.path(), "core.db", b"not an archive at all");

        let err = walk(&path, &Limits::default(), |_| Ok(()), |_| {}).unwrap_err();
        assert!(matches!(err, Error::UnsupportedCompression { .. }), "got {err:?}");
    }

    #[test]
    fn a_duplicate_member_path_keeps_the_first_and_signals_it() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = gzip_tar(&[("foo-1.0.0-1/desc", b"first"), ("foo-1.0.0-1/desc", b"second")]);
        let path = write_archive(dir.path(), "core.db", &bytes);

        let mut texts = Vec::new();
        let mut duplicate_skips = 0;
        walk(
            &path,
            &Limits::default(),
            |item| {
                if let ArchiveItem::Desc { text, .. } = item {
                    texts.push(text);
                }
                Ok(())
            },
            |s| {
                if matches!(s.reason, SkipReason::Duplicate) {
                    duplicate_skips += 1;
                }
            },
        )
        .unwrap();

        assert_eq!(texts, ["first"]);
        assert_eq!(duplicate_skips, 1);
    }

    /// The duplicate check keys on the parsed identity, not the raw path, so a second
    /// spelling of the same member is caught rather than silently accepted as a new one.
    /// `Path::components` normalises the interior `.` away, so both paths denote
    /// `foo-1.0.0-1/desc`.
    #[test]
    fn a_differently_spelled_path_for_the_same_member_is_still_a_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let bytes =
            gzip_tar_raw(&[("foo-1.0.0-1/desc", b"first"), ("foo-1.0.0-1/./desc", b"second")]);
        let path = write_archive(dir.path(), "core.db", &bytes);

        let mut texts = Vec::new();
        let mut duplicate_skips = 0;
        walk(
            &path,
            &Limits::default(),
            |item| {
                if let ArchiveItem::Desc { text, .. } = item {
                    texts.push(text);
                }
                Ok(())
            },
            |s| {
                if matches!(s.reason, SkipReason::Duplicate) {
                    duplicate_skips += 1;
                }
            },
        )
        .unwrap();

        assert_eq!(texts, ["first"], "only the first spelling may be read");
        assert_eq!(duplicate_skips, 1, "the second spelling must be reported as a duplicate");
    }

    #[test]
    fn directory_members_are_skipped_without_a_diagnostic() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append_dir("foo-1.0.0-1", dir.path()).unwrap();
        let tar_bytes = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        let bytes = encoder.finish().unwrap();
        let path = write_archive(dir.path(), "core.db", &bytes);

        let mut skips = 0;
        walk(&path, &Limits::default(), |_| Ok(()), |_| skips += 1).unwrap();
        assert_eq!(skips, 0);
    }

    fn name(s: &str) -> Name {
        use std::str::FromStr as _;
        Name::from_str(s).unwrap()
    }

    #[test]
    fn walk_matching_never_opens_the_archive_when_nothing_is_wanted() {
        let path = Path::new("/nonexistent/does-not-matter.files");
        let wanted = HashSet::new();

        walk_matching(path, &Limits::default(), &wanted, |_, _| Ok(())).unwrap();
    }

    #[test]
    fn walk_matching_only_reports_files_members_of_wanted_packages() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = gzip_tar(&[
            ("foo-1.0.0-1/desc", b"not a files member"),
            ("foo-1.0.0-1/files", b"%FILES%\nusr/bin/foo\n"),
            ("bar-1.0.0-1/files", b"%FILES%\nusr/bin/bar\n"),
        ]);
        let path = write_archive(dir.path(), "core.files", &bytes);

        let foo = name("foo");
        let wanted: HashSet<&Name> = std::iter::once(&foo).collect();

        let mut found = Vec::new();
        walk_matching(&path, &Limits::default(), &wanted, |entry, text| {
            found.push((entry.as_str().to_owned(), text));
            Ok(())
        })
        .unwrap();

        assert_eq!(found, [("foo-1.0.0-1".to_owned(), "%FILES%\nusr/bin/foo\n".to_owned())]);
    }

    #[test]
    fn walk_matching_finds_nothing_for_a_name_absent_from_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = gzip_tar(&[("foo-1.0.0-1/files", b"%FILES%\nusr/bin/foo\n")]);
        let path = write_archive(dir.path(), "core.files", &bytes);

        let absent = name("absent");
        let wanted: HashSet<&Name> = std::iter::once(&absent).collect();

        let mut found = Vec::new();
        walk_matching(&path, &Limits::default(), &wanted, |entry, text| {
            found.push((entry, text));
            Ok(())
        })
        .unwrap();

        assert!(found.is_empty());
    }

    /// The property the whole function exists for: once every wanted name has been seen,
    /// the rest of the archive is never decompressed at all — proven by a limit that a full
    /// walk of the same archive genuinely cannot satisfy, but a stopped-early walk can.
    #[test]
    fn walk_matching_stops_decompressing_once_every_wanted_name_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = gzip_tar(&[
            ("foo-1.0.0-1/files", b"%FILES%\nusr/bin/foo\n"),
            ("bar-1.0.0-1/files", vec![b'x'; 200_000].as_slice()),
        ]);
        let path = write_archive(dir.path(), "core.files", &bytes);

        let limits = Limits { repo_inflated_bytes: 4096, ..Limits::default() };

        let foo = name("foo");
        let wanted: HashSet<&Name> = std::iter::once(&foo).collect();

        let mut found = Vec::new();
        walk_matching(&path, &limits, &wanted, |entry, text| {
            found.push((entry.as_str().to_owned(), text));
            Ok(())
        })
        .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found.first().map(|(name, _)| name.as_str()), Some("foo-1.0.0-1"));

        // Sanity check the premise: this archive and limit cannot be walked in full without
        // tripping the limit, so the success above is proof of stopping early, not of
        // `bar`'s entry merely fitting anyway.
        let err = walk(&path, &limits, |_| Ok(()), |_| {}).unwrap_err();
        assert!(
            matches!(&err, Error::LimitExceeded { limit: Limit::RepoInflated, .. }),
            "got {err:?}"
        );
    }
}
