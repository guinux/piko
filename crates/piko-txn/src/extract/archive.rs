//! Reading a `.pkg.tar.*` archive, member by member.
//!
//! This reader follows the same three rules as `piko-db`'s repository-archive reader, for the
//! same reasons.
//!
//! 1. **Magic-byte sniffing, not extension detection.** A package is usually named
//!    `.pkg.tar.zst`, but the name is not a guarantee. [`piko_db::compression`] reads the
//!    bytes, and decodes gzip and zstd only.
//! 2. **Bounded decompression.** The decoder caps nothing but zstd's window. A bounded reader
//!    wraps it and trips a shared flag on overrun. This flag is what tells a bound violation
//!    apart from a corrupt archive, after `tar` fails.
//! 3. **`tar::Archive` driven directly**, over the bounded reader.
//!
//! A member must be a regular file, a directory, a symbolic link or a hard link. Any other
//! type refuses the whole package: a device node, a FIFO, a contiguous or GNU sparse file, a
//! pax global header, or a type byte `tar` does not name. The extraction writes those four
//! kinds only, so a fifth would reach the disk as something the archive did not say it was.
//! No Arch package carries one.
//!
//! A member's path, and a hard link's target, must also have one spelling:
//! [`crate::rootfs::components`] refuses `.`, `..`, a repeated separator and a leading `/`. Every
//! reader of the walk then sees the path extraction writes.
//!
//! Nothing here writes. [`super::decision`] makes the decisions; the caller writes, through
//! [`crate::rootfs`].

use std::{
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use piko_db::compression::{self, BoundedReader, Bounds, Decoder, Overrun};

use crate::{
    error::{Error, IoAction, Result},
    extract::decision::EntryKind,
};

/// Bounds on what a single package may cost to read.
///
/// Generous rather than tight. The purpose is that a hostile archive costs a *bounded* amount
/// of work, not that a legitimate one is squeezed. The largest `%ISIZE%` in `core` and `extra`
/// is 9.05 GiB (`intel-oneapi-toolkit`), so `inflated_bytes` leaves about 3.5 times that. A
/// package the plan declares a size for gets a much tighter bound on top: see
/// [`PackageLimits::with_declared_size`].
#[derive(Clone, Copy, Debug)]
pub struct PackageLimits {
    /// Largest package file that will be opened.
    pub compressed_bytes: u64,
    /// Largest total inflated size that will be read out of one package.
    ///
    /// The ceiling for every package, and the only bound for one with no declared size.
    pub inflated_bytes: u64,
    /// Largest number of members a package may contain.
    pub max_members: usize,
    /// Largest number of extended attribute records one member may carry.
    ///
    /// A record, not an attribute: bsdtar writes each attribute under two spellings.
    pub max_xattrs: usize,
    /// Largest total size, names and values together, of one member's extended attributes.
    pub max_xattr_bytes: usize,
    /// The installed size the plan declares for this one package, its `%ISIZE%`.
    ///
    /// `None` for a caller with no plan, which gets `inflated_bytes` alone. Set through
    /// [`PackageLimits::with_declared_size`] per package, never as a transaction-wide setting.
    /// See that function for the bound it adds.
    pub declared_size: Option<u64>,
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self {
            // The largest package in Arch's repositories is a few hundred MB compressed.
            compressed_bytes: 8 * 1024 * 1024 * 1024,
            inflated_bytes: 32 * 1024 * 1024 * 1024,
            // `linux-firmware` and the texlive packages run to tens of thousands of files.
            max_members: 2_000_000,
            // Real packages carry one, `security.capability`, on a handful of files. The kernel
            // itself caps a value at 64 KiB (`XATTR_SIZE_MAX`).
            max_xattrs: 64,
            max_xattr_bytes: 256 * 1024,
            declared_size: None,
        }
    }
}

/// What the tar stream may add to a package's declared size, once per package.
///
/// `%ISIZE%` is `du --apparent-size` over the payload. It does not count `.PKGINFO`,
/// `.BUILDINFO` or `.MTREE`, nor the zero blocks that end an archive. Measured over 1099
/// packages: at most 64 KiB of these costs a member count does not explain.
const DECLARED_SLACK_FIXED: u64 = 1024 * 1024;

/// What the tar stream may add to a package's declared size, per member.
///
/// A member costs a 512-byte header, up to 511 bytes of padding, and a PAX header when it needs
/// one: another header block and a body of one block or more. About 2 KiB in the worst ordinary
/// case. Measured over 1099 packages, beyond [`DECLARED_SLACK_FIXED`]'s 64 KiB: at most
/// 898 bytes per member (`systemd-libs`). This is per member and not a ratio of the size,
/// because a package of symbolic links declares almost nothing and still has a header each.
const DECLARED_SLACK_PER_MEMBER: u64 = 4 * 1024;

impl PackageLimits {
    /// These limits, with the stream also bounded by `size`, the package's declared `%ISIZE%`.
    ///
    /// The stream may inflate to `size`, plus 1 MiB (`DECLARED_SLACK_FIXED`), plus 4 KiB
    /// (`DECLARED_SLACK_PER_MEMBER`) for each member read so far. `inflated_bytes` still
    /// applies above that. The bound grows as members are read, since the member count is not
    /// known in advance. So a package that inflates past what it declares is refused after about
    /// that many bytes, not after `inflated_bytes`.
    #[must_use]
    pub const fn with_declared_size(self, size: u64) -> Self {
        Self { declared_size: Some(size), ..self }
    }

    /// The declared bound once `members` members have been read. `u64::MAX` with no declared
    /// size.
    fn declared_bound(&self, members: usize) -> u64 {
        self.declared_size.map_or(u64::MAX, |size| {
            let per_member = DECLARED_SLACK_PER_MEMBER.saturating_mul(to_u64(members));
            size.saturating_add(DECLARED_SLACK_FIXED).saturating_add(per_member)
        })
    }
}

/// Which half of a package a member belongs to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberKind {
    /// A metadata member: a name beginning with `.`, such as `.PKGINFO` or `.MTREE`.
    ///
    /// libalpm reserves the whole `.`-prefixed namespace (`add.c:266`). It extracts only
    /// `.INSTALL`, `.CHANGELOG` and `.MTREE`, into the local database entry rather than into
    /// the installation root. Everything else beginning with `.` is skipped.
    Metadata,
    /// A payload member, destined for the installation root.
    Payload,
}

/// Which kind of link a member is.
///
/// Keeping these apart is not pedantry. `tar` reports a target for both through
/// `link_name()`. So conflating them creates a *symlink* where the archive asked for a hard
/// link. Real packages do contain hard links: `glibc` ships three.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkKind {
    /// A symbolic link. The target is stored verbatim and may point anywhere.
    Symbolic,
    /// A hard link to another member of the same package, named relative to the root.
    Hard,
}

/// A link member's kind and target.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Link {
    /// Symbolic or hard.
    pub kind: LinkKind,
    /// What it points at.
    pub target: PathBuf,
}

/// One extended attribute the archive records for a member.
///
/// The value is raw bytes. `security.capability` is a binary structure, not text.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Xattr {
    /// The full name, namespace included: `security.capability`, `user.foo`.
    pub name: OsString,
    /// The value, verbatim.
    pub value: Vec<u8>,
}

/// One member of a package archive, without its contents.
#[derive(Clone, Debug)]
#[non_exhaustive]
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
    /// The member's size in bytes: its PAX `size` record, or the size field of its header.
    pub size: u64,
    /// The extended attributes the archive records, in archive order.
    ///
    /// Read from the member's PAX `LIBARCHIVE.xattr.*` records. This is only what the archive
    /// says. Which of them reach the disk is decided by [`fn@super::apply`].
    pub xattrs: Vec<Xattr>,
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
/// that cannot seek backwards. Contents must be consumed then, or not at all. Not reading
/// them is fine, since `tar` skips to the next member either way.
///
/// # Errors
///
/// - [`Error::Io`] if the file cannot be opened or read.
/// - [`Error::UnsupportedCompression`] if the magic bytes match no supported format.
/// - [`Error::PackageLimitExceeded`] if a bound is exceeded.
/// - [`Error::UnsupportedMemberType`] if a member is not a regular file, a directory or a
///   link.
/// - [`Error::UnsafeArchivePath`] if a member's path, or a hard link's target, is not a
///   canonical relative path.
/// - [`Error::HardLinkOutsidePackage`] if a hard link's target is not an earlier member.
/// - [`Error::UnusableMemberOwner`] if a member's uid or gid is not one the kernel can set.
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
pub(crate) enum Flow {
    /// Read the next member.
    Continue,
    /// Stop, without an error.
    Stop,
}

/// [`walk`], for a caller that can answer its question before the archive ends.
///
/// Stopping early skips the decompression of everything after the member that answered. A
/// `.PKGINFO` sits at the front of a package makepkg built. So a reader that only wants the
/// metadata pays for a few kilobytes rather than for the whole archive. Every bound
/// [`walk`] enforces still applies to what was read.
///
/// # Errors
///
/// As [`walk`].
pub(crate) fn walk_until(
    path: &Path,
    limits: &PackageLimits,
    on_member: impl FnMut(&Member, &mut dyn Read) -> Result<Flow>,
) -> Result<()> {
    walk_members(path, limits, Decoding::Direct, on_member)
}

/// [`walk`], with the archive decoded on a thread of its own while `on_member` runs.
///
/// For extraction, which writes each member while the next ones are decoded. A reader that
/// does little with the contents uses [`walk`]: see [`Decoder::ahead`] for the measurements.
///
/// # Errors
///
/// As [`walk`].
pub(crate) fn walk_decoded_ahead(
    path: &Path,
    limits: &PackageLimits,
    mut on_member: impl FnMut(&Member, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    walk_members(path, limits, Decoding::Ahead, |member, contents| {
        on_member(member, contents)?;
        Ok(Flow::Continue)
    })
}

/// Which thread decodes an archive: see [`Decoder::ahead`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Decoding {
    Direct,
    Ahead,
}

/// The walk behind [`walk_until`] and [`walk_decoded_ahead`].
fn walk_members(
    path: &Path,
    limits: &PackageLimits,
    decoding: Decoding,
    mut on_member: impl FnMut(&Member, &mut dyn Read) -> Result<Flow>,
) -> Result<()> {
    // The audited door: `O_NONBLOCK`, so a FIFO named on the command line cannot hang the read,
    // and an `fstat` that refuses anything but a regular file.
    let mut file =
        piko_db::fs_util::open_following_symlinks(path).map_err(|error| match error {
            piko_db::Error::Io { source, .. } => Error::io(path, IoAction::Open, source),
            piko_db::Error::NotARegularFile { .. } => Error::UnusableSource {
                path: path.to_path_buf(),
                reason: "not a regular file".to_owned(),
            },
            other => Error::UnusableSource { path: path.to_path_buf(), reason: other.to_string() },
        })?;

    let metadata = file.metadata().map_err(|source| Error::io(path, IoAction::Metadata, source))?;
    if metadata.len() > limits.compressed_bytes {
        return Err(Error::PackageLimitExceeded {
            path: path.to_path_buf(),
            limit: "compressed size",
            max: limits.compressed_bytes,
        });
    }

    let format = sniff_file(&mut file, path)?;
    let decoder = match decoding {
        Decoding::Direct => Decoder::new(file, format),
        Decoding::Ahead => Decoder::ahead(file, format),
    }
    .map_err(|source| Error::io(path, IoAction::Decompress, source))?;

    let budget = Bounds::new(limits.declared_bound(0));
    let bounded = BoundedReader::new(decoder, limits.inflated_bytes, Arc::clone(&budget));
    let mut archive = tar::Archive::new(bounded);

    let classify = |source: std::io::Error| classify_io_error(path, source, &budget, limits);
    let entries = archive.entries().map_err(classify)?;

    let mut seen = 0_usize;
    // The payload members a hard link can name: every one read so far that is not a directory.
    let mut linkable: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for entry in entries {
        let mut entry = entry.map_err(classify)?;

        seen = seen.saturating_add(1);
        budget.set_declared(limits.declared_bound(seen));
        if seen > limits.max_members {
            return Err(Error::PackageLimitExceeded {
                path: path.to_path_buf(),
                limit: "member count",
                max: to_u64(limits.max_members),
            });
        }

        let mut member = describe(&entry).map_err(classify)?;
        if let Some(kind) = unsupported_type(entry.header().entry_type()) {
            return Err(Error::UnsupportedMemberType {
                path: path.to_path_buf(),
                member: member.path,
                kind,
            });
        }
        // One spelling per path, for every reader of this walk. Conflict detection, `%FILES%`
        // and the hook triggers read the path as a string, and extraction resolves it through
        // `rootfs`. A path that is not canonical would be one file to the second and another
        // to the first. A hard link's target is a path inside the root too.
        crate::rootfs::components(&member.path)?;
        if let Some(Link { kind: LinkKind::Hard, target }) = &member.link {
            crate::rootfs::components(target)?;
            // A target the package does not ship is a file already on the system. tar puts a
            // link after its target, so an earlier member is the only valid one.
            if member.kind == MemberKind::Payload && !linkable.contains(target) {
                return Err(Error::HardLinkOutsidePackage {
                    path: path.to_path_buf(),
                    member: member.path,
                    target: target.clone(),
                });
            }
        }
        if member.kind == MemberKind::Payload && member.entry == EntryKind::Other {
            linkable.insert(member.path.clone());
        }
        // Refused here rather than narrowed at extraction, so the package is refused before
        // anything of it is written.
        crate::extract::apply::owner_ids(&member)?;
        member.xattrs = match read_xattrs(&mut entry, limits).map_err(classify)? {
            Ok(xattrs) => xattrs,
            Err((limit, max)) => {
                return Err(Error::PackageLimitExceeded { path: path.to_path_buf(), limit, max });
            }
        };
        // A callback reads the member through the bounded reader, so its error can be a bound
        // that tripped. The budget says which, as it does for the walk's own reads.
        let mut contents = Contents { entry: &mut entry, remaining: member.size };
        match on_member(&member, &mut contents) {
            Ok(Flow::Continue) => {}
            Ok(Flow::Stop) => break,
            Err(error) => return Err(tripped_limit(path, &budget, limits).unwrap_or(error)),
        }
    }

    Ok(())
}

/// A member's contents, which fail rather than end before the size its header declares.
///
/// `tar` reads a member through a `Take` over the stream, so an archive cut inside a member
/// ends that member early, with no error. The walk then fails on the next header, but only if
/// it reads one. A caller that stops at this member never does: `load_pkginfo` stops after
/// `.PKGINFO`, and would parse what is left of a cut one. libarchive refuses a cut member
/// when its data is read ("Truncated tar archive").
struct Contents<'a, R: Read> {
    entry: &'a mut R,
    /// What the header declares and has not been read yet.
    remaining: u64,
}

impl<R: Read> Read for Contents<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.entry.read(buffer)?;
        if read == 0 && self.remaining > 0 && !buffer.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the archive ends inside this member",
            ));
        }
        self.remaining = self.remaining.saturating_sub(to_u64(read));
        Ok(read)
    }
}

/// What a member type piko refuses is called, or `None` for the four types it extracts.
///
/// `tar` has already consumed the extension headers that describe the next member (GNU long
/// name and long link, pax local), so they never reach this test. A pax global header is
/// yielded as a member, and is refused like any other type.
fn unsupported_type(entry_type: tar::EntryType) -> Option<&'static str> {
    if entry_type.is_file()
        || entry_type.is_dir()
        || entry_type.is_symlink()
        || entry_type.is_hard_link()
    {
        return None;
    }
    Some(match entry_type {
        tar::EntryType::Char => "character device",
        tar::EntryType::Block => "block device",
        tar::EntryType::Fifo => "FIFO",
        tar::EntryType::Continuous => "contiguous file",
        tar::EntryType::GNUSparse => "GNU sparse file",
        tar::EntryType::XGlobalHeader => "pax global header",
        _ => "member of an unknown type",
    })
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
        // The size `tar` reads the contents by: a PAX `size` record replaces the header's
        // field. The header's field alone would differ from the bytes that are extracted.
        size: entry.size(),
        xattrs: Vec::new(),
    })
}

/// The PAX prefix under which bsdtar records an extended attribute: the name URL-encoded,
/// the value in base64.
const LIBARCHIVE_XATTR: &[u8] = b"LIBARCHIVE.xattr.";

/// The PAX prefix under which GNU tar and bsdtar record an extended attribute, both raw.
const SCHILY_XATTR: &[u8] = b"SCHILY.xattr.";

/// The extended attributes recorded for `entry`, bounded by `limits`.
///
/// bsdtar, which makepkg uses, writes every attribute twice: `LIBARCHIVE.xattr.` first, then
/// `SCHILY.xattr.`. Only the `LIBARCHIVE` spelling is read. The `tar` crate splits a PAX header
/// on every newline byte, not by each record's length. So a raw binary value, which a
/// `security.capability` is, comes back as malformed fragments whenever it contains a `0x0a`.
/// The encoded spelling contains no newline and always survives.
///
/// A `SCHILY` record is only compared by name with the `LIBARCHIVE` records before it. A name
/// no `LIBARCHIVE` record gave, which is how GNU tar writes an archive, is a damaged archive:
/// the attribute is not dropped in silence. A fragment the splitter broke off is skipped, as
/// the `tar` crate skips it for its own fields. An encoded record that does not decode is a
/// damaged archive.
///
/// The outer error is a damaged PAX header. The inner one names the bound that was exceeded,
/// and its value. The bounds are checked before anything is copied out of the header.
fn read_xattrs<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    limits: &PackageLimits,
) -> std::io::Result<std::result::Result<Vec<Xattr>, (&'static str, u64)>> {
    use std::os::unix::ffi::OsStrExt as _;

    let Some(extensions) = entry.pax_extensions()? else { return Ok(Ok(Vec::new())) };
    let mut xattrs: Vec<Xattr> = Vec::new();
    let mut bytes = 0_usize;
    for extension in extensions {
        let Ok(extension) = extension else { continue };
        let key = extension.key_bytes();
        if let Some(name) = key.strip_prefix(SCHILY_XATTR) {
            // A PAX key ends at its first `=`, so a raw name holding one arrives cut there.
            let twin = |known: &Xattr| {
                let known = known.name.as_bytes();
                known
                    .strip_prefix(name)
                    .is_some_and(|rest| matches!(rest.first(), None | Some(b'=')))
            };
            if !xattrs.iter().any(twin) {
                let name = std::ffi::OsStr::from_bytes(name);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "extended attribute {} is recorded only in the raw SCHILY.xattr form",
                        name.to_string_lossy()
                    ),
                ));
            }
            continue;
        }
        let Some(name) = key.strip_prefix(LIBARCHIVE_XATTR) else { continue };
        let value = extension.value_bytes();
        if xattrs.len() >= limits.max_xattrs {
            return Ok(Err(("extended attribute count", to_u64(limits.max_xattrs))));
        }
        bytes = bytes.saturating_add(name.len()).saturating_add(value.len());
        if bytes > limits.max_xattr_bytes {
            return Ok(Err(("extended attribute size", to_u64(limits.max_xattr_bytes))));
        }
        xattrs.push(Xattr {
            name: std::ffi::OsStr::from_bytes(&url_decode(name)?).to_os_string(),
            value: base64_decode(value)?,
        });
    }
    Ok(Ok(xattrs))
}

/// Decodes libarchive's URL encoding of an attribute name: `%XX` for a byte, anything else
/// as itself.
fn url_decode(name: &[u8]) -> std::io::Result<Vec<u8>> {
    let damaged = || std::io::Error::new(std::io::ErrorKind::InvalidData, "bad xattr name");
    let digit = |byte: u8| char::from(byte).to_digit(16).and_then(|d| u8::try_from(d).ok());
    let mut decoded = Vec::with_capacity(name.len());
    let mut bytes = name.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            decoded.push(byte);
            continue;
        }
        let high = bytes.next().and_then(digit).ok_or_else(damaged)?;
        let low = bytes.next().and_then(digit).ok_or_else(damaged)?;
        decoded.push(high.saturating_mul(16).saturating_add(low));
    }
    Ok(decoded)
}

/// Decodes libarchive's base64 value. libarchive writes it without padding; a padded one is
/// accepted too.
fn base64_decode(value: &[u8]) -> std::io::Result<Vec<u8>> {
    use base64::Engine as _;
    const ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    ENGINE
        .decode(value)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// A bound, as [`Error::PackageLimitExceeded`] reports it.
fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Identifies a compression format from the file's magic bytes, and rewinds it.
fn sniff_file(file: &mut std::fs::File, path: &Path) -> Result<compression::Format> {
    compression::sniff_file(file)
        .map_err(|source| Error::io(path, IoAction::Read, source))?
        .map_err(|format| Error::UnsupportedCompression { path: path.to_path_buf(), format })
}

/// Tells a genuine bound violation apart from an unrelated I/O or tar-format failure.
///
/// `tar` surfaces [`BoundedReader`]'s error as an opaque [`std::io::Error`]. The shared
/// [`Bounds`] is what distinguishes the two: it records a bound only when one was actually
/// exceeded, and which one.
fn classify_io_error(
    path: &Path,
    source: std::io::Error,
    budget: &Bounds,
    limits: &PackageLimits,
) -> Error {
    tripped_limit(path, budget, limits).unwrap_or_else(|| Error::io(path, IoAction::Read, source))
}

/// The bound the walk's reader refused a read on, if one tripped.
fn tripped_limit(path: &Path, budget: &Bounds, limits: &PackageLimits) -> Option<Error> {
    let (limit, max) = match budget.tripped()? {
        Overrun::Limit => ("inflated size", limits.inflated_bytes),
        Overrun::Declared => ("installed size the plan declares", budget.declared()),
    };
    Some(Error::PackageLimitExceeded { path: path.to_path_buf(), limit, max })
}

/// Builds package archives for tests.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test fixtures, over fixed small inputs"
)]
pub(crate) mod fixture {
    /// Appends a PAX local header holding `records`, as full `key`/`value` pairs.
    ///
    /// The header applies to the next member appended. `tar` 0.4 writes no PAX header of its
    /// own, so a test that needs one builds it here, the way bsdtar spells it.
    pub(crate) fn pax(builder: &mut tar::Builder<Vec<u8>>, records: &[(&[u8], &[u8])]) {
        let mut data = Vec::new();
        for (key, value) in records {
            // `<length> <key>=<value>\n`, where the length counts its own digits.
            let body = key.len() + value.len() + 3;
            let mut length = body + body.to_string().len();
            if length.to_string().len() != body.to_string().len() {
                length += 1;
            }
            data.extend_from_slice(format!("{length} ").as_bytes());
            data.extend_from_slice(key);
            data.push(b'=');
            data.extend_from_slice(value);
            data.push(b'\n');
        }
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::XHeader);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, "PaxHeader", data.as_slice()).unwrap();
    }

    /// Appends a member whose name, and link target if any, is written into the header byte
    /// for byte.
    ///
    /// `Builder::append_data` normalises the name it is given, so `usr/./bin/ls` would arrive
    /// as `usr/bin/ls`. A test of a spelling the reader must refuse has to bypass that.
    pub(crate) fn raw(
        builder: &mut tar::Builder<Vec<u8>>,
        name: &str,
        entry_type: tar::EntryType,
        link: Option<&str>,
        contents: &[u8],
    ) {
        raw_bytes(builder, name.as_bytes(), entry_type, link.map(str::as_bytes), contents);
    }

    /// [`raw`], for a name or a link target that is not text.
    pub(crate) fn raw_bytes(
        builder: &mut tar::Builder<Vec<u8>>,
        name: &[u8],
        entry_type: tar::EntryType,
        link: Option<&[u8]>,
        contents: &[u8],
    ) {
        let mut header = tar::Header::new_gnu();
        let gnu = header.as_gnu_mut().unwrap();
        gnu.name.get_mut(..name.len()).unwrap().copy_from_slice(name);
        if let Some(link) = link {
            gnu.linkname.get_mut(..link.len()).unwrap().copy_from_slice(link);
        }
        header.set_entry_type(entry_type);
        header.set_mode(if entry_type.is_dir() { 0o755 } else { 0o644 });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        builder.append(&header, contents).unwrap();
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
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

    /// A member cut short by the end of the file fails when it is read, so a caller that
    /// stops at that member does not take what is left of it for the whole.
    #[test]
    fn a_member_cut_by_the_end_of_the_file_fails_when_it_is_read() {
        let path = tarball(|builder| {
            file_entry(builder, ".PKGINFO", &[b'x'; 2000], 0o644);
        });
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, bytes.get(..1500).unwrap()).unwrap();

        let mut read = None;
        let outcome = walk_until(&path, &PackageLimits::default(), |_, contents| {
            let mut buffer = Vec::new();
            read = Some(contents.read_to_end(&mut buffer).map(|_| buffer.len()));
            Ok(Flow::Stop)
        });

        assert!(outcome.is_ok());
        let error = read.unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
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

    /// Each type the extraction does not write refuses the package, and the error names the
    /// member and its type.
    #[test]
    fn a_member_of_an_unsupported_type_refuses_the_package() {
        for (entry_type, kind) in [
            (tar::EntryType::Char, "character device"),
            (tar::EntryType::Block, "block device"),
            (tar::EntryType::Fifo, "FIFO"),
            (tar::EntryType::Continuous, "contiguous file"),
            (tar::EntryType::XGlobalHeader, "pax global header"),
            (tar::EntryType::new(b'Z'), "member of an unknown type"),
        ] {
            let path = tarball(|builder| {
                file_entry(builder, "usr/bin/foo", b"x", 0o755);
                let mut special = header(0o644);
                special.set_entry_type(entry_type);
                special.set_cksum();
                builder.append_data(&mut special, "dev/node", &[][..]).unwrap();
            });
            let err = walk(&path, &PackageLimits::default(), |_, _| Ok(())).unwrap_err();
            assert!(
                matches!(&err, Error::UnsupportedMemberType { member, kind: found, .. }
                    if member == Path::new("dev/node") && *found == kind),
                "{kind}: got {err:?}"
            );
        }
    }

    /// `tar` reports a target for a hard link through the same `link_name()` as a symlink.
    /// Conflating them would create a symlink where the package asked for a hard link.
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
        assert!(
            matches!(
                err,
                Error::UnsupportedCompression {
                    format: compression::Unsupported::Unrecognized,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// An xz package is refused by its bytes and named, whatever its file name says.
    #[test]
    fn refuses_an_xz_package_and_names_the_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo-1-1-any.pkg.tar.zst");
        std::fs::write(&path, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0, 0]).unwrap();

        let err = walk(&path, &PackageLimits::default(), |_, _| Ok(())).unwrap_err();
        assert!(
            matches!(
                err,
                Error::UnsupportedCompression { format: compression::Unsupported::Xz, .. }
            ),
            "got {err:?}"
        );
    }

    /// A package file named on the command line is read here first, by `file_target::load`. A
    /// FIFO in its place is refused, rather than blocking the open until a writer appears.
    #[test]
    fn refuses_a_fifo_without_waiting_for_a_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo-1-1-any.pkg.tar.zst");
        // `mkfifo(3)` is `unsafe`, which this workspace forbids, so the utility makes it.
        let made = std::process::Command::new("mkfifo").arg(&path).status();
        if !made.is_ok_and(|status| status.success()) {
            eprintln!("skipping: mkfifo is unavailable");
            return;
        }

        let err = walk(&path, &PackageLimits::default(), |_, _| Ok(())).unwrap_err();
        assert!(matches!(err, Error::UnusableSource { .. }), "got {err:?}");
    }

    /// A member path with a second spelling is refused before any caller sees it. Extraction
    /// would write `usr/bin/ls` while conflict detection and `%FILES%` compare the string, so
    /// another package's file could be taken over without a conflict.
    #[test]
    fn refuses_a_member_path_that_is_not_canonical() {
        for name in ["usr/./bin/ls", "usr//bin/ls", "usr/bin/./ls", "usr/bin/ls/."] {
            let path = tarball(|builder| {
                fixture::raw(builder, name, tar::EntryType::Regular, None, b"x");
            });
            let err = walk(&path, &PackageLimits::default(), |_, _| Ok(())).unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::UnsafeArchivePath {
                        reason: crate::rootfs::UnsafePath::CurrentDirectory,
                        ..
                    }
                ),
                "{name:?}: got {err:?}"
            );
        }
    }

    /// A PAX `size` record replaces the size field of the header, and `tar` reads the contents
    /// by it. `Member::size` must be the same number: the disk-space estimate sums it, and the
    /// test for a member cut short counts down from it.
    #[test]
    fn a_member_takes_its_size_from_its_pax_record() {
        fn sized(header_size: u64, pax: &[u8], data: &[u8]) -> PathBuf {
            tarball(|builder| {
                builder.append_pax_extensions([("size", pax)]).unwrap();
                let mut header = tar::Header::new_ustar();
                header.set_path("usr/big").unwrap();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(0o644);
                header.set_uid(0);
                header.set_gid(0);
                header.set_mtime(0);
                header.set_size(header_size);
                header.set_cksum();
                builder.append(&header, data).unwrap();
            })
        }
        let read = |path: &Path| {
            let mut seen = None;
            walk_until(path, &PackageLimits::default(), |member, contents| {
                let mut bytes = Vec::new();
                let read = contents.read_to_end(&mut bytes).map(|_| bytes);
                seen = Some((member.size, read.map_err(|error| error.kind())));
                Ok(Flow::Stop)
            })
            .unwrap();
            seen.unwrap()
        };

        // A header that declares less, then more, than the record.
        for header_size in [0, 100] {
            let (size, contents) = read(&sized(header_size, b"5", b"hello"));
            assert_eq!(size, 5, "header size {header_size}");
            assert_eq!(contents.unwrap(), b"hello", "header size {header_size}");
        }

        // The file ends 3 bytes into a member of 5000: the two blocks of the PAX member, the
        // header block, then the 3 bytes.
        let path = sized(0, b"5000", b"hel");
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, bytes.get(..1539).unwrap()).unwrap();
        let (size, contents) = read(&path);
        assert_eq!(size, 5000);
        assert_eq!(contents.unwrap_err(), std::io::ErrorKind::UnexpectedEof);
    }

    /// An owner the kernel cannot set refuses the package. Narrowed, a uid past 32 bits would
    /// have become root, and `u32::MAX` is `chown`'s "leave unchanged".
    #[test]
    fn refuses_an_owner_the_kernel_cannot_set() {
        for (uid, gid) in [(1_u64 << 32, 0), (0, 1 << 40), (u64::from(u32::MAX), 0)] {
            let path = tarball(|builder| {
                let mut header = header(0o644);
                header.set_uid(uid);
                header.set_gid(gid);
                header.set_size(1);
                header.set_cksum();
                builder.append_data(&mut header, "usr/bin/foo", &b"x"[..]).unwrap();
            });
            let err = walk(&path, &PackageLimits::default(), |_, _| Ok(())).unwrap_err();
            assert!(matches!(err, Error::UnusableMemberOwner { .. }), "{uid}:{gid}: got {err:?}");
        }
    }

    /// A hard link's target names a file inside the root, so it gets the same rule.
    #[test]
    fn refuses_a_hard_link_target_that_is_not_canonical() {
        let path = tarball(|builder| {
            fixture::raw(builder, "usr/bin/a", tar::EntryType::Regular, None, b"x");
            fixture::raw(builder, "usr/bin/b", tar::EntryType::Link, Some("usr//bin/a"), b"");
        });
        let err = walk(&path, &PackageLimits::default(), |_, _| Ok(())).unwrap_err();
        assert!(matches!(err, Error::UnsafeArchivePath { .. }), "got {err:?}");
    }

    /// The directory spelling tar uses, one trailing separator, stays accepted.
    #[test]
    fn accepts_a_directory_spelled_with_its_trailing_separator() {
        let path = tarball(|builder| {
            fixture::raw(builder, "usr/bin/", tar::EntryType::Directory, None, b"");
        });
        let members = collect(&path);
        assert_eq!(members.first().map(|(member, _)| member.path.clone()), Some("usr/bin/".into()));
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

    /// A callback that returns the bounded reader's refusal as a read error still reports the
    /// bound. Extraction and the metadata reads both return it that way.
    #[test]
    fn a_bound_tripped_inside_a_callback_is_reported_as_that_bound() {
        let path = tarball(|builder| {
            file_entry(builder, "usr/share/big", &vec![b'x'; 64 * 1024], 0o644);
        });
        let limits = PackageLimits { inflated_bytes: 1024, ..PackageLimits::default() };

        let err = walk(&path, &limits, |_, reader| {
            let mut sink = Vec::new();
            reader
                .read_to_end(&mut sink)
                .map_err(|source| Error::io("big", IoAction::Read, source))?;
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(err, Error::PackageLimitExceeded { limit: "inflated size", .. }),
            "got {err:?}"
        );
    }

    /// A package that inflates past its declared size is refused at that size plus the slack,
    /// and says which bound it hit.
    #[test]
    fn refuses_a_package_that_inflates_past_its_declared_size() {
        let path = tarball(|builder| {
            file_entry(builder, "usr/share/big", &vec![b'x'; 2 * 1024 * 1024], 0o644);
        });
        let limits = PackageLimits::default().with_declared_size(1024);

        let err = walk(&path, &limits, |_, reader| {
            let mut sink = Vec::new();
            let _ = reader.read_to_end(&mut sink);
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::PackageLimitExceeded { limit: "installed size the plan declares", .. }
            ),
            "got {err:?}"
        );
    }

    /// The per-member slack is what lets a package of many empty members through: it declares
    /// nothing, and its headers alone exceed the fixed slack.
    #[test]
    fn a_package_of_many_empty_members_fits_its_declared_size() {
        let path = tarball(|builder| {
            for index in 0..3000 {
                file_entry(builder, &format!("usr/share/icons/i{index}"), b"", 0o644);
            }
        });
        let limits = PackageLimits::default().with_declared_size(0);

        let mut seen = 0_usize;
        walk(&path, &limits, |_, _| {
            seen += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, 3000);
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

    /// bsdtar writes every attribute twice, the encoded spelling first. The binary value holds a
    /// newline byte, which breaks the raw record apart; the encoded one still yields it, once.
    #[test]
    fn reads_extended_attributes_from_the_encoded_spelling_once() {
        let capability =
            b"\x01\x00\x00\x02\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let path = tarball(|builder| {
            fixture::pax(
                builder,
                &[
                    (b"LIBARCHIVE.xattr.security.capability", b"AQAAAgoAAAAAAAAAAAAAAAAAAAA"),
                    (b"SCHILY.xattr.security.capability", capability),
                    (b"LIBARCHIVE.xattr.user.a%3Db", b"cGlrbw=="),
                    (b"SCHILY.xattr.user.a=b", b"piko"),
                    (b"mtime", b"1"),
                ],
            );
            file_entry(builder, "usr/bin/newuidmap", b"x", 0o755);
            file_entry(builder, "usr/bin/plain", b"x", 0o755);
        });

        let members = collect(&path);
        assert_eq!(
            members.first().unwrap().0.xattrs,
            [
                Xattr { name: "security.capability".into(), value: capability.to_vec() },
                Xattr { name: "user.a=b".into(), value: b"piko".to_vec() },
            ]
        );
        assert!(members.get(1).unwrap().0.xattrs.is_empty(), "a PAX header leaked forward");
    }

    /// The encoded spelling contains no newline, so a value that does not decode is damage,
    /// not a splitting artefact.
    #[test]
    fn refuses_an_encoded_attribute_that_does_not_decode() {
        let path = tarball(|builder| {
            fixture::pax(builder, &[(b"LIBARCHIVE.xattr.user.a", b"not base64!")]);
            file_entry(builder, "usr/share/f", b"x", 0o644);
        });
        let err = walk(&path, &PackageLimits::default(), |_, _| Ok(())).unwrap_err();
        assert!(matches!(err, Error::Io { .. }), "got {err:?}");
    }

    /// A raw record with no encoded twin, as GNU tar writes one, refuses the package rather than
    /// dropping the attribute.
    #[test]
    fn refuses_an_attribute_recorded_only_in_the_raw_spelling() {
        let path = tarball(|builder| {
            fixture::pax(
                builder,
                &[(b"LIBARCHIVE.xattr.user.a", b"MQ"), (b"SCHILY.xattr.user.gnu", b"raw")],
            );
            file_entry(builder, "usr/share/f", b"x", 0o644);
        });
        let err = walk(&path, &PackageLimits::default(), |_, _| Ok(())).unwrap_err();
        assert!(matches!(err, Error::Io { .. }), "got {err:?}");
        assert!(format!("{err:?}").contains("user.gnu is recorded only in the raw"), "{err:?}");
    }

    #[test]
    fn refuses_a_member_with_too_many_extended_attributes() {
        let path = tarball(|builder| {
            fixture::pax(
                builder,
                &[(b"LIBARCHIVE.xattr.user.a", b"MQ"), (b"LIBARCHIVE.xattr.user.b", b"Mg")],
            );
            file_entry(builder, "usr/share/f", b"x", 0o644);
        });
        let limits = PackageLimits { max_xattrs: 1, ..PackageLimits::default() };

        let err = walk(&path, &limits, |_, _| Ok(())).unwrap_err();
        assert!(
            matches!(err, Error::PackageLimitExceeded { limit: "extended attribute count", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn refuses_a_member_whose_extended_attributes_are_too_large() {
        let path = tarball(|builder| {
            fixture::pax(builder, &[(b"LIBARCHIVE.xattr.user.big", &[b'A'; 100])]);
            file_entry(builder, "usr/share/f", b"x", 0o644);
        });
        let limits = PackageLimits { max_xattr_bytes: 64, ..PackageLimits::default() };

        let err = walk(&path, &limits, |_, _| Ok(())).unwrap_err();
        assert!(
            matches!(err, Error::PackageLimitExceeded { limit: "extended attribute size", .. }),
            "got {err:?}"
        );
    }
}
