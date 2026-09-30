//! The compression formats piko decodes: gzip, zstd, and none.
//!
//! This is the one decoder for every archive piko reads, repository databases and package
//! files alike, and [`BoundedReader`], the bound both put on what comes out of it.
//!
//! # Two formats, deliberately
//!
//! The [alpm-repo-db] spec allows nine compression suffixes, and says handling them is
//! "specific to the package repository management tool". Arch publishes its databases in
//! gzip and its packages in zstd. piko decodes those two and refuses the rest, xz and bzip2
//! included. Each decoder is C code reading bytes a mirror chose, before any signature check
//! when the policy asks for none. So each format kept is attack surface kept, and each one
//! dropped removes a library from the binary. liblzma also allocates the dictionary its
//! stream header declares, up to 4 GiB, before it decodes a byte.
//!
//! Neither kept format lets a header decide an allocation. gzip decodes in a fixed window.
//! zstd's window is capped at [`ZSTD_WINDOW_LOG_MAX`], set here explicitly rather than left
//! to the library's default.
//!
//! # Content decides, the name refuses early
//!
//! [`sniff`] reads magic bytes. It is what decides how an archive is decoded, because a
//! repository database is named `core.db`, which says nothing about its compression.
//! [`from_extension`] reads a package file name instead, for one purpose only: to refuse a
//! package before it is downloaded, when its `%FILENAME%` already declares a format piko
//! would refuse after.
//!
//! [alpm-repo-db]: https://alpm.archlinux.page/specifications/alpm-repo-db.7.html

use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read, Seek as _};
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU64, Ordering},
};

use alpm_types::CompressionAlgorithmFileExtension;

/// How many leading bytes [`sniff`] needs to see every format it knows.
///
/// The widest test is the `ustar` tag at offset 257 that marks an uncompressed tar.
pub const HEADER_LEN: usize = 262;

/// The largest zstd window the decoder accepts, as a base-2 logarithm: 128 MiB.
///
/// This is `ZSTD_WINDOWLOG_LIMIT_DEFAULT`, the value zstd applies when a caller sets none.
/// Every preset up to `--ultra -22`, and `--long` at its default of 27, fit. So the bound
/// refuses no archive `makepkg` or `repo-add` writes unless told `--long=28` or more. A frame
/// that declares a larger window is refused before the window is allocated.
pub const ZSTD_WINDOW_LOG_MAX: u32 = 27;

/// A compression format piko decodes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    /// gzip, as Arch's repository databases are published.
    Gzip,
    /// zstd, as Arch's packages are published.
    Zstd,
    /// A tar archive with no compression.
    Uncompressed,
}

/// A compression format piko does not decode.
///
/// The named variants are the formats the [alpm-repo-db] spec lists that piko refuses. They
/// exist so a refusal names what it refused.
///
/// [alpm-repo-db]: https://alpm.archlinux.page/specifications/alpm-repo-db.7.html
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unsupported {
    /// xz (`.xz`).
    Xz,
    /// bzip2 (`.bz2`).
    Bzip2,
    /// Adaptive Lempel-Ziv coding, the `compress` command (`.Z`).
    Compress,
    /// lrzip (`.lrz`).
    Lrzip,
    /// lz4 (`.lz4`).
    Lz4,
    /// lzip (`.lz`).
    Lzip,
    /// lzop (`.lzo`).
    Lzop,
    /// Bytes that match no format piko knows, compressed or not.
    Unrecognized,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Xz => "xz compression",
            Self::Bzip2 => "bzip2 compression",
            Self::Compress => "compress (.Z) compression",
            Self::Lrzip => "lrzip compression",
            Self::Lz4 => "lz4 compression",
            Self::Lzip => "lzip compression",
            Self::Lzop => "lzop compression",
            Self::Unrecognized => "an unrecognized format",
        })
    }
}

/// Identifies a compression format from an archive's leading bytes.
///
/// `header` is at most [`HEADER_LEN`] bytes; a shorter one is a short file, and matches only
/// the formats whose magic fits in it.
///
/// # Errors
///
/// [`Unsupported`], naming the format when its magic is one piko knows and refuses.
pub fn sniff(header: &[u8]) -> Result<Format, Unsupported> {
    const REFUSED: [(&[u8], Unsupported); 7] = [
        (&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], Unsupported::Xz),
        (&[0x42, 0x5a, 0x68], Unsupported::Bzip2),
        (&[0x1f, 0x9d], Unsupported::Compress),
        (b"LRZI", Unsupported::Lrzip),
        (&[0x04, 0x22, 0x4d, 0x18], Unsupported::Lz4),
        (b"LZIP", Unsupported::Lzip),
        (&[0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a], Unsupported::Lzop),
    ];

    if header.starts_with(&[0x1f, 0x8b]) {
        Ok(Format::Gzip)
    } else if header.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Ok(Format::Zstd)
    } else if header.get(257..262) == Some(b"ustar".as_slice()) {
        Ok(Format::Uncompressed)
    } else {
        Err(REFUSED
            .iter()
            .find(|(magic, _)| header.starts_with(magic))
            .map_or(Unsupported::Unrecognized, |&(_, refused)| refused))
    }
}

/// Reads the first [`HEADER_LEN`] bytes of `file`, identifies its format, and rewinds it.
///
/// # Errors
///
/// The outer [`std::io::Error`] if the read or the rewind fails. The inner [`Unsupported`] as
/// [`sniff`].
pub fn sniff_file(file: &mut File) -> std::io::Result<Result<Format, Unsupported>> {
    let mut header = [0_u8; HEADER_LEN];
    let mut read = 0;
    // A single `read` may return fewer bytes than the file holds.
    while let Some(rest) = header.get_mut(read..).filter(|rest| !rest.is_empty()) {
        match file.read(rest)? {
            0 => break,
            count => read = read.saturating_add(count),
        }
    }
    file.rewind()?;
    Ok(sniff(header.get(..read).unwrap_or_default()))
}

/// The format a package file name's compression suffix declares.
///
/// `None` is a name with no suffix, a `.pkg.tar`. This reads a name, not the bytes, so it is
/// only fit to refuse early: [`sniff`] still decides how the file is decoded.
///
/// # Errors
///
/// [`Unsupported`] naming the refused format.
pub const fn from_extension(
    extension: Option<CompressionAlgorithmFileExtension>,
) -> Result<Format, Unsupported> {
    match extension {
        None => Ok(Format::Uncompressed),
        Some(CompressionAlgorithmFileExtension::Gzip) => Ok(Format::Gzip),
        Some(CompressionAlgorithmFileExtension::Zstd) => Ok(Format::Zstd),
        Some(CompressionAlgorithmFileExtension::Xz) => Err(Unsupported::Xz),
        Some(CompressionAlgorithmFileExtension::Bzip2) => Err(Unsupported::Bzip2),
        Some(CompressionAlgorithmFileExtension::Compress) => Err(Unsupported::Compress),
        Some(CompressionAlgorithmFileExtension::Lrzip) => Err(Unsupported::Lrzip),
        Some(CompressionAlgorithmFileExtension::Lz4) => Err(Unsupported::Lz4),
        Some(CompressionAlgorithmFileExtension::Lzip) => Err(Unsupported::Lzip),
        Some(CompressionAlgorithmFileExtension::Lzop) => Err(Unsupported::Lzop),
    }
}

/// The decompressed stream of one archive file.
///
/// It bounds nothing but the zstd window. The caller wraps it in its own counting reader.
///
/// # Decoded ahead, on a thread of its own
///
/// [`Decoder::ahead`] decodes a compressed stream on a second thread, while the caller works on
/// what came before: extraction writes files, and a repository walk parses entries. The two
/// overlap. The commit of an upgrade of 100 real packages (734 MB compressed) took 10.0 s
/// instead of 11.8 s this way, and the open of `extra.db` took 185 ms instead of 248 ms.
///
/// [`Decoder::new`] reads on the caller's thread. It is for a reader that does little with the
/// bytes, or stops early: a thread gains it nothing, and costs a thread and a copy. The archive
/// reads at `verify` are that case. They run four at a time already, and with a thread each they
/// took about 0.4 s longer for 100 packages. A walk that stops at `.PKGINFO` would also decode
/// several chunks that nobody reads.
///
/// The thread stays at most [`AHEAD_CHUNKS`] chunks of [`CHUNK_BYTES`] ahead of the reader,
/// plus the chunk it fills. So the memory it holds is fixed. It can also decode that much past
/// the bound of the caller's counting reader before the caller refuses the stream. That excess
/// is a constant, whatever the archive declares. The thread stops at its next chunk when the
/// reader is dropped, and at the end of the stream or at its first error. It sends the bytes
/// decoded before an error first, so the reader gets what a direct read gets, in the same order.
///
/// An uncompressed tar is always read directly, since there is nothing to decode. A compressed
/// one is read directly too when no thread can be started.
pub struct Decoder(Source);

/// How many decoded chunks the thread keeps ready ahead of the reader.
pub const AHEAD_CHUNKS: usize = 4;

/// The size of one decoded chunk.
pub const CHUNK_BYTES: usize = 1 << 20;

/// Where [`Decoder`]'s bytes come from.
enum Source {
    /// Read on the caller's thread.
    Direct(Inner),
    /// Decoded ahead on another thread.
    Ahead(Ahead),
}

/// The reading end of a decoding thread.
struct Ahead {
    format: Format,
    chunks: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
    current: Vec<u8>,
    position: usize,
    state: AheadState,
}

/// Whether an [`Ahead`] stream can still yield bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
enum AheadState {
    Open,
    Ended,
    Failed,
}

/// The decoder for each [`Format`].
///
/// Each reads one stream: one gzip member, as `GzDecoder` does, and every frame of a zstd
/// file, as `zstd`'s reader does.
enum Inner {
    Gzip(flate2::bufread::GzDecoder<BufReader<File>>),
    Zstd(zstd::stream::read::Decoder<'static, BufReader<File>>),
    Uncompressed(BufReader<File>),
}

impl Inner {
    fn new(file: File, format: Format) -> std::io::Result<Self> {
        Ok(match format {
            Format::Gzip => Self::Gzip(flate2::bufread::GzDecoder::new(BufReader::new(file))),
            Format::Zstd => {
                let mut decoder = zstd::stream::read::Decoder::new(file)?;
                decoder.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
                Self::Zstd(decoder)
            }
            Format::Uncompressed => Self::Uncompressed(BufReader::new(file)),
        })
    }

    const fn format(&self) -> Format {
        match self {
            Self::Gzip(_) => Format::Gzip,
            Self::Zstd(_) => Format::Zstd,
            Self::Uncompressed(_) => Format::Uncompressed,
        }
    }
}

impl Read for Inner {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Gzip(inner) => inner.read(buf),
            Self::Zstd(inner) => inner.read(buf),
            Self::Uncompressed(inner) => inner.read(buf),
        }
    }
}

impl Decoder {
    /// Decodes `file`, which [`sniff_file`] identified as `format`, on the caller's thread.
    ///
    /// # Errors
    ///
    /// Only zstd's decoder can fail to be created, when its context cannot be allocated or
    /// the window bound cannot be set.
    pub fn new(file: File, format: Format) -> std::io::Result<Self> {
        Inner::new(file, format).map(|inner| Self(Source::Direct(inner)))
    }

    /// Decodes `file`, which [`sniff_file`] identified as `format`, on a thread of its own.
    ///
    /// See the type's documentation for when this pays, and what it bounds.
    ///
    /// # Errors
    ///
    /// As [`Decoder::new`].
    pub fn ahead(file: File, format: Format) -> std::io::Result<Self> {
        let inner = Inner::new(file, format)?;
        Ok(Self(match inner {
            Inner::Uncompressed(_) => Source::Direct(inner),
            Inner::Gzip(_) | Inner::Zstd(_) => Ahead::start(inner),
        }))
    }
}

impl Ahead {
    /// Starts a thread that decodes `inner`, or reads it directly when no thread starts.
    fn start(inner: Inner) -> Source {
        let format = inner.format();
        let (sender, chunks) = std::sync::mpsc::sync_channel(AHEAD_CHUNKS);
        // The decoder goes to the thread only once the thread runs. So a spawn that fails
        // leaves it here, to be read directly.
        let (handover, received) = std::sync::mpsc::channel::<Inner>();
        let started = std::thread::Builder::new().name("piko-decode".to_owned()).spawn(move || {
            if let Ok(inner) = received.recv() {
                Self::produce(inner, &sender);
            }
        });
        if started.is_err() {
            return Source::Direct(inner);
        }
        match handover.send(inner) {
            Ok(()) => Source::Ahead(Self {
                format,
                chunks,
                current: Vec::new(),
                position: 0,
                state: AheadState::Open,
            }),
            Err(returned) => Source::Direct(returned.0),
        }
    }

    /// Decodes `inner` into chunks until the stream ends, fails, or the reader is gone.
    ///
    /// An empty chunk marks the end of the stream.
    fn produce(mut inner: Inner, sender: &std::sync::mpsc::SyncSender<std::io::Result<Vec<u8>>>) {
        loop {
            let mut chunk = vec![0_u8; CHUNK_BYTES];
            let mut filled = 0_usize;
            let failure = loop {
                let Some(rest) = chunk.get_mut(filled..).filter(|rest| !rest.is_empty()) else {
                    break None;
                };
                match inner.read(rest) {
                    Ok(0) => break None,
                    Ok(count) => filled = filled.saturating_add(count),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => break Some(error),
                }
            };
            chunk.truncate(filled);
            let ended = chunk.is_empty();
            if (!ended || failure.is_none()) && sender.send(Ok(chunk)).is_err() {
                return;
            }
            if let Some(error) = failure {
                let _ = sender.send(Err(error));
                return;
            }
            if ended {
                return;
            }
        }
    }
}

impl Read for Ahead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let available = self.current.get(self.position..).unwrap_or_default();
            if !available.is_empty() {
                let count = available.len().min(buf.len());
                if let (Some(to), Some(from)) = (buf.get_mut(..count), available.get(..count)) {
                    to.copy_from_slice(from);
                }
                self.position = self.position.saturating_add(count);
                return Ok(count);
            }
            match self.state {
                AheadState::Open => {}
                AheadState::Ended => return Ok(0),
                AheadState::Failed => {
                    return Err(std::io::Error::other("the archive stream already failed"));
                }
            }
            match self.chunks.recv() {
                Ok(Ok(chunk)) if chunk.is_empty() => self.state = AheadState::Ended,
                Ok(Ok(chunk)) => {
                    self.current = chunk;
                    self.position = 0;
                }
                Ok(Err(error)) => {
                    self.state = AheadState::Failed;
                    return Err(error);
                }
                // The thread stopped without an end or an error: it panicked.
                Err(_) => {
                    self.state = AheadState::Failed;
                    return Err(std::io::Error::other("the decoding thread stopped"));
                }
            }
        }
    }
}

impl Read for Decoder {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.0 {
            Source::Direct(inner) => inner.read(buf),
            Source::Ahead(ahead) => ahead.read(buf),
        }
    }
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (format, ahead) = match &self.0 {
            Source::Direct(inner) => (inner.format(), false),
            Source::Ahead(ahead) => (ahead.format, true),
        };
        f.debug_struct("Decoder").field("format", &format).field("ahead", &ahead).finish()
    }
}

/// Which bound a [`BoundedReader`] refused a read on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Overrun {
    /// More bytes than the reader's fixed limit.
    Limit,
    /// More bytes than the declared bound in force.
    Declared,
}

/// The state a [`BoundedReader`] shares with the walk that drives it.
///
/// `tar` returns a reader's error as an opaque [`std::io::Error`], so the walk reads here which
/// bound tripped, to report a limit rather than a read failure.
#[derive(Debug)]
pub struct Bounds {
    /// The declared bound in force. The walk can raise it as it reads.
    declared: AtomicU64,
    /// [`Bounds::CLEAR`], or the [`Overrun`] a read was refused on.
    tripped: AtomicU8,
}

impl Bounds {
    const CLEAR: u8 = 0;
    const LIMIT: u8 = 1;
    const DECLARED: u8 = 2;

    /// Bounds with `declared` as the declared bound in force. `u64::MAX` declares nothing.
    #[must_use]
    pub fn new(declared: u64) -> Arc<Self> {
        Arc::new(Self { declared: AtomicU64::new(declared), tripped: AtomicU8::new(Self::CLEAR) })
    }

    /// Sets the declared bound in force.
    pub fn set_declared(&self, declared: u64) {
        self.declared.store(declared, Ordering::Relaxed);
    }

    /// The declared bound in force.
    #[must_use]
    pub fn declared(&self) -> u64 {
        self.declared.load(Ordering::Relaxed)
    }

    /// The bound a read was refused on, if one was.
    #[must_use]
    pub fn tripped(&self) -> Option<Overrun> {
        match self.tripped.load(Ordering::Relaxed) {
            Self::LIMIT => Some(Overrun::Limit),
            Self::DECLARED => Some(Overrun::Declared),
            _ => None,
        }
    }
}

/// A reader that refuses to yield more than `limit` bytes in total, or more than the declared
/// bound its [`Bounds`] holds.
///
/// A compressed archive can inflate to arbitrarily more than its own size. Without this, a few
/// kilobytes on disk can exhaust memory or fill a filesystem. `alpm-compress`'s `TarballReader`
/// cannot be bounded this way: its field is concretely `Archive<CompressionDecoder>`, not generic
/// over `Read`. Driving `tar::Archive` over this reader is why piko reads archives itself.
#[derive(Debug)]
pub struct BoundedReader<R> {
    inner: R,
    limit: u64,
    read_so_far: u64,
    bounds: Arc<Bounds>,
}

impl<R> BoundedReader<R> {
    /// Bounds `inner` to `limit` bytes and to the declared bound in `bounds`.
    pub const fn new(inner: R, limit: u64, bounds: Arc<Bounds>) -> Self {
        Self { inner, limit, read_so_far: 0, bounds }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.read_so_far = self.read_so_far.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        let tripped = if self.read_so_far > self.limit {
            Bounds::LIMIT
        } else if self.read_so_far > self.bounds.declared() {
            Bounds::DECLARED
        } else {
            return Ok(read);
        };
        self.bounds.tripped.store(tripped, Ordering::Relaxed);
        Err(std::io::Error::other("decompressed size limit exceeded"))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code; a panic is the failure report")]
mod tests {
    use super::*;

    #[test]
    fn sniffs_the_two_decoded_formats_and_a_bare_tar() {
        assert_eq!(sniff(&[0x1f, 0x8b, 0x08]), Ok(Format::Gzip));
        assert_eq!(sniff(&[0x28, 0xb5, 0x2f, 0xfd]), Ok(Format::Zstd));
        let mut tar = [0_u8; HEADER_LEN];
        tar.get_mut(257..262).unwrap().copy_from_slice(b"ustar");
        assert_eq!(sniff(&tar), Ok(Format::Uncompressed));
    }

    #[test]
    fn a_refused_format_is_named() {
        assert_eq!(sniff(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]), Err(Unsupported::Xz));
        assert_eq!(sniff(b"BZh9"), Err(Unsupported::Bzip2));
        assert_eq!(sniff(&[0x1f, 0x9d, 0x90]), Err(Unsupported::Compress));
        assert_eq!(sniff(&[0x04, 0x22, 0x4d, 0x18]), Err(Unsupported::Lz4));
        assert_eq!(sniff(b"LZIP\x01"), Err(Unsupported::Lzip));
        assert_eq!(sniff(b"LRZI\x00"), Err(Unsupported::Lrzip));
        assert_eq!(
            sniff(&[0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a]),
            Err(Unsupported::Lzop)
        );
        assert_eq!(sniff(b"not an archive"), Err(Unsupported::Unrecognized));
        assert_eq!(sniff(&[]), Err(Unsupported::Unrecognized));
    }

    #[test]
    fn a_file_name_suffix_maps_to_the_same_verdicts() {
        use CompressionAlgorithmFileExtension as Ext;
        assert_eq!(from_extension(None), Ok(Format::Uncompressed));
        assert_eq!(from_extension(Some(Ext::Gzip)), Ok(Format::Gzip));
        assert_eq!(from_extension(Some(Ext::Zstd)), Ok(Format::Zstd));
        assert_eq!(from_extension(Some(Ext::Xz)), Err(Unsupported::Xz));
        assert_eq!(from_extension(Some(Ext::Bzip2)), Err(Unsupported::Bzip2));
    }

    /// Bytes that do not repeat within a chunk, so both formats have work to do.
    fn payload(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes().first().copied().unwrap_or_default()
            })
            .collect()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn zstd(bytes: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(bytes, 1).unwrap()
    }

    /// A decoder over `compressed`, written to a file in `dir`.
    fn decoder(dir: &tempfile::TempDir, compressed: &[u8]) -> Decoder {
        let path = dir.path().join("archive");
        std::fs::write(&path, compressed).unwrap();
        let mut file = File::open(&path).unwrap();
        let format = sniff_file(&mut file).unwrap().unwrap();
        Decoder::ahead(file, format).unwrap()
    }

    /// Reads `reader` in small, uneven pieces until the end or the first error.
    fn drain(reader: &mut impl Read) -> (Vec<u8>, Option<std::io::Error>) {
        let mut out = Vec::new();
        let mut buf = [0_u8; 7919];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => return (out, None),
                Ok(count) => out.extend_from_slice(buf.get(..count).unwrap()),
                Err(error) => return (out, Some(error)),
            }
        }
    }

    #[test]
    fn a_stream_decoded_ahead_is_the_stream() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = payload(CHUNK_BYTES.saturating_mul(AHEAD_CHUNKS.saturating_add(2)) + 12_345);
        for compressed in [gzip(&bytes), zstd(&bytes)] {
            let mut decoder = decoder(&dir, &compressed);
            assert!(format!("{decoder:?}").contains("ahead: true"), "{decoder:?}");
            let (out, error) = drain(&mut decoder);
            assert!(error.is_none(), "{error:?}");
            assert!(out == bytes, "the decoded bytes differ");
            // The end stays the end.
            assert_eq!(decoder.read(&mut [0_u8; 16]).unwrap(), 0);
        }
    }

    /// A stream cut short yields the bytes a direct read yields, then an error.
    #[test]
    fn a_truncated_stream_fails_after_the_same_bytes_as_a_direct_read() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = payload(CHUNK_BYTES.saturating_mul(3));
        let compressed = gzip(&bytes);
        let cut = compressed.get(..compressed.len() / 2).unwrap();

        let (ahead, ahead_error) = drain(&mut decoder(&dir, cut));
        let mut direct = flate2::bufread::GzDecoder::new(cut);
        let (expected, direct_error) = drain(&mut direct);

        assert!(direct_error.is_some() && ahead_error.is_some());
        assert!(!ahead.is_empty());
        assert!(ahead == expected, "{} bytes, not {}", ahead.len(), expected.len());
        assert!(decoder(&dir, cut).read(&mut []).is_ok());
    }

    /// A reader that stops early does not wait for the rest of the stream.
    #[test]
    fn a_reader_dropped_half_way_returns_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = payload(CHUNK_BYTES.saturating_mul(AHEAD_CHUNKS.saturating_add(4)));
        let mut decoder = decoder(&dir, &zstd(&bytes));
        let mut first = [0_u8; 4096];
        decoder.read_exact(&mut first).unwrap();
        assert!(first == bytes.get(..4096).unwrap());
        drop(decoder);
    }

    #[test]
    fn a_zstd_frame_past_the_window_bound_is_refused() {
        // One past the bound; `zstd --long=28` writes such a frame.
        let payload = vec![0_u8; 1 << 16];
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        encoder.window_log(ZSTD_WINDOW_LOG_MAX.saturating_add(1)).unwrap();
        std::io::Write::write_all(&mut encoder, &payload).unwrap();
        let compressed = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wide.zst");
        std::fs::write(&path, &compressed).unwrap();
        let mut file = File::open(&path).unwrap();
        let format = sniff_file(&mut file).unwrap().unwrap();
        assert_eq!(format, Format::Zstd);
        let mut decoder = Decoder::new(file, format).unwrap();
        let err = std::io::copy(&mut decoder, &mut std::io::sink()).unwrap_err();
        assert!(err.to_string().contains("too much memory"), "got {err}");
    }
}
