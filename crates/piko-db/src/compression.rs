//! The compression formats piko decodes: gzip, zstd, and none.
//!
//! This is the one decoder for every archive piko reads, repository databases and package
//! files alike. Both callers bound what comes out of it themselves; this module decides only
//! which bytes are decoded, and by what.
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
pub struct Decoder(Inner);

/// The decoder for each [`Format`].
///
/// Each reads one stream: one gzip member, as `GzDecoder` does, and every frame of a zstd
/// file, as `zstd`'s reader does.
enum Inner {
    Gzip(flate2::bufread::GzDecoder<BufReader<File>>),
    Zstd(zstd::stream::read::Decoder<'static, BufReader<File>>),
    Uncompressed(BufReader<File>),
}

impl Decoder {
    /// Decodes `file`, which [`sniff_file`] identified as `format`.
    ///
    /// # Errors
    ///
    /// Only zstd's decoder can fail to be created, when its context cannot be allocated or
    /// the window bound cannot be set.
    pub fn new(file: File, format: Format) -> std::io::Result<Self> {
        Ok(Self(match format {
            Format::Gzip => Inner::Gzip(flate2::bufread::GzDecoder::new(BufReader::new(file))),
            Format::Zstd => {
                let mut decoder = zstd::stream::read::Decoder::new(file)?;
                decoder.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
                Inner::Zstd(decoder)
            }
            Format::Uncompressed => Inner::Uncompressed(BufReader::new(file)),
        }))
    }
}

impl Read for Decoder {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.0 {
            Inner::Gzip(inner) => inner.read(buf),
            Inner::Zstd(inner) => inner.read(buf),
            Inner::Uncompressed(inner) => inner.read(buf),
        }
    }
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let format = match self.0 {
            Inner::Gzip(_) => Format::Gzip,
            Inner::Zstd(_) => Format::Zstd,
            Inner::Uncompressed(_) => Format::Uncompressed,
        };
        f.debug_tuple("Decoder").field(&format).finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code; a panic is the failure report")]
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
