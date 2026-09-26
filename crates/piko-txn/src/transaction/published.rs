//! What a repository database publishes about a package file: its checksum and its signature.

use std::path::Path;

use alpm_types::{Base64OpenPGPSignature, Sha256Checksum};
use base64::Engine as _;
use piko_db::repo::RepoDescView;
use sha2::Digest as _;

use crate::error::{Error, IoAction, Result};

/// What a repository database says a package file is, byte for byte.
///
/// `%SHA256SUM%` and `%PGPSIG%`, from the candidate's `desc`. libalpm keeps both on the sync
/// package and gives that package to `_alpm_pkg_validate_internal` (`be_package.c:279`). A
/// package file named on the command line has no repository, so it has no `Published`: `pacman
/// -U` gives no sync package either.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Published {
    sha256: Sha256Checksum,
    signature: Option<Base64OpenPGPSignature>,
}

impl Published {
    /// What `desc` publishes.
    #[must_use]
    pub fn of(desc: &RepoDescView<'_>) -> Self {
        Self::new(desc.sha256_checksum().clone(), desc.pgp_signature().cloned())
    }

    /// A checksum and, if the database has one, a signature.
    #[must_use]
    pub const fn new(sha256: Sha256Checksum, signature: Option<Base64OpenPGPSignature>) -> Self {
        Self { sha256, signature }
    }

    /// Whether the database publishes a signature.
    #[must_use]
    pub const fn has_signature(&self) -> bool {
        self.signature.is_some()
    }

    /// The published signature, decoded, or `None` when the database publishes none.
    ///
    /// # Errors
    ///
    /// [`Error::SignatureRejected`] if the signature is not base64. `alpm-types` decodes it once
    /// when it reads the `desc`, so this does not occur. libalpm refuses such a package as badly
    /// signed (`signing.c:596`), and so does this.
    pub(crate) fn decoded_signature(&self, package: &Path) -> Result<Option<Vec<u8>>> {
        let Some(signature) = &self.signature else { return Ok(None) };
        base64::engine::general_purpose::STANDARD.decode(signature.as_str()).map(Some).map_err(
            |error| Error::SignatureRejected {
                package: package.to_path_buf(),
                reason: format!("the repository database's signature is not base64: {error}"),
                unsigned: false,
            },
        )
    }

    /// Fails unless the file at `package` has the published SHA-256.
    ///
    /// The file is hashed as it is read, so memory stays flat whatever its size. It is opened
    /// through `piko_db::fs_util::open_following_symlinks`, as the signature check opens it: a
    /// FIFO or a device node is refused rather than read.
    ///
    /// # Errors
    ///
    /// [`Error::ChecksumMismatch`] naming both digests, or [`Error::UnusableSource`] and
    /// [`Error::Io`] if the file cannot be read.
    pub(crate) fn check_checksum(&self, package: &Path) -> Result<()> {
        let mut file = piko_db::fs_util::open_following_symlinks(package).map_err(|error| {
            Error::UnusableSource { path: package.to_path_buf(), reason: error.to_string() }
        })?;
        let mut hasher = sha2::Sha256::new();
        std::io::copy(&mut file, &mut hasher)
            .map_err(|source| Error::io(package, IoAction::Read, source))?;
        let found = hasher.finalize();
        if found.as_slice() == self.sha256.inner() {
            return Ok(());
        }
        let found: String = found.iter().map(|byte| format!("{byte:02x}")).collect();
        Err(Error::ChecksumMismatch {
            package: package.to_path_buf(),
            reason: format!(
                "its SHA-256 is {found}, but the repository database publishes {}",
                self.sha256
            ),
        })
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

    /// `sha256("package")`.
    const PACKAGE_SHA256: &str = "bc4a71180870f7945155fbb02f4b0a2e3faa2a62d6d31b7039013055ed19869a";

    fn published(sha256: &str) -> Published {
        Published::new(sha256.parse().unwrap(), None)
    }

    #[test]
    fn a_file_with_the_published_checksum_passes() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("foo-1.0.0-1-x86_64.pkg.tar");
        std::fs::write(&package, b"package").unwrap();

        published(PACKAGE_SHA256).check_checksum(&package).unwrap();
    }

    /// Both digests are named, so the message tells a damaged download from a stale database.
    #[test]
    fn a_file_with_another_checksum_is_refused_naming_both() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("foo-1.0.0-1-x86_64.pkg.tar");
        std::fs::write(&package, b"another package").unwrap();

        let error = published(PACKAGE_SHA256).check_checksum(&package).unwrap_err();
        let Error::ChecksumMismatch { reason, .. } = &error else {
            panic!("expected a checksum mismatch, got {error:?}");
        };
        assert!(reason.contains(PACKAGE_SHA256), "{reason}");
    }

    /// A FIFO in place of the package is refused without blocking on it.
    #[test]
    fn a_fifo_in_place_of_the_package_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("foo-1.0.0-1-x86_64.pkg.tar");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &package,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();

        let error = published(PACKAGE_SHA256).check_checksum(&package).unwrap_err();
        assert!(matches!(error, Error::UnusableSource { .. }), "got {error:?}");
    }

    #[test]
    fn a_published_signature_is_decoded() {
        let signature = Base64OpenPGPSignature::new("cGFja2FnZQ==".to_owned()).unwrap();
        let published = Published::new(PACKAGE_SHA256.parse().unwrap(), Some(signature));

        assert!(published.has_signature());
        assert_eq!(
            published.decoded_signature(Path::new("foo")).unwrap().as_deref(),
            Some(b"package".as_slice())
        );
        assert_eq!(
            self::published(PACKAGE_SHA256).decoded_signature(Path::new("foo")).unwrap(),
            None
        );
    }
}
