//! Asking GnuPG whether a detached signature is good, and how far its key is trusted.
//!
//! This is the only module in piko that talks to GPGME, and it does as little as possible:
//! turn a file and its `.sig` into a list of [`SignatureOutcome`]s. What those mean is
//! [`crate::decision`]'s job, and it needs no keyring to be tested.
//!
//! # Why GPGME rather than a Rust OpenPGP library
//!
//! Trust. A signature being cryptographically good is the easy half. `SigLevel`'s
//! `TrustedOnly` is defined in terms of GnuPG's web of trust, which lives in `trustdb.gpg`
//! alongside ownertrust and turns "signed by some key in the keyring" into "signed by a key
//! three Arch master keys vouch for". libalpm verifies through GPGME (`signing.c`) for the
//! same reason, so piko inherits that model instead of reimplementing it.
//!
//! Two things were measured, not assumed:
//!
//! - A pure-Rust alternative (rpgp) verified real Arch signatures correctly but silently
//!   dropped every subkey when reading `/etc/pacman.d/gnupg/pubring.gpg`: 0 parsed against
//!   the 308 packet-level subkeys `gpg` reports there, because the keyring interleaves 3417
//!   GnuPG ring-trust packets. Arch packagers sign with subkeys, so roughly 30% of a real
//!   cache found no signing key, with no error raised.
//! - GPGME, over the same corpus, returned `good` with `Full` validity for every package.

use std::path::{Path, PathBuf};

use piko_db::config::SigLevel;

use crate::{
    decision::{Policy, SignatureOutcome, Status, Trust, Verdict},
    error::{Error, Result},
};

/// Binds a GPGME context to `home` as its `GNUPGHOME`.
///
/// Free-standing, not a [`Keyring`] method, because the `piko-sig-write` crate needs the
/// identical binding for a directory that may not exist yet (`init`, before the `mkdir`) — a
/// case [`Keyring::open`]'s own precondition (`home` must already be a directory) does not
/// fit. This is the only piece of GPGME setup shared across the read/write split; everything
/// past binding the context stays on its own side of it.
///
/// # Errors
///
/// Returns [`Error::KeyringUnusable`] if no OpenPGP engine is available, or `home` is rejected
/// as an engine home directory.
pub fn open_context(home: &Path) -> Result<gpgme::Context> {
    let mut context =
        gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp).map_err(|source| {
            Error::KeyringUnusable {
                home: home.to_path_buf(),
                reason: format!("no OpenPGP engine: {source}"),
            }
        })?;
    // Equivalent to `GNUPGHOME`. libalpm does the same through `gpgme_ctx_set_engine_info`
    // (`signing.c:144`).
    context.set_engine_home_dir(home.as_os_str().as_encoded_bytes()).map_err(|source| {
        Error::KeyringUnusable {
            home: home.to_path_buf(),
            reason: format!("engine home rejected: {source}"),
        }
    })?;
    Ok(context)
}

/// A GnuPG keyring directory — pacman's is `/etc/pacman.d/gnupg`.
///
/// Holds only the path. A GPGME context is created per verification rather than cached. A
/// context is not `Sync`, and caching one would push that constraint onto every caller for a
/// saving invisible next to reading the package being verified.
#[derive(Clone, Debug)]
pub struct Keyring {
    home: PathBuf,
}

impl Keyring {
    /// Opens the keyring at `home`, checking that GnuPG can be reached.
    ///
    /// The check is done here rather than at the first verification so that a broken or
    /// missing keyring is reported before a transaction starts, not part-way through one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyringUnusable`] if `home` is not a directory, or if a GPGME context
    /// cannot be created for it.
    pub fn open(home: impl AsRef<Path>) -> Result<Self> {
        let home = home.as_ref().to_path_buf();
        if !home.is_dir() {
            return Err(Error::KeyringUnusable { home, reason: "not a directory".to_owned() });
        }
        let keyring = Self { home };
        // Constructed and dropped purely to prove it can be.
        drop(keyring.context()?);
        Ok(keyring)
    }

    /// The keyring directory.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// A GPGME context bound to this keyring.
    fn context(&self) -> Result<gpgme::Context> {
        open_context(&self.home)
    }

    /// Verifies `signature` over the contents of `path`.
    ///
    /// Both are streamed from disk rather than buffered. A package archive runs to hundreds
    /// of megabytes, and reading one into memory to hash it would undo the care taken
    /// everywhere else in piko to keep reads bounded.
    ///
    /// An empty result means GnuPG found no signature at all. This is
    /// [`crate::decision::decide`]'s "missing" case, not an error here. Whether that is fatal
    /// is the policy's decision, not this function's.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Gpgme`] if GnuPG could not be run, or the files could not be opened.
    pub fn verify_detached(&self, path: &Path, signature: &Path) -> Result<Vec<SignatureOutcome>> {
        let mut context = self.context()?;

        let signed = gpgme::Data::load(path_arg(path)).map_err(|source| Error::Gpgme {
            path: path.to_path_buf(),
            action: "read the signed file",
            message: source.to_string(),
        })?;
        let detached = gpgme::Data::load(path_arg(signature)).map_err(|source| Error::Gpgme {
            path: signature.to_path_buf(),
            action: "read the signature",
            message: source.to_string(),
        })?;

        let result = context.verify_detached(detached, signed).map_err(|source| Error::Gpgme {
            path: path.to_path_buf(),
            action: "verify",
            message: source.to_string(),
        })?;

        Ok(result.signatures().map(describe).collect())
    }

    /// Verifies `path` against the `.sig` beside it and applies `policy`.
    ///
    /// The whole check in one call, because there are two callers — a package about to be
    /// installed and a repository database about to be opened — and the rule they share is
    /// easy to get subtly different between them. In particular, a missing `.sig` is not an
    /// error here. It produces no signatures, which is [`crate::decision::decide`]'s "missing"
    /// case, so whether it is fatal is decided by `Required` versus `Optional`, not by
    /// whichever caller happened to stat the file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Gpgme`] if a signature is present but GnuPG could not be run over it.
    pub fn check(&self, path: &Path, policy: Policy) -> Result<Verdict> {
        // Skipping the whole thing when the policy asks for nothing also skips spawning gpg.
        // This is what keeps `SigLevel = Never` free rather than merely permissive.
        if !policy.check {
            return Ok(Verdict::Accepted { verified: false });
        }

        let signature = signature_path(path);
        let outcomes =
            if signature.is_file() { self.verify_detached(path, &signature)? } else { Vec::new() };
        Ok(crate::decision::decide(&outcomes, policy))
    }
}

/// Verifies `archive` — a repository database — against `sig_level`, opening the keyring at
/// `gpg_dir` only if the resulting policy actually asks for a check.
///
/// This is the open-time half of "checked at download and again at open"
/// The download half is `piko_net::Refresher::install`'s job.
/// A caller opening an already-local repository archive by name should call this instead of
/// composing [`Policy::for_database`], [`Keyring::open`], and [`Keyring::check`] itself. The
/// point is that a `SigLevel` alone is enough to ask the question. Opening a keyring costs
/// ~13.5 ms the first time in a process and ~3 µs after (measured). Checking `policy.check`
/// first is what keeps a repository with `SigLevel = Never`, or a system with no configured
/// `SigLevel` at all, free of that cost rather than merely tolerant of a slow one.
///
/// # Errors
///
/// Returns [`Error::KeyringUnusable`] if the policy demands a check and `gpg_dir` cannot be
/// opened, or [`Error::Gpgme`] if a signature is present but GnuPG could not be run over it. A
/// signature that was checked and refused is not an error here. See [`Verdict::Rejected`].
pub fn verify_database(archive: &Path, gpg_dir: &Path, sig_level: SigLevel) -> Result<Verdict> {
    let policy = Policy::for_database(sig_level);
    if !policy.check {
        return Ok(Verdict::Accepted { verified: false });
    }
    Keyring::open(gpg_dir)?.check(archive, policy)
}

/// GPGME takes a NUL-terminated path. A Rust path may legitimately not be UTF-8.
fn path_arg(path: &Path) -> std::ffi::CString {
    // A path containing an interior NUL cannot name a real file, so the lossy fallback can
    // only ever be reached by a path that would fail to open anyway.
    std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .unwrap_or_else(|_| c"/nonexistent".to_owned())
}

/// Translates one GPGME signature into piko's own vocabulary.
///
/// The mapping is `signing.c:537`'s, which reads the same summary bits.
fn describe(signature: gpgme::Signature<'_>) -> SignatureOutcome {
    let fingerprint = signature.fingerprint().ok().map(str::to_owned);

    let status = match signature.status() {
        Ok(()) => {
            // A good signature whose key has since expired is reported through the summary,
            // not through an error, and must stay distinguishable. See `decision`.
            if signature.summary().contains(gpgme::SignatureSummary::KEY_EXPIRED) {
                Status::KeyExpired
            } else {
                Status::Valid
            }
        }
        Err(error) => {
            // Compared by code rather than matched: `gpg_error::Error`'s constants are
            // associated consts, not variants, so a `match` on them is not available.
            let code = error.code();
            if code == gpgme::Error::SIG_EXPIRED.code() {
                Status::SigExpired
            } else if code == gpgme::Error::KEY_EXPIRED.code() {
                Status::KeyExpired
            } else if code == gpgme::Error::NO_PUBKEY.code() {
                Status::KeyUnknown
            } else {
                Status::Invalid
            }
        }
    };

    // A disabled key outranks whatever else the summary says about it.
    let status = if signature.summary().contains(gpgme::SignatureSummary::KEY_MISSING) {
        Status::KeyUnknown
    } else if signature.summary().contains(gpgme::SignatureSummary::KEY_REVOKED) {
        Status::KeyDisabled
    } else {
        status
    };

    let trust = match signature.validity() {
        gpgme::Validity::Full | gpgme::Validity::Ultimate => Trust::Full,
        gpgme::Validity::Marginal => Trust::Marginal,
        gpgme::Validity::Never => Trust::Never,
        _ => Trust::Unknown,
    };

    SignatureOutcome { status, trust, fingerprint }
}

/// The conventional location of a detached signature: the file's own name plus `.sig`.
///
/// pacman uses the same convention for both packages and databases, which is why this lives
/// here rather than being spelled out at each call site.
#[must_use]
pub fn signature_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_os_string();
    name.push(".sig");
    PathBuf::from(name)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_path_is_the_file_plus_sig() {
        assert_eq!(
            signature_path(Path::new("/cache/foo-1.0-1-x86_64.pkg.tar.zst")),
            PathBuf::from("/cache/foo-1.0-1-x86_64.pkg.tar.zst.sig")
        );
    }

    /// The extension is appended, not replaced. A package name is full of dots, and
    /// `set_extension` would eat `.zst`.
    #[test]
    fn a_signature_path_does_not_replace_the_existing_extension() {
        let signed = signature_path(Path::new("core.db"));
        assert_eq!(signed, PathBuf::from("core.db.sig"));
    }

    #[test]
    fn a_missing_keyring_is_reported_rather_than_panicking() {
        let error = Keyring::open("/nonexistent/keyring").unwrap_err();
        assert!(matches!(error, Error::KeyringUnusable { .. }), "{error:?}");
    }

    /// An empty directory is a usable GnuPG home — it simply knows no keys. Refusing it here
    /// would make a fresh chroot impossible to verify into, and "no keys" is already the
    /// `KeyUnknown` rejection the decision layer handles.
    #[test]
    fn an_empty_directory_opens() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Keyring::open(dir.path()).is_ok());
    }

    /// This is the whole reason [`verify_database`] exists rather than a caller composing
    /// `Policy::for_database` + `Keyring::open` + `Keyring::check` itself: a policy that asks
    /// for nothing must not pay to open a keyring at all. A directory that cannot possibly be
    /// opened as one proves it. `Keyring::open` would return `Error::KeyringUnusable` if it
    /// were even attempted.
    #[test]
    fn verify_database_opens_no_keyring_when_the_policy_asks_for_nothing() {
        let verdict = verify_database(
            Path::new("/nonexistent/archive.db"),
            Path::new("/nonexistent/keyring"),
            SigLevel::default(),
        )
        .unwrap();
        assert!(matches!(verdict, Verdict::Accepted { verified: false }));
    }
}
