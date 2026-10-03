//! Asking GnuPG whether a detached signature is good, and how far its key is trusted.
//!
//! This is the only module in piko that talks to GPGME, and it does as little as possible.
//! It turns a file and its `.sig` into a list of [`SignatureOutcome`]s. What those mean is
//! [`crate::decision`]'s job, and it needs no keyring to be tested.
//!
//! # Why GPGME rather than a Rust OpenPGP library
//!
//! Trust. A signature being cryptographically good is the easy half. `SigLevel`'s
//! `TrustedOnly` is defined in terms of GnuPG's web of trust. That trust lives in
//! `trustdb.gpg`, alongside ownertrust. It turns "signed by some key in the keyring" into
//! "signed by a key three Arch master keys vouch for". libalpm verifies through GPGME
//! (`signing.c`) for the same reason, so piko inherits that model rather than reimplementing
//! it.
//!
//! Two things were measured, not assumed:
//!
//! - A pure-Rust alternative (rpgp) verifies real Arch signatures correctly. But it silently
//!   drops every subkey when reading `/etc/pacman.d/gnupg/pubring.gpg`. It parses 0 against
//!   the 308 packet-level subkeys `gpg` reports there, because the keyring interleaves 3417
//!   GnuPG ring-trust packets. Arch packagers sign with subkeys, so roughly 30% of a real
//!   cache finds no signing key, and no error is raised.
//! - GPGME, over the same corpus, returned `good` with `Full` validity for every package.

use std::{
    path::{Path, PathBuf},
    time::SystemTime,
};

use piko_db::config::SigLevel;

use crate::{
    decision::{Policy, SignatureOutcome, Status, Trust, Verdict, newest_creation},
    error::{Error, Result},
};

/// Binds a GPGME context to `home` as its `GNUPGHOME`.
///
/// This is free-standing rather than a [`Keyring`] method. The `piko-sig-write` crate needs
/// the identical binding for a directory that may not exist yet: `init`, before the `mkdir`.
/// [`Keyring::open`]'s own precondition does not fit that case, since it requires `home` to
/// be a directory already.
///
/// This is the only piece of GPGME setup shared across the read/write split. Everything past
/// binding the context stays on its own side of it.
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

/// The most entries [`ensure_trusted`] reads from a keyring directory. `pacman-key --init`
/// writes about twenty.
const MAX_KEYRING_ENTRIES: usize = 4096;

/// Fails if a user other than root and this process's own could change the keyring at `home`:
/// the directory, a directory on the way to it
/// ([`piko_db::fs_util::ensure_trusted_directory`]), or anything directly in it.
///
/// The keyring decides which signature is trusted. `pubring.gpg` and `trustdb.gpg` say which
/// keys are valid, and `gpg.conf` and `gpg-agent.conf` configure the programs GPGME runs. A
/// user who can change any of them can make every package verify. The rule is
/// [`piko_db::fs_util::distrust`]. An entry that is a symbolic link is refused: GnuPG creates
/// none, and a link would put a directory outside `home` in charge of what GnuPG reads. GnuPG
/// itself only warns about unsafe permissions, and libalpm checks none.
///
/// # Errors
///
/// [`Error::KeyringUnusable`] naming the entry and why, or when the directory cannot be listed,
/// holds a symbolic link, or holds more than [`MAX_KEYRING_ENTRIES`] entries.
fn ensure_trusted(home: &Path) -> Result<()> {
    let unusable = |reason: String| Error::KeyringUnusable { home: home.to_path_buf(), reason };
    let untrusted = |path: &Path, distrust: piko_db::fs_util::Distrust| {
        unusable(format!("{} is {distrust}, so another user could change it", path.display()))
    };

    match piko_db::fs_util::ensure_trusted_directory(home) {
        Ok(()) => {}
        Err(piko_db::Error::Untrusted { path, distrust }) => {
            return Err(untrusted(&path, distrust));
        }
        Err(error) => return Err(unusable(error.to_string())),
    }
    let entries = std::fs::read_dir(home).map_err(|error| unusable(error.to_string()))?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_KEYRING_ENTRIES {
            return Err(unusable(format!("more than {MAX_KEYRING_ENTRIES} entries")));
        }
        let path = entry.map_err(|error| unusable(error.to_string()))?.path();
        // An entry removed since the listing, such as an agent's socket, is not read either.
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(unusable(format!("{}: {error}", path.display()))),
        };
        if metadata.is_symlink() {
            return Err(unusable(format!("{} is a symbolic link", path.display())));
        }
        if let Some(distrust) = piko_db::fs_util::distrust(&metadata) {
            return Err(untrusted(&path, distrust));
        }
    }
    Ok(())
}

/// A GnuPG keyring directory — pacman's is `/etc/pacman.d/gnupg`.
///
/// Holds only the path. A GPGME context is created per verification rather than cached. A
/// context is not `Sync`, so caching one would push that constraint onto every caller. The
/// saving is invisible next to reading the package being verified.
#[derive(Clone, Debug)]
pub struct Keyring {
    home: PathBuf,
}

impl Keyring {
    /// Opens the keyring at `home`, checking that GnuPG can be reached.
    ///
    /// The check runs here rather than at the first verification. That way a broken or
    /// missing keyring is reported before a transaction starts, not part-way through one.
    ///
    /// The keyring must also be one no other user could change: not the directory, and not
    /// anything directly in it, by [`piko_db::fs_util::distrust`]'s rule. Nothing directly in it
    /// may be a symbolic link. The keyring decides which signature is trusted, and `gpg.conf`
    /// configures what GPGME runs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyringUnusable`] if `home` is not a directory, if another user could
    /// change it or anything directly in it, if it holds a symbolic link, or if a GPGME context
    /// cannot be created for it.
    pub fn open(home: impl AsRef<Path>) -> Result<Self> {
        let home = home.as_ref().to_path_buf();
        if !home.is_dir() {
            return Err(Error::KeyringUnusable { home, reason: "not a directory".to_owned() });
        }
        ensure_trusted(&home)?;
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
    /// Both are streamed from disk rather than buffered. GnuPG pulls bytes through a file
    /// descriptor as it hashes them, so memory stays flat whatever the file's size. A package
    /// archive runs to gigabytes, and a mirror decides how large the file it serves is. A buffer
    /// sized to the file would let a mirror exhaust memory before the signature is ever
    /// checked. `gpgme::Data::load` is that buffer: it `stat`s the file and allocates its whole
    /// size. libalpm streams for the same reason (`gpgme_data_new_from_stream`,
    /// `signing.c:586`).
    ///
    /// Both files are opened through `piko_db::fs_util::open_following_symlinks`: a final
    /// symlink is followed, as for a repository archive, but a FIFO or device node is refused
    /// rather than read.
    ///
    /// An empty result means GnuPG found no signature at all. This is
    /// [`crate::decision::decide`]'s "missing" case, not an error here. Whether that is fatal
    /// is the policy's decision, not this function's.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Gpgme`] if GnuPG could not be run, the files could not be opened or are
    /// not regular files, or a signing key could not be looked up.
    pub fn verify_detached(&self, path: &Path, signature: &Path) -> Result<Vec<SignatureOutcome>> {
        self.verify_against(path, stream(signature, "read the signature")?)
    }

    /// Verifies `signature`, held in memory, over the contents of `path`.
    ///
    /// As [`Keyring::verify_detached`], for a signature that is not a file: a repository
    /// database's `%PGPSIG%`, decoded. libalpm hands GPGME the decoded bytes the same way
    /// (`gpgme_data_new_from_mem`, `signing.c:598`). `path` is still streamed.
    ///
    /// # Errors
    ///
    /// As [`Keyring::verify_detached`].
    pub fn verify_detached_bytes(
        &self,
        path: &Path,
        signature: &[u8],
    ) -> Result<Vec<SignatureOutcome>> {
        let detached = gpgme::Data::from_bytes(signature).map_err(|source| Error::Gpgme {
            path: path.to_path_buf(),
            action: "read the signature of",
            message: source.to_string(),
        })?;
        self.verify_against(path, detached)
    }

    /// Verifies `detached` over the contents of `path`, streamed.
    fn verify_against(
        &self,
        path: &Path,
        detached: gpgme::Data<'_>,
    ) -> Result<Vec<SignatureOutcome>> {
        let mut context = self.context()?;
        let signed = stream(path, "read the signed file")?;

        let result = context.verify_detached(detached, signed).map_err(|source| Error::Gpgme {
            path: path.to_path_buf(),
            action: "verify",
            message: source.to_string(),
        })?;

        result.signatures().map(|signature| describe(&mut context, path, &signature)).collect()
    }

    /// Verifies `path` against the `.sig` beside it and applies `policy`.
    ///
    /// This is the whole check in one call. There are two callers: a package about to be
    /// installed, and a repository database about to be opened. The rule they share is easy
    /// to get subtly different between them.
    ///
    /// In particular, a missing `.sig` is not an error here. It produces no signatures, which
    /// is [`crate::decision::decide`]'s "missing" case. So `Required` versus `Optional`
    /// decides whether it is fatal, not whichever caller happened to stat the file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Gpgme`] if a signature is present but GnuPG could not be run over it.
    pub fn check(&self, path: &Path, policy: Policy) -> Result<Verdict> {
        self.check_dated(path, policy).map(|checked| checked.verdict)
    }

    /// As [`Keyring::check`], and also reports when the accepted signature was made.
    ///
    /// # Errors
    ///
    /// As [`Keyring::check`].
    pub fn check_dated(&self, path: &Path, policy: Policy) -> Result<Checked> {
        // Skipping the whole thing when the policy asks for nothing also skips spawning gpg.
        // This is what keeps `SigLevel = Never` free rather than merely permissive.
        if !policy.check {
            return Ok(Checked { verdict: Verdict::Accepted { verified: false }, signed_at: None });
        }

        let signature = signature_path(path);
        // Only an absent `.sig` is "unsigned". Anything else at that path — a directory, a
        // FIFO, a file that cannot be opened — is handed to `verify_detached`, which refuses
        // it as an error. Under `Optional`, reading such a path as "no signature" would accept
        // the file unverified.
        let outcomes = match std::fs::metadata(&signature) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            _ => self.verify_detached(path, &signature)?,
        };
        Ok(Checked::from_outcomes(&outcomes, policy))
    }

    /// Verifies `path` against `signature`, held in memory, and applies `policy`.
    ///
    /// The caller has a signature from somewhere other than the file system: a repository
    /// database's `%PGPSIG%`. The `.sig` beside `path` is not read, whatever it holds. This is
    /// `_alpm_pkg_validate_internal` (`be_package.c:332`): a package with a database signature
    /// is verified against it alone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Gpgme`] if GnuPG could not be run over the signature.
    pub fn check_bytes(&self, path: &Path, signature: &[u8], policy: Policy) -> Result<Verdict> {
        if !policy.check {
            return Ok(Verdict::Accepted { verified: false });
        }
        let outcomes = self.verify_detached_bytes(path, signature)?;
        Ok(crate::decision::decide(&outcomes, policy))
    }
}

/// A verdict, and when the signature behind it was made.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checked {
    /// Whether the policy accepts the file.
    pub verdict: Verdict,
    /// When the newest good signature was made.
    ///
    /// Set only when the verdict is `Accepted { verified: true }`. An unsigned file, or one
    /// the policy refused, has no signature time worth trusting.
    pub signed_at: Option<SystemTime>,
}

impl Checked {
    /// Applies `policy` to `outcomes`, and dates the result if it verified.
    #[must_use]
    pub fn from_outcomes(outcomes: &[SignatureOutcome], policy: Policy) -> Self {
        let verdict = crate::decision::decide(outcomes, policy);
        let signed_at = match verdict {
            Verdict::Accepted { verified: true } => newest_creation(outcomes),
            _ => None,
        };
        Self { verdict, signed_at }
    }
}

/// Verifies `archive`, a repository database, against `sig_level`. It opens the keyring at
/// `gpg_dir` only if the resulting policy actually asks for a check.
///
/// This is the open-time half of "checked at download and again at open"
/// The download half is `piko_net::Refresher::install`'s job.
/// A caller opening an already-local repository archive by name should call this instead of
/// composing [`Policy::for_database`], [`Keyring::open`], and [`Keyring::check`] itself. The
/// point is that a `SigLevel` alone is enough to ask the question. Opening a keyring costs
/// ~13.5 ms the first time in a process and ~3 µs after (measured). Checking `policy.check`
/// first is what keeps that cost off a repository with `SigLevel = Never`, or a system with
/// no configured `SigLevel` at all. Such a caller pays nothing rather than merely tolerating
/// a slow path.
///
/// # Errors
///
/// Returns [`Error::KeyringUnusable`] if the policy demands a check and `gpg_dir` cannot be
/// opened. Returns [`Error::Gpgme`] if a signature is present but GnuPG could not run. A
/// signature that was checked and refused is not an error here. See [`Verdict::Rejected`].
pub fn verify_database(archive: &Path, gpg_dir: &Path, sig_level: SigLevel) -> Result<Verdict> {
    verify_database_dated(archive, gpg_dir, sig_level).map(|checked| checked.verdict)
}

/// As [`verify_database`], and also reports when the accepted signature was made.
///
/// A caller that judges how recent a database is wants this date. It is the only date about a
/// signed database that a mirror cannot forge.
///
/// # Errors
///
/// As [`verify_database`].
pub fn verify_database_dated(
    archive: &Path,
    gpg_dir: &Path,
    sig_level: SigLevel,
) -> Result<Checked> {
    let policy = Policy::for_database(sig_level);
    if !policy.check {
        return Ok(Checked { verdict: Verdict::Accepted { verified: false }, signed_at: None });
    }
    Keyring::open(gpg_dir)?.check_dated(archive, policy)
}

/// Opens `path` as a GPGME data object that GnuPG reads from as it hashes.
fn stream(path: &Path, action: &'static str) -> Result<gpgme::Data<'static>> {
    let describe = |message: String| Error::Gpgme { path: path.to_path_buf(), action, message };
    let file = piko_db::fs_util::open_following_symlinks(path)
        .map_err(|source| describe(source.to_string()))?;
    gpgme::Data::from_seekable_reader(file).map_err(|wrapped| describe(wrapped.error().to_string()))
}

/// Translates one GPGME signature into piko's own vocabulary.
///
/// The status mapping is `signing.c:675`'s, and so is the disabled-key test after it.
///
/// # Errors
///
/// [`Error::Gpgme`] if the signing key is in the keyring but GnuPG cannot list it. The
/// disabled flag and the key's length live on that listing, so a key that cannot be listed
/// cannot be accepted.
fn describe(
    context: &mut gpgme::Context,
    path: &Path,
    signature: &gpgme::Signature<'_>,
) -> Result<SignatureOutcome> {
    let fingerprint = signature.fingerprint().ok().map(str::to_owned);
    let summary = signature.summary();

    let status = match signature.status() {
        Ok(()) => {
            // A good signature whose key has since expired is reported through the summary,
            // not through an error, and must stay distinguishable. See `decision`.
            if summary.contains(gpgme::SignatureSummary::KEY_EXPIRED) {
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
            } else if code == gpgme::Error::CERT_REVOKED.code() {
                Status::KeyRevoked
            } else {
                Status::Invalid
            }
        }
    };

    let unknown =
        status == Status::KeyUnknown || summary.contains(gpgme::SignatureSummary::KEY_MISSING);
    let key = if unknown { None } else { signing_key(context, path, fingerprint.as_deref())? };

    let status = if unknown {
        Status::KeyUnknown
    } else if key.as_ref().is_some_and(gpgme::Key::is_disabled) {
        // GnuPG reports a signature from a disabled key as good, with the key's usual
        // validity: a disabled key is only noted, never refused, by `gpg --verify`. So the
        // flag is read off the key itself, as `signing.c:695` does. This is what gives
        // `piko key populate`'s `-revoked` list, and any manual `disable`, an effect.
        Status::KeyDisabled
    } else if summary.contains(gpgme::SignatureSummary::KEY_REVOKED) {
        // GnuPG can report a revocation through the validity reason alone, with a status of
        // `NO_ERROR`. The summary bit covers both routes.
        Status::KeyRevoked
    } else {
        status
    };

    // Last, and only over a signature that verified: a bad one stays bad, whatever it hashed
    // and whatever key made it.
    let status = match status {
        Status::Valid | Status::KeyExpired => weak_digest(signature.hash_algorithm())
            .map(|algorithm| Status::WeakDigest { algorithm })
            .or_else(|| key.as_ref().and_then(|key| weak_key(key, fingerprint.as_deref())))
            .unwrap_or(status),
        other => other,
    };

    let trust = match signature.validity() {
        gpgme::Validity::Full | gpgme::Validity::Ultimate => Trust::Full,
        gpgme::Validity::Marginal => Trust::Marginal,
        gpgme::Validity::Never => Trust::Never,
        _ => Trust::Unknown,
    };

    Ok(SignatureOutcome { status, trust, fingerprint, created: signature.creation_time() })
}

/// The name of `algorithm` when it is too weak to sign with, or `None` when it is strong enough.
///
/// A denylist rather than an allowlist: GPGME's list ends at SHA-512, so a digest newer than
/// it (an OpenPGP v6 SHA3) must not read as weak. MD2, MD4 and MD5 are broken, SHA-1 has
/// chosen-prefix collisions (SHA-mbles, 2020), RIPEMD-160, Tiger and Haval are 160 bits or
/// less and unmaintained, and a signature reporting no digest at all cannot be judged.
fn weak_digest(algorithm: gpgme::HashAlgorithm) -> Option<&'static str> {
    use gpgme::HashAlgorithm as Hash;
    let weak = [
        Hash::None,
        Hash::Md2,
        Hash::Md4,
        Hash::Md5,
        Hash::Sha1,
        Hash::RipeMd160,
        Hash::Tiger,
        Hash::Haval,
    ];
    weak.contains(&algorithm).then(|| algorithm.name().unwrap_or("an unnamed digest"))
}

/// The shortest RSA key a signature is accepted from.
///
/// NIST SP 800-57 rates 2048 bits at 112-bit security, the floor it accepts until 2030.
const MIN_RSA_BITS: usize = 2048;

/// A [`Status::WeakKey`] when the subkey that made a signature is too weak to sign with, or
/// `None` when it is strong enough.
///
/// The subkey is read from the keyring, not from the signature: only the key records its
/// length. It is found by fingerprint, or by key ID when GnuPG reported only that.
///
/// A denylist, as for digests, so an algorithm newer than GPGME's list does not read as weak.
/// DSA is refused at every size: FIPS 186-5 withdrew it for new signatures, and a signature
/// made with a predictable nonce gives away the key. ElGamal signing is broken. RSA is refused
/// below [`MIN_RSA_BITS`]. Elliptic-curve keys pass, because GnuPG offers no curve below
/// 255 bits.
fn weak_key(key: &gpgme::Key, fingerprint: Option<&str>) -> Option<Status> {
    use gpgme::KeyAlgorithm as Algorithm;
    let fingerprint = fingerprint?;
    let names = |candidate: Result<&str, _>| {
        candidate.is_ok_and(|candidate: &str| candidate.eq_ignore_ascii_case(fingerprint))
    };
    let subkey = key.subkeys().find(|subkey| names(subkey.fingerprint()) || names(subkey.id()))?;
    let algorithm = subkey.algorithm();
    let bits = subkey.length();
    let weak = match algorithm {
        Algorithm::Dsa | Algorithm::Elgamal | Algorithm::ElgamalEncrypt => true,
        Algorithm::Rsa | Algorithm::RsaSign | Algorithm::RsaEncrypt => bits < MIN_RSA_BITS,
        _ => false,
    };
    weak.then(|| Status::WeakKey {
        algorithm: algorithm.name().unwrap_or("an unnamed algorithm"),
        bits,
    })
}

/// The key that made a signature, as the keyring holds it.
///
/// `gpgme_get_key` resolves a subkey's fingerprint to the key holding it. The disabled flag
/// belongs to that whole key, and the length to the subkey inside it. `EOF` means no key holds
/// it, which the signature's own status already reports.
fn signing_key(
    context: &mut gpgme::Context,
    path: &Path,
    fingerprint: Option<&str>,
) -> Result<Option<gpgme::Key>> {
    let Some(fingerprint) = fingerprint else { return Ok(None) };
    match context.get_key(fingerprint) {
        Ok(key) => Ok(Some(key)),
        Err(error) if error.code() == gpgme::Error::EOF.code() => Ok(None),
        Err(error) => Err(Error::Gpgme {
            path: path.to_path_buf(),
            action: "look up the signing key of",
            message: error.to_string(),
        }),
    }
}

/// The largest detached signature piko downloads or copies: 16 KiB, libalpm's own bound
/// (`dload.c:667`).
///
/// A detached signature is a few hundred bytes. The bound limits what a mirror can hand
/// GnuPG to parse before any trust is established, which is also why it is no larger than
/// libalpm's.
pub const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;

/// The conventional location of a detached signature: the file's own name plus `.sig`.
///
/// pacman uses the same convention for both packages and databases. That is why this lives
/// here rather than being spelled out at each call site.
#[must_use]
pub fn signature_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_os_string();
    name.push(".sig");
    PathBuf::from(name)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    /// The extension is appended, not replaced. A package name is full of dots, and
    /// `set_extension` would eat `.zst`.
    #[test]
    fn a_signature_path_is_the_file_plus_sig() {
        assert_eq!(
            signature_path(Path::new("/cache/foo-1.0-1-x86_64.pkg.tar.zst")),
            PathBuf::from("/cache/foo-1.0-1-x86_64.pkg.tar.zst.sig")
        );
        assert_eq!(signature_path(Path::new("core.db")), PathBuf::from("core.db.sig"));
    }

    /// A keyring another user could change is refused before GnuPG reads it: the directory,
    /// or any file directly in it.
    #[test]
    fn a_keyring_another_user_could_change_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let chmod = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let home = tempfile::tempdir().unwrap();
        let conf = home.path().join("gpg.conf");
        std::fs::write(&conf, "").unwrap();

        chmod(&conf, 0o666);
        let error = Keyring::open(home.path()).unwrap_err();
        assert!(
            matches!(&error, Error::KeyringUnusable { reason, .. } if reason.contains("gpg.conf")),
            "{error:?}"
        );

        chmod(&conf, 0o644);
        chmod(home.path(), 0o777);
        let error = Keyring::open(home.path()).unwrap_err();
        chmod(home.path(), 0o700);
        assert!(
            matches!(&error, Error::KeyringUnusable { reason, .. }
                if reason.contains("writable by its group or others")),
            "{error:?}"
        );
    }

    /// A symbolic link directly in the keyring is refused, even to a trusted file: the link
    /// would put another directory in charge of what GnuPG reads.
    #[test]
    fn a_keyring_holding_a_symbolic_link_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let conf = elsewhere.path().join("gpg.conf");
        std::fs::write(&conf, "").unwrap();
        std::os::unix::fs::symlink(&conf, home.path().join("gpg.conf")).unwrap();

        let error = Keyring::open(home.path()).unwrap_err();
        assert!(
            matches!(&error, Error::KeyringUnusable { reason, .. }
                if reason.ends_with("gpg.conf is a symbolic link")),
            "{error:?}"
        );
    }

    #[test]
    fn a_missing_keyring_is_reported_rather_than_panicking() {
        let error = Keyring::open("/nonexistent/keyring").unwrap_err();
        assert!(matches!(error, Error::KeyringUnusable { .. }), "{error:?}");
    }

    /// An empty directory is a usable GnuPG home. It simply knows no keys. Refusing it here
    /// would make a fresh chroot impossible to verify into. And "no keys" is already the
    /// `KeyUnknown` rejection the decision layer handles.
    #[test]
    fn an_empty_directory_opens() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Keyring::open(dir.path()).is_ok());
    }

    /// A policy that asks for nothing must not pay to open a keyring at all. That is the
    /// whole reason [`verify_database`] exists, rather than a caller composing
    /// `Policy::for_database` + `Keyring::open` + `Keyring::check` itself. A directory that
    /// cannot possibly be opened as one proves it. `Keyring::open` would return
    /// `Error::KeyringUnusable` if it were even attempted.
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
