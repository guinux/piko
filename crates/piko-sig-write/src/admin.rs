//! Creating a keyring, importing keys into it, and granting or revoking their trust.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    edit::ScriptedInteractor,
    error::{Error, Result},
};

/// The identity piko's own local signing key is generated and found under.
///
/// Distinct from pacman-key's own "Pacman Keyring Master Key <pacman@localhost>" so the two
/// tools' keys never collide inside a keyring shared between them.
pub(crate) const MASTER_KEY_USERID: &str = "piko Local Keyring Master Key <piko@localhost>";

/// A key's ownertrust: how much its own certifications of *other* keys should count towards
/// their validity. Mirrors [`gpgme::Validity`]'s six levels; kept as piko's own type so no
/// `gpgme` type crosses this crate's public API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerTrust {
    /// No ownertrust has been assigned.
    Unknown,
    /// Explicitly recorded as "I don't know or won't say".
    Undefined,
    /// This key's certifications must never count.
    Never,
    /// This key's certifications count partially (GnuPG's default needs three marginal
    /// certifiers to reach full validity).
    Marginal,
    /// This key's certifications count fully on their own.
    Full,
    /// This key is trusted absolutely — normally reserved for keys piko holds the secret half
    /// of.
    Ultimate,
}

impl OwnerTrust {
    /// Parses `gpg --export-ownertrust`'s numeric code (also the `-trusted` file's `LEVEL`
    /// field): `1..=6`, confirmed empirically against GnuPG 2.4.9 by driving `--edit-key
    /// trust` for each interactive level and reading back `--export-ownertrust`. `Unknown` and
    /// `Undefined` are not reachable through the interactive `trust` menu (there is no menu
    /// option for either — they are the state of a key nobody has judged), but still appear as
    /// valid codes in an ownertrust dump, so this parser accepts all six.
    pub(crate) fn from_file_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Unknown),
            2 => Some(Self::Undefined),
            3 => Some(Self::Never),
            4 => Some(Self::Marginal),
            5 => Some(Self::Full),
            6 => Some(Self::Ultimate),
            _ => None,
        }
    }

    /// The digit `--edit-key`'s `trust` subcommand's `edit_ownertrust.value` prompt expects.
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] for [`Self::Unknown`]/[`Self::Undefined`] — GnuPG's interactive trust
    /// menu has no option that sets either; both are only ever the *absence* of a trust
    /// judgement, not something `--edit-key` can be asked to produce.
    fn interactive_digit(self) -> Result<&'static str> {
        match self {
            Self::Never => Ok("2"),
            Self::Marginal => Ok("3"),
            Self::Full => Ok("4"),
            Self::Ultimate => Ok("5"),
            Self::Unknown | Self::Undefined => Err(Error::Gpgme {
                path: PathBuf::new(),
                action: "set ownertrust",
                message: format!("{self:?} cannot be assigned through the trust menu"),
            }),
        }
    }
}

impl From<gpgme::Validity> for OwnerTrust {
    fn from(validity: gpgme::Validity) -> Self {
        match validity {
            gpgme::Validity::Undefined => Self::Undefined,
            gpgme::Validity::Never => Self::Never,
            gpgme::Validity::Marginal => Self::Marginal,
            gpgme::Validity::Full => Self::Full,
            gpgme::Validity::Ultimate => Self::Ultimate,
            _ => Self::Unknown,
        }
    }
}

/// One key in the keyring, as reported by [`KeyringAdmin::list_keys`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyInfo {
    /// The key's full fingerprint.
    pub fingerprint: String,
    /// Every user ID string (`"Name <email>"`), in keyring order.
    pub user_ids: Vec<String>,
    /// How much this key's own certifications of other keys count.
    pub owner_trust: OwnerTrust,
    /// Whether the key has been disabled (`piko-key delete`'s softer sibling).
    pub is_disabled: bool,
    /// Whether the key (or its primary user ID) has been revoked.
    pub is_revoked: bool,
    /// Whether the key has expired.
    pub is_expired: bool,
}

/// A summary of one [`KeyringAdmin::import`] or [`KeyringAdmin::populate`] call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImportSummary {
    /// Keys found in the imported material.
    pub considered: u32,
    /// Keys actually added or updated.
    pub imported: u32,
    /// Keys already present, identically.
    pub unchanged: u32,
    /// New certifications learned.
    pub new_signatures: u32,
    /// New revocations learned.
    pub new_revocations: u32,
}

impl From<gpgme::ImportResult> for ImportSummary {
    fn from(result: gpgme::ImportResult) -> Self {
        Self {
            considered: result.considered(),
            imported: result.imported(),
            unchanged: result.unchanged(),
            new_signatures: result.new_signatures(),
            new_revocations: result.new_revocations(),
        }
    }
}

/// What [`KeyringAdmin::init`] did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitOutcome {
    /// Whether a new master signing key was generated. `false` means an existing one (from an
    /// earlier `init`) was left alone.
    pub master_key_created: bool,
}

/// Administers a GnuPG keyring: creates it, imports keys, and grants or revokes their trust.
///
/// Holds only the path, the same design [`piko_sig::Keyring`] uses and for the same reason — a
/// GPGME context is not `Sync`, so one is opened per operation rather than cached.
#[derive(Clone, Debug)]
pub struct KeyringAdmin {
    home: PathBuf,
}

impl KeyringAdmin {
    /// Creates `home` (mode `0700`) if it does not exist yet, and generates piko's local
    /// master signing key inside it if none exists yet. Idempotent: calling this again against
    /// an already-initialized keyring changes nothing and reports
    /// `InitOutcome { master_key_created: false }`.
    ///
    /// This call sets the mode only on a directory it created itself. An existing keyring keeps
    /// its current mode. See [`create_keyring_dir`].
    ///
    /// The master key is RSA-4096, certify-capable, unprotected (no passphrase — this keyring
    /// is meant to be usable by an unattended `piko install`, exactly like pacman's own
    /// keyring), with no expiry. It exists only to locally sign ([`Self::lsign`]) other keys;
    /// piko never uses it to sign a document.
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] if the directory cannot be created, or key generation fails.
    pub fn init(home: impl AsRef<Path>) -> Result<(Self, InitOutcome)> {
        let home = home.as_ref().to_path_buf();
        if create_keyring_dir(&home)? {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).map_err(
                    |source| Error::Gpgme {
                        path: home.clone(),
                        action: "set the keyring directory's permissions",
                        message: source.to_string(),
                    },
                )?;
            }
        }

        let admin = Self { home };
        let mut context = admin.context()?;

        let master_key_created = match admin.find_master_key(&mut context)? {
            Some(_) => false,
            None => {
                context
                    .create_key_with_flags(
                        MASTER_KEY_USERID,
                        "rsa4096",
                        Duration::ZERO,
                        gpgme::CreateKeyFlags::CERT | gpgme::CreateKeyFlags::NOPASSWD,
                    )
                    .map_err(|source| Error::Gpgme {
                        path: admin.home.clone(),
                        action: "generate the master key",
                        message: source.to_string(),
                    })?;
                true
            }
        };

        Ok((admin, InitOutcome { master_key_created }))
    }

    /// Opens an already-initialized keyring for administration.
    ///
    /// # Errors
    ///
    /// [`Error::KeyringUnusable`] if `home` is not a directory or GPGME cannot reach it.
    pub fn open(home: impl AsRef<Path>) -> Result<Self> {
        let home = home.as_ref().to_path_buf();
        if !home.is_dir() {
            return Err(Error::KeyringUnusable { home, reason: "not a directory".to_owned() });
        }
        let admin = Self { home };
        drop(admin.context()?);
        Ok(admin)
    }

    /// The keyring directory.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    pub(crate) fn context(&self) -> Result<gpgme::Context> {
        Ok(piko_sig::open_context(&self.home)?)
    }

    /// Finds piko's own master key by its fixed identity, without touching the network.
    pub(crate) fn find_master_key(
        &self,
        context: &mut gpgme::Context,
    ) -> Result<Option<gpgme::Key>> {
        let candidates =
            context.find_secret_keys(["piko@localhost"]).map_err(|source| Error::Gpgme {
                path: self.home.clone(),
                action: "search for the master key",
                message: source.to_string(),
            })?;
        // `find_secret_keys` matches substrings across every user ID field, not just email —
        // require the exact identity so an unrelated key mentioning "piko@localhost" in a
        // comment can never be mistaken for piko's own master key.
        for candidate in candidates {
            let candidate = self.readable(candidate)?;
            if candidate.user_ids().any(|uid| uid.id().ok() == Some(MASTER_KEY_USERID)) {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    /// As [`Self::find_master_key`], failing with [`Error::NoMasterKey`] instead of `None`.
    pub(crate) fn master_key(&self, context: &mut gpgme::Context) -> Result<gpgme::Key> {
        self.find_master_key(context)?.ok_or_else(|| Error::NoMasterKey { home: self.home.clone() })
    }

    /// Imports OpenPGP key material from `path` (armored or binary).
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] if `path` cannot be read or does not hold key material GnuPG accepts.
    pub fn import(&self, path: &Path) -> Result<ImportSummary> {
        let mut context = self.context()?;
        let data = gpgme::Data::load(path_arg(path)).map_err(|source| Error::Gpgme {
            path: path.to_path_buf(),
            action: "read",
            message: source.to_string(),
        })?;
        let result = context.import(data).map_err(|source| Error::Gpgme {
            path: path.to_path_buf(),
            action: "import",
            message: source.to_string(),
        })?;
        Ok(result.into())
    }

    /// Locally (non-exportably) certifies `fingerprint`'s primary user ID with piko's master
    /// key. A no-op if it is already certified — returns `false` rather than signing again, so
    /// a caller counting how many keys it *newly* signed (as [`Self::populate`] does) does not
    /// have to re-derive "already signed" itself.
    ///
    /// Certifying only the primary user ID, not every one a key carries, is
    /// [`gpgme_op_keysign`]'s own default with no user IDs named — measured to hold even when
    /// every user ID is passed explicitly, so it is not merely an unset parameter. It is also
    /// sufficient: a key's validity for verifying a signature is decided by the *best*
    /// certification path any of its user IDs has, not by all of them at once, which is why
    /// `piko-key verify` reports full trust for packages from a key whose secondary user IDs
    /// were never separately signed.
    ///
    /// [`gpgme_op_keysign`]: https://www.gnupg.org/documentation/manuals/gpgme/Signing-Keys.html
    ///
    /// # Errors
    ///
    /// [`Error::NoMasterKey`] if [`Self::init`] was never run. [`Error::KeyNotFound`] if
    /// `fingerprint` is not in the keyring.
    pub fn lsign(&self, fingerprint: &str) -> Result<bool> {
        let mut context = self.context()?;
        // GPGME does not fetch a key's certifications by default — `UserId::signatures()` is
        // silently empty without this, which would make the idempotency check below always
        // say "not yet signed" and pile up a duplicate local signature on every `populate`.
        context.set_key_list_mode(gpgme::KeyListMode::LOCAL | gpgme::KeyListMode::SIGS).map_err(
            |source| Error::Gpgme {
                path: self.home.clone(),
                action: "set key list mode for",
                message: source.to_string(),
            },
        )?;
        let master = self.master_key(&mut context)?;
        let target = self.get_key(&mut context, fingerprint)?;

        // `UserId::signature` returns only a usable certification. It already drops a bad
        // one, a revocation, and one whose status is not `NO_ERROR` (`gpgme-0.11.0`
        // `keys.rs:622`). Its presence alone answers "already signed".
        let already_signed =
            target.user_ids().next().is_some_and(|uid| uid.signature(&master).is_some());
        if already_signed {
            return Ok(false);
        }

        context.add_signer(&master).map_err(|source| Error::Gpgme {
            path: self.home.clone(),
            action: "select the master key as signer",
            message: source.to_string(),
        })?;
        context
            .sign_key_with_flags(
                &target,
                std::iter::empty::<String>(),
                Duration::ZERO,
                gpgme::KeySigningFlags::LOCAL,
            )
            .map_err(|source| Error::Gpgme {
                path: self.home.clone(),
                action: "locally sign",
                message: source.to_string(),
            })?;
        Ok(true)
    }

    /// Sets ownertrust on `fingerprint`. A no-op if the key already carries `level`. It then
    /// returns `false` rather than setting it again, as [`Self::lsign`] and [`Self::disable`]
    /// do.
    ///
    /// Each call that is not a no-op drives a whole `gpgme_op_interact` session, and
    /// `populate` calls this once per `-trusted` line on every run. So an already-populated
    /// keyring runs none of those sessions. The no-op is also what makes
    /// `PopulateSummary::trust_set` count keys the call changed, rather than lines it read.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] if `fingerprint` is not in the keyring. [`Error::Gpgme`] if
    /// `level` is [`OwnerTrust::Unknown`] or [`OwnerTrust::Undefined`] — neither is settable
    /// through GnuPG's trust menu, see [`OwnerTrust::interactive_digit`].
    pub fn set_owner_trust(&self, fingerprint: &str, level: OwnerTrust) -> Result<bool> {
        let digit = level.interactive_digit()?;
        let mut context = self.context()?;
        let target = self.get_key(&mut context, fingerprint)?;
        if OwnerTrust::from(target.owner_trust()) == level {
            return Ok(false);
        }
        context
            .interact(
                &target,
                ScriptedInteractor::set_owner_trust(digit, level == OwnerTrust::Ultimate),
                gpgme::Data::new().map_err(|source| Error::Gpgme {
                    path: self.home.clone(),
                    action: "allocate a scratch buffer",
                    message: source.to_string(),
                })?,
            )
            .map_err(|source| Error::Gpgme {
                path: self.home.clone(),
                action: "set ownertrust on",
                message: source.to_string(),
            })?;
        Ok(true)
    }

    /// Disables `fingerprint`: GnuPG will not use it to satisfy a signature check, without
    /// removing it. A no-op if already disabled — returns `false` rather than disabling again,
    /// for the same counting reason [`Self::lsign`] does.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] if `fingerprint` is not in the keyring.
    pub fn disable(&self, fingerprint: &str) -> Result<bool> {
        let mut context = self.context()?;
        let target = self.get_key(&mut context, fingerprint)?;
        if target.is_disabled() {
            return Ok(false);
        }
        context
            .interact(
                &target,
                ScriptedInteractor::disable(),
                gpgme::Data::new().map_err(|source| Error::Gpgme {
                    path: self.home.clone(),
                    action: "allocate a scratch buffer",
                    message: source.to_string(),
                })?,
            )
            .map_err(|source| Error::Gpgme {
                path: self.home.clone(),
                action: "disable",
                message: source.to_string(),
            })?;
        Ok(true)
    }

    /// Deletes the public key `fingerprint`. `allow_secret` must be `true` to also delete a
    /// matching secret key — piko's own master key included — so it is never removed by
    /// accident.
    ///
    /// piko decides this refusal, rather than GnuPG. GPGME rejects the same case on its own,
    /// but reports only `GPG_ERR_CONFLICT`. That message names neither the key nor the next
    /// step. This method searches the secret keyring first, and returns
    /// [`Error::SecretKeyRefused`] instead.
    ///
    /// The cost of the mistake is why the refusal is explicit. piko's master key signs every
    /// local certification in the keyring. A deleted master key therefore leaves every key
    /// [`Self::lsign`] certified without a trust path.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] if `fingerprint` is not in the keyring.
    /// [`Error::SecretKeyRefused`] if the key has a secret key and `allow_secret` is `false`.
    pub fn delete(&self, fingerprint: &str, allow_secret: bool) -> Result<()> {
        let mut context = self.context()?;
        let target = self.get_key(&mut context, fingerprint)?;
        let mut flags = gpgme::DeleteKeyFlags::empty();
        if allow_secret {
            flags |= gpgme::DeleteKeyFlags::ALLOW_SECRET;
        } else if context.get_secret_key(fingerprint).is_ok() {
            return Err(Error::SecretKeyRefused {
                home: self.home.clone(),
                keyid: fingerprint.to_owned(),
            });
        }
        context.delete_key_with_flags(&target, flags).map_err(|source| Error::Gpgme {
            path: self.home.clone(),
            action: "delete",
            message: source.to_string(),
        })
    }

    /// Every public key currently in the keyring.
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] if GnuPG cannot be run.
    pub fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        self.find_keys(&[])
    }

    /// Every public key that matches one of `patterns`. An empty `patterns` matches every key,
    /// so this is also what [`Self::list_keys`] calls.
    ///
    /// GnuPG does the matching, through `gpgme_op_keylist_ext`. A pattern is a fingerprint, a
    /// short or long key ID, an email address, or a user ID substring. `gpg --list-keys` accepts
    /// the same set, and treats hex case-insensitively.
    ///
    /// A caller must not filter [`Self::list_keys`] itself instead. A substring test over the
    /// fingerprint matches no email address. It matches no lowercase fingerprint either, because
    /// GPGME reports hex in upper case. It also matches anywhere in the fingerprint, while GnuPG
    /// anchors a key ID at the end. [`Self::describe_key`] makes the same point for the
    /// single-key case.
    ///
    /// Unlike [`Self::describe_key`], an ambiguous pattern is not an error here. It lists every
    /// key it matches, as `gpg --list-keys` does.
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] if GnuPG cannot be run.
    pub fn find_keys(&self, patterns: &[String]) -> Result<Vec<KeyInfo>> {
        let mut context = self.context()?;
        let keys = context.find_keys(patterns.iter().map(String::as_str)).map_err(|source| {
            Error::Gpgme {
                path: self.home.clone(),
                action: "list keys in",
                message: source.to_string(),
            }
        })?;
        keys.map(|key| self.describe(&self.readable(key)?)).collect()
    }

    /// Resolves one key by `keyid`, then describes it. `keyid` is a fingerprint, a short or
    /// long key ID, an email address, or any other pattern GnuPG accepts.
    ///
    /// Use this lookup to show a user which key an operation will change. It calls the same
    /// [`Self::get_key`] every mutating operation here calls. A caller that filters
    /// [`Self::list_keys`] instead runs a second resolver, and the two can name different keys.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] if `keyid` matches no key, or matches more than one.
    pub fn describe_key(&self, keyid: &str) -> Result<KeyInfo> {
        let mut context = self.context()?;
        let key = self.get_key(&mut context, keyid)?;
        self.describe(&key)
    }

    /// Unwraps one entry of a GPGME key listing.
    ///
    /// A listing can yield an error in place of a key. Such an entry, dropped, silently
    /// truncates the answer. [`Self::find_keys`] would return a short list.
    /// [`Self::find_master_key`] would report no master key, and [`Self::init`] would then
    /// generate a second one. Design principle 3 rules out both. The error is the answer.
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] carrying what GnuPG said.
    fn readable(&self, entry: std::result::Result<gpgme::Key, gpgme::Error>) -> Result<gpgme::Key> {
        entry.map_err(|source| Error::Gpgme {
            path: self.home.clone(),
            action: "read a key from",
            message: source.to_string(),
        })
    }

    fn describe(&self, key: &gpgme::Key) -> Result<KeyInfo> {
        let fingerprint = key.fingerprint().map_err(|_| Error::Gpgme {
            path: self.home.clone(),
            action: "read the fingerprint of",
            message: "not valid UTF-8".to_owned(),
        })?;
        Ok(KeyInfo {
            fingerprint: fingerprint.to_owned(),
            user_ids: key.user_ids().filter_map(|uid| uid.id().ok().map(str::to_owned)).collect(),
            owner_trust: key.owner_trust().into(),
            is_disabled: key.is_disabled(),
            is_revoked: key.is_revoked(),
            is_expired: key.is_expired(),
        })
    }

    /// Forces GnuPG to recompute key validity from the current trust database (`gpg
    /// --check-trustdb`'s effect). GPGME exposes no dedicated operation for this — GnuPG's own
    /// trust model already recomputes validity whenever keys are queried, so a full listing
    /// achieves the same thing natively, without shelling out to `gpg --check-trustdb`.
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] if GnuPG cannot be run.
    pub fn update_trustdb(&self) -> Result<()> {
        let mut context = self.context()?;
        let keys = context.keys().map_err(|source| Error::Gpgme {
            path: self.home.clone(),
            action: "list keys in",
            message: source.to_string(),
        })?;
        // Walked, not collected. [`Self::list_keys`] would allocate a `KeyInfo` per key, with a
        // `String` per user ID, and drop all of it. GnuPG recomputes validity as it produces
        // each key. The walk alone is therefore the whole effect.
        for key in keys {
            drop(self.readable(key)?);
        }
        Ok(())
    }

    /// Looks up `fingerprint` (or any GnuPG-accepted key identifier), failing with
    /// [`Error::KeyNotFound`] rather than propagating GPGME's own "ambiguous name"/"not found"
    /// distinction, which no caller here needs.
    fn get_key(&self, context: &mut gpgme::Context, fingerprint: &str) -> Result<gpgme::Key> {
        context.get_key(fingerprint).map_err(|_| Error::KeyNotFound {
            home: self.home.clone(),
            keyid: fingerprint.to_owned(),
        })
    }
}

/// Creates `home`. Returns `true` if this call created it, and `false` if it already existed.
///
/// [`KeyringAdmin::init`] reads that answer before it sets mode `0700`. Only a directory piko
/// created itself gets piko's mode.
///
/// An existing keyring keeps its current mode. The default `home` is `/etc/pacman.d/gnupg`,
/// which piko shares with pacman. `pacman-key --init` creates that directory `0755`
/// (`pacman-key.sh.in:225`), and leaves `pubring.gpg` and `trustdb.gpg` world-readable. It does
/// so on purpose. It supports `--list-keys` and `--verify` for an unprivileged user. It also
/// checks that both files stay readable (`pacman-key.sh.in:269`). `0700` is correct for a
/// keyring piko creates. It is not correct for a directory another tool created, from a call
/// that reports no change.
///
/// An existing symlink to a directory counts as existing. pacman-key tests for existence, not
/// for a directory. Its own comment gives the reason: "someone may want to use a symlink here".
fn create_keyring_dir(home: &Path) -> Result<bool> {
    let describe = |source: std::io::Error| Error::Gpgme {
        path: home.to_path_buf(),
        action: "create the keyring directory",
        message: source.to_string(),
    };
    match std::fs::create_dir(home) {
        Ok(()) => Ok(true),
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        // A missing parent, not a missing leaf. `create_dir_all` creates the whole chain.
        // The leaf is still new, so it still gets piko's mode.
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(home).map_err(describe)?;
            Ok(true)
        }
        Err(source) => Err(describe(source)),
    }
}

/// GPGME takes a NUL-terminated path. A Rust path may legitimately not be UTF-8.
fn path_arg(path: &Path) -> std::ffi::CString {
    std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .unwrap_or_else(|_| c"/nonexistent".to_owned())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// A `KeyringAdmin` whose master key is ed25519, not `init`'s real RSA-4096 — this exercises
    /// every real GPGME operation `init`/`lsign`/`set_owner_trust`/`disable`/`delete`/
    /// `list_keys` drive, without RSA-4096's wall-clock cost. `init`'s own key generation is
    /// covered separately, `#[ignore]`d, in `tests/key_real_system.rs`.
    ///
    /// `None` if GnuPG cannot be reached at all here, the same graceful skip
    /// `piko-sig/tests/signed_database.rs` uses.
    fn fast_admin() -> Option<KeyringAdmin> {
        let home = tempfile::tempdir().ok()?;
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).ok()?;
        let admin = KeyringAdmin { home: home.path().to_path_buf() };
        let mut context = admin.context().ok()?;
        context
            .create_key_with_flags(
                MASTER_KEY_USERID,
                "ed25519",
                Duration::ZERO,
                gpgme::CreateKeyFlags::CERT | gpgme::CreateKeyFlags::NOPASSWD,
            )
            .ok()?;
        // Leaked, not dropped: `KeyringAdmin` only holds a path, so the directory must outlive
        // it. Each test's home is unique and the OS reclaims `/tmp` regardless.
        std::mem::forget(home);
        Some(admin)
    }

    /// A second, unrelated keyring holding one ed25519 key with no secret material in
    /// `fast_admin`'s keyring — a "foreign" key to import, sign, and trust, standing in for a
    /// vendor's packager key the way `archlinux.gpg`'s keys stand in for real ones.
    fn foreign_public_key() -> Option<(PathBuf, String)> {
        let home = tempfile::tempdir().ok()?;
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).ok()?;
        let mut context = piko_sig::open_context(home.path()).ok()?;
        let generated = context
            .create_key_with_flags(
                "foreign test key <foreign@example.invalid>",
                "ed25519",
                Duration::ZERO,
                gpgme::CreateKeyFlags::SIGN | gpgme::CreateKeyFlags::NOPASSWD,
            )
            .ok()?;
        let fingerprint = generated.fingerprint().ok()?.to_owned();
        let key = context.get_key(&fingerprint).ok()?;
        let mut exported = gpgme::Data::new().ok()?;
        context.export_keys([&key], gpgme::ExportMode::empty(), &mut exported).ok()?;
        let path = home.path().join("foreign.pub");
        std::fs::write(&path, exported.try_into_bytes()?).ok()?;
        std::mem::forget(home);
        Some((path, fingerprint))
    }

    /// As [`foreign_public_key`], but with a second user ID.
    ///
    /// Guards a narrow case: an `already_signed` check that requires *every* user ID to carry
    /// a certification can never be satisfied, because certifying only ever covers the primary
    /// one (measured, see [`KeyringAdmin::lsign`]'s doc comment). Every `populate` then
    /// re-signs the same key.
    ///
    /// This test pins the intended behavior, but does not on its own prove it. False
    /// idempotency shows up only across separate processes, each with a fresh `gpg-agent`
    /// interaction — not within one already-warmed-up test process. Run the `piko-key` binary
    /// twice from a shell to see that half.
    fn foreign_public_key_with_two_uids() -> Option<(PathBuf, String)> {
        let home = tempfile::tempdir().ok()?;
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).ok()?;
        let mut context = piko_sig::open_context(home.path()).ok()?;
        let generated = context
            .create_key_with_flags(
                "foreign multi-uid key <foreign@example.invalid>",
                "ed25519",
                Duration::ZERO,
                gpgme::CreateKeyFlags::SIGN | gpgme::CreateKeyFlags::NOPASSWD,
            )
            .ok()?;
        let fingerprint = generated.fingerprint().ok()?.to_owned();
        let key = context.get_key(&fingerprint).ok()?;
        context.add_uid(&key, "foreign multi-uid key (second) <foreign2@example.invalid>").ok()?;
        let key = context.get_key(&fingerprint).ok()?;
        assert_eq!(key.user_ids().count(), 2, "fixture must actually carry two user IDs");
        let mut exported = gpgme::Data::new().ok()?;
        context.export_keys([&key], gpgme::ExportMode::empty(), &mut exported).ok()?;
        let path = home.path().join("foreign.pub");
        std::fs::write(&path, exported.try_into_bytes()?).ok()?;
        std::mem::forget(home);
        Some((path, fingerprint))
    }

    #[test]
    fn lsign_converges_on_a_key_with_more_than_one_user_id() {
        let Some(admin) = fast_admin() else { return };
        let Some((foreign_path, fingerprint)) = foreign_public_key_with_two_uids() else { return };
        admin.import(&foreign_path).unwrap();

        assert!(admin.lsign(&fingerprint).unwrap(), "the first lsign should be new");
        assert!(!admin.lsign(&fingerprint).unwrap(), "the second lsign should be a no-op");
        assert!(!admin.lsign(&fingerprint).unwrap(), "a third call must stay a no-op too");
    }

    #[test]
    fn a_key_can_be_imported_signed_trusted_disabled_and_deleted() {
        let Some(admin) = fast_admin() else { return };
        let Some((foreign_path, fingerprint)) = foreign_public_key() else { return };

        let imported = admin.import(&foreign_path).unwrap();
        assert_eq!(imported.imported, 1);

        // Not yet trusted: no lsign, no ownertrust.
        let before = admin.list_keys().unwrap();
        let foreign = before.iter().find(|key| key.fingerprint == fingerprint).unwrap();
        assert_eq!(foreign.owner_trust, OwnerTrust::Unknown);

        assert!(admin.lsign(&fingerprint).unwrap(), "the first lsign should be new");
        // Idempotent: signing an already-signed key must not error or duplicate the signature.
        assert!(!admin.lsign(&fingerprint).unwrap(), "the second lsign should be a no-op");

        admin.set_owner_trust(&fingerprint, OwnerTrust::Full).unwrap();
        let trusted = admin.list_keys().unwrap();
        let foreign = trusted.iter().find(|key| key.fingerprint == fingerprint).unwrap();
        assert_eq!(foreign.owner_trust, OwnerTrust::Full);
        assert!(!foreign.is_disabled);

        assert!(admin.disable(&fingerprint).unwrap(), "the first disable should be new");
        let disabled = admin.list_keys().unwrap();
        assert!(disabled.iter().find(|key| key.fingerprint == fingerprint).unwrap().is_disabled);
        // Idempotent.
        assert!(!admin.disable(&fingerprint).unwrap(), "the second disable should be a no-op");

        admin.delete(&fingerprint, false).unwrap();
        let after = admin.list_keys().unwrap();
        assert!(after.iter().all(|key| key.fingerprint != fingerprint));
    }

    /// Ultimate is the one level GnuPG asks an extra confirmation for. No other test drives
    /// that prompt, so this is what checks `edit_ownertrust.set_ultimate.okay`'s own name.
    #[test]
    fn ultimate_answers_gnupgs_extra_confirmation() {
        let Some(admin) = fast_admin() else { return };
        let Some((foreign_path, fingerprint)) = foreign_public_key() else { return };
        admin.import(&foreign_path).unwrap();

        assert!(admin.set_owner_trust(&fingerprint, OwnerTrust::Ultimate).unwrap());

        let keys = admin.list_keys().unwrap();
        let foreign = keys.iter().find(|key| key.fingerprint == fingerprint).unwrap();
        assert_eq!(foreign.owner_trust, OwnerTrust::Ultimate);
    }

    /// `set_owner_trust` joins `lsign` and `disable` in reporting whether it changed anything.
    /// A second call must drive no `gpgme_op_interact` session at all.
    #[test]
    fn set_owner_trust_is_idempotent() {
        let Some(admin) = fast_admin() else { return };
        let Some((foreign_path, fingerprint)) = foreign_public_key() else { return };
        admin.import(&foreign_path).unwrap();

        assert!(
            admin.set_owner_trust(&fingerprint, OwnerTrust::Full).unwrap(),
            "first is a change"
        );
        assert!(
            !admin.set_owner_trust(&fingerprint, OwnerTrust::Full).unwrap(),
            "the second call must find the level already set"
        );
        // A different level is still a change.
        assert!(admin.set_owner_trust(&fingerprint, OwnerTrust::Marginal).unwrap());
    }

    #[test]
    fn lsign_and_set_owner_trust_refuse_a_key_that_is_not_in_the_keyring() {
        let Some(admin) = fast_admin() else { return };
        let err = admin.lsign("0".repeat(40).as_str()).unwrap_err();
        assert!(matches!(err, Error::KeyNotFound { .. }), "{err:?}");
    }

    #[test]
    fn set_owner_trust_refuses_unknown_and_undefined() {
        assert!(OwnerTrust::Unknown.interactive_digit().is_err());
        assert!(OwnerTrust::Undefined.interactive_digit().is_err());
        assert_eq!(OwnerTrust::Never.interactive_digit().unwrap(), "2");
        assert_eq!(OwnerTrust::Marginal.interactive_digit().unwrap(), "3");
        assert_eq!(OwnerTrust::Full.interactive_digit().unwrap(), "4");
        assert_eq!(OwnerTrust::Ultimate.interactive_digit().unwrap(), "5");
    }

    #[test]
    fn file_code_round_trips_every_level() {
        for (code, level) in [
            (1, OwnerTrust::Unknown),
            (2, OwnerTrust::Undefined),
            (3, OwnerTrust::Never),
            (4, OwnerTrust::Marginal),
            (5, OwnerTrust::Full),
            (6, OwnerTrust::Ultimate),
        ] {
            assert_eq!(OwnerTrust::from_file_code(code), Some(level));
        }
        assert_eq!(OwnerTrust::from_file_code(0), None);
        assert_eq!(OwnerTrust::from_file_code(7), None);
    }

    /// `update_trustdb` walks the keyring without building a `KeyInfo` for each key. The walk
    /// is the whole effect. The only thing left to check is that it still succeeds, and still
    /// reaches every key.
    #[test]
    fn update_trustdb_walks_the_keyring() {
        let Some(admin) = fast_admin() else { return };
        let Some((foreign_path, _)) = foreign_public_key() else { return };
        admin.import(&foreign_path).unwrap();

        admin.update_trustdb().unwrap();
        assert_eq!(admin.list_keys().unwrap().len(), 2, "the walk must not change the keyring");
    }

    #[test]
    fn open_refuses_a_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent");
        let err = KeyringAdmin::open(&missing).unwrap_err();
        assert!(matches!(err, Error::KeyringUnusable { .. }), "{err:?}");
    }

    #[test]
    fn init_is_idempotent() {
        let Some(admin) = fast_admin() else { return };
        // `init` against an already-initialized keyring (via `fast_admin`'s own ed25519 key,
        // standing in for a real one) must find it rather than generating a second master key.
        let (_, outcome) = KeyringAdmin::init(admin.home()).unwrap();
        assert!(!outcome.master_key_created, "{outcome:?}");
    }

    /// `init` reports an existing keyring as unchanged. It must therefore leave the mode
    /// alone. The default keyring is pacman's own, at mode `0755`. See [`create_keyring_dir`].
    #[test]
    fn init_does_not_remode_an_existing_keyring() {
        let Some(admin) = fast_admin() else { return };
        std::fs::set_permissions(admin.home(), std::fs::Permissions::from_mode(0o755)).unwrap();

        KeyringAdmin::init(admin.home()).unwrap();

        let mode = std::fs::metadata(admin.home()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "an existing keyring's mode is its owner's business");
    }

    #[test]
    fn init_creates_a_new_keyring_at_0700() {
        let parent = tempfile::tempdir().unwrap();
        // Two levels deep, so this exercises the `create_dir_all` branch.
        let home = parent.path().join("missing").join("gnupg");
        assert!(create_keyring_dir(&home).unwrap(), "a fresh directory must report as created");
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(!create_keyring_dir(&home).unwrap(), "the second call must report as existing");
        let mode = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// `describe_key` must resolve every identifier GnuPG resolves. The CLI's confirmation
    /// prompt must name the same key `lsign` and `delete` will change.
    #[test]
    fn describe_key_resolves_the_same_identifiers_the_operations_do() {
        let Some(admin) = fast_admin() else { return };
        let Some((foreign_path, fingerprint)) = foreign_public_key() else { return };
        admin.import(&foreign_path).unwrap();

        let by_fingerprint = admin.describe_key(&fingerprint).unwrap();
        assert_eq!(by_fingerprint.fingerprint, fingerprint);

        // An email address. GnuPG resolves it, but no fingerprint contains it as text.
        let by_email = admin.describe_key("foreign@example.invalid").unwrap();
        assert_eq!(by_email.fingerprint, fingerprint);

        // A hex slice from the middle of a fingerprint is not a key ID. It must not resolve.
        let middle = fingerprint.get(8..16).unwrap();
        let err = admin.describe_key(middle).unwrap_err();
        assert!(matches!(err, Error::KeyNotFound { .. }), "{err:?}");
    }
}
