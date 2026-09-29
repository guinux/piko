//! Creating a keyring, importing keys into it, and granting or revoking their trust.

use std::{
    fs::File,
    io::{Read as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    edit::ScriptedInteractor,
    error::{Error, Result},
};

/// The agent socket GnuPG binds inside a keyring directory, when no runtime directory is
/// available to hold it.
const AGENT_SOCKET: &str = "S.gpg-agent";

/// The longest agent socket path GnuPG will bind, in bytes.
///
/// `sockaddr_un::sun_path` is 108 bytes on Linux. GnuPG keeps a margin for the longer names it
/// derives from this one (`S.gpg-agent.extra`, `.browser`, `.ssh`). Measured by bisection
/// against GnuPG 2.4: 98 binds, 99 reports "socket name … is too long".
const MAX_AGENT_SOCKET_LEN: usize = 98;

/// The identity piko's own local signing key is generated and found under.
///
/// Distinct from pacman-key's own "Pacman Keyring Master Key <pacman@localhost>" so the two
/// tools' keys never collide inside a keyring shared between them.
pub(crate) const MASTER_KEY_USERID: &str = "piko Local Keyring Master Key <piko@localhost>";

/// A key's ownertrust: how much its own certifications of *other* keys should count towards their
/// validity.
///
/// Mirrors [`gpgme::Validity`]'s six levels; kept as piko's own type so no `gpgme` type crosses
/// this crate's public API.
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
    /// Parses `gpg --export-ownertrust`'s numeric code, which is also the `-trusted` file's
    /// `LEVEL` field. The range is `1..=6`, confirmed empirically against GnuPG 2.4.9. The
    /// measurement drove `--edit-key trust` for each interactive level and read back
    /// `--export-ownertrust`.
    ///
    /// `Unknown` and `Undefined` are not reachable through the interactive `trust` menu. There is
    /// no menu option for either, because they are the state of a key nobody has judged. They
    /// still appear as valid codes in an ownertrust dump, so this parser accepts all six.
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
    /// [`Error::Gpgme`] for [`Self::Unknown`]/[`Self::Undefined`]. GnuPG's interactive trust
    /// menu has no option that sets either. Both are only ever the *absence* of a trust
    /// judgement, not something `--edit-key` can be asked to produce.
    fn interactive_digit(self) -> Result<&'static str> {
        match self {
            Self::Never => Ok("2"),
            Self::Marginal => Ok("3"),
            Self::Full => Ok("4"),
            Self::Ultimate => Ok("5"),
            Self::Unknown | Self::Undefined => Err(Error::gpgme(
                PathBuf::new(),
                "set ownertrust",
                format!("{self:?} cannot be assigned through the trust menu"),
            )),
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
    /// Whether the key has been disabled (`piko key delete`'s softer sibling).
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
    /// earlier `init`) was kept.
    pub master_key_created: bool,
    /// Whether an existing master key carried an expiry date that this call removed.
    ///
    /// Always `false` when [`Self::master_key_created`] is `true`: a new key is generated
    /// without one.
    pub master_key_expiry_removed: bool,
}

/// Administers a GnuPG keyring: creates it, imports keys, and grants or revokes their trust.
///
/// Holds only the path, the same design [`piko_sig::Keyring`] uses and for the same reason. A
/// GPGME context is not `Sync`, so one is opened per operation rather than cached.
#[derive(Clone, Debug)]
pub struct KeyringAdmin {
    home: PathBuf,
}

impl KeyringAdmin {
    /// Builds an [`Error::Gpgme`], naming the socket-path limit when that limit is what
    /// stopped an agent from starting.
    ///
    /// GPGME reports every such failure as `No agent running`, because `gpg-agent` writes the
    /// real reason to a stderr GPGME discards. That message names nothing a caller can act
    /// on.
    ///
    /// The reason worth recovering is the keyring path itself. GnuPG binds the agent socket in
    /// `/run/user/<uid>/gnupg` when that directory exists. It falls back to the keyring home
    /// when it does not. That happens inside a user namespace mapped to root, in a container,
    /// and in any process whose runtime directory is absent. `sockaddr_un` then bounds the path.
    /// Measured against GnuPG 2.4 on Linux: a `<home>/S.gpg-agent` of 98 bytes binds, 99 fails.
    ///
    /// The check runs only after GnuPG has already refused, never before. A long keyring path is
    /// perfectly usable whenever the standard socket directory exists. Testing the length up
    /// front would refuse a working keyring.
    fn agent_error(&self, action: &'static str, source: &gpgme::Error) -> Error {
        let mut message = source.to_string();
        if source.code() == gpgme::Error::NO_AGENT.code() {
            let socket = self.home.join(AGENT_SOCKET);
            let length = socket.as_os_str().as_encoded_bytes().len();
            if length > MAX_AGENT_SOCKET_LEN {
                message = format!(
                    "{message}; the agent socket {} would be {length} bytes, over the {} \
                     GnuPG binds, so no agent can start here. Use a shorter --gpgdir.",
                    socket.display(),
                    MAX_AGENT_SOCKET_LEN,
                );
            }
        }
        Error::Gpgme { path: self.home.clone(), action, message }
    }

    /// Creates `home` (mode `0755`) if it does not exist yet. It then generates piko's local
    /// master signing key inside it, if none exists yet.
    ///
    /// Idempotent: calling this again against an already-initialized keyring changes nothing and
    /// reports `master_key_created: false`. The one exception is an existing master key that
    /// carries an expiry date, which this call removes, and reports in
    /// [`InitOutcome::master_key_expiry_removed`]. An expired master key leaves every key it
    /// signed without a trust path.
    ///
    /// This call sets the mode only on a directory it created itself. An existing keyring keeps its
    /// current mode.
    ///
    /// The master key is RSA-4096, certify-capable, and has no expiry. It carries no passphrase,
    /// because this keyring must be usable by an unattended `piko install`, exactly like pacman's
    /// own keyring. It exists only to locally sign ([`Self::lsign`]) other keys. piko never uses
    /// it to sign a document.
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] if the directory cannot be created, or key generation fails.
    pub fn init(home: impl AsRef<Path>) -> Result<(Self, InitOutcome)> {
        let home = home.as_ref().to_path_buf();
        if create_keyring_dir(&home)? {
            set_mode(&home, KEYRING_DIR_MODE, "set the keyring directory's permissions")?;
        }
        // Before any GPGME context opens. An existing `pubring.gpg` is what makes GnuPG use the
        // legacy keyring format rather than create `pubring.kbx` beside it. `pacman-key` reads
        // only the former.
        write_layout(&home)?;

        let admin = Self { home };
        let mut context = admin.context()?;

        let (master_key_created, master_key_expiry_removed) =
            match admin.find_master_key(&mut context)? {
                Some(master) => (false, admin.clear_master_expiry(&mut context, &master)?),
                None => {
                    // `NOEXPIRE` is required, not implied by the zero duration.
                    // `gpgme_op_createkey` reads an expiry of zero as "GnuPG's default", three
                    // years in GnuPG 2.4, and only the flag asks for none.
                    context
                        .create_key_with_flags(
                            MASTER_KEY_USERID,
                            "rsa4096",
                            Duration::ZERO,
                            gpgme::CreateKeyFlags::CERT
                                | gpgme::CreateKeyFlags::NOPASSWD
                                | gpgme::CreateKeyFlags::NOEXPIRE,
                        )
                        .map_err(|source| admin.agent_error("generate the master key", &source))?;
                    (true, false)
                }
            };

        // `pacman-key` runs `gpg --update-trustdb` for the same reason. `check_keyring` refuses
        // a keyring whose `trustdb.gpg` it cannot read, and a fresh home has none until
        // something writes trust.
        let trustdb = admin.home.join(TRUSTDB);
        if !piko_db::fs_util::exists_no_follow(&trustdb) {
            admin.update_trustdb()?;
        }
        if piko_db::fs_util::exists_no_follow(&trustdb) {
            set_mode(&trustdb, READABLE_MODE, "set the trust database's permissions")?;
        }

        Ok((admin, InitOutcome { master_key_created, master_key_expiry_removed }))
    }

    /// Removes `master`'s expiry date, if it has one. Returns whether it had one.
    ///
    /// The master key is the root of every trust path in the keyring. Past its expiry date,
    /// GnuPG stops using it as an ultimately trusted key. Every key it locally signed then falls
    /// to unknown validity, and `TrustedOnly` refuses every package. Measured against GnuPG
    /// 2.4: `gpg --faked-system-time` past the date reports "ultimately trusted key … expired",
    /// and `TRUST_UNDEFINED` for a packager key that verified as `TRUST_FULLY` before it.
    ///
    /// A key created with an expiry of zero and without `GPGME_CREATE_NOEXPIRE` carries GnuPG's
    /// default expiry. So an existing master key is checked here, not assumed to be permanent.
    /// `pacman-key --init` generates its own master key with `Expire-Date: 0`.
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] if GnuPG refuses to change the expiry date.
    fn clear_master_expiry(
        &self,
        context: &mut gpgme::Context,
        master: &gpgme::Key,
    ) -> Result<bool> {
        if master.primary_key().is_none_or(|primary| primary.never_expires()) {
            return Ok(false);
        }
        // Zero means "never" to `gpgme_op_setexpire`. No subkey is named, so only the primary
        // key changes; `init` generates a master key with no subkeys.
        context
            .set_expire(master, Duration::ZERO, std::iter::empty::<&str>())
            .map_err(|source| self.agent_error("remove the master key's expiry date", &source))?;
        Ok(true)
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
        let candidates = context
            .find_secret_keys(["piko@localhost"])
            .map_err(|source| Error::gpgme(&self.home, "search for the master key", source))?;
        // `find_secret_keys` matches substrings across every user ID field, not just email. So
        // require the exact identity. An unrelated key mentioning "piko@localhost" in a comment
        // can then never be mistaken for piko's own master key.
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
        // The open refuses a FIFO or device node rather than blocking on it or reading it
        // without end.
        let file = piko_db::fs_util::open_following_symlinks(path)
            .map_err(|source| Error::gpgme(path, "read", source))?;
        self.import_file(file, path)
    }

    /// Imports OpenPGP key material from `file`, already opened from `path` and checked by the
    /// caller.
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] if `file` cannot be read or does not hold key material GnuPG accepts.
    pub(crate) fn import_file(&self, file: std::fs::File, path: &Path) -> Result<ImportSummary> {
        let mut context = self.context()?;
        // Streamed, not loaded: `gpgme::Data::load` allocates the whole file up front, and the
        // file is as large as its writer chose.
        let describe =
            |message: String| Error::Gpgme { path: path.to_path_buf(), action: "read", message };
        let data = gpgme::Data::from_seekable_reader(file)
            .map_err(|wrapped| describe(wrapped.error().to_string()))?;
        let result = context.import(data).map_err(|source| Error::gpgme(path, "import", source))?;
        Ok(result.into())
    }

    /// Locally (non-exportably) certifies `fingerprint`'s primary user ID with piko's master key.
    ///
    /// A no-op if it is already certified. It then returns `false` rather than sign again. So a
    /// caller counting how many keys it *newly* signed, as [`Self::populate`] does, need not
    /// re-derive "already signed" itself.
    ///
    /// Certifying only the primary user ID, not every one a key carries, is
    /// [`gpgme_op_keysign`]'s own default with no user IDs named. That was measured to hold even
    /// when every user ID is passed explicitly, so it is not merely an unset parameter.
    ///
    /// It is also sufficient. A key's validity for verifying a signature is decided by the *best*
    /// certification path any of its user IDs has. It is not decided by all of them at once. That
    /// is why
    /// `piko key verify` reports full trust for packages from a key whose secondary user IDs were
    /// never separately signed.
    ///
    /// [`gpgme_op_keysign`]: https://www.gnupg.org/documentation/manuals/gpgme/Signing-Keys.html
    ///
    /// # Errors
    ///
    /// [`Error::NoMasterKey`] if [`Self::init`] was never run. [`Error::KeyNotFound`] if
    /// `fingerprint` is not in the keyring.
    pub fn lsign(&self, fingerprint: &str) -> Result<bool> {
        let mut context = self.context()?;
        // GPGME does not fetch a key's certifications by default. `UserId::signatures()` is
        // silently empty without this. The idempotency check below would then always say "not yet
        // signed", and pile up a duplicate local signature on every `populate`.
        context
            .set_key_list_mode(gpgme::KeyListMode::LOCAL | gpgme::KeyListMode::SIGS)
            .map_err(|source| Error::gpgme(&self.home, "set key list mode for", source))?;
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

        context
            .add_signer(&master)
            .map_err(|source| self.agent_error("select the master key as signer", &source))?;
        context
            .sign_key_with_flags(
                &target,
                std::iter::empty::<String>(),
                Duration::ZERO,
                gpgme::KeySigningFlags::LOCAL,
            )
            .map_err(|source| self.agent_error("locally sign", &source))?;
        Ok(true)
    }

    /// Sets ownertrust on `fingerprint`.
    ///
    /// A no-op if the key already carries `level`. It then returns `false` rather than setting it
    /// again, as [`Self::lsign`] and [`Self::disable`] do.
    ///
    /// Each call that is not a no-op drives a whole `gpgme_op_interact` session. `populate` calls
    /// this once per `-trusted` line on every run. So an already-populated keyring runs none of
    /// those sessions. The no-op is also what makes `PopulateSummary::trust_set` count keys the
    /// call changed, rather than lines it read.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] if `fingerprint` is not in the keyring. [`Error::Gpgme`] if `level`
    /// is [`OwnerTrust::Unknown`] or [`OwnerTrust::Undefined`]. Neither is settable through
    /// GnuPG's trust menu.
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
                gpgme::Data::new().map_err(|source| {
                    Error::gpgme(&self.home, "allocate a scratch buffer", source)
                })?,
            )
            .map_err(|source| Error::gpgme(&self.home, "set ownertrust on", source))?;
        Ok(true)
    }

    /// Disables `fingerprint`: GnuPG will not use it to satisfy a signature check, without removing
    /// it.
    ///
    /// A no-op if already disabled — returns `false` rather than disabling again, for the same
    /// counting reason [`Self::lsign`] does.
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
                gpgme::Data::new().map_err(|source| {
                    Error::gpgme(&self.home, "allocate a scratch buffer", source)
                })?,
            )
            .map_err(|source| Error::gpgme(&self.home, "disable", source))?;
        Ok(true)
    }

    /// Deletes the public key `fingerprint`.
    ///
    /// `allow_secret` must be `true` to also delete a matching secret key. That covers piko's own
    /// master key, so it is never removed by accident.
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
        context
            .delete_key_with_flags(&target, flags)
            .map_err(|source| Error::gpgme(&self.home, "delete", source))
    }

    /// Every public key currently in the keyring.
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] if GnuPG cannot be run.
    pub fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        self.find_keys(&[])
    }

    /// Every public key that matches one of `patterns`.
    ///
    /// An empty `patterns` matches every key, so this is also what [`Self::list_keys`] calls.
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
        let keys = context
            .find_keys(patterns.iter().map(String::as_str))
            .map_err(|source| Error::gpgme(&self.home, "list keys in", source))?;
        keys.map(|key| self.describe(&self.readable(key)?)).collect()
    }

    /// Resolves one key by `keyid`, then describes it.
    ///
    /// `keyid` is a fingerprint, a short or long key ID, an email address, or any other pattern
    /// GnuPG accepts.
    ///
    /// Use this lookup to show a user which key an operation will change. It calls the same key
    /// resolver every mutating operation here calls. A caller that filters [`Self::list_keys`]
    /// instead runs a second resolver, and the two can name different keys.
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
        entry.map_err(|source| Error::gpgme(&self.home, "read a key from", source))
    }

    fn describe(&self, key: &gpgme::Key) -> Result<KeyInfo> {
        let fingerprint = key
            .fingerprint()
            .map_err(|_| Error::gpgme(&self.home, "read the fingerprint of", "not valid UTF-8"))?;
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
    /// --check-trustdb`'s effect).
    ///
    /// GPGME exposes no dedicated operation for this. GnuPG's own trust model already recomputes
    /// validity whenever keys are queried. So a full listing achieves the same thing natively,
    /// without shelling out to `gpg --check-trustdb`.
    ///
    /// # Errors
    ///
    /// [`Error::Gpgme`] if GnuPG cannot be run.
    pub fn update_trustdb(&self) -> Result<()> {
        let mut context = self.context()?;
        let keys =
            context.keys().map_err(|source| Error::gpgme(&self.home, "list keys in", source))?;
        // Walked, not collected. [`Self::list_keys`] would allocate a `KeyInfo` per key, with a
        // `String` per user ID, and drop all of it. GnuPG recomputes validity as it produces
        // each key. The walk alone is therefore the whole effect.
        for key in keys {
            drop(self.readable(key)?);
        }
        Ok(())
    }

    /// Looks up `fingerprint`, or any GnuPG-accepted key identifier. It fails with
    /// [`Error::KeyNotFound`] rather than propagate GPGME's own "ambiguous name"/"not found"
    /// distinction, which no caller here needs.
    fn get_key(&self, context: &mut gpgme::Context, fingerprint: &str) -> Result<gpgme::Key> {
        context.get_key(fingerprint).map_err(|_| Error::KeyNotFound {
            home: self.home.clone(),
            keyid: fingerprint.to_owned(),
        })
    }
}

/// The trust database `pacman-key`'s `check_keyring` insists on reading.
const TRUSTDB: &str = "trustdb.gpg";

/// The mode `pacman-key --init` gives the keyring directory (`pacman-key.sh.in:225`).
const KEYRING_DIR_MODE: u32 = 0o755;

/// The mode `pacman-key --init` gives `pubring.gpg` and `trustdb.gpg`
/// (`pacman-key.sh.in:231`).
const READABLE_MODE: u32 = 0o644;

/// The empty files `pacman-key --init` lays down, with the mode it gives each
/// (`pacman-key.sh.in:228-232`).
///
/// `pubring.gpg` carries the layout decision. GnuPG 2.1 and later create `pubring.kbx` instead,
/// unless a `pubring.gpg` is already there. `pacman-key` tests `-r pubring.gpg` and refuses the
/// keyring outright when it is absent. So a keyring without one is a keyring `pacman-key` cannot
/// read at all.
///
/// `secring.gpg` is a GnuPG 1.x artifact that 2.1 and later ignore; private keys live in
/// `private-keys-v1.d`. `pacman-key` still creates it, and an empty file mode `0600` costs
/// nothing.
const LAYOUT_FILES: &[(&str, u32)] = &[("pubring.gpg", READABLE_MODE), ("secring.gpg", 0o600)];

/// The `gpg.conf` options `pacman-key --init` adds (`pacman-key.sh.in:238-246`).
///
/// `no-self-sigs-only` is left out. `pacman-key` adds it only for GnuPG 2.2.17 and later. And an
/// option GnuPG does not recognize makes *every* later invocation fail rather than warn.
/// The gate costs a version parse for a keyserver option piko never reaches: `piko key` has no
/// `--recv-keys` or `--refresh-keys`.
const GPG_CONF_OPTIONS: &[&str] = &[
    "no-greeting",
    "no-permission-warning",
    "keyserver-options timeout=10",
    "keyserver-options import-clean",
];

/// The `gpg-agent.conf` option `pacman-key --init` adds (`pacman-key.sh.in:252`).
const GPG_AGENT_CONF_OPTIONS: &[&str] = &["disable-scdaemon"];

/// Lays down the files `pacman-key --init` creates beside the keys, if they are absent.
///
/// A file another tool wrote is left exactly as it is, mode included, for the reason
/// [`create_keyring_dir`] gives about the directory itself. Only what this call creates gets
/// a mode from piko.
fn write_layout(home: &Path) -> Result<()> {
    for (name, mode) in LAYOUT_FILES {
        let path = home.join(name);
        // `create_new` is `O_EXCL`, which never follows a symlink. The mode is then set on the
        // descriptor just created, not on the path, which could be swapped in between.
        match no_follow(File::options().write(true).create_new(true)).open(&path) {
            Ok(file) => fchmod(&file, &path, *mode, "set a keyring file's permissions")?,
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(Error::gpgme(path, "create a keyring file", source));
            }
        }
    }

    ensure_conf_options(&home.join("gpg.conf"), GPG_CONF_OPTIONS)?;
    ensure_conf_options(&home.join("gpg-agent.conf"), GPG_AGENT_CONF_OPTIONS)
}

/// The largest `gpg.conf` or `gpg-agent.conf` [`ensure_conf_options`] reads.
///
/// Both files hold a handful of short option lines. A file past this size is not one GnuPG
/// wrote or a user edited, and reading it whole is how an unbounded read starts.
const MAX_CONF_BYTES: u64 = 1024 * 1024;

/// Appends every option of `options` that `path` does not already carry.
///
/// This is `add_gpg_conf_option` (`pacman-key.sh.in:173`). It matches an option already present
/// in any of three shapes: bare, commented out, or followed by a value. So a user who wrote
/// `# no-greeting` or changed a timeout keeps their line, and a repeated `init` appends nothing.
///
/// The file is read and appended through one descriptor, opened `O_NOFOLLOW | O_NONBLOCK` and
/// `fstat`-checked, the properties `piko_db::fs_util` enforces for a read. That module opens
/// read-only, and a second open for the append could land on a different file. A symlink is
/// refused rather than followed, unlike `pacman-key`: `init` runs as root, and a link planted
/// in a keyring directory another user can write to would otherwise create or extend any file
/// on the system.
fn ensure_conf_options(path: &Path, options: &[&str]) -> Result<()> {
    let describe =
        |action: &'static str| move |source: std::io::Error| Error::gpgme(path, action, source);

    let (mut file, created) = match no_follow(File::options().read(true).append(true)).open(path) {
        Ok(file) => (file, false),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            let file = no_follow(File::options().read(true).append(true).create_new(true))
                .open(path)
                .map_err(describe("create a keyring configuration file"))?;
            (file, true)
        }
        Err(source) => return Err(describe("open a keyring configuration file")(source)),
    };
    ensure_regular(&file, path)?;

    let mut current = String::new();
    (&file)
        .take(MAX_CONF_BYTES.saturating_add(1))
        .read_to_string(&mut current)
        .map_err(describe("read a keyring configuration file"))?;
    if current.len() as u64 > MAX_CONF_BYTES {
        return Err(Error::gpgme(
            path,
            "read a keyring configuration file",
            format!("it is larger than {MAX_CONF_BYTES} bytes"),
        ));
    }

    let mut appended = String::new();
    for option in options {
        if current.lines().chain(appended.lines()).any(|line| carries_option(line, option)) {
            continue;
        }
        appended.push_str(option);
        appended.push('\n');
    }

    file.write_all(appended.as_bytes()).map_err(describe("write a keyring configuration file"))?;
    if created {
        fchmod(&file, path, READABLE_MODE, "set a keyring configuration file's permissions")?;
    }
    Ok(())
}

/// Whether `line` already carries `option`, in any of the shapes `add_gpg_conf_option`
/// accepts.
///
/// Its regular expression is `^[[:space:]#]*<option>([[:space:]].*)*$`. That is any run of spaces
/// and `#` first, then the option, then either nothing or a space and anything.
fn carries_option(line: &str, option: &str) -> bool {
    let bare = line.trim_start_matches([' ', '\t', '#']);
    match bare.strip_prefix(option) {
        Some("") => true,
        Some(rest) => rest.starts_with([' ', '\t']),
        None => false,
    }
}

/// Adds `O_NOFOLLOW | O_NONBLOCK` to `options`: a final symlink is refused, and a FIFO does not
/// block the open.
fn no_follow(options: &mut std::fs::OpenOptions) -> &mut std::fs::OpenOptions {
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
}

/// Fails unless `file`, opened from `path`, is a regular file.
fn ensure_regular(file: &File, path: &Path) -> Result<()> {
    let is_file = file.metadata().is_ok_and(|metadata| metadata.is_file());
    if is_file {
        return Ok(());
    }
    Err(Error::gpgme(path, "use a keyring file", "it is not a regular file"))
}

/// Sets `path`'s mode through a descriptor, never through the path.
///
/// `chmod(2)` follows a final symlink. `init` runs as root, so a `trustdb.gpg -> /etc/shadow`
/// link in a keyring directory another user can write to would make that file world-readable.
/// The path is opened `O_NOFOLLOW`, and the mode goes to the descriptor with `fchmod(2)`.
/// Only a regular file or a directory is changed.
fn set_mode(path: &Path, mode: u32, action: &'static str) -> Result<()> {
    let file = no_follow(File::options().read(true))
        .open(path)
        .map_err(|source| Error::gpgme(path, action, source))?;
    let usable = file.metadata().is_ok_and(|metadata| metadata.is_file() || metadata.is_dir());
    if !usable {
        return Err(Error::gpgme(path, action, "it is neither a regular file nor a directory"));
    }
    fchmod(&file, path, mode, action)
}

/// Sets the mode of the open `file`, naming `path` and `action` if that fails.
fn fchmod(file: &File, path: &Path, mode: u32, action: &'static str) -> Result<()> {
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|source| Error::gpgme(path, action, source))
}

/// Creates `home`. Returns `true` if this call created it, and `false` if it already existed.
///
/// [`KeyringAdmin::init`] reads that answer before it sets [`KEYRING_DIR_MODE`]. Only a directory
/// piko created itself gets a mode from piko. An existing keyring keeps its own.
///
/// The mode is `pacman-key --init`'s `0755` (`pacman-key.sh.in:225`), not something stricter. The
/// default `home` is `/etc/pacman.d/gnupg`, a directory piko shares with pacman rather than owns.
/// pacman keeps `pubring.gpg` and `trustdb.gpg` world-readable on purpose, so `--list-keys` and
/// `--verify` work for an unprivileged user. `check_keyring` (`pacman-key.sh.in:262`) refuses the
/// keyring when either stops being readable. A private keyring is not a stricter version of this
/// one. It is one the rest of the system cannot use. Secret key material stays private either
/// way, because GnuPG keeps it in `private-keys-v1.d`, which it creates `0700` itself.
///
/// An existing symlink to a directory counts as existing. pacman-key tests for existence, not for
/// a directory. Its own comment gives the reason: "someone may want to use a symlink here".
fn create_keyring_dir(home: &Path) -> Result<bool> {
    let describe =
        |source: std::io::Error| Error::gpgme(home, "create the keyring directory", source);
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// `pacman-key`'s `check_keyring` (`pacman-key.sh.in:262`) refuses a keyring whose
    /// `pubring.gpg` or `trustdb.gpg` it cannot read. Without both, `archlinux-keyring`'s
    /// `.INSTALL` scriptlet takes its `pacman-key -l` guard as a no and populates nothing. A new
    /// root then ends up with an empty keyring, and cannot verify any later package.
    #[test]
    fn init_lays_down_the_layout_pacman_key_insists_on() {
        let Some(admin) = fast_admin() else { return };
        let home = admin.home().to_path_buf();
        for name in ["pubring.gpg", "secring.gpg", "gpg.conf", "gpg-agent.conf"] {
            std::fs::remove_file(home.join(name)).ok();
        }

        KeyringAdmin::init(&home).unwrap();

        let mode =
            |name: &str| std::fs::metadata(home.join(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("pubring.gpg"), READABLE_MODE);
        assert_eq!(mode("secring.gpg"), 0o600);
        assert_eq!(mode(TRUSTDB), READABLE_MODE);
        assert_eq!(mode("gpg.conf"), READABLE_MODE);
        assert_eq!(mode("gpg-agent.conf"), READABLE_MODE);
    }

    /// The directory is shared with pacman, which needs it readable. A keyring only piko can
    /// open is one `pacman-key` refuses.
    ///
    /// `init` sets the mode before it opens GnuPG, so the mode is checked whether or not the
    /// key generation that follows succeeds here. Only a directory `init` creates gets the
    /// mode, so this is the one test here that pays for a real RSA-4096 key.
    #[test]
    fn a_keyring_piko_creates_is_readable_by_everyone() {
        let parent = tempfile::tempdir().unwrap();
        let home = parent.path().join("gnupg");

        drop(KeyringAdmin::init(&home));

        let mode = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEYRING_DIR_MODE);
    }

    /// A second `init` must append nothing, and must leave a line the user edited alone.
    #[test]
    fn conf_options_are_added_once_and_never_over_an_existing_line() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("gpg.conf");
        std::fs::write(&conf, "# no-greeting\nkeyserver-options timeout=99\n").unwrap();

        ensure_conf_options(&conf, GPG_CONF_OPTIONS).unwrap();
        let after_first = std::fs::read_to_string(&conf).unwrap();
        ensure_conf_options(&conf, GPG_CONF_OPTIONS).unwrap();

        assert_eq!(std::fs::read_to_string(&conf).unwrap(), after_first);
        // Commented out counts as present, exactly as `add_gpg_conf_option` reads it.
        assert_eq!(after_first.lines().filter(|l| l.contains("no-greeting")).count(), 1);
        // `add_gpg_conf_option` matches the whole option *and its value*, so a different
        // value is a different option and both lines end up present. GnuPG takes the last
        // one. This is `pacman-key`'s own behavior, reproduced rather than improved on.
        assert!(after_first.contains("keyserver-options timeout=99"), "{after_first}");
        assert!(after_first.contains("keyserver-options timeout=10"), "{after_first}");
        // An option that was genuinely absent is added.
        assert!(after_first.contains("no-permission-warning"), "{after_first}");
    }

    /// The hint fires only on `NO_AGENT`, and only when the keyring's own path is what prevents a
    /// socket. Both halves matter. A long keyring path is fine wherever the runtime socket
    /// directory exists. A hint that fired on length alone would blame a working keyring.
    #[test]
    fn a_missing_agent_names_the_socket_limit_only_when_the_path_is_the_cause() {
        let long = PathBuf::from("/").join("x".repeat(MAX_AGENT_SOCKET_LEN));
        let admin = KeyringAdmin { home: long.clone() };
        assert!(
            long.join(AGENT_SOCKET).as_os_str().as_encoded_bytes().len() > MAX_AGENT_SOCKET_LEN,
            "the fixture must exceed the limit"
        );

        let named = admin.agent_error("generate the master key", &gpgme::Error::NO_AGENT);
        let other = admin.agent_error("generate the master key", &gpgme::Error::GENERAL);

        assert!(named.to_string().contains("would be"), "{named}");
        assert!(named.to_string().contains("S.gpg-agent"), "{named}");
        assert!(!other.to_string().contains("would be"), "{other}");
    }

    /// A keyring short enough to hold a socket reports what GnuPG said, and nothing more.
    #[test]
    fn a_missing_agent_under_a_short_path_adds_no_hint() {
        let admin = KeyringAdmin { home: PathBuf::from("/tmp/k") };

        let error = admin.agent_error("locally sign", &gpgme::Error::NO_AGENT);

        assert!(!error.to_string().contains("would be"), "{error}");
    }

    /// A `KeyringAdmin` whose master key is ed25519, not `init`'s real RSA-4096. This exercises
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

    /// A second, unrelated keyring holding one ed25519 key, with no secret material in
    /// `fast_admin`'s keyring. It is a "foreign" key to import, sign, and trust. It stands in for
    /// a vendor's packager key the way `archlinux.gpg`'s keys stand in for real ones.
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
    /// Guards a narrow case. An `already_signed` check that requires *every* user ID to carry a
    /// certification can never be satisfied. Certifying only ever covers the primary one. That is
    /// measured; see [`KeyringAdmin::lsign`]'s doc comment. Every `populate` then re-signs the
    /// same key.
    ///
    /// This test pins the intended behavior, but does not on its own prove it. False
    /// idempotency shows up only across separate processes, each with a fresh `gpg-agent`
    /// interaction — not within one already-warmed-up test process. Run `piko key lsign-key`
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
        let absent = "0".repeat(40);
        let err = admin.lsign(&absent).unwrap_err();
        assert!(matches!(err, Error::KeyNotFound { .. }), "{err:?}");
        let err = admin.set_owner_trust(&absent, OwnerTrust::Full).unwrap_err();
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
        // `init` against an already-initialized keyring must find it, rather than generate a
        // second master key. `fast_admin`'s own ed25519 key stands in for a real one here.
        let (_, outcome) = KeyringAdmin::init(admin.home()).unwrap();
        assert!(!outcome.master_key_created, "{outcome:?}");
    }

    /// A symlink planted as a keyring configuration file is refused. Nothing outside the
    /// keyring is created, extended, or re-moded, whether the link dangles or names an existing
    /// file. `init` runs as root; followed, either link writes wherever its owner points it.
    #[test]
    fn init_refuses_a_symlinked_configuration_file_and_touches_nothing_outside() {
        let Some(admin) = fast_admin() else { return };
        let home = admin.home().to_path_buf();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, "secret\n").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        let dangling = outside.path().join("created-by-init");

        for (name, target) in [("gpg.conf", &dangling), ("gpg-agent.conf", &victim)] {
            for file in ["gpg.conf", "gpg-agent.conf"] {
                std::fs::remove_file(home.join(file)).ok();
            }
            std::os::unix::fs::symlink(target, home.join(name)).unwrap();

            let err = KeyringAdmin::init(&home).unwrap_err();
            assert!(matches!(err, Error::Gpgme { .. }), "{name}: {err:?}");
            std::fs::remove_file(home.join(name)).unwrap();
        }

        assert!(!dangling.exists(), "init created a file through a dangling link");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "secret\n");
        let mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// `trustdb.gpg` is re-moded on every `init`, including one over an existing keyring. A
    /// link planted there must not carry the `0644` to the file it names.
    #[test]
    fn init_does_not_remode_the_target_of_a_symlinked_trust_database() {
        let Some(admin) = fast_admin() else { return };
        let home = admin.home().to_path_buf();
        KeyringAdmin::init(&home).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("trustdb.gpg");
        // A copy of the real trust database, so GnuPG itself can still read through the link.
        std::fs::copy(home.join(TRUSTDB), &victim).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(home.join(TRUSTDB)).unwrap();
        std::os::unix::fs::symlink(&victim, home.join(TRUSTDB)).unwrap();

        assert!(KeyringAdmin::init(&home).is_err(), "a symlinked trust database was accepted");

        let mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "init changed the mode of a file outside the keyring");
    }

    /// `set_mode` refuses a symlink rather than changing what it names.
    #[test]
    fn set_mode_does_not_follow_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        assert!(set_mode(&link, READABLE_MODE, "test").is_err());
        let mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// Whether the keyring's master key has no expiry date.
    fn master_never_expires(admin: &KeyringAdmin) -> bool {
        let mut context = admin.context().unwrap();
        let master = admin.find_master_key(&mut context).unwrap().unwrap();
        master.primary_key().unwrap().never_expires()
    }

    /// `fast_admin` generates its key the way a zero duration without `NOEXPIRE` does, so it
    /// carries GnuPG's default expiry. `init` must remove it once, and report that it did.
    #[test]
    fn init_removes_an_expiry_date_from_an_existing_master_key() {
        let Some(admin) = fast_admin() else { return };
        assert!(!master_never_expires(&admin), "the fixture must start with an expiring key");

        let (_, first) = KeyringAdmin::init(admin.home()).unwrap();
        assert!(first.master_key_expiry_removed, "{first:?}");
        assert!(master_never_expires(&admin), "the master key still expires after init");

        let (_, second) = KeyringAdmin::init(admin.home()).unwrap();
        assert!(!second.master_key_expiry_removed, "a second init must change nothing");
    }

    /// `import` streams its file through the audited door. A FIFO is refused rather than
    /// opened for a read that blocks until a writer appears.
    #[test]
    fn import_refuses_a_fifo_without_blocking() {
        let Some(admin) = fast_admin() else { return };
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("keys.gpg");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|status| status.success());
        if !made {
            return;
        }
        let err = admin.import(&fifo).unwrap_err();
        assert!(matches!(err, Error::Gpgme { .. }), "{err:?}");
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

    /// `init` sets the directory's mode only when this answer says the directory is new. The
    /// mode itself is `a_keyring_piko_creates_is_readable_by_everyone`'s subject, and leaving
    /// an existing keyring's mode alone is `init_does_not_remode_an_existing_keyring`'s.
    #[test]
    fn create_keyring_dir_reports_whether_it_created_the_directory() {
        let parent = tempfile::tempdir().unwrap();
        // Two levels deep, so this exercises the `create_dir_all` branch.
        let home = parent.path().join("missing").join("gnupg");
        assert!(create_keyring_dir(&home).unwrap(), "a fresh directory must report as created");
        assert!(home.is_dir());
        assert!(!create_keyring_dir(&home).unwrap(), "the second call must report as existing");
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
