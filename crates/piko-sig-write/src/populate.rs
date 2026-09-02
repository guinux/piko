//! `populate`: importing a vendor's keyring and granting it trust in one step.
//!
//! Reads the same three files pacman-key's own `--populate` reads from
//! `/usr/share/pacman/keyrings` (shipped by the `archlinux-keyring` package): `<name>.gpg`
//! (the key material), `<name>-trusted` (which fingerprints to certify and how much to trust
//! them), and `<name>-revoked` (which fingerprints to disable). piko invents no format of its
//! own here — these three files, and their `FINGERPRINT:LEVEL:` / bare-fingerprint layouts,
//! are GnuPG's own `--export-ownertrust` dump format and a plain fingerprint list,
//! respectively. No upstream crate parses either, so the two line parsers below are hand-rolled.

use std::path::Path;

use crate::{
    admin::{ImportSummary, KeyringAdmin, OwnerTrust},
    error::{Error, Result},
};

/// Which side file a [`SkippedLine`] came from.
///
/// A line number alone does not locate a line, because `populate` reads two files. Line 4 of
/// `<name>-trusted` and line 4 of `<name>-revoked` need to stay apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SideFile {
    /// `<name>-trusted`.
    Trusted,
    /// `<name>-revoked`.
    Revoked,
}

impl SideFile {
    /// The suffix this file's name carries after the keyring name.
    ///
    /// The caller joins it to the keyring name. `populate` does not render the file name
    /// itself, because a caller may already print that name for other reasons.
    #[must_use]
    pub fn suffix(self) -> &'static str {
        match self {
            Self::Trusted => "-trusted",
            Self::Revoked => "-revoked",
        }
    }
}

/// One line of a side file that [`KeyringAdmin::populate`] could not act on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkippedLine {
    /// Which side file holds the line.
    pub file: SideFile,
    /// The line number, counting from 1.
    pub line: usize,
    /// Why `populate` skipped the line.
    pub reason: String,
}

/// A summary of one [`KeyringAdmin::populate`] call.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PopulateSummary {
    /// The `<name>.gpg` import's own summary.
    pub imported: ImportSummary,
    /// How many fingerprints from `<name>-trusted` were newly locally signed.
    pub lsigned: usize,
    /// How many fingerprints from `<name>-trusted` had their ownertrust changed. A key that
    /// already carries the level the file names does not count, as
    /// [`KeyringAdmin::set_owner_trust`] explains.
    pub trust_set: usize,
    /// How many fingerprints from `<name>-revoked` were newly disabled.
    pub disabled: usize,
    /// Every line `populate` could not act on, in the order it read them.
    ///
    /// A line lands here for one of two reasons. It does not parse, or it names a fingerprint
    /// the keyring does not hold. Nothing else lands here: a GnuPG failure is an error, not a
    /// skipped line. See [`KeyringAdmin::populate`].
    pub skipped: Vec<SkippedLine>,
}

impl KeyringAdmin {
    /// Imports `<keyrings_dir>/<name>.gpg`, then locally signs and trusts every fingerprint
    /// `<name>-trusted` lists, then disables every fingerprint `<name>-revoked` lists. Either
    /// side file being absent is not an error — plenty of real keyrings ship no revocations.
    ///
    /// Both loops treat a failure the same way. A fingerprint the keyring does not hold becomes
    /// a [`SkippedLine`]. A side file may outlive a key a later keyring update pruned from
    /// `<name>.gpg`. Every other failure stops the call. Such a failure means GnuPG itself is
    /// broken, or the keyring is unwritable. The next line would fail the same way.
    ///
    /// # Errors
    ///
    /// [`Error::PopulateFile`] if `<name>.gpg` itself is missing or unreadable.
    /// [`Error::NoMasterKey`] if [`KeyringAdmin::init`] was never run — checked up front, before
    /// anything is imported, so a populate that cannot finish does not leave a half-trusted
    /// keyring. Any other [`Error`] a keyring operation raises, per the rule above.
    pub fn populate(&self, keyrings_dir: &Path, name: &str) -> Result<PopulateSummary> {
        let gpg_path = keyrings_dir.join(format!("{name}.gpg"));
        if !gpg_path.is_file() {
            return Err(Error::PopulateFile { path: gpg_path, reason: "not a file".to_owned() });
        }
        // Resolved up front and discarded: proves a master key exists before anything is
        // imported, matching `lsign`'s own check but failing before the import step rather
        // than partway through the trusted-file loop.
        self.require_master_key()?;

        let mut summary =
            PopulateSummary { imported: self.import(&gpg_path)?, ..PopulateSummary::default() };

        let trusted_path = keyrings_dir.join(format!("{name}-trusted"));
        if let Some(contents) = read_side_file(&trusted_path)? {
            for (index, line) in contents.lines().enumerate() {
                let line_number = index.saturating_add(1);
                let mut skip = |reason: String| {
                    summary.skipped.push(SkippedLine {
                        file: SideFile::Trusted,
                        line: line_number,
                        reason,
                    });
                };
                match parse_trusted_line(line) {
                    Ok(None) => {}
                    Err(reason) => skip(reason.to_owned()),
                    Ok(Some(entry)) => match self.populate_trusted_entry(&entry)? {
                        Some((lsigned, trust_set)) => {
                            summary.lsigned = summary.lsigned.saturating_add(usize::from(lsigned));
                            summary.trust_set =
                                summary.trust_set.saturating_add(usize::from(trust_set));
                        }
                        None => skip(not_in_keyring(&entry.fingerprint)),
                    },
                }
            }
        }

        let revoked_path = keyrings_dir.join(format!("{name}-revoked"));
        if let Some(contents) = read_side_file(&revoked_path)? {
            for (index, line) in contents.lines().enumerate() {
                let line_number = index.saturating_add(1);
                let mut skip = |reason: String| {
                    summary.skipped.push(SkippedLine {
                        file: SideFile::Revoked,
                        line: line_number,
                        reason,
                    });
                };
                match parse_revoked_line(line) {
                    Ok(None) => {}
                    Err(reason) => skip(reason.to_owned()),
                    Ok(Some(fingerprint)) => match self.disable(&fingerprint) {
                        Ok(disabled) => {
                            summary.disabled =
                                summary.disabled.saturating_add(usize::from(disabled));
                        }
                        Err(Error::KeyNotFound { .. }) => skip(not_in_keyring(&fingerprint)),
                        Err(other) => return Err(other),
                    },
                }
            }
        }

        Ok(summary)
    }

    /// Locally signs and trusts one `-trusted` entry. `Ok(None)` means the keyring does not hold
    /// that fingerprint, which the caller records as a [`SkippedLine`].
    ///
    /// This mirrors how the `-revoked` loop reads [`Self::disable`]. Both turn
    /// [`Error::KeyNotFound`] into a skipped line, and pass every other error to the caller. A
    /// broken GnuPG must not read as a list of skipped lines and an exit code of `0`.
    ///
    /// # Errors
    ///
    /// Any [`Error`] other than [`Error::KeyNotFound`], from [`Self::lsign`] or
    /// [`Self::set_owner_trust`].
    fn populate_trusted_entry(&self, entry: &TrustedLine) -> Result<Option<(bool, bool)>> {
        let lsigned = match self.lsign(&entry.fingerprint) {
            Ok(lsigned) => lsigned,
            Err(Error::KeyNotFound { .. }) => return Ok(None),
            Err(other) => return Err(other),
        };
        let trust_set = self.set_owner_trust(&entry.fingerprint, entry.level)?;
        Ok(Some((lsigned, trust_set)))
    }

    /// Checks a master key exists, discarding it — [`Self::master_key`] under a name that
    /// reads plainly at the one call site that doesn't need the key itself.
    fn require_master_key(&self) -> Result<()> {
        let mut context = self.context()?;
        self.master_key(&mut context).map(drop)
    }
}

/// The skip reason both loops record for a fingerprint the keyring does not hold. One function,
/// so the two loops cannot word the same case differently.
fn not_in_keyring(fingerprint: &str) -> String {
    format!("{fingerprint} is not in the keyring")
}

/// Reads an optional `-trusted` or `-revoked` side file. `None` means the file does not exist,
/// which is not an error. Many real keyrings ship no revocations.
///
/// Only `NotFound` counts as absent. This function reports every other failure. An unreadable
/// `-trusted` file otherwise looks like an absent one. The keyring then trusts no key, and no
/// package can verify against it, yet piko reports success. Design principle 3 rules out that
/// "cached emptiness".
///
/// # Errors
///
/// [`Error::PopulateFile`] for any failure other than the file not existing.
fn read_side_file(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => {
            Err(Error::PopulateFile { path: path.to_path_buf(), reason: source.to_string() })
        }
    }
}

/// One parsed `<name>-trusted` line: `FINGERPRINT:LEVEL:`.
struct TrustedLine {
    fingerprint: String,
    level: OwnerTrust,
}

/// A side file names a key by hex digits, and by nothing else.
///
/// Both files feed GPGME's `get_key`, which resolves a pattern. A pattern matches a user ID
/// substring too. A line reading `vendor@example.invalid:6:` would therefore locally sign
/// whichever key matches, and would grant it Ultimate ownertrust. The next keyring update could
/// bind the same line to a different key. pacman-key cannot express such a line: it pipes the
/// file into `gpg --import-ownertrust`, which takes a key rather than a pattern. The hex-only
/// rule restores that contract.
///
/// A short key ID still parses. GnuPG resolves it as a key ID, not as a text search, and
/// rejects an ambiguous one as [`Error::KeyNotFound`].
fn parse_key_reference(line: &str) -> std::result::Result<&str, &'static str> {
    if line.is_empty() {
        return Err("missing fingerprint field");
    }
    if !line.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("not a hex fingerprint");
    }
    Ok(line)
}

/// Parses one line of a `-trusted` file (GnuPG's `--export-ownertrust` dump format:
/// `FINGERPRINT:LEVEL:`, `#`-comments and blank lines allowed, confirmed against a real
/// `/usr/share/pacman/keyrings/archlinux-trusted`).
///
/// `Ok(None)` for a blank or comment line. `Err` for a line that is neither blank, a comment,
/// nor a well-formed entry.
fn parse_trusted_line(line: &str) -> std::result::Result<Option<TrustedLine>, &'static str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let mut fields = line.split(':');
    let fingerprint = parse_key_reference(fields.next().unwrap_or_default())?;
    let level = fields.next().ok_or("missing trust-level field")?;
    let level: u8 = level.parse().map_err(|_| "trust level is not a number")?;
    let level = OwnerTrust::from_file_code(level).ok_or("trust level out of range 1..=6")?;
    Ok(Some(TrustedLine { fingerprint: fingerprint.to_owned(), level }))
}

/// Parses one line of a `-revoked` file: a bare fingerprint per line, `#`-comments and blank
/// lines allowed.
fn parse_revoked_line(line: &str) -> std::result::Result<Option<String>, &'static str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    Ok(Some(parse_key_reference(line)?.to_owned()))
}

/// Every `<name>.gpg` stem directly under `keyrings_dir`, sorted — used when `piko-key
/// populate` is given no names, matching pacman-key's own glob-everything default.
///
/// # Errors
///
/// [`Error::PopulateFile`] if `keyrings_dir` cannot be listed.
pub fn discover_keyrings(keyrings_dir: &Path) -> Result<Vec<String>> {
    let entries = std::fs::read_dir(keyrings_dir).map_err(|source| Error::PopulateFile {
        path: keyrings_dir.to_path_buf(),
        reason: source.to_string(),
    })?;
    // Only `.gpg` stems: a directory also holds `<name>-trusted`/`<name>-revoked`, whose
    // stems are not themselves populatable keyring names.
    let mut names: Vec<String> = entries
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("gpg"))
        .filter_map(|entry| {
            entry.path().file_stem().and_then(|stem| stem.to_str()).map(str::to_owned)
        })
        .collect();
    names.sort();
    Ok(names)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::{os::unix::fs::PermissionsExt as _, time::Duration};

    use super::*;
    use crate::admin::MASTER_KEY_USERID;

    /// Builds a keyring with an ed25519 master key (fast, unlike `init`'s real RSA-4096), a
    /// second "vendor" ed25519 key exported to `<keyrings_dir>/<name>.gpg`, and matching
    /// `-trusted`/`-revoked` files — everything one `populate(keyrings_dir, name)` call reads.
    /// `None` if GnuPG cannot be reached here, the same graceful skip used throughout this
    /// crate's tests.
    fn populate_fixture(name: &str) -> Option<(KeyringAdmin, tempfile::TempDir, String)> {
        let admin_home = tempfile::tempdir().ok()?;
        std::fs::set_permissions(admin_home.path(), std::fs::Permissions::from_mode(0o700)).ok()?;
        let mut admin_context = piko_sig::open_context(admin_home.path()).ok()?;
        admin_context
            .create_key_with_flags(
                MASTER_KEY_USERID,
                "ed25519",
                Duration::ZERO,
                gpgme::CreateKeyFlags::CERT | gpgme::CreateKeyFlags::NOPASSWD,
            )
            .ok()?;
        let admin = KeyringAdmin::open(admin_home.path()).ok()?;
        std::mem::forget(admin_home);

        let vendor_home = tempfile::tempdir().ok()?;
        std::fs::set_permissions(vendor_home.path(), std::fs::Permissions::from_mode(0o700))
            .ok()?;
        let mut vendor_context = piko_sig::open_context(vendor_home.path()).ok()?;
        let generated = vendor_context
            .create_key_with_flags(
                "vendor packager <vendor@example.invalid>",
                "ed25519",
                Duration::ZERO,
                gpgme::CreateKeyFlags::SIGN | gpgme::CreateKeyFlags::NOPASSWD,
            )
            .ok()?;
        let fingerprint = generated.fingerprint().ok()?.to_owned();
        let vendor_key = vendor_context.get_key(&fingerprint).ok()?;
        let mut exported = gpgme::Data::new().ok()?;
        vendor_context
            .export_keys([&vendor_key], gpgme::ExportMode::empty(), &mut exported)
            .ok()?;

        let keyrings_dir = tempfile::tempdir().ok()?;
        std::fs::write(keyrings_dir.path().join(format!("{name}.gpg")), exported.try_into_bytes()?)
            .ok()?;
        std::fs::write(
            keyrings_dir.path().join(format!("{name}-trusted")),
            format!("{fingerprint}:4:\n"),
        )
        .ok()?;
        // A stale entry that is not in `<name>.gpg` at all — `populate` must skip it, not fail.
        std::fs::write(keyrings_dir.path().join(format!("{name}-revoked")), "0".repeat(40)).ok()?;

        Some((admin, keyrings_dir, fingerprint))
    }

    #[test]
    fn populate_imports_locally_signs_and_trusts_from_real_files() {
        let Some((admin, keyrings_dir, fingerprint)) = populate_fixture("vendor") else { return };

        let summary = admin.populate(keyrings_dir.path(), "vendor").unwrap();
        assert_eq!(summary.imported.imported, 1);
        assert_eq!(summary.lsigned, 1);
        assert_eq!(summary.trust_set, 1);
        assert_eq!(summary.disabled, 0);
        // The fixture's one stale line is in `-revoked`, and the summary must say so.
        assert_eq!(
            summary.skipped,
            vec![SkippedLine {
                file: SideFile::Revoked,
                line: 1,
                reason: not_in_keyring(&"0".repeat(40)),
            }],
        );

        let keys = admin.list_keys().unwrap();
        let vendor_key = keys.iter().find(|key| key.fingerprint == fingerprint).unwrap();
        assert_eq!(vendor_key.owner_trust, OwnerTrust::Marginal);

        // A second run must change nothing, and must count nothing.
        let second = admin.populate(keyrings_dir.path(), "vendor").unwrap();
        assert_eq!(second.lsigned, 0, "the second populate must find the key already lsigned");
        assert_eq!(second.trust_set, 0, "the second populate must find the ownertrust already set");
    }

    /// A line number locates a line only together with its file. Both side files can hold a
    /// bad line at the same number.
    #[test]
    fn a_skipped_line_names_which_side_file_it_came_from() {
        let Some((admin, keyrings_dir, _)) = populate_fixture("both") else { return };
        // Line 1 of each file is unusable.
        std::fs::write(keyrings_dir.path().join("both-trusted"), "nothex:4:\n").unwrap();
        std::fs::write(keyrings_dir.path().join("both-revoked"), "also-not-hex\n").unwrap();

        let summary = admin.populate(keyrings_dir.path(), "both").unwrap();

        assert_eq!(
            summary.skipped,
            vec![
                SkippedLine {
                    file: SideFile::Trusted,
                    line: 1,
                    reason: "not a hex fingerprint".to_owned(),
                },
                SkippedLine {
                    file: SideFile::Revoked,
                    line: 1,
                    reason: "not a hex fingerprint".to_owned(),
                },
            ],
        );
    }

    /// Both loops must answer a missing key the same way. Each records a skipped line, and
    /// neither fails the whole call.
    #[test]
    fn both_side_files_skip_a_fingerprint_the_keyring_does_not_hold() {
        let Some((admin, keyrings_dir, _)) = populate_fixture("absent") else { return };
        let absent = "A".repeat(40);
        std::fs::write(keyrings_dir.path().join("absent-trusted"), format!("{absent}:4:\n"))
            .unwrap();
        std::fs::write(keyrings_dir.path().join("absent-revoked"), format!("{absent}\n")).unwrap();

        let summary = admin.populate(keyrings_dir.path(), "absent").unwrap();

        assert_eq!(summary.lsigned, 0);
        assert_eq!(summary.disabled, 0);
        assert_eq!(
            summary.skipped.iter().map(|entry| entry.file).collect::<Vec<_>>(),
            vec![SideFile::Trusted, SideFile::Revoked],
        );
        for entry in &summary.skipped {
            assert_eq!(entry.reason, not_in_keyring(&absent), "{entry:?}");
        }
    }

    #[test]
    fn populate_refuses_a_missing_gpg_file() {
        let Some((admin, keyrings_dir, _)) = populate_fixture("vendor") else { return };
        let err = admin.populate(keyrings_dir.path(), "no-such-keyring").unwrap_err();
        assert!(matches!(err, Error::PopulateFile { .. }), "{err:?}");
    }

    #[test]
    fn discover_keyrings_finds_only_gpg_stems() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("archlinux.gpg"), b"").unwrap();
        std::fs::write(dir.path().join("archlinux-trusted"), b"").unwrap();
        std::fs::write(dir.path().join("archlinux-revoked"), b"").unwrap();
        std::fs::write(dir.path().join("other.gpg"), b"").unwrap();

        assert_eq!(
            discover_keyrings(dir.path()).unwrap(),
            vec!["archlinux".to_owned(), "other".to_owned()]
        );
    }

    #[test]
    fn parses_a_real_trusted_line() {
        let entry =
            parse_trusted_line("2AC0A42EFB0B5CBC7A0402ED4DC95B6D7BE9892E:4:").unwrap().unwrap();
        assert_eq!(entry.fingerprint, "2AC0A42EFB0B5CBC7A0402ED4DC95B6D7BE9892E");
        assert_eq!(entry.level, OwnerTrust::Marginal);
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        assert!(parse_trusted_line("").unwrap().is_none());
        assert!(parse_trusted_line("   ").unwrap().is_none());
        assert!(parse_trusted_line("# a comment").unwrap().is_none());
        assert!(parse_revoked_line("").unwrap().is_none());
        assert!(parse_revoked_line("# a comment").unwrap().is_none());
    }

    #[test]
    fn refuses_a_malformed_trusted_line() {
        assert!(parse_trusted_line("not-a-fingerprint").is_err());
        assert!(parse_trusted_line("ABCDEF:not-a-number:").is_err());
        assert!(parse_trusted_line("ABCDEF:9:").is_err());
        assert!(parse_trusted_line(":4:").is_err());
    }

    /// A `-trusted` fingerprint reaches GPGME's `get_key`, which resolves a pattern. A pattern
    /// matches a user ID substring too. Both side files must therefore accept hex only. One
    /// such line would otherwise locally sign and trust whichever key matches. See
    /// [`parse_key_reference`].
    #[test]
    fn refuses_a_trusted_line_naming_a_user_id_instead_of_a_fingerprint() {
        assert!(parse_trusted_line("vendor@example.invalid:6:").is_err());
        assert!(parse_trusted_line("Vendor Packager:6:").is_err());
        assert!(parse_revoked_line("vendor@example.invalid").is_err());
    }

    /// [`read_side_file`] exists for this case. An unreadable `-trusted` file must not look
    /// like a vendor that ships no trust list.
    #[test]
    fn an_unreadable_trusted_file_is_not_silently_treated_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archlinux-trusted");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        // The mode has no effect for root, so assert the distinction only when it holds.
        if std::fs::read_to_string(&path).is_ok() {
            return;
        }
        let err = read_side_file(&path).unwrap_err();
        assert!(matches!(err, Error::PopulateFile { .. }), "{err:?}");

        assert!(read_side_file(&dir.path().join("absent")).unwrap().is_none());
    }

    #[test]
    fn parses_a_real_revoked_line() {
        let fingerprint =
            parse_revoked_line("0A9DDABB64B993D82AD45E4F32EAB0A976938292").unwrap().unwrap();
        assert_eq!(fingerprint, "0A9DDABB64B993D82AD45E4F32EAB0A976938292");
    }

    #[test]
    fn refuses_a_non_hex_revoked_line() {
        assert!(parse_revoked_line("not hex at all").is_err());
    }
}
