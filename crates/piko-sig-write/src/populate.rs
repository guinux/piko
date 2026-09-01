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

/// A summary of one [`KeyringAdmin::populate`] call.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PopulateSummary {
    /// The `<name>.gpg` import's own summary.
    pub imported: ImportSummary,
    /// How many fingerprints from `<name>-trusted` were newly locally signed.
    pub lsigned: usize,
    /// How many fingerprints from `<name>-trusted` had their ownertrust set.
    pub trust_set: usize,
    /// How many fingerprints from `<name>-revoked` were newly disabled.
    pub disabled: usize,
    /// `(line number, reason)` for any `-trusted`/`-revoked` line that named a fingerprint not
    /// present in the keyring, or that could not be parsed.
    pub skipped: Vec<(usize, String)>,
}

impl KeyringAdmin {
    /// Imports `<keyrings_dir>/<name>.gpg`, then locally signs and trusts every fingerprint
    /// `<name>-trusted` lists, then disables every fingerprint `<name>-revoked` lists. Either
    /// side file being absent is not an error — plenty of real keyrings ship no revocations.
    ///
    /// # Errors
    ///
    /// [`Error::PopulateFile`] if `<name>.gpg` itself is missing or unreadable.
    /// [`Error::NoMasterKey`] if [`KeyringAdmin::init`] was never run — checked up front, before
    /// anything is imported, so a populate that cannot finish does not leave a half-trusted
    /// keyring.
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
        if let Ok(contents) = std::fs::read_to_string(&trusted_path) {
            for (index, line) in contents.lines().enumerate() {
                let line_number = index.saturating_add(1);
                match parse_trusted_line(line) {
                    Ok(None) => {}
                    Err(reason) => summary.skipped.push((line_number, reason.to_owned())),
                    Ok(Some(entry)) => match self.populate_trusted_entry(&entry) {
                        Ok((lsigned, trust_set)) => {
                            summary.lsigned = summary.lsigned.saturating_add(usize::from(lsigned));
                            summary.trust_set =
                                summary.trust_set.saturating_add(usize::from(trust_set));
                        }
                        Err(reason) => summary.skipped.push((line_number, reason)),
                    },
                }
            }
        }

        let revoked_path = keyrings_dir.join(format!("{name}-revoked"));
        if let Ok(contents) = std::fs::read_to_string(&revoked_path) {
            for (index, line) in contents.lines().enumerate() {
                let line_number = index.saturating_add(1);
                match parse_revoked_line(line) {
                    Ok(None) => {}
                    Err(reason) => summary.skipped.push((line_number, reason.to_owned())),
                    Ok(Some(fingerprint)) => match self.disable(&fingerprint) {
                        Ok(disabled) => {
                            summary.disabled =
                                summary.disabled.saturating_add(usize::from(disabled));
                        }
                        Err(Error::KeyNotFound { .. }) => {
                            summary.skipped.push((
                                line_number,
                                format!("{fingerprint} is not in the keyring"),
                            ));
                        }
                        Err(other) => return Err(other),
                    },
                }
            }
        }

        Ok(summary)
    }

    /// Locally signs and trusts one `-trusted` entry, skipping (not failing) a fingerprint the
    /// keyring does not have — a `-trusted` file may legitimately outlive a key that was
    /// pruned from `<name>.gpg` in a later keyring update.
    fn populate_trusted_entry(
        &self,
        entry: &TrustedLine,
    ) -> std::result::Result<(bool, bool), String> {
        let lsigned = match self.lsign(&entry.fingerprint) {
            Ok(lsigned) => lsigned,
            Err(Error::KeyNotFound { .. }) => {
                return Err(format!("{} is not in the keyring", entry.fingerprint));
            }
            Err(other) => return Err(other.to_string()),
        };
        self.set_owner_trust(&entry.fingerprint, entry.level).map_err(|error| error.to_string())?;
        Ok((lsigned, true))
    }

    /// Checks a master key exists, discarding it — [`Self::master_key`] under a name that
    /// reads plainly at the one call site that doesn't need the key itself.
    fn require_master_key(&self) -> Result<()> {
        let mut context = self.context()?;
        self.master_key(&mut context).map(drop)
    }
}

/// One parsed `<name>-trusted` line: `FINGERPRINT:LEVEL:`.
struct TrustedLine {
    fingerprint: String,
    level: OwnerTrust,
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
    let fingerprint = fields.next().filter(|s| !s.is_empty()).ok_or("missing fingerprint field")?;
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
    if !line.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("not a hex fingerprint");
    }
    Ok(Some(line.to_owned()))
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
        assert_eq!(summary.skipped.len(), 1, "{:?}", summary.skipped);

        let keys = admin.list_keys().unwrap();
        let vendor_key = keys.iter().find(|key| key.fingerprint == fingerprint).unwrap();
        assert_eq!(vendor_key.owner_trust, OwnerTrust::Marginal);

        // Running it again must not error, duplicate the lsign, or re-count the trust set.
        let second = admin.populate(keyrings_dir.path(), "vendor").unwrap();
        assert_eq!(second.lsigned, 0, "the second populate must find the key already lsigned");
        assert_eq!(second.trust_set, 1, "ownertrust is set unconditionally, but stays idempotent");
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
