//! One function per subcommand.

use std::{path::Path, process::ExitCode};

use piko_sig_write::{KeyInfo, KeyringAdmin};

use crate::output::{confirm, emit, report};

/// `piko-key init`.
pub fn init(gpgdir: &Path, out: &mut impl std::io::Write) -> ExitCode {
    match KeyringAdmin::init(gpgdir) {
        Ok((_, outcome)) => {
            if outcome.master_key_created {
                emit!(out, "generated a new master signing key in {}", gpgdir.display());
            } else {
                emit!(out, "{} is already initialized", gpgdir.display());
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}

/// `piko-key populate`.
pub fn populate(
    gpgdir: &Path,
    keyring_dir: &Path,
    names: &[String],
    out: &mut impl std::io::Write,
) -> ExitCode {
    let admin = match KeyringAdmin::open(gpgdir) {
        Ok(admin) => admin,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    let names = if names.is_empty() {
        match piko_sig_write::discover_keyrings(keyring_dir) {
            Ok(names) => names,
            Err(error) => {
                report(&error);
                return ExitCode::FAILURE;
            }
        }
    } else {
        names.to_vec()
    };

    if names.is_empty() {
        emit!(out, "no keyrings found under {}", keyring_dir.display());
        return ExitCode::SUCCESS;
    }

    for name in &names {
        match admin.populate(keyring_dir, name) {
            Ok(summary) => {
                emit!(
                    out,
                    "{name}: imported {}, locally signed {}, trusted {}, disabled {}",
                    summary.imported.imported,
                    summary.lsigned,
                    summary.trust_set,
                    summary.disabled,
                );
                for (line, reason) in &summary.skipped {
                    emit!(out, "  {name}-trusted/{name}-revoked:{line}: {reason}");
                }
            }
            Err(error) => {
                report(&error);
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// `piko-key add`.
pub fn add(gpgdir: &Path, files: &[std::path::PathBuf], out: &mut impl std::io::Write) -> ExitCode {
    let admin = match KeyringAdmin::open(gpgdir) {
        Ok(admin) => admin,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    for file in files {
        match admin.import(file) {
            Ok(summary) => {
                emit!(
                    out,
                    "{}: imported {}, unchanged {}",
                    file.display(),
                    summary.imported,
                    summary.unchanged
                );
            }
            Err(error) => {
                report(&error);
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// `piko-key lsign-key`.
pub fn lsign_key(
    gpgdir: &Path,
    keyids: &[String],
    noconfirm: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let admin = match KeyringAdmin::open(gpgdir) {
        Ok(admin) => admin,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    for keyid in keyids {
        if let Some(code) = confirm_trust_action(&admin, keyid, "locally sign", noconfirm, out) {
            return code;
        }
        match admin.lsign(keyid) {
            Ok(true) => emit!(out, "locally signed {keyid}"),
            Ok(false) => emit!(out, "{keyid} is already locally signed"),
            Err(error) => {
                report(&error);
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// `piko-key list-keys`.
pub fn list_keys(gpgdir: &Path, keyids: &[String], out: &mut impl std::io::Write) -> ExitCode {
    let admin = match KeyringAdmin::open(gpgdir) {
        Ok(admin) => admin,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    let keys = match admin.list_keys() {
        Ok(keys) => keys,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    let matches = |key: &KeyInfo| {
        keyids.is_empty() || keyids.iter().any(|id| key.fingerprint.contains(id.as_str()))
    };
    let mut printed = 0_usize;
    for key in keys.iter().filter(|key| matches(key)) {
        printed = printed.saturating_add(1);
        emit!(
            out,
            "{}  {:?}{}{}{}",
            key.fingerprint,
            key.owner_trust,
            disabled_suffix(key),
            revoked_suffix(key),
            expired_suffix(key)
        );
        for user_id in &key.user_ids {
            emit!(out, "  uid  {user_id}");
        }
    }
    if printed == 0 {
        emit!(out, "no matching keys");
    }
    ExitCode::SUCCESS
}

fn disabled_suffix(key: &KeyInfo) -> &'static str {
    if key.is_disabled { " [disabled]" } else { "" }
}

fn revoked_suffix(key: &KeyInfo) -> &'static str {
    if key.is_revoked { " [revoked]" } else { "" }
}

fn expired_suffix(key: &KeyInfo) -> &'static str {
    if key.is_expired { " [expired]" } else { "" }
}

/// `piko-key delete`.
pub fn delete(
    gpgdir: &Path,
    keyids: &[String],
    noconfirm: bool,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let admin = match KeyringAdmin::open(gpgdir) {
        Ok(admin) => admin,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    for keyid in keyids {
        if let Some(code) = confirm_trust_action(&admin, keyid, "delete", noconfirm, out) {
            return code;
        }
        if let Err(error) = admin.delete(keyid, true) {
            report(&error);
            return ExitCode::FAILURE;
        }
        emit!(out, "deleted {keyid}");
    }
    ExitCode::SUCCESS
}

/// `piko-key verify`.
pub fn verify(
    gpgdir: &Path,
    signature: &Path,
    file: Option<&Path>,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let keyring = match piko_sig::Keyring::open(gpgdir) {
        Ok(keyring) => keyring,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };
    let default_file;
    let file = match file {
        Some(file) => file,
        None => {
            default_file = signature.with_extension("");
            &default_file
        }
    };

    match keyring.verify_detached(file, signature) {
        Ok(outcomes) if outcomes.is_empty() => {
            emit!(out, "no signature found");
            ExitCode::FAILURE
        }
        Ok(outcomes) => {
            for outcome in &outcomes {
                emit!(
                    out,
                    "{:?} (trust: {:?}){}",
                    outcome.status,
                    outcome.trust,
                    outcome
                        .fingerprint
                        .as_deref()
                        .map(|fpr| format!(", key {fpr}"))
                        .unwrap_or_default(),
                );
            }
            if outcomes.iter().all(|outcome| {
                matches!(outcome.status, piko_sig::Status::Valid | piko_sig::Status::KeyExpired)
            }) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}

/// `piko-key updatedb`.
pub fn updatedb(gpgdir: &Path, out: &mut impl std::io::Write) -> ExitCode {
    let admin = match KeyringAdmin::open(gpgdir) {
        Ok(admin) => admin,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };
    match admin.update_trustdb() {
        Ok(()) => {
            emit!(out, "trust database recomputed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}

/// Prints the key about to be acted on and asks for confirmation, unless `noconfirm`.
///
/// Returns `Some(code)` when the caller must stop here — either the key could not be found, or
/// the user declined.
fn confirm_trust_action(
    admin: &KeyringAdmin,
    keyid: &str,
    verb: &str,
    noconfirm: bool,
    out: &mut impl std::io::Write,
) -> Option<ExitCode> {
    let keys = match admin.list_keys() {
        Ok(keys) => keys,
        Err(error) => {
            report(&error);
            return Some(ExitCode::FAILURE);
        }
    };
    let Some(key) = keys.iter().find(|key| key.fingerprint.contains(keyid)) else {
        report(&piko_sig_write::Error::KeyNotFound {
            home: admin.home().to_path_buf(),
            keyid: keyid.to_owned(),
        });
        return Some(ExitCode::FAILURE);
    };

    let _ = writeln!(out, "{}  {}", key.fingerprint, key.user_ids.join(", "));
    if noconfirm {
        return None;
    }
    if confirm(out, &format!("{verb} this key? [y/N] "), false) {
        None
    } else {
        Some(ExitCode::SUCCESS)
    }
}
