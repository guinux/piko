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
                // `SkippedLine` names its own side file, so each entry prints as one location
                // the user can open. A line number needs that name: both files can hold a bad
                // line at the same number.
                for skipped in &summary.skipped {
                    emit!(
                        out,
                        "  {name}{}:{}: {}",
                        skipped.file.suffix(),
                        skipped.line,
                        skipped.reason
                    );
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
        let fingerprint = match confirm_trust_action(&admin, keyid, "locally sign", noconfirm, out)
        {
            Decision::Proceed(fingerprint) => fingerprint,
            Decision::Declined => {
                emit!(out, "skipped {keyid}");
                continue;
            }
            Decision::Failed => return ExitCode::FAILURE,
        };
        match admin.lsign(&fingerprint) {
            Ok(true) => emit!(out, "locally signed {fingerprint}"),
            Ok(false) => emit!(out, "{fingerprint} is already locally signed"),
            Err(error) => {
                report(&error);
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// `piko-key list-keys`.
///
/// [`KeyringAdmin::find_keys`] does the matching, so `keyids` accepts every pattern
/// `gpg --list-keys` accepts. An empty `keyids` lists the whole keyring.
///
/// An empty result is an error only when the user named a pattern. A keyring with no key at all
/// is not a failure, and `gpg --list-keys` draws the same line.
pub fn list_keys(gpgdir: &Path, keyids: &[String], out: &mut impl std::io::Write) -> ExitCode {
    let admin = match KeyringAdmin::open(gpgdir) {
        Ok(admin) => admin,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    let keys = match admin.find_keys(keyids) {
        Ok(keys) => keys,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    for key in &keys {
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
    if keys.is_empty() {
        emit!(out, "no matching keys");
        if !keyids.is_empty() {
            return ExitCode::FAILURE;
        }
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
///
/// `secret` is the `--secret` flag. It becomes `allow_secret`, and defaults to `false`. piko
/// then refuses a key that has a secret key, and names that key in the error. pacman-key makes
/// the same choice: its `--delete` runs `gpg --delete-key`, which deletes public keys only
/// (`pacman-key.sh.in:392`).
pub fn delete(
    gpgdir: &Path,
    keyids: &[String],
    secret: bool,
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
        let fingerprint = match confirm_trust_action(&admin, keyid, "delete", noconfirm, out) {
            Decision::Proceed(fingerprint) => fingerprint,
            Decision::Declined => {
                emit!(out, "skipped {keyid}");
                continue;
            }
            Decision::Failed => return ExitCode::FAILURE,
        };
        if let Err(error) = admin.delete(&fingerprint, secret) {
            report(&error);
            return ExitCode::FAILURE;
        }
        emit!(out, "deleted {fingerprint}");
    }
    ExitCode::SUCCESS
}

/// The policy `piko-key verify` judges a signature against.
///
/// A signature is required, and its key must be fully trusted. That is pacman's own default for
/// a package file: `SigLevel = Required` sets `check`, and `TrustedOnly` clears `marginal_ok`
/// and `unknown_ok`. `TrustedOnly` applies whenever `pacman.conf` names no `TrustAll`.
const VERIFY_POLICY: piko_sig::Policy =
    piko_sig::Policy { check: true, optional: false, marginal_ok: false, unknown_ok: false };

/// `piko-key verify`.
///
/// The exit code comes from [`piko_sig::decide`], the same function `piko install` and
/// `piko update` reach through `Transaction::verify`. This command therefore answers the
/// question a user asks it: would piko accept this signature?
///
/// The status lines still print first, so a rejected signature shows both its status and its
/// trust before the reason. This diverges from `gpg --verify`, which reports trust as a
/// warning and still exits `0`.
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
            match piko_sig::decide(&outcomes, VERIFY_POLICY) {
                piko_sig::Verdict::Accepted { .. } => ExitCode::SUCCESS,
                piko_sig::Verdict::Rejected(rejection) => {
                    eprintln!(
                        "error: the signature on {} was rejected: {rejection}",
                        file.display()
                    );
                    ExitCode::FAILURE
                }
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

/// The answer to one key's confirmation prompt.
enum Decision {
    /// Act on this fingerprint. Never act on the identifier the user typed.
    Proceed(String),
    /// The user declined this key. The caller continues with the next key, because each key
    /// is a separate question. A decline is not an error, so this carries no exit code.
    /// `crates/piko` also ends a declined transaction with `ExitCode::SUCCESS`.
    Declined,
    /// piko could not resolve the key. The caller stops. pacman-key's `check_keyids_exist`
    /// does the same, and refuses the whole command rather than part of it.
    Failed,
}

/// Resolves `keyid`, prints the key it names, then asks for confirmation unless `noconfirm`.
///
/// [`KeyringAdmin::describe_key`] does the resolution. It calls the same `get_key` the
/// operation itself calls, and the caller acts on the fingerprint it returns. The prompt
/// therefore describes the key the operation will change.
///
/// A second resolver here would break that. A substring filter over
/// [`KeyringAdmin::list_keys`] matches anywhere in a fingerprint, but GnuPG anchors a key ID
/// at the end. Such a filter also rejects identifiers GnuPG accepts, such as an email
/// address.
fn confirm_trust_action(
    admin: &KeyringAdmin,
    keyid: &str,
    verb: &str,
    noconfirm: bool,
    out: &mut impl std::io::Write,
) -> Decision {
    let key = match admin.describe_key(keyid) {
        Ok(key) => key,
        Err(error) => {
            report(&error);
            return Decision::Failed;
        }
    };

    let _ = writeln!(out, "{}  {}", key.fingerprint, key.user_ids.join(", "));
    if noconfirm || confirm(out, &format!("{verb} this key? [y/N] "), false) {
        Decision::Proceed(key.fingerprint)
    } else {
        Decision::Declined
    }
}
