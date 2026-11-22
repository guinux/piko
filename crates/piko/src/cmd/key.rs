//! `piko key`: bootstrapping and administering the keyring piko verifies against.
//!
//! This is pacman-key's counterpart, with one function per subcommand. Bootstrapping and
//! administering a keyring is a distinct concern from verifying against one. See
//! `piko-sig-write`'s crate doc for why that split runs one way. It also says why every real
//! operation here happens through GPGME rather than a `gpg` subprocess.

use std::{path::Path, process::ExitCode};

use piko_sig_write::{KeyInfo, KeyringAdmin};

use crate::cli::KeyCommand;
use crate::output::{confirm, emit, escaped, report};

/// Runs one `piko key` subcommand against the keyring at `gpgdir`.
pub fn key(
    gpgdir: &Path,
    keyring_dir: &Path,
    command: &KeyCommand,
    out: &mut impl std::io::Write,
) -> ExitCode {
    match command {
        KeyCommand::Init => init(gpgdir, out),
        KeyCommand::Populate { keyrings } => populate(gpgdir, keyring_dir, keyrings, out),
        KeyCommand::Add { files } => add(gpgdir, files, out),
        KeyCommand::LsignKey { keyids, noconfirm } => lsign_key(gpgdir, keyids, *noconfirm, out),
        KeyCommand::ListKeys { keyids } => list_keys(gpgdir, keyids, out),
        KeyCommand::Delete { keyids, secret, noconfirm } => {
            delete(gpgdir, keyids, *secret, *noconfirm, out)
        }
        KeyCommand::Verify { signature, file } => verify(gpgdir, signature, file.as_deref(), out),
        KeyCommand::Updatedb => updatedb(gpgdir, out),
    }
}

/// `piko key init`.
fn init(gpgdir: &Path, out: &mut impl std::io::Write) -> ExitCode {
    match KeyringAdmin::init(gpgdir) {
        Ok((_, outcome)) => {
            if outcome.master_key_created {
                emit!(
                    out,
                    "{}",
                    crate::i18n::tr!("key-generated", path = gpgdir.display().to_string())
                );
            } else if outcome.master_key_expiry_removed {
                emit!(
                    out,
                    "{}",
                    crate::i18n::tr!("key-expiry-removed", path = gpgdir.display().to_string())
                );
            } else {
                emit!(
                    out,
                    "{}",
                    crate::i18n::tr!(
                        "key-already-initialized",
                        path = gpgdir.display().to_string()
                    )
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}

/// `piko key populate`.
fn populate(
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
        emit!(
            out,
            "{}",
            crate::i18n::tr!("key-no-keyrings", path = keyring_dir.display().to_string())
        );
        return ExitCode::SUCCESS;
    }

    for name in &names {
        match admin.populate(keyring_dir, name) {
            Ok(summary) => {
                let line = crate::i18n::tr!(
                    "key-populated",
                    name = name.as_str(),
                    imported = summary.imported.imported,
                    lsigned = summary.lsigned,
                    trusted = summary.trust_set,
                    disabled = summary.disabled
                );
                emit!(out, "{line}");
                // `SkippedLine` names its own side file, so each entry prints as one location
                // the user can open. A line number needs that name: both files can hold a bad
                // line at the same number.
                for skipped in &summary.skipped {
                    emit!(
                        out,
                        "  {name}{}:{}: {}",
                        skipped.file.suffix(),
                        skipped.line,
                        escaped(&skipped.reason)
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

/// `piko key add`.
fn add(gpgdir: &Path, files: &[std::path::PathBuf], out: &mut impl std::io::Write) -> ExitCode {
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
                let line = crate::i18n::tr!(
                    "key-imported",
                    file = file.display().to_string(),
                    imported = summary.imported,
                    unchanged = summary.unchanged
                );
                emit!(out, "{line}");
            }
            Err(error) => {
                report(&error);
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// `piko key lsign-key`.
fn lsign_key(
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
        let fingerprint = match confirm_trust_action(
            &admin,
            keyid,
            &crate::i18n::tr!("key-prompt-lsign"),
            noconfirm,
            out,
        ) {
            Decision::Proceed(fingerprint) => fingerprint,
            Decision::Declined => {
                emit!(out, "{}", crate::i18n::tr!("key-skipped", key = keyid));
                continue;
            }
            Decision::Failed => return ExitCode::FAILURE,
        };
        match admin.lsign(&fingerprint) {
            Ok(true) => {
                emit!(out, "{}", crate::i18n::tr!("key-lsigned", key = fingerprint.as_str()))
            }
            Ok(false) => emit!(
                out,
                "{}",
                crate::i18n::tr!("key-already-lsigned", key = fingerprint.as_str())
            ),
            Err(error) => {
                report(&error);
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// `piko key list-keys`.
///
/// [`KeyringAdmin::find_keys`] does the matching, so `keyids` accepts every pattern
/// `gpg --list-keys` accepts. An empty `keyids` lists the whole keyring.
///
/// An empty result is an error only when the user named a pattern. A keyring with no key at all
/// is not a failure, and `gpg --list-keys` draws the same line.
fn list_keys(gpgdir: &Path, keyids: &[String], out: &mut impl std::io::Write) -> ExitCode {
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
            emit!(out, "  Uid  {}", escaped(user_id));
        }
    }
    if keys.is_empty() {
        emit!(out, "{}", crate::i18n::tr!("key-no-match"));
        if !keyids.is_empty() {
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn disabled_suffix(key: &KeyInfo) -> String {
    if key.is_disabled {
        format!(" {}", crate::i18n::tr!("key-mark-disabled"))
    } else {
        String::new()
    }
}

fn revoked_suffix(key: &KeyInfo) -> String {
    if key.is_revoked {
        format!(" {}", crate::i18n::tr!("key-mark-revoked"))
    } else {
        String::new()
    }
}

fn expired_suffix(key: &KeyInfo) -> String {
    if key.is_expired {
        format!(" {}", crate::i18n::tr!("key-mark-expired"))
    } else {
        String::new()
    }
}

/// `piko key delete`.
///
/// `secret` is the `--secret` flag. It becomes `allow_secret`, and defaults to `false`. piko
/// then refuses a key that has a secret key, and names that key in the error. pacman-key makes
/// the same choice: its `--delete` runs `gpg --delete-key`, which deletes public keys only
/// (`pacman-key.sh.in:392`).
fn delete(
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
        let fingerprint = match confirm_trust_action(
            &admin,
            keyid,
            &crate::i18n::tr!("key-prompt-delete"),
            noconfirm,
            out,
        ) {
            Decision::Proceed(fingerprint) => fingerprint,
            Decision::Declined => {
                emit!(out, "{}", crate::i18n::tr!("key-skipped", key = keyid));
                continue;
            }
            Decision::Failed => return ExitCode::FAILURE,
        };
        if let Err(error) = admin.delete(&fingerprint, secret) {
            report(&error);
            return ExitCode::FAILURE;
        }
        emit!(out, "{}", crate::i18n::tr!("key-deleted", key = fingerprint.as_str()));
    }
    ExitCode::SUCCESS
}

/// `piko key verify`.
///
/// The exit code comes from [`piko_sig::decide`], the same function `piko install` and
/// `piko update` reach through `Transaction::verify`. This command therefore answers the
/// question a user asks it: would piko accept this signature?
///
/// The status lines still print first, so a rejected signature shows both its status and its
/// trust before the reason. This diverges from `gpg --verify`, which reports trust as a
/// warning and still exits `0`.
fn verify(
    gpgdir: &Path,
    signature: &Path,
    file: Option<&Path>,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let checked = match piko_sig_write::verify(gpgdir, signature, file) {
        Ok(checked) => checked,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };
    for outcome in &checked.outcomes {
        let line = match outcome.fingerprint.as_deref() {
            Some(key) => crate::i18n::tr!(
                "key-verify-outcome-key",
                status = format!("{:?}", outcome.status),
                trust = format!("{:?}", outcome.trust),
                key = key
            ),
            None => crate::i18n::tr!(
                "key-verify-outcome",
                status = format!("{:?}", outcome.status),
                trust = format!("{:?}", outcome.trust)
            ),
        };
        emit!(out, "{line}");
    }
    match checked.verdict {
        piko_sig::Verdict::Accepted { .. } => ExitCode::SUCCESS,
        piko_sig::Verdict::Rejected(rejection) => {
            crate::i18n::print_error!(
                "error-signature-rejected",
                archive = checked.file.display().to_string(),
                reason = piko_i18n::Localize::message(&rejection)
            );
            ExitCode::FAILURE
        }
    }
}

/// `piko key updatedb`.
fn updatedb(gpgdir: &Path, out: &mut impl std::io::Write) -> ExitCode {
    let admin = match KeyringAdmin::open(gpgdir) {
        Ok(admin) => admin,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };
    match admin.update_trustdb() {
        Ok(()) => {
            emit!(out, "{}", crate::i18n::tr!("key-trustdb-updated"));
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
    /// is a separate question. A decline is not an error, so this carries no exit code. A
    /// declined transaction also ends with `ExitCode::SUCCESS`.
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
    prompt: &str,
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

    let _ = writeln!(out, "{}", key_line(&key.fingerprint, &key.user_ids));
    if noconfirm || confirm(out, &format!("{prompt} "), false) {
        Decision::Proceed(key.fingerprint)
    } else {
        Decision::Declined
    }
}

/// The line naming a key before a trust question: its fingerprint, then its user IDs.
///
/// A user ID is whatever the key's owner wrote, so each one is escaped by [`escaped`].
/// Unescaped, a carriage return or an escape sequence could redraw this line with another
/// fingerprint, just before the user approves the one shown.
fn key_line(fingerprint: &str, user_ids: &[String]) -> String {
    let user_ids = user_ids.iter().map(escaped).collect::<Vec<_>>().join(", ");
    format!("{fingerprint}  {user_ids}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A user ID cannot move the cursor back over the fingerprint the question names.
    #[test]
    fn a_user_id_cannot_redraw_the_key_line() {
        let line = key_line(
            "AAAA",
            &["Mallory <m@example.invalid>\r\u{1b}[2KBBBB  Arch Linux".to_owned()],
        );
        assert_eq!(line, "AAAA  Mallory <m@example.invalid>\\r\\u{1b}[2KBBBB  Arch Linux");
    }
}
