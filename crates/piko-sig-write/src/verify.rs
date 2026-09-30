//! `pacman-key --verify`: checking a detached signature against the keyring.
//!
//! The check is read-only, and still a `pacman-key` operation rather than a transaction one:
//! its policy is fixed, not read from `pacman.conf`, and its file is found from the signature's
//! own name. Both rules live here, so a second frontend verifies what `piko key verify`
//! verifies.

use std::path::{Path, PathBuf};

use piko_sig::{Keyring, Policy, SignatureOutcome, Verdict};

/// The policy a signature is judged against: required, and made by a fully trusted key.
///
/// That is pacman's own default for a package file: `SigLevel = Required` sets `check`, and
/// `TrustedOnly` clears `marginal_ok` and `unknown_ok`. `TrustedOnly` applies whenever
/// `pacman.conf` names no `TrustAll`.
pub const VERIFY_POLICY: Policy =
    Policy { check: true, optional: false, marginal_ok: false, unknown_ok: false };

/// What [`verify`] found.
#[derive(Clone, Debug)]
pub struct Verification {
    /// The file the signature was checked over.
    pub file: PathBuf,
    /// Each signature, as the keyring reports it.
    pub outcomes: Vec<SignatureOutcome>,
    /// Whether [`VERIFY_POLICY`] accepts them, through [`piko_sig::decide`], the function a
    /// transaction's check reaches too.
    pub verdict: Verdict,
}

/// Checks `signature` over `file` against the keyring at `gpg_dir`, under [`VERIFY_POLICY`].
///
/// `file` defaults to `signature` without its last extension, so `foo.pkg.tar.zst.sig` checks
/// `foo.pkg.tar.zst`, the file `gpg --verify` finds beside a detached signature.
///
/// # Errors
///
/// Whatever [`Keyring::open`] or [`Keyring::verify_detached`] refuses. A signature that was
/// checked and refused is not an error: see [`Verification::verdict`].
pub fn verify(
    gpg_dir: &Path,
    signature: &Path,
    file: Option<&Path>,
) -> piko_sig::Result<Verification> {
    let keyring = Keyring::open(gpg_dir)?;
    let file = file.map_or_else(|| signature.with_extension(""), Path::to_path_buf);
    let outcomes = keyring.verify_detached(&file, signature)?;
    let verdict = piko_sig::decide(&outcomes, VERIFY_POLICY);
    Ok(Verification { file, outcomes, verdict })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    /// The policy is what `SigLevel = Required TrustedOnly` gives a package, derived through
    /// the same function a transaction uses rather than restated.
    #[test]
    fn the_policy_is_required_trusted_only_for_a_package() {
        assert_eq!(VERIFY_POLICY, Policy::for_package(piko_db::config::SigLevel::PACKAGE));
    }

    /// A keyring that cannot be opened is an error, never an unchecked pass.
    #[test]
    fn an_unusable_keyring_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-keyring");
        let signature = dir.path().join("file.sig");
        assert!(verify(&missing, &signature, None).is_err());
    }
}
