//! Whether a set of signature results satisfies a `SigLevel`.
//!
//! A pure function over values, separate from anything that talks to GnuPG, for the same
//! reason [`piko_txn::extract::decision`] is separate from extraction. This is the rule that
//! decides whether piko will install code onto a system, so it has to be readable and
//! enumerable in tests without a keyring.
//!
//! Transcribed from `_alpm_check_pgp_helper` (`signing.c:803`). libalpm spreads the same rule
//! across that function (which decides) and `_alpm_process_siglist` (which explains), with the
//! outcome carried as an `int` that is `-1` for every kind of failure.
//!
//! # Two things a first reading of `signing.c` gets wrong
//!
//! - **An expired key is not a rejection.** `ALPM_SIGSTATUS_KEY_EXPIRED` falls through into
//!   the same branch as `ALPM_SIGSTATUS_VALID` and is judged on trust alone. The signature was
//!   made while the key was valid. Only an expired signature (`SIG_EXPIRED`) is fatal. Given
//!   how many Arch packager keys carry expiry dates, collapsing the two would reject a large
//!   share of a real cache.
//! - **Every signature must pass, not just one of them.** libalpm's loop is
//!   `for(num = 0; !ret && num < count; num++)`. It stops at the first failure and returns it.
//!   A file carrying two signatures, one good and one invalid, is rejected. "Any valid
//!   signature is enough" is the intuitive reading, and the insecure one.

use piko_db::config::SigLevel;

/// What GnuPG concluded about one signature.
///
/// Mirrors `alpm_sigstatus_t`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// The signature is cryptographically good.
    Valid,
    /// Good, but the signing key has since expired.
    ///
    /// Deliberately distinct from [`Status::Valid`] so it can be reported differently while
    /// being judged identically. See the module docs.
    KeyExpired,
    /// The signature itself carried an expiry date that has passed.
    SigExpired,
    /// The signing key is not in the keyring.
    KeyUnknown,
    /// The signing key is present but disabled.
    KeyDisabled,
    /// The signature does not verify.
    Invalid,
}

/// How much the keyring trusts the signing key.
///
/// Mirrors `alpm_sigvalidity_t`, which GnuPG computes from the web of trust in `trustdb.gpg`.
/// piko does not compute this itself. That is the whole reason it verifies through GPGME.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Trust {
    /// Fully trusted. Every correctly-configured Arch keyring reaches this for packager keys.
    Full,
    /// Marginally trusted.
    Marginal,
    /// The key is known but its trust has not been established.
    Unknown,
    /// The key is explicitly distrusted.
    Never,
}

/// One signature over a file, as the keyring reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureOutcome {
    /// Whether it verified.
    pub status: Status,
    /// How far the signing key is trusted.
    pub trust: Trust,
    /// The signing key's fingerprint, when GnuPG reported one.
    pub fingerprint: Option<String>,
}

/// What a `SigLevel` asks of one kind of file.
///
/// `SigLevel` carries the package and database policies in one bitmask. This is one of them,
/// already selected, so the decision below cannot read the wrong half.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Whether signatures are checked at all. `false` is `SigLevel = Never`.
    pub check: bool,
    /// Whether a missing signature is acceptable (`...Optional`).
    pub optional: bool,
    /// Whether marginal trust is acceptable (`TrustAll` sets this).
    pub marginal_ok: bool,
    /// Whether unknown trust is acceptable (`TrustAll` sets this).
    pub unknown_ok: bool,
}

impl Policy {
    /// The policy `level` states for package files.
    #[must_use]
    pub fn for_package(level: SigLevel) -> Self {
        Self {
            check: level.contains(SigLevel::PACKAGE),
            optional: level.contains(SigLevel::PACKAGE_OPTIONAL),
            marginal_ok: level.contains(SigLevel::PACKAGE_MARGINAL_OK),
            unknown_ok: level.contains(SigLevel::PACKAGE_UNKNOWN_OK),
        }
    }

    /// The policy `level` states for repository databases.
    #[must_use]
    pub fn for_database(level: SigLevel) -> Self {
        Self {
            check: level.contains(SigLevel::DATABASE),
            optional: level.contains(SigLevel::DATABASE_OPTIONAL),
            marginal_ok: level.contains(SigLevel::DATABASE_MARGINAL_OK),
            unknown_ok: level.contains(SigLevel::DATABASE_UNKNOWN_OK),
        }
    }
}

/// Why a file was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rejection {
    /// The policy requires a signature and there was none.
    MissingRequired,
    /// The signing key is only marginally trusted.
    MarginalTrust {
        /// The key, when known.
        fingerprint: Option<String>,
    },
    /// The signing key's trust has not been established.
    UnknownTrust {
        /// The key, when known.
        fingerprint: Option<String>,
    },
    /// The signing key is explicitly distrusted.
    NeverTrust {
        /// The key, when known.
        fingerprint: Option<String>,
    },
    /// The signature carried an expiry date that has passed.
    SignatureExpired,
    /// The signing key is not in the keyring.
    KeyUnknown {
        /// The key GnuPG was looking for, when it said.
        fingerprint: Option<String>,
    },
    /// The signing key is disabled.
    KeyDisabled {
        /// The key.
        fingerprint: Option<String>,
    },
    /// The signature does not verify.
    Invalid,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        /// Renders a key for a message, or a stand-in when GnuPG named none.
        fn key(fingerprint: Option<&String>) -> &str {
            fingerprint.map_or("an unnamed key", |value| value.as_str())
        }
        match self {
            Self::MissingRequired => f.write_str("it is not signed"),
            Self::MarginalTrust { fingerprint } => {
                write!(
                    f,
                    "the signature from {} is only marginally trusted",
                    key(fingerprint.as_ref())
                )
            }
            Self::UnknownTrust { fingerprint } => {
                write!(f, "the signature from {} is of unknown trust", key(fingerprint.as_ref()))
            }
            Self::NeverTrust { fingerprint } => {
                write!(f, "the signature from {} must never be trusted", key(fingerprint.as_ref()))
            }
            Self::SignatureExpired => f.write_str("the signature has expired"),
            Self::KeyUnknown { fingerprint } => {
                write!(f, "the signing key {} is not in the keyring", key(fingerprint.as_ref()))
            }
            Self::KeyDisabled { fingerprint } => {
                write!(f, "the signing key {} is disabled", key(fingerprint.as_ref()))
            }
            Self::Invalid => f.write_str("the signature is invalid"),
        }
    }
}

/// Whether a file may be used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// It may. Carries whether anything was actually checked, which is what
    /// `%VALIDATION%` records.
    Accepted {
        /// Whether a signature was verified, as opposed to the policy not asking.
        verified: bool,
    },
    /// It may not, for this reason.
    Rejected(Rejection),
}

/// Decides whether `signatures` satisfy `policy`.
///
/// Every signature must pass. The first that does not decides the verdict. See the module
/// docs for why that is not "any valid signature is enough".
#[must_use]
pub fn decide(signatures: &[SignatureOutcome], policy: Policy) -> Verdict {
    if !policy.check {
        // `SigLevel = Never`. Nothing was asked for, so nothing was verified. Saying
        // `verified: false` here is what keeps `%VALIDATION%` honest.
        return Verdict::Accepted { verified: false };
    }

    if signatures.is_empty() {
        return if policy.optional {
            Verdict::Accepted { verified: false }
        } else {
            Verdict::Rejected(Rejection::MissingRequired)
        };
    }

    for signature in signatures {
        let fingerprint = signature.fingerprint.clone();
        match signature.status {
            // An expired key still made a good signature at the time, so it is judged on
            // trust alone, exactly as `signing.c:830` does by falling through.
            Status::Valid | Status::KeyExpired => match signature.trust {
                Trust::Full => {}
                Trust::Marginal if policy.marginal_ok => {}
                Trust::Unknown if policy.unknown_ok => {}
                Trust::Marginal => {
                    return Verdict::Rejected(Rejection::MarginalTrust { fingerprint });
                }
                Trust::Unknown => {
                    return Verdict::Rejected(Rejection::UnknownTrust { fingerprint });
                }
                Trust::Never => {
                    return Verdict::Rejected(Rejection::NeverTrust { fingerprint });
                }
            },
            Status::SigExpired => return Verdict::Rejected(Rejection::SignatureExpired),
            Status::KeyUnknown => {
                return Verdict::Rejected(Rejection::KeyUnknown { fingerprint });
            }
            Status::KeyDisabled => {
                return Verdict::Rejected(Rejection::KeyDisabled { fingerprint });
            }
            Status::Invalid => return Verdict::Rejected(Rejection::Invalid),
        }
    }

    Verdict::Accepted { verified: true }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// pacman's default for packages on a stock Arch system: Required, TrustedOnly.
    const REQUIRED_TRUSTED: Policy =
        Policy { check: true, optional: false, marginal_ok: false, unknown_ok: false };

    fn signature(status: Status, trust: Trust) -> SignatureOutcome {
        SignatureOutcome { status, trust, fingerprint: Some("ABC123".to_owned()) }
    }

    #[test]
    fn a_fully_trusted_signature_is_accepted() {
        let sigs = [signature(Status::Valid, Trust::Full)];
        assert_eq!(decide(&sigs, REQUIRED_TRUSTED), Verdict::Accepted { verified: true });
    }

    /// The rule that would otherwise reject a large share of a real cache.
    #[test]
    fn an_expired_key_is_judged_on_trust_not_rejected() {
        let sigs = [signature(Status::KeyExpired, Trust::Full)];
        assert_eq!(decide(&sigs, REQUIRED_TRUSTED), Verdict::Accepted { verified: true });
    }

    /// An expired signature is fatal, unlike an expired key. The two are one character apart
    /// in `signing.c` and opposite in effect.
    #[test]
    fn an_expired_signature_is_rejected() {
        let sigs = [signature(Status::SigExpired, Trust::Full)];
        assert_eq!(decide(&sigs, REQUIRED_TRUSTED), Verdict::Rejected(Rejection::SignatureExpired));
    }

    #[test]
    fn an_unsigned_file_is_rejected_when_required_and_accepted_when_optional() {
        assert_eq!(decide(&[], REQUIRED_TRUSTED), Verdict::Rejected(Rejection::MissingRequired));

        let optional = Policy { optional: true, ..REQUIRED_TRUSTED };
        assert_eq!(decide(&[], optional), Verdict::Accepted { verified: false });
    }

    /// `SigLevel = Never` accepts without checking, and must not claim it verified anything.
    #[test]
    fn a_disabled_policy_accepts_without_claiming_verification() {
        let never = Policy { check: false, ..REQUIRED_TRUSTED };
        assert_eq!(decide(&[], never), Verdict::Accepted { verified: false });
        // Even a bad signature is not consulted, matching libalpm.
        let sigs = [signature(Status::Invalid, Trust::Never)];
        assert_eq!(decide(&sigs, never), Verdict::Accepted { verified: false });
    }

    #[test]
    fn marginal_and_unknown_trust_follow_their_flags() {
        let marginal = [signature(Status::Valid, Trust::Marginal)];
        assert!(matches!(
            decide(&marginal, REQUIRED_TRUSTED),
            Verdict::Rejected(Rejection::MarginalTrust { .. })
        ));
        let ok = Policy { marginal_ok: true, ..REQUIRED_TRUSTED };
        assert_eq!(decide(&marginal, ok), Verdict::Accepted { verified: true });

        let unknown = [signature(Status::Valid, Trust::Unknown)];
        assert!(matches!(
            decide(&unknown, REQUIRED_TRUSTED),
            Verdict::Rejected(Rejection::UnknownTrust { .. })
        ));
        let ok = Policy { unknown_ok: true, ..REQUIRED_TRUSTED };
        assert_eq!(decide(&unknown, ok), Verdict::Accepted { verified: true });
    }

    /// `Never` trust is refused however permissive the policy is. There is no flag for it.
    #[test]
    fn explicit_distrust_cannot_be_relaxed() {
        let sigs = [signature(Status::Valid, Trust::Never)];
        let permissive =
            Policy { optional: true, marginal_ok: true, unknown_ok: true, check: true };
        assert!(matches!(
            decide(&sigs, permissive),
            Verdict::Rejected(Rejection::NeverTrust { .. })
        ));
    }

    /// The security-critical one: all signatures must pass, not any.
    #[test]
    fn one_bad_signature_rejects_the_file_however_many_good_ones_there_are() {
        let sigs = [
            signature(Status::Valid, Trust::Full),
            signature(Status::Invalid, Trust::Full),
            signature(Status::Valid, Trust::Full),
        ];
        assert_eq!(decide(&sigs, REQUIRED_TRUSTED), Verdict::Rejected(Rejection::Invalid));
    }

    #[test]
    fn an_unknown_key_is_rejected_and_names_it() {
        let sigs = [signature(Status::KeyUnknown, Trust::Unknown)];
        assert_eq!(
            decide(&sigs, REQUIRED_TRUSTED),
            Verdict::Rejected(Rejection::KeyUnknown { fingerprint: Some("ABC123".to_owned()) })
        );
    }

    /// `Optional` relaxes only absence. A signature that is present and bad is still fatal.
    #[test]
    fn optional_does_not_excuse_a_present_but_invalid_signature() {
        let optional = Policy { optional: true, ..REQUIRED_TRUSTED };
        let sigs = [signature(Status::Invalid, Trust::Full)];
        assert_eq!(decide(&sigs, optional), Verdict::Rejected(Rejection::Invalid));
    }

    #[test]
    fn policies_read_their_own_half_of_the_siglevel() {
        // Package half set, database half clear.
        let level = SigLevel::PACKAGE | SigLevel::PACKAGE_OPTIONAL;
        assert!(Policy::for_package(level).check);
        assert!(Policy::for_package(level).optional);
        assert!(!Policy::for_database(level).check);
    }
}
