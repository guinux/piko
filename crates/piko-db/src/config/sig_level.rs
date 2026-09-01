//! `SigLevel`: the `ALPM_SIG_*`-shaped bitmask parsed from `SigLevel`/`LocalFileSigLevel`/
//! `RemoteFileSigLevel` directives.
//!
//! Signature verification itself is a non-goal of piko (see the crate's top-level docs).
//! This module exists purely so `pacman.conf` parses faithfully.
//! `LocalFileSigLevel`/`RemoteFileSigLevel` only partially override the global `SigLevel`.
//! For example, `LocalFileSigLevel = PackageTrustAll` changes the package half but leaves
//! the database half inherited from the global value. That is why this tracks a mask
//! alongside the bits, translating `process_siglevel`/`merge_siglevel` in `conf.c` almost
//! line for line. A coarser all-or-nothing representation would get that inheritance wrong.

use std::path::Path;

use crate::Error;

/// A `pacman.conf` `SigLevel`-style bitmask, named after `ALPM_SIG_*` in `alpm.h`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SigLevel(u32);

impl SigLevel {
    /// Package signatures must be present.
    pub const PACKAGE: Self = Self(1 << 0);
    /// A missing package signature is not an error.
    pub const PACKAGE_OPTIONAL: Self = Self(1 << 1);
    /// A signature from a marginally trusted key is accepted for packages.
    pub const PACKAGE_MARGINAL_OK: Self = Self(1 << 2);
    /// A signature from an unknown key is accepted for packages.
    pub const PACKAGE_UNKNOWN_OK: Self = Self(1 << 3);
    /// Database signatures must be present.
    pub const DATABASE: Self = Self(1 << 4);
    /// A missing database signature is not an error.
    pub const DATABASE_OPTIONAL: Self = Self(1 << 5);
    /// A signature from a marginally trusted key is accepted for databases.
    pub const DATABASE_MARGINAL_OK: Self = Self(1 << 6);
    /// A signature from an unknown key is accepted for databases.
    pub const DATABASE_UNKNOWN_OK: Self = Self(1 << 7);
    /// Sentinel meaning "not set here; inherit from the enclosing scope".
    pub const USE_DEFAULT: Self = Self(1 << 31);

    /// `config_new`'s default global `SigLevel`, assuming signature support (the common
    /// case — piko has no `alpm_capabilities` check to gate on). `PACKAGE | DATABASE`,
    /// required, and `TrustedOnly` since neither `_MARGINAL_OK` nor `_UNKNOWN_OK` is set.
    #[must_use]
    pub const fn default_global() -> Self {
        Self(Self::PACKAGE.0 | Self::DATABASE.0)
    }

    /// Returns `true` if every bit in `flag` is set.
    #[must_use]
    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }

    fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// This level with every bit of `other` also set.
    ///
    /// Public, because a bitmask a caller can test with [`Self::contains`] but cannot build
    /// is only half an API. `piko-sig` needs it to state a policy in a test. The CLI will
    /// need it to express a `--sig-level` override.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    fn unset(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }

    /// Merges an override on top of a base value. Bits present in `mask` come from `over`;
    /// every other bit comes from `base`. Translates `merge_siglevel` in `conf.c`.
    #[must_use]
    pub(crate) fn merge(base: Self, over: Self, mask: Self) -> Self {
        if mask.0 == 0 { over } else { Self((over.0 & mask.0) | (base.0 & !mask.0)) }
    }
}

/// Applies a space-separated list of `SigLevel` keywords (`Never`, `Optional`, `Required`,
/// `TrustedOnly`, `TrustAll`, each optionally `Package`- or `Database`-prefixed) on top of
/// `*level`/`*mask`. Commits the result only if every keyword was valid, translating
/// `process_siglevel`, including its "discard everything on the first bad keyword"
/// behavior.
///
/// `level`/`mask` are threaded through rather than reset per call, because the same
/// directive can legally appear on more than one line. Each call accumulates onto the
/// previous one's result, exactly as `config->siglevel_mask` does in `conf.c`.
pub(crate) fn apply_values(
    level: &mut SigLevel,
    mask: &mut SigLevel,
    values: &str,
    path: &Path,
    line: usize,
    directive: &str,
) -> Result<(), Error> {
    let mut new_level = *level;
    let mut new_mask = *mask;

    for original in values.split_whitespace() {
        let (value, package, database) = if let Some(rest) = original.strip_prefix("Package") {
            (rest, true, false)
        } else if let Some(rest) = original.strip_prefix("Database") {
            (rest, false, true)
        } else {
            (original, true, true)
        };

        match value {
            "Never" => {
                if package {
                    new_level.unset(SigLevel::PACKAGE);
                    new_mask.set(SigLevel::PACKAGE);
                }
                if database {
                    new_level.unset(SigLevel::DATABASE);
                    new_mask.set(SigLevel::DATABASE);
                }
            }
            "Optional" => {
                if package {
                    new_level.set(SigLevel::PACKAGE);
                    new_mask.set(SigLevel::PACKAGE);
                    new_level.set(SigLevel::PACKAGE_OPTIONAL);
                    new_mask.set(SigLevel::PACKAGE_OPTIONAL);
                }
                if database {
                    new_level.set(SigLevel::DATABASE);
                    new_mask.set(SigLevel::DATABASE);
                    new_level.set(SigLevel::DATABASE_OPTIONAL);
                    new_mask.set(SigLevel::DATABASE_OPTIONAL);
                }
            }
            "Required" => {
                if package {
                    new_level.set(SigLevel::PACKAGE);
                    new_mask.set(SigLevel::PACKAGE);
                    new_level.unset(SigLevel::PACKAGE_OPTIONAL);
                    new_mask.set(SigLevel::PACKAGE_OPTIONAL);
                }
                if database {
                    new_level.set(SigLevel::DATABASE);
                    new_mask.set(SigLevel::DATABASE);
                    new_level.unset(SigLevel::DATABASE_OPTIONAL);
                    new_mask.set(SigLevel::DATABASE_OPTIONAL);
                }
            }
            "TrustedOnly" => {
                if package {
                    new_level.unset(SigLevel::PACKAGE_MARGINAL_OK);
                    new_mask.set(SigLevel::PACKAGE_MARGINAL_OK);
                    new_level.unset(SigLevel::PACKAGE_UNKNOWN_OK);
                    new_mask.set(SigLevel::PACKAGE_UNKNOWN_OK);
                }
                if database {
                    new_level.unset(SigLevel::DATABASE_MARGINAL_OK);
                    new_mask.set(SigLevel::DATABASE_MARGINAL_OK);
                    new_level.unset(SigLevel::DATABASE_UNKNOWN_OK);
                    new_mask.set(SigLevel::DATABASE_UNKNOWN_OK);
                }
            }
            "TrustAll" => {
                if package {
                    new_level.set(SigLevel::PACKAGE_MARGINAL_OK);
                    new_mask.set(SigLevel::PACKAGE_MARGINAL_OK);
                    new_level.set(SigLevel::PACKAGE_UNKNOWN_OK);
                    new_mask.set(SigLevel::PACKAGE_UNKNOWN_OK);
                }
                if database {
                    new_level.set(SigLevel::DATABASE_MARGINAL_OK);
                    new_mask.set(SigLevel::DATABASE_MARGINAL_OK);
                    new_level.set(SigLevel::DATABASE_UNKNOWN_OK);
                    new_mask.set(SigLevel::DATABASE_UNKNOWN_OK);
                }
            }
            _ => {
                return Err(Error::ConfigInvalidDirective {
                    path: path.to_path_buf(),
                    line,
                    directive: directive.to_owned(),
                    value: original.to_owned(),
                    reason: "expected Never, Optional, Required, TrustedOnly or TrustAll, \
                             optionally Package- or Database-prefixed"
                        .to_owned(),
                });
            }
        }
        new_level.unset(SigLevel::USE_DEFAULT);
    }

    *level = new_level;
    *mask = new_mask;
    Ok(())
}

impl std::ops::BitOr for SigLevel {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for SigLevel {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = self.union(rhs);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::path::Path;

    use super::*;

    fn apply(level: SigLevel, mask: SigLevel, values: &str) -> (SigLevel, SigLevel) {
        let mut level = level;
        let mut mask = mask;
        apply_values(&mut level, &mut mask, values, Path::new("pacman.conf"), 1, "SigLevel")
            .unwrap();
        (level, mask)
    }

    #[test]
    fn required_sets_both_package_and_database_by_default() {
        let (level, _) = apply(SigLevel::default(), SigLevel::default(), "Required");
        assert!(level.contains(SigLevel::PACKAGE));
        assert!(level.contains(SigLevel::DATABASE));
    }

    #[test]
    fn a_package_prefixed_keyword_leaves_database_bits_untouched() {
        let base = SigLevel::default_global();
        let (level, mask) = apply(base, SigLevel::default(), "PackageTrustAll");
        assert!(level.contains(SigLevel::PACKAGE_MARGINAL_OK));
        assert!(level.contains(SigLevel::PACKAGE_UNKNOWN_OK));
        assert!(!mask.contains(SigLevel::DATABASE_MARGINAL_OK), "database bits must not be masked");
    }

    #[test]
    fn never_unsets_the_corresponding_bit() {
        let (level, _) = apply(SigLevel::default_global(), SigLevel::default(), "Never");
        assert!(!level.contains(SigLevel::PACKAGE));
        assert!(!level.contains(SigLevel::DATABASE));
    }

    #[test]
    fn an_unrecognised_keyword_is_rejected() {
        let mut level = SigLevel::default();
        let mut mask = SigLevel::default();
        let err = apply_values(&mut level, &mut mask, "Bogus", Path::new("p"), 3, "SigLevel")
            .unwrap_err();
        assert!(matches!(err, Error::ConfigInvalidDirective { line: 3, .. }), "got {err:?}");
    }

    /// This is the case that matters most. `LocalFileSigLevel = PackageTrustAll` must leave
    /// the database half free to inherit from the global `SigLevel` when merged, rather than
    /// silently forcing `DatabaseNever`.
    #[test]
    fn merge_only_overrides_the_bits_the_override_actually_touched() {
        let base = SigLevel::default_global(); // PACKAGE | DATABASE
        let (over, mask) = apply(SigLevel::default(), SigLevel::default(), "PackageTrustAll");

        let merged = SigLevel::merge(base, over, mask);

        assert!(merged.contains(SigLevel::PACKAGE), "package required bit inherited from base");
        assert!(merged.contains(SigLevel::PACKAGE_MARGINAL_OK), "override's trust-all applied");
        assert!(merged.contains(SigLevel::DATABASE), "database half must still inherit from base");
        assert!(!merged.contains(SigLevel::DATABASE_MARGINAL_OK));
    }

    #[test]
    fn merge_with_an_empty_mask_returns_the_override_verbatim() {
        let base = SigLevel::default_global();
        let over = SigLevel::default();
        let merged = SigLevel::merge(base, over, SigLevel::default());
        assert_eq!(merged, over, "ALPM_SIG_USE_DEFAULT: nothing overridden, override wins as-is");
    }

    #[test]
    fn a_bad_keyword_discards_the_whole_call_rather_than_partially_applying() {
        let mut level = SigLevel::default_global();
        let original = level;
        let mut mask = SigLevel::default();
        let err =
            apply_values(&mut level, &mut mask, "Required Bogus", Path::new("p"), 1, "SigLevel")
                .unwrap_err();
        assert!(matches!(err, Error::ConfigInvalidDirective { .. }));
        assert_eq!(level, original, "a rejected value must not leave a partial mutation behind");
    }
}
