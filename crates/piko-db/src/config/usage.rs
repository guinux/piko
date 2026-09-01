//! `DbUsage`: the bitmask parsed from a repository section's `Usage` directive.

use std::path::Path;

use crate::Error;

/// What a configured repository may be used for, named after `ALPM_DB_USAGE_*` in `alpm.h`.
///
/// `Default` is the empty mask (no bits set), matching `config_repo_t`'s zero-initialized
/// `usage` field in `conf.h` before any `Usage` directive or default resolution. It is not
/// the `ALL` a repository with no `Usage` directive at all ends up with. That resolution is
/// `setdefaults`'s job, applied in [`super::PacmanConfig::open_with`], not this type's.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DbUsage(u32);

impl DbUsage {
    /// The repository may be synced (`pacman -Sy`).
    pub const SYNC: Self = Self(1 << 0);
    /// The repository may be searched (`pacman -Ss`).
    pub const SEARCH: Self = Self(1 << 1);
    /// Packages may be installed from the repository (`pacman -S`).
    pub const INSTALL: Self = Self(1 << 2);
    /// The repository may be used for system upgrades (`pacman -Su`).
    pub const UPGRADE: Self = Self(1 << 3);
    /// Every use above.
    pub const ALL: Self = Self(Self::SYNC.0 | Self::SEARCH.0 | Self::INSTALL.0 | Self::UPGRADE.0);

    fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Returns `true` if every bit in `flag` is set.
    #[must_use]
    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }
}

/// Applies a space-separated list of `Usage` keywords (`Sync`, `Search`, `Install`,
/// `Upgrade`, `All`) on top of `*usage`. Translates `process_usage`, including its behavior
/// of applying every valid keyword even when one of them was invalid, rather than
/// discarding the whole call as [`super::sig_level::apply_values`] does.
pub(crate) fn apply_values(
    usage: &mut DbUsage,
    values: &str,
    path: &Path,
    line: usize,
) -> Result<(), Error> {
    let mut level = *usage;
    let mut error = None;

    for key in values.split_whitespace() {
        match key {
            "Sync" => level.set(DbUsage::SYNC),
            "Search" => level.set(DbUsage::SEARCH),
            "Install" => level.set(DbUsage::INSTALL),
            "Upgrade" => level.set(DbUsage::UPGRADE),
            "All" => level.set(DbUsage::ALL),
            _ => {
                error.get_or_insert_with(|| Error::ConfigInvalidDirective {
                    path: path.to_path_buf(),
                    line,
                    directive: "Usage".to_owned(),
                    value: key.to_owned(),
                    reason: "expected Sync, Search, Install, Upgrade or All".to_owned(),
                });
            }
        }
    }

    *usage = level;
    error.map_or(Ok(()), Err)
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

    #[test]
    fn defaults_to_the_empty_mask() {
        assert!(!DbUsage::default().contains(DbUsage::ALL));
    }

    #[test]
    fn accumulates_multiple_keywords() {
        let mut usage = DbUsage::default();
        apply_values(&mut usage, "Sync Search", Path::new("p"), 1).unwrap();
        assert!(usage.contains(DbUsage::SYNC));
        assert!(usage.contains(DbUsage::SEARCH));
        assert!(!usage.contains(DbUsage::INSTALL));
    }

    /// Matches `process_usage`'s unconditional `*usage = level;`. Valid keywords in the same
    /// call still apply even though the call as a whole reports an error.
    #[test]
    fn valid_keywords_still_apply_even_when_another_keyword_in_the_same_call_is_invalid() {
        let mut usage = DbUsage::default();
        let err = apply_values(&mut usage, "Sync Bogus", Path::new("p"), 5).unwrap_err();
        assert!(matches!(err, Error::ConfigInvalidDirective { line: 5, .. }), "got {err:?}");
        assert!(usage.contains(DbUsage::SYNC), "the valid keyword must still have been applied");
    }
}
