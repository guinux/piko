//! Parsing of local database entry directory names.
//!
//! Per [alpm-db], an entry directory is named after an **alpm-package-name**, directly
//! followed by `-`, directly followed by an **alpm-package-version** in the _full_ or
//! _full with epoch_ form:
//!
//! ```text
//! example-package-1.0.0-1
//! example-package-1:1.0.0-1
//! ```
//!
//! This is the only piece of the format the official `alpm-*` crates do not implement.
//! `PackageFileName` and `InstalledPackage` both parse a similar shape, but both require a
//! trailing `-<architecture>` component. Neither accepts `example-package-1:1.0.0-1`.
//!
//! [alpm-db]: https://alpm.archlinux.page/specifications/alpm-db.7.html

use std::fmt;

use alpm_types::{FullVersion, Name};

/// Why a directory name is not a valid database entry name.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EntryNameError {
    /// The name contains fewer than the two `-` separators the format requires.
    ///
    /// This is what rejects `ALPM_DB_VERSION`, `db.lck` and other stray filenames.
    #[error("expected a '<name>-<pkgver>-<pkgrel>' directory name with at least two '-'")]
    TooFewSeparators,

    /// The version occupies the whole name, leaving nothing for the package name.
    #[error("the package name is empty")]
    EmptyName,

    /// The package name portion is not a valid **alpm-package-name**.
    #[error("invalid package name {name:?}")]
    InvalidName {
        /// The rejected name portion.
        name: String,
        /// Why `alpm-types` rejected it.
        #[source]
        source: alpm_types::Error,
    },

    /// The version portion is not a valid **alpm-package-version** in _full_ form.
    #[error("invalid package version {version:?}")]
    InvalidVersion {
        /// The rejected version portion.
        version: String,
        /// Why `alpm-types` rejected it.
        #[source]
        source: alpm_types::Error,
    },

    /// The name parses, but is not the canonical spelling of what it parses to.
    ///
    /// For example, `foo-1-01` parses to name `foo` and version `1-1`. The canonical spelling
    /// of that version is `foo-1-1`. Accepting both spellings would let two directories denote
    /// the same package, so the non-canonical one is refused.
    #[error("{raw:?} is not the canonical spelling of {canonical:?}")]
    NotCanonical {
        /// The directory name as found on disk.
        raw: String,
        /// The spelling it should have had.
        canonical: String,
    },
}

/// A validated `<name>-<version>` local database entry directory name.
///
/// Holding this type proves the directory name denotes exactly one package. It also proves
/// the name and version were obtained without opening a single file.
///
/// ```
/// use piko_db::EntryName;
///
/// let entry = EntryName::parse("pulse-native-provider-1:1.6.8-1")?;
/// assert_eq!(entry.name().as_ref(), "pulse-native-provider");
/// assert_eq!(entry.version().to_string(), "1:1.6.8-1");
///
/// // The name may contain dashes; the last two always delimit the version.
/// let entry = EntryName::parse("qemu-hw-display-virtio-gpu-pci-rutabaga-11.0.3-1")?;
/// assert_eq!(entry.name().as_ref(), "qemu-hw-display-virtio-gpu-pci-rutabaga");
/// # Ok::<(), piko_db::EntryNameError>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryName {
    /// The directory name exactly as it appeared on disk.
    raw: Box<str>,
    /// Byte offset of the `-` that separates name from version, i.e. `raw[..name_len]`
    /// is the name.
    name_len: usize,
    name: Name,
    version: FullVersion,
}

impl EntryName {
    /// Parses a directory name.
    ///
    /// The split point is the **second-from-last** `-`. This is unambiguous: an
    /// **alpm-package-version** may not contain `-` in its `pkgver`, and its `pkgrel` is
    /// numeric. Any dashes before those last two belong to the package name. An epoch needs
    /// no special handling, since it is attached to the `pkgver` by `:`.
    ///
    /// This is the same rule as libalpm's `_alpm_splitname`, which scans backwards for two
    /// `-`. It differs in two ways: it never reads past the start of the string, and it
    /// validates both halves through `alpm-types` instead of accepting arbitrary bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EntryNameError`] if `raw` is not a canonical `<name>-<pkgver>-<pkgrel>`.
    pub fn parse(raw: &str) -> Result<Self, EntryNameError> {
        let name_len = raw
            .rmatch_indices('-')
            .nth(1)
            .map(|(index, _)| index)
            .ok_or(EntryNameError::TooFewSeparators)?;

        // `rmatch_indices` yields indices of an ASCII byte. The split is always on a
        // character boundary and cannot fail. `split_at_checked` avoids the panicking form.
        let (name_str, rest) =
            raw.split_at_checked(name_len).ok_or(EntryNameError::TooFewSeparators)?;
        let version_str = rest.strip_prefix('-').ok_or(EntryNameError::TooFewSeparators)?;

        if name_str.is_empty() {
            return Err(EntryNameError::EmptyName);
        }

        let name = name_str
            .parse::<Name>()
            .map_err(|source| EntryNameError::InvalidName { name: name_str.to_owned(), source })?;
        let version = version_str.parse::<FullVersion>().map_err(|source| {
            EntryNameError::InvalidVersion { version: version_str.to_owned(), source }
        })?;

        // Reject spellings that parse but do not round-trip, such as a zero-padded pkgrel.
        // Without this check, two directories could resolve to the same package. The path
        // built later from `raw` would then disagree with the identity reported here.
        let canonical = format!("{name}-{version}");
        if canonical != raw {
            return Err(EntryNameError::NotCanonical { raw: raw.to_owned(), canonical });
        }

        Ok(Self { raw: raw.into(), name_len, name, version })
    }

    /// Builds the entry name for a package that is about to be written.
    ///
    /// Deliberately routed through [`EntryName::parse`] rather than storing the rendered
    /// string directly. That costs a redundant parse but guarantees every directory the
    /// writer creates is one the scanner accepts, including the
    /// [`EntryNameError::NotCanonical`] round-trip check. A writer that can create entries its
    /// own reader rejects is a writer that can corrupt a database.
    ///
    /// # Errors
    ///
    /// [`EntryNameError`] if `name` and `version` do not render to a canonical entry name.
    /// With both halves already validated by `alpm-types` this should be unreachable, which
    /// is precisely why it is checked rather than assumed.
    pub fn new(name: &Name, version: &FullVersion) -> Result<Self, EntryNameError> {
        Self::parse(&format!("{name}-{version}"))
    }

    /// The directory name exactly as it appears on disk.
    ///
    /// Paths into the entry are always built from this, never from a re-rendered
    /// `<name>-<version>`. libalpm rebuilds the path from the parsed halves, which can address
    /// a directory other than the one scanned. Retaining the original string makes that drift
    /// impossible.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The package name.
    #[must_use]
    pub const fn name(&self) -> &Name {
        &self.name
    }

    /// The package version.
    #[must_use]
    pub const fn version(&self) -> &FullVersion {
        &self.version
    }

    /// The name portion of the directory name, as a string slice.
    #[must_use]
    pub fn name_str(&self) -> &str {
        self.raw.get(..self.name_len).unwrap_or_default()
    }
}

impl fmt::Display for EntryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl AsRef<str> for EntryName {
    fn as_ref(&self) -> &str {
        &self.raw
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

    /// Every case here, except the two marked otherwise, is a real directory name taken from
    /// an installed Arch system. A regression here breaks a package that actually exists.
    #[test]
    fn accepts_real_world_entry_names() {
        let cases: &[(&str, &str, &str)] = &[
            // (directory name, expected package name, expected version)
            ("0ad-0.28.0-3", "0ad", "0.28.0-3"),
            ("0ad-data-0.28.0-1", "0ad-data", "0.28.0-1"),
            ("aalib-1.4rc5-19", "aalib", "1.4rc5-19"),
            // A one-component name whose version halves are both bare integers.
            ("base-3-3", "base", "3-3"),
            ("base-devel-1-2", "base-devel", "1-2"),
            // Eight dashes; six of them belong to the name.
            (
                "qemu-hw-display-virtio-gpu-pci-rutabaga-11.0.3-1",
                "qemu-hw-display-virtio-gpu-pci-rutabaga",
                "11.0.3-1",
            ),
            // Epoch form.
            ("pulse-native-provider-1:1.6.8-1", "pulse-native-provider", "1:1.6.8-1"),
            ("pipewire-session-manager-1:1.6.8-1", "pipewire-session-manager", "1:1.6.8-1"),
            // '+' inside pkgver.
            ("gcc-libs-16.1.1+r595+g171d15ac6959-1", "gcc-libs", "16.1.1+r595+g171d15ac6959-1"),
            (
                "python-opentelemetry-exporter-otlp-proto-common-1.44.0-1",
                "python-opentelemetry-exporter-otlp-proto-common",
                "1.44.0-1",
            ),
            ("abseil-cpp-20260526.0-2", "abseil-cpp", "20260526.0-2"),
            // Not from a real system: proves the *last* two dashes win, not the first two.
            ("foo-1-1-1", "foo-1", "1-1"),
        ];

        for &(raw, expected_name, expected_version) in cases {
            let entry = EntryName::parse(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
            assert_eq!(entry.name().as_ref(), expected_name, "name of {raw:?}");
            assert_eq!(entry.version().to_string(), expected_version, "version of {raw:?}");
            assert_eq!(entry.as_str(), raw, "raw of {raw:?}");
            assert_eq!(entry.name_str(), expected_name, "name_str of {raw:?}");
        }
    }

    /// `ALPM_DB_VERSION` and `db.lck` are the two names that actually turn up next to real
    /// entries. Both must be rejected rather than mistaken for packages.
    #[test]
    fn rejects_names_with_fewer_than_two_separators() {
        for raw in ["ALPM_DB_VERSION", "db.lck", "", "foo", "foo-1", "-", "1.0.0-1"] {
            assert!(
                matches!(EntryName::parse(raw), Err(EntryNameError::TooFewSeparators)),
                "{raw:?} should have too few separators, got {:?}",
                EntryName::parse(raw)
            );
        }
    }

    #[test]
    fn rejects_an_empty_package_name() {
        assert!(matches!(EntryName::parse("-1.0.0-1"), Err(EntryNameError::EmptyName)));
    }

    /// libalpm accepts a leading `.` at split time and only logs a warning afterwards. That
    /// leaves a hidden directory masquerading as a package. piko refuses it outright.
    #[test]
    fn rejects_invalid_package_names() {
        for raw in [".foo-1.0.0-1", "fo o-1.0.0-1", "foo!-1.0.0-1", "föo-1.0.0-1"] {
            assert!(
                matches!(EntryName::parse(raw), Err(EntryNameError::InvalidName { .. })),
                "{raw:?} should have an invalid name, got {:?}",
                EntryName::parse(raw)
            );
        }
    }

    #[test]
    fn rejects_invalid_versions() {
        for raw in [
            "foo-1.0/0-1",   // '/' would escape the entry directory
            "foo-1 0-1",     // whitespace
            "foo-1.0.0-x",   // non-numeric pkgrel
            "foo-1.0.0-",    // empty pkgrel
            "foo-0:1.0.0-1", // epoch must be >= 1
        ] {
            assert!(
                matches!(EntryName::parse(raw), Err(EntryNameError::InvalidVersion { .. })),
                "{raw:?} should have an invalid version, got {:?}",
                EntryName::parse(raw)
            );
        }
    }

    /// Two directories must never denote the same package. A zero-padded pkgrel parses to the
    /// same `FullVersion` as the unpadded one, so piko must refuse it.
    #[test]
    fn rejects_non_canonical_spellings() {
        let err = EntryName::parse("foo-1-01");
        assert!(
            matches!(&err, Err(EntryNameError::NotCanonical { canonical, .. }) if canonical == "foo-1-1"),
            "got {err:?}"
        );
    }

    /// A directory name is a path component. If `as_str` did not reproduce it byte for byte,
    /// a later read would target a different directory than the one scanned.
    #[test]
    fn as_str_round_trips_the_original_bytes() {
        let raw = "qemu-hw-display-virtio-gpu-pci-rutabaga-11.0.3-1";
        let entry = EntryName::parse(raw).unwrap();
        assert_eq!(entry.as_str(), raw);
        assert_eq!(entry.to_string(), raw);
        assert_eq!(AsRef::<str>::as_ref(&entry), raw);
    }

    #[test]
    fn parsing_is_deterministic() {
        let first = EntryName::parse("linux-firmware-20260101.abcdef-1").unwrap();
        let second = EntryName::parse("linux-firmware-20260101.abcdef-1").unwrap();
        assert_eq!(first, second);
    }
}
