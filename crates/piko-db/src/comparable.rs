//! Version values that `alpm-types` can compare.
//!
//! `alpm-types` compares two package versions segment by segment. It reads a numeric segment
//! with `str::parse::<usize>` and unwraps the result (`version/comparison.rs`). So a run of
//! digits past `usize::MAX`, twenty digits or more, panics in every `==`, `<` and sort that
//! reaches it: a dependency check, an update check, a plan. A `PackageRelation`, a soname and an
//! optional dependency hold a version too, and compare through the same code.
//!
//! A repository database comes from a mirror, usually unsigned. So piko refuses such a value
//! where it reads it, and none reaches a comparison. Each reader refuses it as it refuses any
//! other value that does not convert. libalpm's `rpmvercmp` compares digit runs of any length;
//! no package carries one this long.
//!
//! The same check refuses a control character. `alpm-types` accepts every ASCII character in a
//! `pkgver` except white space and six delimiters, so it accepts an escape sequence. A frontend
//! prints a version on almost every line, and a sequence in one could set the terminal's title
//! or write its clipboard. Every reader of a version passes here, so one refusal covers each
//! place a version is printed.

use std::str::FromStr;

use alpm_types::{
    FullVersion, OptionalDependency, PackageRelation, PackageVersion, RelationOrSoname, Soname,
    SonameV1, SonameV2, Version, VersionOrSoname, VersionRequirement,
};

/// A value whose versions `alpm-types` can compare without a panic.
pub trait Comparable {
    /// Checks every version this value holds.
    ///
    /// # Errors
    ///
    /// [`alpm_types::Error::InvalidInteger`] for the first numeric segment that does not fit
    /// a `usize`. [`alpm_types::Error::ValueContainsInvalidChars`] for a control character.
    fn check_comparable(&self) -> Result<(), alpm_types::Error>;
}

/// Parses `value` with the `alpm-types` parser of `T`, and refuses a value it cannot compare.
///
/// # Errors
///
/// The parser's error, or the one [`Comparable::check_comparable`] returns.
pub fn parse<T>(value: &str) -> Result<T, alpm_types::Error>
where
    T: FromStr<Err = alpm_types::Error> + Comparable,
{
    let parsed = T::from_str(value)?;
    parsed.check_comparable()?;
    Ok(parsed)
}

/// Checks each numeric segment of a `pkgver` as `alpm-types` reads it: a maximal run of numeric
/// characters, which a `pkgver` holds in ASCII only. Refuses a control character first.
fn check_pkgver(pkgver: &str) -> Result<(), alpm_types::Error> {
    if let Some(invalid_char) = pkgver.chars().find(|character| character.is_control()) {
        return Err(alpm_types::Error::ValueContainsInvalidChars { invalid_char });
    }
    for run in pkgver.split(|c: char| !c.is_numeric()).filter(|run| !run.is_empty()) {
        run.parse::<usize>()?;
    }
    Ok(())
}

impl Comparable for PackageVersion {
    fn check_comparable(&self) -> Result<(), alpm_types::Error> {
        check_pkgver(self.inner())
    }
}

impl Comparable for FullVersion {
    fn check_comparable(&self) -> Result<(), alpm_types::Error> {
        self.pkgver.check_comparable()
    }
}

impl Comparable for Version {
    fn check_comparable(&self) -> Result<(), alpm_types::Error> {
        self.pkgver.check_comparable()
    }
}

impl Comparable for VersionRequirement {
    fn check_comparable(&self) -> Result<(), alpm_types::Error> {
        self.version.check_comparable()
    }
}

impl Comparable for PackageRelation {
    fn check_comparable(&self) -> Result<(), alpm_types::Error> {
        self.version_requirement.as_ref().map_or(Ok(()), Comparable::check_comparable)
    }
}

impl Comparable for Soname {
    fn check_comparable(&self) -> Result<(), alpm_types::Error> {
        self.version.as_ref().map_or(Ok(()), Comparable::check_comparable)
    }
}

impl Comparable for SonameV1 {
    fn check_comparable(&self) -> Result<(), alpm_types::Error> {
        match self {
            Self::Explicit { version, .. } => version.check_comparable(),
            // libalpm reads `name=soname-arch` as an `=` constraint whose version is the
            // soname, and `crate::depcmp` compares it as one. So its digits are checked as a
            // `pkgver`'s are.
            Self::Unversioned { soname, .. } => check_pkgver(soname.as_str()),
            Self::Basic(_) => Ok(()),
        }
    }
}

impl Comparable for SonameV2 {
    fn check_comparable(&self) -> Result<(), alpm_types::Error> {
        self.soname.check_comparable()
    }
}

impl Comparable for VersionOrSoname {
    fn check_comparable(&self) -> Result<(), alpm_types::Error> {
        match self {
            Self::Version(version) => version.check_comparable(),
            Self::Soname(soname) => check_pkgver(soname.as_str()),
        }
    }
}

impl Comparable for RelationOrSoname {
    fn check_comparable(&self) -> Result<(), alpm_types::Error> {
        match self {
            Self::Relation(relation) => relation.check_comparable(),
            Self::SonameV1(soname) => soname.check_comparable(),
            Self::SonameV2(soname) => soname.check_comparable(),
        }
    }
}

impl Comparable for OptionalDependency {
    fn check_comparable(&self) -> Result<(), alpm_types::Error> {
        self.package_relation().check_comparable()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    /// The value the check exists for: `alpm-types` itself panics when it compares it.
    const PAST_USIZE: &str = "99999999999999999999";

    #[test]
    fn a_numeric_segment_past_usize_is_refused_in_every_kind_of_value() {
        let values = [
            format!("{PAST_USIZE}-1"),
            format!("1.{PAST_USIZE}a.2-1"),
            format!("1:1.0.r{PAST_USIZE}.g0abc-1"),
        ];
        for value in &values {
            assert!(parse::<FullVersion>(value).is_err(), "{value}");
            let relation = format!("foo>={value}");
            assert!(parse::<PackageRelation>(&relation).is_err(), "{relation}");
            assert!(parse::<RelationOrSoname>(&relation).is_err(), "{relation}");
            let optional = format!("{relation}: a reason");
            assert!(parse::<OptionalDependency>(&optional).is_err(), "{optional}");
        }
        let soname = format!("libfoo.so={PAST_USIZE}-64");
        assert!(parse::<RelationOrSoname>(&soname).is_err(), "{soname}");
    }

    /// `libfoo.so=libfoo-<digits>.so-64` holds no version in the `alpm-types` sense, but a
    /// dependency check compares its soname as one. So its digits are checked too.
    #[test]
    fn a_numeric_segment_past_usize_is_refused_in_an_unversioned_soname() {
        let soname = format!("libfoo.so=libfoo-{PAST_USIZE}.so-64");
        assert!(matches!(
            RelationOrSoname::from_str(&soname),
            Ok(RelationOrSoname::SonameV1(SonameV1::Unversioned { .. }))
        ));
        assert!(parse::<RelationOrSoname>(&soname).is_err(), "{soname}");
        assert!(parse::<RelationOrSoname>("libgegl-npd-0.4.so=libgegl-npd-0.4.so-64").is_ok());
    }

    /// `alpm-types` accepts an escape sequence in a `pkgver`. A version is printed on almost
    /// every line a frontend writes, so the readers refuse one.
    #[test]
    fn a_control_character_in_a_version_is_refused() {
        // A title change: an escape, an operating system command, and the bell that ends it.
        let version = "1\u{1b}]0;PWNED\u{7}-1";
        assert!(FullVersion::from_str(version).is_ok(), "alpm-types refuses it now");
        assert!(parse::<FullVersion>(version).is_err());
        assert!(parse::<PackageRelation>(&format!("foo>={version}")).is_err());
        assert!(parse::<RelationOrSoname>(&format!("foo={version}")).is_err());
        for version in ["1\u{0}-1", "1\u{7f}-1", "1\u{8}-1"] {
            assert!(parse::<FullVersion>(version).is_err(), "{version:?}");
        }
    }

    #[test]
    fn a_value_that_fits_is_kept() {
        let longest = "18446744073709551615";
        assert_eq!(usize::MAX.to_string(), longest);
        for value in [format!("{longest}-1"), "0000000000000000000000001-1".to_owned()] {
            assert!(parse::<FullVersion>(&value).is_ok(), "{value}");
        }
        for value in ["foo", "foo>=1.0-1", "libfoo.so=1-64", "lib:libfoo.so.1"] {
            assert!(parse::<RelationOrSoname>(value).is_ok(), "{value}");
        }
    }

    /// The panic this module prevents, so the test fails once `alpm-types` compares safely
    /// and the check can be reconsidered.
    #[test]
    fn alpm_types_panics_comparing_such_a_version() {
        let big = FullVersion::from_str(&format!("{PAST_USIZE}-1")).unwrap();
        let small = FullVersion::from_str("1-1").unwrap();
        assert!(std::panic::catch_unwind(|| big == small).is_err());
    }
}
