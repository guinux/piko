//! Reading a `.PKGINFO`, with the one compatibility shim its typed parse needs.
//!
//! `alpm-pkginfo` converts every field or none, exactly as the two `desc` parsers do. So the
//! same value that costs a `desc` its every section costs a package file its every field —
//! and here the cost is worse: a package whose `.PKGINFO` does not parse cannot be installed
//! at all.
//!
//! The value is `packager`. `alpm_types::Packager` demands a `<email>`, and makepkg writes
//! [`UNKNOWN_PACKAGER`] whenever `PACKAGER` is unset in `makepkg.conf` — which is how it
//! ships. libalpm copies the field through untouched (`be_package.c:215`).
//!
//! [`crate::record::desc`] writes `%PACKAGER%` from the raw text rather than from the parsed
//! value, so the substitute made here is never stored.

use std::{borrow::Cow, str::FromStr as _};

use alpm_pkginfo::PackageInfo;
use piko_db::desc_compat::UNKNOWN_PACKAGER;

/// The `key = value` separator every `.PKGINFO` line uses, for the `packager` key.
const PACKAGER_PREFIX: &str = "packager = ";

/// The line put in place of makepkg's default, so the typed parse accepts the file.
///
/// It never reaches the database: [`crate::record::desc`] writes `%PACKAGER%` from the raw
/// text.
const UNKNOWN_PACKAGER_SUBSTITUTE: &str = "packager = Unknown Packager <unknown@example.invalid>";

/// Whether `line` is the `packager` line makepkg writes when `PACKAGER` is unset.
fn is_unknown_packager(line: &str) -> bool {
    line.strip_prefix(PACKAGER_PREFIX) == Some(UNKNOWN_PACKAGER)
}

/// Parses a `.PKGINFO`, accepting makepkg's default packager.
///
/// Only [`UNKNOWN_PACKAGER`] is accepted. Every other value `alpm_types::Packager` refuses
/// still fails the parse, because it is a defect in that package rather than a documented
/// default of the tool that built it.
///
/// # Errors
///
/// Whatever `alpm-pkginfo` returns for the text, once the substitution is done.
pub fn parse(raw: &str) -> Result<PackageInfo, alpm_pkginfo::Error> {
    PackageInfo::from_str(&substitute_unknown_packager(raw))
}

/// Rewrites a `packager` line holding [`UNKNOWN_PACKAGER`] into one that parses.
///
/// `.PKGINFO` is `key = value` per line, with `#` comments, so the value is matched against
/// the whole of what follows `packager = ` and no other packager is touched. Every matching
/// line is rewritten, not only the first: unlike the `desc` case, this hides nothing, because
/// a duplicated `packager` line stays duplicated for `alpm-pkginfo` to report.
///
/// Borrows when there is nothing to rewrite, which is every package built by someone who set
/// the variable.
fn substitute_unknown_packager(raw: &str) -> Cow<'_, str> {
    if !raw.lines().any(is_unknown_packager) {
        return Cow::Borrowed(raw);
    }

    let mut out =
        String::with_capacity(raw.len().saturating_add(UNKNOWN_PACKAGER_SUBSTITUTE.len()));
    for line in raw.lines() {
        out.push_str(if is_unknown_packager(line) { UNKNOWN_PACKAGER_SUBSTITUTE } else { line });
        out.push('\n');
    }
    Cow::Owned(out)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// A `.PKGINFO` with `packager` left as `$1`.
    fn pkginfo(packager: &str) -> String {
        format!(
            "pkgname = foo\npkgbase = foo\npkgver = 1.0.0-1\npkgdesc = an example\n\
             url = https://example.org/\nbuilddate = 1\npackager = {packager}\nsize = 1\n\
             arch = x86_64\n"
        )
    }

    #[test]
    fn makepkgs_default_packager_is_accepted() {
        let info = parse(&pkginfo(UNKNOWN_PACKAGER)).unwrap();
        let PackageInfo::V1(v1) = info else { panic!("a .PKGINFO with no xdata is v1") };
        assert_eq!(v1.pkgname.as_ref(), "foo");
    }

    /// The substitution is the only one. A packager that is merely malformed still fails, so a
    /// broken package file is not quietly accepted as a locally built one.
    #[test]
    fn any_other_packager_without_an_email_still_fails() {
        for packager in ["Jane Doe", "", "Unknown Packager!", "unknown packager"] {
            assert!(parse(&pkginfo(packager)).is_err(), "{packager:?} must not be accepted");
        }
    }

    #[test]
    fn a_real_packager_is_parsed_and_the_text_is_not_copied() {
        let raw = pkginfo("Jane Doe <jane@example.org>");
        assert!(matches!(substitute_unknown_packager(&raw), Cow::Borrowed(_)));
        assert!(parse(&raw).is_ok());
    }
}
