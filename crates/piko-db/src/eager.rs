//! The `desc` sections both databases parse themselves, without `alpm-db`/`alpm-repo-db`.
//!
//! # Why this exists
//!
//! `DbDescFile::from_str_with_schema` and `RepoDescFile::from_str_with_schema` are
//! all-or-nothing. They convert every section of a `desc` into its typed form, including
//! `%LICENSE%` (SPDX), `%URL%` (through the `url` crate's IDNA machinery), `%PACKAGER%`, and
//! the checksum fields. Measured against this machine's real databases, that conversion costs
//! **18x a raw `%KEYWORD%` section split**, and dominates opening either database.
//!
//! All-or-nothing is also why `%URL%` and `%PACKAGER%` are taken out of the text before
//! either parser sees it ([`crate::desc_compat::take_fields`]): a value their typed
//! conversion refuses would otherwise cost the `desc` every other section, down to the
//! `%FILENAME%` an install downloads.
//!
//! Only a handful of sections are needed by everything. [`crate::solve::Universe`] reads the
//! relation sections and `%GROUPS%` for every candidate in the universe, so deferring *those*
//! buys nothing. This module parses exactly that subset, cheaply. Every other section stays
//! behind the lazy full parse — [`crate::repo::RepoPackage::desc`] and
//! [`crate::LocalPackage::desc`].
//!
//! # This is not a hand-rolled parser for a format `alpm-*` already implements
//!
//! Every *value* goes through `alpm-types`' own parser. This
//! module skips only the upstream crates' typed conversion of sections it does not need. The
//! `%KEYWORD%` section split that replaces it already exists in
//! [`crate::desc_compat::filter_unknown_sections`].
//!
//! # Why one module rather than one per database
//!
//! The two `desc` formats differ only in which sections they carry. Both share an identical
//! section grammar and an identical set of relation sections. The repository format adds
//! `%CSIZE%`/`%ISIZE%`; the local format adds `%REASON%` and a dozen others. The scan that
//! finds them is the same scan. [`scan`] does it once and hands every other section's lines
//! to the caller, so neither side walks the text twice, and the two cannot drift on what a
//! relation section is.

use std::str::FromStr;

use alpm_types::{Group, PackageRelation, RelationOrSoname};

/// The relation sections every caller of this module needs.
#[derive(Debug, Default)]
pub(crate) struct Relations {
    /// `%DEPENDS%`, the run-time dependencies — empty when [`Depends::Deferred`] was asked
    /// for, in which case [`Relations::depends_text`] holds the raw section instead.
    pub(crate) depends: Box<[RelationOrSoname]>,
    /// `%PROVIDES%`.
    pub(crate) provides: Box<[RelationOrSoname]>,
    /// `%CONFLICTS%`.
    pub(crate) conflicts: Box<[PackageRelation]>,
    /// `%REPLACES%`.
    pub(crate) replaces: Box<[PackageRelation]>,
    /// `%GROUPS%`.
    pub(crate) groups: Box<[Group]>,
    /// Where `%DEPENDS%` lives in the scanned text, as a `(start, end)` byte range, when it
    /// was deferred. `None` means it was parsed into `depends`, or the section was absent.
    pub(crate) depends_text: Option<(usize, usize)>,
}

/// Whether [`scan`] converts `%DEPENDS%` or only records where it is.
///
/// # Why this is a choice and not a constant
///
/// `%DEPENDS%` is by far the largest relation section — 73 286 of the 86 006 relation entries
/// in this machine's `extra.db` — and the only one whose *whole-universe* conversion is
/// wasted work. [`crate::solve::Universe::index`] builds its maps from `%PROVIDES%`,
/// `%CONFLICTS%`, `%GROUPS%` and `%REPLACES%`, never from `%DEPENDS%`; only
/// `crate::solve::encode` reads dependencies, and only for the solvables inside its
/// reachable cone — **2629 of 16 429** on this machine's sysupgrade, 16%.
///
/// Deferring it is worth 61 ms -> 27 ms across `extra.db` (`docs/perf-study.md` §3.4).
///
/// It is deferred for **repository** candidates only. Every installed package is a seed of
/// that cone, so a local `desc`'s `%DEPENDS%` is always needed and deferring it would buy
/// nothing but a second pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Depends {
    /// Convert `%DEPENDS%` during the scan, like every other relation section.
    Eager,
    /// Record the section's byte range and convert it on demand, through [`parse_depends`].
    Deferred,
}

/// Why a `desc` could not yield the fields every package must have.
///
/// Carried by [`crate::repo::RepoDiagnostic::InvalidDesc`], whose package is dropped, and by
/// [`crate::LocalPackage`]'s cached load failure. The full typed parse is deferred, so an
/// `alpm_repo_db::Error` cannot occur at open time — it surfaces through the lazy `desc`
/// accessor instead.
#[derive(Debug)]
#[non_exhaustive]
pub enum DescFieldError {
    /// A section every `desc` must carry was absent.
    MissingSection {
        /// The `%KEYWORD%` name, without the percent signs.
        section: &'static str,
    },
    /// An entry in a relation section did not parse.
    InvalidEntry {
        /// The `%KEYWORD%` name, without the percent signs.
        section: &'static str,
        /// The line that failed.
        value: String,
        /// The underlying `alpm-types` failure.
        source: alpm_types::Error,
    },
    /// A section did not hold the scalar its keyword requires.
    InvalidSize {
        /// The `%KEYWORD%` name, without the percent signs.
        section: &'static str,
        /// The line that failed.
        value: String,
    },
}

impl std::fmt::Display for DescFieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSection { section } => write!(f, "missing mandatory section %{section}%"),
            Self::InvalidEntry { section, value, source } => {
                write!(f, "%{section}%: {value:?} is not valid: {source}")
            }
            Self::InvalidSize { section, value } => {
                write!(f, "%{section}%: {value:?} is not a decimal integer")
            }
        }
    }
}

impl std::error::Error for DescFieldError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEntry { source, .. } => Some(source),
            Self::MissingSection { .. } | Self::InvalidSize { .. } => None,
        }
    }
}

/// Parses one `%DEPENDS%` or `%PROVIDES%` entry, avoiding two failed parses in the common case.
///
/// `RelationOrSoname::from_str` tries alpm-sonamev2, then alpm-sonamev1, then
/// alpm-package-relation, constructing and discarding a `winnow` error for each failed
/// attempt. Measured over the 73 286 real `%DEPENDS%` entries in this machine's `extra.db`,
/// that costs **1.47 µs** per entry against `PackageRelation::from_str`'s **0.15 µs** — a
/// factor of ten.
///
/// The screen is conservative and derived from the two upstream parsers, not guessed:
/// `SonameV2::parser` requires the `<prefix>:<soname>` delimiter, and `SonameV1`'s
/// `SharedObjectName::parser` requires a literal `.so` suffix. A string containing neither
/// can only be a `PackageRelation`, which is precisely the branch
/// `RelationOrSoname::parser` would reach after its two failures.
///
/// # The screen must run before the fast parse, not after it
///
/// The obvious shortcut — try `PackageRelation::from_str` first and accept whatever it
/// returns — is **wrong**, and quietly so. `libexample.so` is a perfectly valid *package
/// name*, so `PackageRelation` accepts it and the result would be `Relation` where the real
/// parser returns `SonameV1`. That is not rare: of the 82 461 `%DEPENDS%` and `%PROVIDES%`
/// entries across this machine's `core` and `extra`, **5320 are sonames**, and only 7 of
/// `extra`'s `%DEPENDS%` entries fail `PackageRelation` outright. Testing the string first is
/// what makes the difference, and
/// `the_fast_path_agrees_on_every_real_relation_in_every_repository` is what proves it.
///
/// The fallback is unconditional on failure, not just on a match, so a malformed entry still
/// reports the error `RelationOrSoname::from_str` would have reported rather than
/// `PackageRelation`'s narrower one. That keeps this observationally identical to the parser
/// it replaces, at a cost paid only on input that was going to be rejected anyway.
pub(crate) fn relation_or_soname(value: &str) -> Result<RelationOrSoname, alpm_types::Error> {
    // The screen, first: anything that could be either soname form goes to the real parser.
    if value.contains(':') || value.contains(".so") {
        return RelationOrSoname::from_str(value);
    }
    PackageRelation::from_str(value)
        .map(RelationOrSoname::Relation)
        .or_else(|_| RelationOrSoname::from_str(value))
}

/// Which section the scanner is currently inside.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Section<'a> {
    Depends,
    Provides,
    Conflicts,
    Replaces,
    Groups,
    /// Any other `%KEYWORD%`, carried so the caller can read the ones it cares about.
    Other(&'a str),
    /// Before the first `%KEYWORD%` line, where a value line has no section to belong to.
    None,
}

impl<'a> Section<'a> {
    /// Classifies a `%KEYWORD%` name.
    fn classify(keyword: &'a str) -> Self {
        // Matched as bytes because `str` cannot be matched in a `const fn` at all — not an
        // MSRV limitation that a newer toolchain lifts, but unstable outright ("`str` cannot
        // be compared in compile-time", rust-lang/rust#143874).
        match keyword.as_bytes() {
            b"DEPENDS" => Self::Depends,
            b"PROVIDES" => Self::Provides,
            b"CONFLICTS" => Self::Conflicts,
            b"REPLACES" => Self::Replaces,
            b"GROUPS" => Self::Groups,
            _ => Self::Other(keyword),
        }
    }
}

/// Walks `text` once, collecting the relation sections and handing every other section's
/// value lines to `other` as `(keyword, line)`.
///
/// `text` is the *filtered* text — unknown sections already removed by
/// [`crate::desc_compat::filter_unknown_sections`] — so a keyword reaching `other` is one
/// this build knows but this module does not read.
///
/// # Errors
///
/// [`DescFieldError::InvalidEntry`] if any relation entry fails to parse, or whatever `other`
/// returns for a section it recognises.
pub(crate) fn scan<'a>(
    text: &'a str,
    depends_mode: Depends,
    mut other: impl FnMut(&'a str, &'a str) -> Result<(), DescFieldError>,
) -> Result<Relations, DescFieldError> {
    let mut depends = Vec::new();
    let mut depends_text: Option<(usize, usize)> = None;
    // Byte offsets into `text`, so a deferred `%DEPENDS%` can be re-read without a second
    // scan of the whole entry. `str::lines` yields borrowed slices of `text`, so each line's
    // offset is recoverable from its pointer without tracking a running counter.
    let offset_of = |line: &str| {
        // Both pointers are into `text`; `line` is always a subslice of it.
        (line.as_ptr() as usize).saturating_sub(text.as_ptr() as usize)
    };
    let mut provides = Vec::new();
    let mut conflicts = Vec::new();
    let mut replaces = Vec::new();
    let mut groups = Vec::new();
    let mut section = Section::None;

    for line in text.lines() {
        if let Some(keyword) = line.strip_prefix('%').and_then(|rest| rest.strip_suffix('%')) {
            section = Section::classify(keyword);
            if section == Section::Depends && depends_mode == Depends::Deferred {
                // The section body starts on the next line; its end is fixed up by every
                // subsequent line that still belongs to it.
                let start = offset_of(line).saturating_add(line.len());
                depends_text = Some((start, start));
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }

        match section {
            Section::Depends if depends_mode == Depends::Deferred => {
                if let Some(range) = depends_text.as_mut() {
                    range.1 = offset_of(line).saturating_add(line.len());
                }
            }
            Section::Depends => depends.push(entry(line, "DEPENDS", relation_or_soname)?),
            Section::Provides => provides.push(entry(line, "PROVIDES", relation_or_soname)?),
            Section::Conflicts => {
                conflicts.push(entry(line, "CONFLICTS", PackageRelation::from_str)?);
            }
            Section::Replaces => {
                replaces.push(entry(line, "REPLACES", PackageRelation::from_str)?);
            }
            Section::Groups => groups.push(line.to_owned()),
            Section::Other(keyword) => other(keyword, line)?,
            Section::None => {}
        }
    }

    Ok(Relations {
        depends: depends.into_boxed_slice(),
        provides: provides.into_boxed_slice(),
        conflicts: conflicts.into_boxed_slice(),
        replaces: replaces.into_boxed_slice(),
        groups: groups.into_boxed_slice(),
        depends_text,
    })
}

/// Converts a `%DEPENDS%` section that [`scan`] deferred.
///
/// `text` is the same text that was scanned, and `range` the `(start, end)` [`scan`] recorded.
///
/// # Errors
///
/// [`DescFieldError::InvalidEntry`] if any entry fails to parse — the same error, from the
/// same parser, that an eager scan would have reported at open time.
pub(crate) fn parse_depends(
    text: &str,
    range: Option<(usize, usize)>,
) -> Result<Box<[RelationOrSoname]>, DescFieldError> {
    let Some((start, end)) = range else { return Ok(Box::default()) };
    let Some(section) = text.get(start..end) else { return Ok(Box::default()) };

    let mut depends = Vec::new();
    for line in section.lines() {
        if line.is_empty() {
            continue;
        }
        depends.push(entry(line, "DEPENDS", relation_or_soname)?);
    }
    Ok(depends.into_boxed_slice())
}

/// Applies `parse_one` to `value`, attaching the section name to any failure.
fn entry<T>(
    value: &str,
    section: &'static str,
    parse_one: impl Fn(&str) -> Result<T, alpm_types::Error>,
) -> Result<T, DescFieldError> {
    parse_one(value).map_err(|source| DescFieldError::InvalidEntry {
        section,
        value: value.to_owned(),
        source,
    })
}

/// Parses a decimal scalar section such as `%CSIZE%`, `%ISIZE%` or `%REASON%`.
///
/// # Errors
///
/// [`DescFieldError::InvalidSize`] if `value` does not parse as `T` — a non-numeric or
/// out-of-range line.
pub(crate) fn scalar<T: FromStr>(value: &str, section: &'static str) -> Result<T, DescFieldError> {
    value.parse().map_err(|_| DescFieldError::InvalidSize { section, value: value.to_owned() })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// The screen must not change which variant a value parses into. This is the property the
    /// whole optimisation rests on, so it is asserted per variant rather than in aggregate.
    #[test]
    fn the_fast_path_agrees_with_the_parser_it_replaces() {
        for value in [
            "glibc",
            "bash>=5.0",
            "python<4",
            "foo=1.0.0-1",
            "libexample.so",
            "libexample.so=1-64",
            "libexample.so.1",
            "lib:libexample.so.1",
            "lib:libexample.so",
            "a-package-with-dots.in.name",
            "gcc-libs",
        ] {
            let fast = relation_or_soname(value);
            let slow = RelationOrSoname::from_str(value);
            assert_eq!(
                fast.as_ref().ok(),
                slow.as_ref().ok(),
                "{value:?} parsed differently by the fast path"
            );
        }
    }

    /// A malformed entry must report the same failure as the parser being replaced, which is
    /// why the fallback is unconditional rather than gated on the screen.
    #[test]
    fn a_malformed_entry_still_reports_the_upstream_error() {
        let value = "not a valid relation at all!!";
        assert!(relation_or_soname(value).is_err());
        assert!(RelationOrSoname::from_str(value).is_err());
    }

    /// The acceptance gate for the screen: every `%DEPENDS%` and `%PROVIDES%` entry in every
    /// repository on this machine must parse to the **identical** value through the fast path
    /// and through `RelationOrSoname::from_str`.
    ///
    /// A fixture cannot establish this. The whole optimisation is a claim about which real
    /// strings can be sonames, and only the real repositories can refute it — `extra` alone
    /// holds 73 286 `%DEPENDS%` entries, of which 7 are sonames.
    #[test]
    #[ignore = "requires this machine's real /var/lib/pacman/sync"]
    fn the_fast_path_agrees_on_every_real_relation_in_every_repository() {
        use crate::repo::archive::{self, ArchiveItem};

        let sync = std::path::Path::new("/var/lib/pacman/sync");
        if !sync.is_dir() {
            println!("skipping: {} not present", sync.display());
            return;
        }

        let mut checked = 0_usize;
        let mut sonames = 0_usize;
        let mut archives = 0_usize;

        for entry in std::fs::read_dir(sync).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|ext| ext != "db") {
                continue;
            }
            archives += 1;

            archive::walk(
                &path,
                &crate::limits::Limits::default(),
                |item| {
                    let ArchiveItem::Desc { entry, text } = item else { return Ok(()) };
                    let mut inside = false;
                    for line in text.lines() {
                        if let Some(keyword) =
                            line.strip_prefix('%').and_then(|rest| rest.strip_suffix('%'))
                        {
                            inside = matches!(keyword, "DEPENDS" | "PROVIDES");
                            continue;
                        }
                        if line.is_empty() || !inside {
                            continue;
                        }

                        let fast = relation_or_soname(line);
                        let slow = RelationOrSoname::from_str(line);
                        assert_eq!(
                            fast.as_ref().ok(),
                            slow.as_ref().ok(),
                            "{}: {line:?} parsed differently by the fast path",
                            entry.as_str(),
                        );
                        if !matches!(slow, Ok(RelationOrSoname::Relation(_))) {
                            sonames += 1;
                        }
                        checked += 1;
                    }
                    Ok(())
                },
                |_skipped| {},
            )
            .unwrap();
        }

        assert!(archives > 0, "no .db archives found to check");
        println!(
            "{checked} relations across {archives} repositories agree; {sonames} were sonames"
        );
    }
}
