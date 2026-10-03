//! The `desc` sections both databases read for every package.
//!
//! # Why this exists
//!
//! The typed conversion of a whole `desc` includes `%LICENSE%` (SPDX), `%URL%` (through the
//! `url` crate's IDNA machinery), `%PACKAGER%`, and the checksum fields. Measured against this
//! machine's real databases, converting every section costs **18x a raw `%KEYWORD%` section
//! split**, and would dominate opening either database.
//!
//! Only a handful of sections are needed by everything. [`crate::solve::Universe`] reads the
//! relation sections and `%GROUPS%` for every candidate in the universe, so deferring *those*
//! buys nothing. This module parses exactly that subset, cheaply. Every other section stays
//! behind the lazy full parse — [`crate::repo::RepoPackage::desc`] and
//! [`crate::LocalPackage::desc`].
//!
//! Every *value* goes through `alpm-types`' own parser. The sections come from
//! [`crate::meta::section`], the one reader of the `%KEYWORD%` grammar.
//!
//! # Why one module rather than one per database
//!
//! The two `desc` formats differ only in which sections they carry. Both share an identical section
//! grammar and an identical set of relation sections. The repository format adds
//! `%CSIZE%`/`%ISIZE%`; the local format adds `%REASON%` and a dozen others. The scan that finds
//! them is the same scan. `scan` does it once and hands every other section to the caller. So neither side walks the text twice, and the two cannot drift on what a relation
//! section is.

use std::str::FromStr;

use alpm_types::{Group, PackageRelation, RelationOrSoname};

use crate::meta::section::{Section as TextSection, Sections};

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
    /// Where `%DEPENDS%` lives in the scanned text, as one `(start, end)` byte range per
    /// section, when it was deferred. Empty means it was parsed into `depends`, or the section
    /// was absent.
    pub(crate) depends_text: Box<[(usize, usize)]>,
}

/// Whether [`scan`] converts `%DEPENDS%` or only records where it is.
///
/// # Why this is a choice and not a constant
///
/// `%DEPENDS%` is by far the largest relation section. It holds 73 286 of the 86 006 relation
/// entries in this machine's `extra.db`. It is also the only one whose *whole-universe*
/// conversion is wasted work. [`crate::solve::Universe::index`] builds its maps from
/// `%PROVIDES%`, `%CONFLICTS%`, `%GROUPS%` and `%REPLACES%`, never from `%DEPENDS%`. Only
/// `crate::solve::encode` reads dependencies. It reads them only for the solvables inside its
/// reachable cone — **2629 of 16 429** on this machine's sysupgrade, 16%.
///
/// Deferring it is worth 61 ms -> 27 ms across `extra.db` (`docs/perf-study.md` §3.4).
///
/// It is deferred for **repository** candidates only. Every installed package is a seed of
/// that cone, so a local `desc`'s `%DEPENDS%` is always needed. Deferring it would buy
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
/// [`crate::LocalPackage`]'s cached load failure, and by the full `desc` of either database
/// for a section that decides something. A section that is shown only keeps its error to
/// itself.
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
    /// A value line is not one of the values its section allows.
    InvalidValue {
        /// The `%KEYWORD%` name, without the percent signs.
        section: &'static str,
        /// The line that failed.
        value: String,
    },
    /// A section that holds one value appears twice.
    DuplicateSection {
        /// The `%KEYWORD%` name, without the percent signs.
        section: &'static str,
    },
    /// A section that holds one value has more than one value line.
    TooManyValues {
        /// The `%KEYWORD%` name, without the percent signs.
        section: &'static str,
    },
    /// A section this build does not recognise, refused under
    /// [`UnknownSectionPolicy::Reject`](crate::UnknownSectionPolicy::Reject).
    UnknownSection {
        /// The `%KEYWORD%` name, without the percent signs.
        keyword: String,
        /// The 1-based line number of the header.
        line: usize,
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
            Self::InvalidValue { section, value } => {
                write!(f, "%{section}%: {value:?} is not valid")
            }
            Self::DuplicateSection { section } => write!(f, "section %{section}% appears twice"),
            Self::TooManyValues { section } => {
                write!(f, "section %{section}% holds more than one value")
            }
            Self::UnknownSection { keyword, line } => {
                write!(f, "line {line}: unknown section %{keyword}%")
            }
        }
    }
}

impl std::error::Error for DescFieldError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEntry { source, .. } => Some(source),
            Self::MissingSection { .. }
            | Self::InvalidSize { .. }
            | Self::InvalidValue { .. }
            | Self::DuplicateSection { .. }
            | Self::TooManyValues { .. }
            | Self::UnknownSection { .. } => None,
        }
    }
}

/// Why [`scan`] stopped before the end of a `desc`.
///
/// Two outcomes with two different scopes, so they are not one error type. A
/// [`DescFieldError`] is a defect in one `desc`: the caller drops that package and reads the
/// rest. An exhausted [`RelationBudget`] is a property of the whole database: the caller must
/// fail the open, or the next `desc` parses past the bound.
#[derive(Debug)]
pub(crate) enum ScanError {
    /// A section of this `desc` is missing or malformed.
    Field(DescFieldError),
    /// The database holds more relation entries than its [`RelationBudget`] allows.
    Budget {
        /// The configured maximum.
        max: usize,
    },
}

impl From<DescFieldError> for ScanError {
    fn from(error: DescFieldError) -> Self {
        Self::Field(error)
    }
}

/// How many more relation entries one database open may parse.
///
/// Shared by every `desc` of one repository archive, so it bounds the sum over all packages,
/// not each package alone. A bound per package would let an archive spread its entries over
/// [`crate::Limits::repo_max_packages`] packages instead. See
/// [`crate::Limits::repo_max_relations`] for why the byte bounds do not already cover this.
#[derive(Debug)]
pub(crate) struct RelationBudget {
    remaining: usize,
    max: usize,
}

impl RelationBudget {
    /// A budget of `max` entries.
    pub(crate) const fn new(max: usize) -> Self {
        Self { remaining: max, max }
    }

    /// Counts one entry, before it is parsed.
    fn charge(&mut self) -> Result<(), ScanError> {
        match self.remaining.checked_sub(1) {
            Some(remaining) => {
                self.remaining = remaining;
                Ok(())
            }
            None => Err(ScanError::Budget { max: self.max }),
        }
    }
}

/// Parses one `%DEPENDS%` or `%PROVIDES%` entry, avoiding two failed parses in the common case.
///
/// `RelationOrSoname::from_str` tries alpm-sonamev2, then alpm-sonamev1, then
/// alpm-package-relation, constructing and discarding a `winnow` error for each failed
/// attempt. Measured over the 73 286 real `%DEPENDS%` entries in this machine's `extra.db`,
/// that costs **1.47 µs** per entry. `PackageRelation::from_str` costs **0.15 µs**, a factor
/// of ten less.
///
/// The screen is conservative, and derived from the two upstream parsers rather than guessed.
/// `SonameV2::parser` requires the `<prefix>:<soname>` delimiter, and `SonameV1`'s
/// `SharedObjectName::parser` requires a literal `.so` suffix. A string containing neither
/// can only be a `PackageRelation`, which is precisely the branch
/// `RelationOrSoname::parser` would reach after its two failures.
///
/// # The screen must run before the fast parse, not after it
///
/// The obvious shortcut — try `PackageRelation::from_str` first and accept whatever it
/// returns — is **wrong**, and quietly so. `libexample.so` is a perfectly valid *package
/// name*. So `PackageRelation` accepts it, and the result reads `Relation` where the real
/// parser returns `SonameV1`. That is not rare. Of the 82 461 `%DEPENDS%` and `%PROVIDES%`
/// entries across this machine's `core` and `extra`, **5320 are sonames**. Only 7 of
/// `extra`'s `%DEPENDS%` entries fail `PackageRelation` outright. Testing the string first is
/// what makes the difference, and
/// `the_fast_path_agrees_on_every_real_relation_in_every_repository` is what proves it.
///
/// The fallback is unconditional on failure, not just on a match. So a malformed entry still
/// reports the error `RelationOrSoname::from_str` would have reported, rather than
/// `PackageRelation`'s narrower one. That keeps this observationally identical to the parser
/// it replaces. The cost is paid only on input that was going to be rejected anyway.
pub(crate) fn relation_or_soname(value: &str) -> Result<RelationOrSoname, alpm_types::Error> {
    // The screen, first: anything that could be either soname form goes to the real parser.
    if value.contains(':') || value.contains(".so") {
        return RelationOrSoname::from_str(value);
    }
    PackageRelation::from_str(value)
        .map(RelationOrSoname::Relation)
        .or_else(|_| RelationOrSoname::from_str(value))
}

/// Which section a header opens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Section<'a> {
    Depends,
    Provides,
    Conflicts,
    Replaces,
    Groups,
    /// Any other `%KEYWORD%`, carried so the caller can read the ones it cares about.
    Other(&'a str),
}

impl<'a> Section<'a> {
    /// Classifies a `%KEYWORD%` name.
    fn classify(keyword: &'a str) -> Self {
        // Matched as bytes because `str` cannot be matched in a `const fn` at all. This is
        // not an MSRV limitation that a newer toolchain lifts. It is unstable outright
        // ("`str` cannot be compared in compile-time", rust-lang/rust#143874).
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

/// Walks `text` once, collecting the relation sections and handing every other section to
/// `other`.
///
/// The sections come from [`crate::meta::section::Sections`], which is libalpm's reader
/// (`be_sync.c:595`, `be_local.c`). A section that appears twice adds to the first, as
/// `alpm_list_add` does.
///
/// A section reaching `other` is one this module does not read, known to this build or not.
/// The caller decides what an unknown one means.
///
/// Every relation entry is charged to `budget` before it is parsed, a deferred `%DEPENDS%`
/// entry included. So [`parse_depends`] later builds no entry the budget has not counted.
/// `None` counts nothing. That is for the local database, whose `desc` is read uncompressed
/// and capped by [`crate::Limits::desc_bytes`], so its text bounds its parse at a fixed ratio.
///
/// # Errors
///
/// - [`ScanError::Field`] carrying [`DescFieldError::InvalidEntry`] if any relation entry fails
///   to parse, or whatever `other` returns for a section it recognises.
/// - [`ScanError::Budget`] if `budget` runs out.
pub(crate) fn scan<'a>(
    text: &'a str,
    depends_mode: Depends,
    mut budget: Option<&mut RelationBudget>,
    mut other: impl FnMut(&TextSection<'a>) -> Result<(), DescFieldError>,
) -> Result<Relations, ScanError> {
    let mut depends = Vec::new();
    let mut depends_text: Vec<(usize, usize)> = Vec::new();
    let mut provides = Vec::new();
    let mut conflicts = Vec::new();
    let mut replaces = Vec::new();
    let mut groups = Vec::new();

    for found in Sections::new(text) {
        let section = Section::classify(found.keyword);
        if let Section::Other(_) = section {
            other(&found)?;
            continue;
        }

        if section == Section::Depends && depends_mode == Depends::Deferred {
            // Each entry is still charged now, so the deferred parse builds nothing uncounted.
            if let Some(budget) = budget.as_deref_mut() {
                for _ in found.values() {
                    budget.charge()?;
                }
            }
            let range = found.body_range();
            depends_text.push((range.start, range.end));
            continue;
        }

        for line in found.values() {
            if let Some(budget) = budget.as_deref_mut() {
                budget.charge()?;
            }
            match section {
                Section::Depends => depends.push(entry(line, "DEPENDS", relation_or_soname)?),
                Section::Provides => provides.push(entry(line, "PROVIDES", relation_or_soname)?),
                Section::Conflicts => {
                    conflicts.push(entry(line, "CONFLICTS", PackageRelation::from_str)?);
                }
                Section::Replaces => {
                    replaces.push(entry(line, "REPLACES", PackageRelation::from_str)?);
                }
                Section::Groups => groups.push(line.to_owned()),
                Section::Other(_) => {}
            }
        }
    }

    Ok(Relations {
        depends: depends.into_boxed_slice(),
        provides: provides.into_boxed_slice(),
        conflicts: conflicts.into_boxed_slice(),
        replaces: replaces.into_boxed_slice(),
        groups: groups.into_boxed_slice(),
        depends_text: depends_text.into_boxed_slice(),
    })
}

/// Converts a `%DEPENDS%` section that [`scan`] deferred.
///
/// `text` is the same text that was scanned, and `ranges` the `(start, end)` ranges [`scan`]
/// recorded, one per `%DEPENDS%` section, in order.
///
/// # Errors
///
/// [`DescFieldError::InvalidEntry`] if any entry fails to parse. That is the same error, from
/// the same parser, that an eager scan would have reported at open time.
pub(crate) fn parse_depends(
    text: &str,
    ranges: &[(usize, usize)],
) -> Result<Box<[RelationOrSoname]>, DescFieldError> {
    let mut depends = Vec::new();
    for (start, end) in ranges {
        let Some(section) = text.get(*start..*end) else { continue };
        for line in section.lines() {
            if line.is_empty() {
                continue;
            }
            depends.push(entry(line, "DEPENDS", relation_or_soname)?);
        }
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
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    /// `%DEPENDS%` of `text`, read the way `mode` reads it.
    fn depends_of(text: &str, mode: Depends) -> Vec<String> {
        let relations = scan(text, mode, None, |_| Ok(())).unwrap();
        let depends = match mode {
            Depends::Eager => relations.depends,
            Depends::Deferred => parse_depends(text, &relations.depends_text).unwrap(),
        };
        depends.iter().map(ToString::to_string).collect()
    }

    /// A section's values run to the first blank line, as `READ_AND_STORE_ALL` reads them. A
    /// line after it and before the next header belongs to no section.
    #[test]
    fn a_blank_line_ends_a_section() {
        let text = "%DEPENDS%\nfoo\n\nbar\n\n%PROVIDES%\nbaz\n";
        for mode in [Depends::Eager, Depends::Deferred] {
            assert_eq!(depends_of(text, mode), ["foo"], "{mode:?}");
        }
    }

    /// A section that appears twice adds to the first, as `alpm_list_add` does, whether the
    /// section is converted during the scan or deferred.
    #[test]
    fn a_repeated_section_adds_to_the_first() {
        let text = "%DEPENDS%\nfoo\n\n%PROVIDES%\nbaz\n\n%DEPENDS%\nbar\n";
        for mode in [Depends::Eager, Depends::Deferred] {
            assert_eq!(depends_of(text, mode), ["foo", "bar"], "{mode:?}");
        }
    }

    /// A header is what `meta::section::section_keyword` reads as one. `%A%B%` is not, so it
    /// is not a header here either, and it does not end the section before it.
    #[test]
    fn a_header_is_read_as_the_text_filters_read_it() {
        let text = "%GROUPS%\nbase\n%A%B%\n\n%DEPENDS%\nfoo\n";
        let relations = scan(text, Depends::Eager, None, |_| Ok(())).unwrap();
        assert_eq!(relations.groups.as_ref(), ["base".to_owned(), "%A%B%".to_owned()]);
    }

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

    /// A malformed entry must report the same failure as the parser being replaced. That is
    /// why the fallback is unconditional rather than gated on the screen.
    #[test]
    fn a_malformed_entry_still_reports_the_upstream_error() {
        let value = "not a valid relation at all!!";
        assert!(relation_or_soname(value).is_err());
        assert!(RelationOrSoname::from_str(value).is_err());
    }

    /// The acceptance gate for the screen. Take every `%DEPENDS%` and `%PROVIDES%` entry in
    /// every repository on this machine. Each must parse to the **identical** value through
    /// the fast path and through `RelationOrSoname::from_str`.
    ///
    /// A fixture cannot establish this. The whole optimisation is a claim about which real
    /// strings can be sonames, and only the real repositories can refute it. `extra` alone
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
