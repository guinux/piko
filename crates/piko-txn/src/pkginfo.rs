//! Reading a package's `.PKGINFO`, one field at a time.
//!
//! libalpm reads every line as a string (`be_package.c:parse_descfile`), and converts only
//! what it uses. piko reads the lines through `piko_db::meta::kv`, and splits the keys in two.
//!
//! The keys that decide something refuse the package when they are missing, repeated or
//! invalid: `pkgname`, `pkgver`, `arch`, `size`, and the relation lists `depend`, `provides`,
//! `conflict`, `replaces` and `group`. The transaction compares them with the plan, and the
//! solver plans by them.
//!
//! Every other key is shown only, and is written to the local `desc` as it stands. Each one is
//! a [`Shown`]: its values in their typed rendering when they convert, the values as written
//! when they do not, and the reason. A defect in such a key costs nothing more than its typed
//! form, so makepkg's [`UNKNOWN_PACKAGER`] needs no substitution.

use std::{fmt::Display, str::FromStr};

use alpm_types::{
    Architecture, ExtraData, ExtraDataEntry, FullVersion, Group, InstalledSize, License, Name,
    OptionalDependency, PackageDescription, PackageRelation, RelationOrSoname,
};
use piko_db::comparable::Comparable;
use piko_db::{desc_compat::UNKNOWN_PACKAGER, meta::kv::Pairs};

/// Every key of the `PKGINFOv1` and `PKGINFOv2` specifications, and `basever`, which libalpm
/// reads and ignores.
const KNOWN_KEYS: &[&str] = &[
    "pkgname",
    "pkgbase",
    "basever",
    "pkgver",
    "pkgdesc",
    "url",
    "builddate",
    "packager",
    "size",
    "arch",
    "license",
    "replaces",
    "group",
    "conflict",
    "provides",
    "backup",
    "depend",
    "optdepend",
    "makedepend",
    "checkdepend",
    "xdata",
];

/// The most unknown keys one `.PKGINFO` names in [`PkgInfo::unknown`].
///
/// A real package has none. The bound keeps the list small, and keeps the test for a repeated
/// key to a fixed number of comparisons per line. Without it, a file of distinct unknown keys
/// costs a time quadratic in its length.
pub const MAX_UNKNOWN_KEYS: usize = 32;

/// Why a `.PKGINFO` key could not be read.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum PkgInfoError {
    /// A line that is not `key = value`, a comment or empty.
    #[error("line {line} is not `key = value`")]
    Malformed {
        /// The 1-based line number.
        line: usize,
    },
    /// A key the package must carry is absent.
    #[error("{key} is missing")]
    Missing {
        /// The key.
        key: &'static str,
    },
    /// A key that holds one value appears twice.
    #[error("{key} appears twice")]
    Duplicate {
        /// The key.
        key: &'static str,
    },
    /// A value does not convert.
    #[error("{key}: {value:?} is not valid: {reason}")]
    Invalid {
        /// The key.
        key: &'static str,
        /// The value as written.
        value: String,
        /// Why it does not convert.
        reason: String,
    },
}

/// Something a `.PKGINFO` holds that piko reads past, without refusing the package.
///
/// libalpm warns about an unknown key (`be_package.c:255`), and converts no shown key at all.
/// [`PkgInfo::problems`] lists both, for a frontend to show as warnings.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Problem {
    /// A shown key whose values do not convert. They are recorded as written.
    #[error("{0}; it is recorded as written")]
    InvalidField(PkgInfoError),
    /// A shown key the `PKGINFO` specification requires, and the package does not carry.
    ///
    /// The installed entry then has no section for it, which the local `desc` reader reports
    /// as a missing section.
    #[error("key {key:?} is missing")]
    MissingKey {
        /// The key.
        key: &'static str,
    },
    /// A key this build does not know. It is not recorded.
    #[error("unknown key {key:?} on line {line}")]
    UnknownKey {
        /// The key.
        key: String,
        /// The 1-based line of its first use.
        line: usize,
    },
    /// Unknown key lines past [`MAX_UNKNOWN_KEYS`], which are not named.
    #[error("{count} further unknown key line(s)")]
    UnknownKeysDropped {
        /// The number of lines.
        count: usize,
    },
}

/// A key that is shown only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Shown {
    /// The values, in their typed rendering when every one converts, as written otherwise.
    ///
    /// A key that holds one value keeps its first one.
    pub values: Vec<String>,
    /// Why the values are kept as written, if they are.
    pub error: Option<PkgInfoError>,
}

impl Shown {
    /// The first value, if the key appears.
    #[must_use]
    pub fn first(&self) -> Option<&str> {
        self.values.first().map(String::as_str)
    }
}

/// A parsed `.PKGINFO`.
///
/// The fields are public, as the fields of a record: nothing here depends on another field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkgInfo {
    /// `pkgname`.
    pub name: Name,
    /// `pkgver`.
    pub version: FullVersion,
    /// `arch`.
    pub architecture: Architecture,
    /// `size`, the installed size in bytes.
    pub size: InstalledSize,
    /// `depend`.
    pub depends: Vec<RelationOrSoname>,
    /// `provides`.
    pub provides: Vec<RelationOrSoname>,
    /// `conflict`.
    pub conflicts: Vec<PackageRelation>,
    /// `replaces`.
    pub replaces: Vec<PackageRelation>,
    /// `group`.
    pub groups: Vec<Group>,
    /// `backup`, each value as written, as libalpm keeps it (`be_package.c:242`).
    ///
    /// A value is compared with the archive's member paths as a string, so it is not converted:
    /// a typed path could normalise a spelling and change which member it names. A value that
    /// names no member protects nothing, as in libalpm.
    pub backups: Vec<String>,
    /// `pkgbase`.
    pub base: Shown,
    /// `pkgdesc`, with its white space folded.
    pub description: Shown,
    /// `url`, as written: libalpm copies it through, where `url::Url` would normalize it.
    pub url: Shown,
    /// `builddate`.
    pub build_date: Shown,
    /// `packager`, as written: libalpm copies it through.
    pub packager: Shown,
    /// `license`.
    pub licenses: Shown,
    /// `optdepend`.
    pub optional_depends: Shown,
    /// `xdata`, which only a v2 `.PKGINFO` has.
    pub xdata: Shown,
    /// The keys this build does not know, with the line of their first use. libalpm warns
    /// about each one and reads on.
    ///
    /// At most [`MAX_UNKNOWN_KEYS`] keys, the first ones in text order.
    pub unknown: Vec<(String, usize)>,
    /// The number of unknown key lines not named in [`Self::unknown`], because the list was
    /// full.
    pub unknown_dropped: usize,
}

impl PkgInfo {
    /// Every shown key whose values did not convert.
    #[must_use]
    pub fn invalid_fields(&self) -> Vec<&PkgInfoError> {
        [
            &self.base,
            &self.description,
            &self.url,
            &self.build_date,
            &self.packager,
            &self.licenses,
            &self.optional_depends,
            &self.xdata,
        ]
        .into_iter()
        .filter_map(|shown| shown.error.as_ref())
        .collect()
    }

    /// Every [`Problem`] this `.PKGINFO` holds: the invalid shown keys, the missing ones, then
    /// the unknown keys.
    ///
    /// At most one entry for each shown key, [`MAX_UNKNOWN_KEYS`] unknown keys, and one count of
    /// the unknown keys past that bound. Empty for an ordinary package.
    #[must_use]
    pub fn problems(&self) -> Vec<Problem> {
        let invalid = self.invalid_fields().into_iter().cloned().map(Problem::InvalidField);
        let missing = self
            .required_shown()
            .into_iter()
            .filter(|(_, shown)| shown.values.is_empty())
            .map(|(key, _)| Problem::MissingKey { key });
        let unknown = self
            .unknown
            .iter()
            .map(|(key, line)| Problem::UnknownKey { key: key.clone(), line: *line });
        let dropped = (self.unknown_dropped > 0)
            .then_some(Problem::UnknownKeysDropped { count: self.unknown_dropped });
        invalid.chain(missing).chain(unknown).chain(dropped).collect()
    }

    /// The shown keys that become a section the local `desc` reader requires: `%BASE%`,
    /// `%DESC%`, `%BUILDDATE%` and `%PACKAGER%`.
    ///
    /// `url` is left out: the reader reads an absent `%URL%` as no URL.
    fn required_shown(&self) -> [(&'static str, &Shown); 4] {
        [
            ("pkgbase", &self.base),
            ("pkgdesc", &self.description),
            ("builddate", &self.build_date),
            ("packager", &self.packager),
        ]
    }
}

/// Parses a `.PKGINFO`.
///
/// # Errors
///
/// [`PkgInfoError`] when a line is not `key = value`, or a key that decides something is
/// missing, repeated or invalid. A shown key never refuses the file.
pub fn parse(raw: &str) -> Result<PkgInfo, PkgInfoError> {
    let mut lines = Pairs::new(raw);
    let mut values: Vec<(&'static str, &str)> = Vec::new();
    let mut unknown: Vec<(String, usize)> = Vec::new();
    let mut unknown_dropped = 0_usize;
    for pair in lines.by_ref() {
        match KNOWN_KEYS.iter().find(|key| **key == pair.key) {
            Some(key) => values.push((key, pair.value)),
            None if unknown.iter().any(|(key, _)| key == pair.key) => {}
            None if unknown.len() < MAX_UNKNOWN_KEYS => {
                unknown.push((pair.key.to_owned(), pair.line));
            }
            // The line count is bounded by the text length, so this cannot overflow.
            None => unknown_dropped = unknown_dropped.saturating_add(1),
        }
    }
    if let Some(line) = lines.first_malformed_line() {
        return Err(PkgInfoError::Malformed { line });
    }
    let read = Read { values };

    let info = PkgInfo {
        name: read.required("pkgname")?,
        version: read.required("pkgver")?,
        architecture: read.required("arch")?,
        size: read.required("size")?,
        depends: read.list("depend")?,
        provides: read.list("provides")?,
        conflicts: read.list("conflict")?,
        replaces: read.list("replaces")?,
        groups: read.all("group").map(str::to_owned).collect(),
        backups: read.all("backup").map(str::to_owned).collect(),
        base: read.shown_one::<Name>("pkgbase"),
        description: read.shown_one::<PackageDescription>("pkgdesc"),
        url: read.as_written("url"),
        build_date: read.shown_one::<i64>("builddate"),
        packager: read.as_written("packager"),
        licenses: read.shown_list::<License>("license"),
        optional_depends: read.shown_list::<OptionalDependency>("optdepend"),
        xdata: read.xdata(),
        unknown,
        unknown_dropped,
    };
    check_comparable(&info)?;
    Ok(info)
}

/// Refuses a `pkgver`, or a version in a relation that decides something, that `alpm-types`
/// cannot compare: see [`piko_db::comparable`].
fn check_comparable(info: &PkgInfo) -> Result<(), PkgInfoError> {
    fn check<T: Comparable + Display>(key: &'static str, value: &T) -> Result<(), PkgInfoError> {
        value.check_comparable().map_err(|reason| PkgInfoError::Invalid {
            key,
            value: value.to_string(),
            reason: reason.to_string(),
        })
    }
    check("pkgver", &info.version)?;
    info.depends.iter().try_for_each(|value| check("depend", value))?;
    info.provides.iter().try_for_each(|value| check("provides", value))?;
    info.conflicts.iter().try_for_each(|value| check("conflict", value))?;
    info.replaces.iter().try_for_each(|value| check("replaces", value))
}

/// The `pkgname` and `pkgver` of a `.PKGINFO`.
#[must_use]
pub const fn name_and_version(info: &PkgInfo) -> (&Name, &FullVersion) {
    (&info.name, &info.version)
}

/// The known pairs of one `.PKGINFO`, in text order.
struct Read<'a> {
    values: Vec<(&'static str, &'a str)>,
}

impl<'a> Read<'a> {
    /// Every value of `key`, in text order.
    fn all<'k>(&'k self, key: &'k str) -> impl Iterator<Item = &'a str> + 'k {
        self.values.iter().filter(move |(found, _)| *found == key).map(|(_, value)| *value)
    }

    /// The one value of `key`, or `None` when it is absent.
    fn one(&self, key: &'static str) -> Result<Option<&'a str>, PkgInfoError> {
        let mut found = self.all(key);
        let first = found.next();
        if found.next().is_some() {
            return Err(PkgInfoError::Duplicate { key });
        }
        Ok(first)
    }

    /// The one value of a key that decides something, converted.
    fn required<T>(&self, key: &'static str) -> Result<T, PkgInfoError>
    where
        T: FromStr,
        T::Err: Display,
    {
        let value = self.one(key)?.ok_or(PkgInfoError::Missing { key })?;
        convert(key, value)
    }

    /// Every value of a list key that decides something, converted.
    fn list<T>(&self, key: &'static str) -> Result<Vec<T>, PkgInfoError>
    where
        T: FromStr,
        T::Err: Display,
    {
        self.all(key).map(|value| convert(key, value)).collect()
    }

    /// A shown key that holds one value, in its typed rendering when it converts.
    fn shown_one<T>(&self, key: &'static str) -> Shown
    where
        T: FromStr + Display,
        T::Err: Display,
    {
        let first = self.all(key).next();
        let typed =
            self.one(key).and_then(|value| value.map(|value| convert::<T>(key, value)).transpose());
        match typed {
            Ok(value) => Shown {
                values: value.map(|value| value.to_string()).into_iter().collect(),
                error: None,
            },
            Err(error) => {
                Shown { values: first.map(str::to_owned).into_iter().collect(), error: Some(error) }
            }
        }
    }

    /// A shown key that holds one value, kept as written.
    ///
    /// `packager` is reported when it is not a valid packager, unless it is makepkg's
    /// [`UNKNOWN_PACKAGER`] default.
    fn as_written(&self, key: &'static str) -> Shown {
        let first = self.all(key).next();
        let mut error = self.one(key).err();
        if key == "packager"
            && error.is_none()
            && let Some(value) = first.filter(|value| *value != UNKNOWN_PACKAGER)
        {
            error = convert::<alpm_types::Packager>(key, value).err();
        }
        Shown { values: first.map(str::to_owned).into_iter().collect(), error }
    }

    /// A shown list key, in its typed rendering when every value converts.
    fn shown_list<T>(&self, key: &'static str) -> Shown
    where
        T: FromStr + Display,
        T::Err: Display,
    {
        let raw: Vec<&str> = self.all(key).collect();
        match raw.iter().map(|value| convert::<T>(key, value)).collect::<Result<Vec<_>, _>>() {
            Ok(typed) => {
                Shown { values: typed.iter().map(ToString::to_string).collect(), error: None }
            }
            Err(error) => {
                Shown { values: raw.into_iter().map(str::to_owned).collect(), error: Some(error) }
            }
        }
    }

    /// `xdata`, whose entries must together name a `pkgtype`.
    fn xdata(&self) -> Shown {
        let mut shown = self.shown_list::<ExtraDataEntry>("xdata");
        if shown.error.is_none() && !shown.values.is_empty() {
            let entries: Result<Vec<ExtraDataEntry>, _> =
                self.all("xdata").map(ExtraDataEntry::from_str).collect();
            if let Err(reason) = entries.and_then(ExtraData::try_from) {
                shown.error = Some(PkgInfoError::Invalid {
                    key: "xdata",
                    value: String::new(),
                    reason: reason.to_string(),
                });
            }
        }
        shown
    }
}

/// Converts `value` of `key` with the parser of `T`.
fn convert<T>(key: &'static str, value: &str) -> Result<T, PkgInfoError>
where
    T: FromStr,
    T::Err: Display,
{
    T::from_str(value).map_err(|reason| PkgInfoError::Invalid {
        key,
        value: value.to_owned(),
        reason: reason.to_string(),
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    /// A `.PKGINFO` with `packager` left as `$1`.
    fn pkginfo(packager: &str) -> String {
        format!(
            "# Generated by makepkg\npkgname = foo\npkgbase = foo\npkgver = 1.0.0-1\n\
             pkgdesc = an  example\nurl = https://example.org\nbuilddate = 1\n\
             packager = {packager}\nsize = 1\narch = x86_64\nlicense = MIT\ndepend = bar>=2\n\
             depend = libbaz.so=1-64\ngroup = tools\n"
        )
    }

    #[test]
    fn reads_every_key() {
        let info = parse(&pkginfo("Jane Doe <jane@example.org>")).unwrap();

        assert_eq!(info.name.as_ref(), "foo");
        assert_eq!(info.version.to_string(), "1.0.0-1");
        assert_eq!(info.architecture.to_string(), "x86_64");
        assert_eq!(info.size, 1);
        assert_eq!(info.depends.len(), 2);
        assert_eq!(info.groups, ["tools"]);
        assert_eq!(info.description.values, ["an example"], "white space is folded");
        assert_eq!(info.url.values, ["https://example.org"], "the URL is kept as written");
        assert_eq!(info.licenses.values, ["MIT"]);
        assert!(info.xdata.values.is_empty());
        assert!(info.invalid_fields().is_empty());
        assert!(info.unknown.is_empty());
    }

    /// A version `alpm-types` cannot compare refuses the package, in `pkgver` or in a
    /// relation: the plan check and the solver compare both.
    #[test]
    fn a_version_alpm_types_cannot_compare_is_refused() {
        let base = pkginfo("Jane Doe <jane@example.org>");
        let big = "99999999999999999999";
        for (from, to) in [
            ("pkgver = 1.0.0-1", format!("pkgver = {big}-1")),
            ("depend = bar>=2", format!("depend = bar>={big}")),
            ("depend = libbaz.so=1-64", format!("depend = libbaz.so={big}-64")),
        ] {
            let raw = base.replace(from, &to);
            assert!(matches!(parse(&raw), Err(PkgInfoError::Invalid { .. })), "{to}");
        }
    }

    /// Each `backup` value is kept as written, in text order, white space included: it is
    /// compared with the archive's member paths as a string. A line in a comment is not one.
    #[test]
    fn backup_values_are_kept_as_written() {
        let raw = pkginfo("Jane Doe <jane@example.org>")
            + "backup = etc/foo.conf\n# backup = etc/old.conf\nbackup = etc/./bar.conf \n";
        let info = parse(&raw).unwrap();
        assert_eq!(info.backups, ["etc/foo.conf", "etc/./bar.conf "]);
        assert!(parse(&pkginfo("Jane Doe <jane@example.org>")).unwrap().backups.is_empty());
    }

    /// makepkg's default packager is kept, and is not reported: it is a documented default.
    #[test]
    fn makepkgs_default_packager_is_kept_and_not_reported() {
        let info = parse(&pkginfo(UNKNOWN_PACKAGER)).unwrap();
        assert_eq!(info.packager.first(), Some(UNKNOWN_PACKAGER));
        assert!(info.invalid_fields().is_empty());
    }

    /// Any other packager without an email is reported, and costs nothing else.
    #[test]
    fn another_invalid_packager_is_reported_and_kept() {
        let info = parse(&pkginfo("Jane Doe")).unwrap();
        assert_eq!(info.packager.first(), Some("Jane Doe"));
        assert_eq!(info.invalid_fields().len(), 1);
        assert_eq!(info.name.as_ref(), "foo");
    }

    /// A shown key that does not convert is kept as written.
    #[test]
    fn an_invalid_shown_key_is_kept_as_written() {
        let raw = pkginfo("Jane Doe <jane@example.org>").replace("builddate = 1", "builddate = x");
        let info = parse(&raw).unwrap();
        assert_eq!(info.build_date.values, ["x"]);
        assert!(info.build_date.error.is_some());
    }

    /// A key that decides something refuses the file when missing, repeated or invalid, and
    /// so does a line that is not `key = value`.
    #[test]
    fn a_defect_in_a_deciding_key_refuses_the_file() {
        let base = pkginfo("Jane Doe <jane@example.org>");
        for raw in [
            base.replace("pkgname = foo\n", ""),
            base.replace("arch = x86_64", "arch = x86_64\narch = any"),
            base.replace("size = 1", "size = big"),
            base.replace("depend = bar>=2", "depend = bar>="),
            base.replace("group = tools", "group=tools"),
        ] {
            assert!(parse(&raw).is_err(), "{raw:?}");
        }
    }

    /// An unknown key is set aside, as libalpm warns about it and reads on.
    #[test]
    fn an_unknown_key_is_set_aside() {
        let raw = format!("{}futurekey = 1\nfuturekey = 2\nbasever = 1\n", pkginfo("A <a@b.c>"));
        let info = parse(&raw).unwrap();
        assert_eq!(info.unknown, [("futurekey".to_owned(), 15)]);
        assert_eq!(info.unknown_dropped, 0);
    }

    /// The unknown keys past [`MAX_UNKNOWN_KEYS`] are counted, not named. A key already named
    /// is not counted again.
    #[test]
    fn unknown_keys_past_the_bound_are_counted() {
        let mut raw = pkginfo("A <a@b.c>");
        for index in 0..1000 {
            raw.push_str(&format!("future{index} = 1\n"));
        }
        raw.push_str("future0 = 2\n");
        let info = parse(&raw).unwrap();

        assert_eq!(info.unknown.len(), MAX_UNKNOWN_KEYS);
        assert_eq!(info.unknown.first().map(|(key, _)| key.as_str()), Some("future0"));
        assert_eq!(info.unknown_dropped, 1000 - MAX_UNKNOWN_KEYS);

        let problems = info.problems();
        assert_eq!(problems.len(), MAX_UNKNOWN_KEYS + 1);
        assert_eq!(
            problems.last(),
            Some(&Problem::UnknownKeysDropped { count: 1000 - MAX_UNKNOWN_KEYS })
        );
    }

    /// The invalid shown keys come first, then the unknown keys, each once.
    #[test]
    fn problems_name_invalid_fields_then_unknown_keys() {
        let raw = pkginfo("A <a@b.c>").replace("builddate = 1", "builddate = x")
            + "futurekey = 1\nfuturekey = 2\n";
        let problems = parse(&raw).unwrap().problems();

        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(matches!(
            problems.first(),
            Some(Problem::InvalidField(PkgInfoError::Invalid { key: "builddate", .. }))
        ));
        assert!(
            matches!(problems.get(1), Some(Problem::UnknownKey { key, .. }) if key == "futurekey")
        );
        assert!(parse(&pkginfo("A <a@b.c>")).unwrap().problems().is_empty());
    }

    /// A required shown key that is absent is named. An empty value is not an absence.
    #[test]
    fn problems_name_a_missing_required_key() {
        let raw = pkginfo("A <a@b.c>").replace("builddate = 1\n", "").replace("an  example", "");
        let problems = parse(&raw).unwrap().problems();
        assert_eq!(problems, [Problem::MissingKey { key: "builddate" }]);
    }

    #[test]
    fn xdata_must_name_a_package_type() {
        let base = pkginfo("A <a@b.c>");
        let info = parse(&format!("{base}xdata = pkgtype=pkg\n")).unwrap();
        assert_eq!(info.xdata.values, ["pkgtype=pkg"]);
        assert!(info.xdata.error.is_none());

        let info = parse(&format!("{base}xdata = other=1\n")).unwrap();
        assert!(info.xdata.error.is_some());
    }
}

#[cfg(test)]
mod properties {
    use proptest::prelude::*;

    use super::*;
    use crate::record::{InstallFacts, desc};

    /// A text of `key = value` lines, comments, and lines that are neither.
    fn pkginfo_shaped() -> impl Strategy<Value = String> {
        let key =
            prop_oneof![prop::sample::select(KNOWN_KEYS).prop_map(str::to_owned), "[a-z]{1,8}",];
        let line = prop_oneof![
            (key, "[a-zA-Z0-9 ./=<>:@_+-]{0,16}")
                .prop_map(|(key, value)| format!("{key} = {value}")),
            "#[ -~]{0,12}",
            "[ -~]{0,16}",
            Just(String::new()),
        ];
        prop::collection::vec(line, 0..32).prop_map(|lines| lines.join("\n"))
    }

    proptest! {
        /// A `.PKGINFO` is read or refused, and a read one becomes a `desc` record or is refused
        /// by the record's own check. Neither panics.
        #[test]
        fn a_pkginfo_is_read_or_refused(raw in prop_oneof![any::<String>(), pkginfo_shaped()]) {
            if let Ok(info) = parse(&raw) {
                let facts = InstallFacts {
                    install_date: 0,
                    reason: alpm_types::PackageInstallReason::Explicit,
                    validation: Vec::new(),
                };
                let _ = desc(&info, &facts);
            }
        }
    }
}
