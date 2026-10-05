//! A single installed package: one entry directory in the local database.

use std::{
    io::Read as _,
    path::{Path, PathBuf},
};

use alpm_mtree::Mtree;
use alpm_types::{
    FullVersion, Group, InstalledSize, Name, PackageInstallReason, PackageRelation,
    RelationOrSoname,
};

use crate::{
    desc_compat::{UnknownSection, UnknownSectionPolicy},
    entry_name::EntryName,
    error::{Error, IoAction, Result, SharedError},
    fs_util,
    lazy::Lazy,
    limits::{Limit, Limits},
    local::desc::{DescView, LocalDesc},
    meta::files::{Backup, FilePaths, LocalFiles},
};

/// The gzip magic number. pacman stores `mtree` files gzip-compressed.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// The `desc` file name inside an entry directory.
const DESC_FILE: &str = "desc";
/// The `files` file name inside an entry directory.
const FILES_FILE: &str = "files";
/// The `mtree` file name inside an entry directory.
const MTREE_FILE: &str = "mtree";
/// The install scriptlet file name inside an entry directory (pacman's `.INSTALL`, written
/// lowercase in the local database — see `piko-txn`'s `step.rs`).
const INSTALL_FILE: &str = "install";

/// A disagreement between an entry's directory name and its `desc` file.
///
/// The directory name always wins — see [`LocalPackage::check_consistency`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Inconsistency {
    /// `%NAME%` does not match the name in the directory name.
    NameMismatch {
        /// The name taken from the directory name, which is authoritative.
        directory: Name,
        /// The name declared by `%NAME%`.
        desc: Name,
    },
    /// `%VERSION%` does not match the version in the directory name.
    VersionMismatch {
        /// The version taken from the directory name, which is authoritative.
        directory: FullVersion,
        /// The version declared by `%VERSION%`.
        desc: FullVersion,
    },
    /// The `desc` file contained a section this build does not recognise.
    UnknownDescSection(UnknownSection),
    /// A section that is shown only, such as `%LICENSE%`, holds an invalid value. The rest of
    /// the `desc` is still read.
    InvalidField {
        /// The reason, naming the section.
        reason: String,
    },
}

impl std::fmt::Display for Inconsistency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameMismatch { directory, desc } => {
                write!(f, "directory says the name is {directory}, but %NAME% says {desc}")
            }
            Self::VersionMismatch { directory, desc } => {
                write!(f, "directory says the version is {directory}, but %VERSION% says {desc}")
            }
            Self::UnknownDescSection(section) => {
                write!(f, "unknown section %{}% on line {}", section.keyword, section.line)
            }
            Self::InvalidField { reason } => f.write_str(reason),
        }
    }
}

/// Metadata parsed from a `desc` file, together with every disagreement found while parsing it.
///
/// The disagreements are computed once, inside [`LocalPackage::load_desc`], rather than
/// recomputed on every [`LocalPackage::check_consistency`] call.
#[derive(Debug)]
struct LoadedDesc {
    desc: LocalDesc,
    inconsistencies: Vec<Inconsistency>,
}

/// A `desc` file read, and converted only as far as everything needs it.
///
/// The relation sections and `%REASON%` are here. Every other section stays as `text`, and
/// is converted by [`LocalPackage::desc`] only if something asks for it. See [`crate::eager`]
/// for why the full typed parse should not be the cost of every load. It measures **23.4 ms**
/// across this machine's 1206 installed packages, against **6.1 ms** for the relations alone.
/// `crate::solve::Universe` reads nothing else.
#[derive(Debug)]
struct LoadedEager {
    /// The `desc` text, retained to back the deferred typed parse.
    text: Box<str>,
    /// The relation sections, shared with the repository database's eager tier.
    relations: crate::eager::Relations,
    /// `%REASON%`. Absent means [`PackageInstallReason::Explicit`], which is how libalpm
    /// writes an explicitly installed package (`be_local.c:1029`).
    install_reason: PackageInstallReason,
    /// `%SIZE%`, the installed size in bytes. Eager because `crate::solve::Plan` reports the
    /// size delta of a transaction. Forcing the typed parse for that alone would undo the
    /// split for every package the plan touches.
    installed_size: InstalledSize,
}

/// The `desc` sections available without the full typed parse.
///
/// The local counterpart of [`crate::repo::RepoPackage`]'s eager accessors, and the same
/// split for the same reason. Obtained from [`LocalPackage::eager`].
#[derive(Clone, Copy, Debug)]
pub struct EagerView<'a> {
    inner: &'a LoadedEager,
}

impl<'a> EagerView<'a> {
    /// `%DEPENDS%`, the run-time dependencies.
    #[must_use]
    pub const fn depends(&self) -> &'a [RelationOrSoname] {
        &self.inner.relations.depends
    }

    /// `%PROVIDES%`.
    #[must_use]
    pub const fn provides(&self) -> &'a [RelationOrSoname] {
        &self.inner.relations.provides
    }

    /// `%CONFLICTS%`.
    #[must_use]
    pub const fn conflicts(&self) -> &'a [PackageRelation] {
        &self.inner.relations.conflicts
    }

    /// `%REPLACES%`.
    #[must_use]
    pub const fn replaces(&self) -> &'a [PackageRelation] {
        &self.inner.relations.replaces
    }

    /// `%GROUPS%`.
    #[must_use]
    pub const fn groups(&self) -> &'a [Group] {
        &self.inner.relations.groups
    }

    /// `%REASON%`: whether the user asked for this package or it arrived as a dependency.
    #[must_use]
    pub const fn install_reason(&self) -> PackageInstallReason {
        self.inner.install_reason
    }

    /// `%SIZE%`, the installed size in bytes.
    #[must_use]
    pub const fn installed_size(&self) -> InstalledSize {
        self.inner.installed_size
    }

    /// The whole `desc` text.
    pub(crate) fn text(&self) -> &'a str {
        &self.inner.text
    }
}

/// An installed package.
///
/// The name and version are known as soon as the database is opened, because they come from
/// the entry's directory name. Everything else is read from disk on first access and cached.
/// A failure is cached too: every later call returns the same failure, instead of the field
/// being downgraded to empty data.
///
/// `LocalPackage` is [`Send`] and [`Sync`]. Concurrent readers may force the lazy fields in
/// parallel without a lock.
#[derive(Debug)]
pub struct LocalPackage {
    entry: EntryName,
    dir: PathBuf,
    limits: Limits,
    policy: UnknownSectionPolicy,
    eager: Lazy<LoadedEager>,
    /// Boxed: a `Lazy` holds its value inline, empty or not, and most entries are never asked
    /// for their full `desc`.
    desc: Lazy<Box<LoadedDesc>>,
    files: Lazy<LocalFiles>,
    mtree: Lazy<Option<Mtree>>,
}

impl LocalPackage {
    /// Creates a package rooted at `dir`, without touching the filesystem.
    pub(crate) fn new(
        entry: EntryName,
        dir: PathBuf,
        limits: Limits,
        policy: UnknownSectionPolicy,
    ) -> Self {
        Self {
            entry,
            dir,
            limits,
            policy,
            eager: Lazy::new(),
            desc: Lazy::new(),
            files: Lazy::new(),
            mtree: Lazy::new(),
        }
    }

    /// The package name, from the entry directory name.
    ///
    /// Free: no file is read.
    #[must_use]
    pub const fn name(&self) -> &Name {
        self.entry.name()
    }

    /// The package version, from the entry directory name.
    ///
    /// Free: no file is read.
    #[must_use]
    pub const fn version(&self) -> &FullVersion {
        self.entry.version()
    }

    /// The parsed entry directory name.
    #[must_use]
    pub const fn entry(&self) -> &EntryName {
        &self.entry
    }

    /// The entry directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The parsed `desc` file, reading it on first access.
    ///
    /// # Errors
    ///
    /// If the file cannot be read or parsed. The failure is cached and returned again by
    /// every later call.
    pub fn desc(&self) -> std::result::Result<DescView<'_>, SharedError> {
        let eager = self.eager()?;
        self.load_desc().map(|loaded| DescView::new(&loaded.desc, eager))
    }

    /// The sections every caller needs, without the full typed parse.
    ///
    /// This is what [`crate::solve::Universe`] reads, and reading it does **not** force
    /// [`Self::desc`]. See [`EagerView`].
    ///
    /// # Errors
    ///
    /// If the `desc` file cannot be read, or a relation section fails to parse. The failure
    /// is cached and returned again by every later call, exactly as [`Self::desc`]'s is.
    pub fn eager(&self) -> std::result::Result<EagerView<'_>, SharedError> {
        self.load_eager().map(|inner| EagerView { inner })
    }

    /// The parsed `files` file, reading it on first access.
    ///
    /// # Errors
    ///
    /// If the file cannot be read or parsed.
    pub fn files(&self) -> std::result::Result<&LocalFiles, SharedError> {
        self.files.get_or_load(|| self.read_files())
    }

    /// The parsed `mtree` file, reading and decompressing it on first access.
    ///
    /// `Ok(None)` means the entry has no `mtree` file. libalpm treats a missing `mtree` as
    /// absent rather than as an error, and so does piko.
    ///
    /// # Errors
    ///
    /// If the file exists but cannot be read, decompressed or parsed.
    pub fn mtree(&self) -> std::result::Result<Option<&Mtree>, SharedError> {
        self.mtree.get_or_load(|| self.read_mtree()).map(Option::as_ref)
    }

    /// Whether this entry ships an install scriptlet (pacman's `.INSTALL`,
    /// `pacman -Qi`'s "Install Script").
    ///
    /// A plain existence check, not a `Lazy` field like `desc`/`files`/`mtree`. There is
    /// nothing to parse, so caching would only save a `stat` call.
    #[must_use]
    pub fn has_install_scriptlet(&self) -> bool {
        fs_util::exists_in(&self.dir, INSTALL_FILE)
    }

    /// The paths owned by this package, relative to the installation root.
    ///
    /// Paths are relative, written as the `files` file holds them, and carry pacman's trailing
    /// `/` on directories, e.g. `usr/bin/` versus `usr/bin/foo`.
    ///
    /// # Ordering
    ///
    /// The order compares **component by component**, as [`Path`] does. pacman sorts the raw
    /// strings **byte-wise**. So the two disagree wherever a directory name is a prefix of a
    /// sibling. pacman puts `usr/share/makepkg-template/` before `usr/share/makepkg/…`,
    /// because `-` (`0x2d`) sorts below `/` (`0x2f`). Component-wise comparison puts `makepkg`
    /// first.
    ///
    /// The *set* is exact either way. Sort the strings if you need pacman's exact order.
    ///
    /// # Errors
    ///
    /// If the `files` file cannot be read or parsed.
    pub fn file_list(&self) -> std::result::Result<FilePaths<'_>, SharedError> {
        self.files().map(LocalFiles::files)
    }

    /// The backup entries declared by this package, `(null)` entries included.
    ///
    /// # Errors
    ///
    /// If the `files` file cannot be read or parsed.
    pub fn backups(&self) -> std::result::Result<&[Backup], SharedError> {
        self.files().map(LocalFiles::backups)
    }

    /// Whether the `files` file can list a path that `wanted` accepts. The file is not parsed.
    ///
    /// This is a cheap filter in front of [`Self::file_list`], for a caller that looks for a few
    /// paths in every installed package. `false` is certain: the file was read, and no line of
    /// it is a path that `wanted` accepts. `true` only means that the parse must answer. `true`
    /// is also the answer when the file cannot be read, so that the error still comes from
    /// [`Self::file_list`], and when the file list is already parsed.
    ///
    /// Each line goes to `wanted` as the `files` reader delimits a path: the split is at `\n` or `\r\n`,
    /// and nothing is trimmed. A line that is not a path, such as a section header or a
    /// `%BACKUP%` entry, can only change the answer to `true`.
    ///
    /// The parse is the cost that this filter avoids. The parse sorts and validates every path,
    /// at about 1.4 µs for each path, and a real system lists about 300,000 paths. To read the
    /// text and split its lines costs about a twentieth of that.
    pub fn files_may_list(&self, mut wanted: impl FnMut(&str) -> bool) -> bool {
        if self.is_files_loaded() {
            return true;
        }
        let Ok(text) = fs_util::read_capped_utf8_in(
            &self.dir,
            FILES_FILE,
            Limit::Files,
            self.limits.get(Limit::Files),
        ) else {
            return true;
        };
        text.lines().any(&mut wanted)
    }

    /// Compares the entry directory name against the `desc` file's own claims.
    ///
    /// The directory name is authoritative: this reports disagreements, it does not resolve
    /// them. libalpm behaves the same way, logging a "database is inconsistent" error and
    /// carrying on with the directory name.
    ///
    /// Forces a `desc` load. The comparison itself runs once, at load time, so a caller who
    /// already forced `desc()` for another reason gets this for free.
    ///
    /// # Errors
    ///
    /// If the `desc` file cannot be read or parsed.
    pub fn check_consistency(&self) -> std::result::Result<Vec<Inconsistency>, SharedError> {
        self.load_desc().map(|loaded| loaded.inconsistencies.clone())
    }

    /// Forces every lazy field.
    ///
    /// This is useful before handing packages to a consumer that needs all their metadata
    /// anyway. It also verifies that a whole database is readable.
    ///
    /// # Errors
    ///
    /// The first failure encountered, in `desc`, `files`, `mtree` order.
    pub fn load_all(&self) -> std::result::Result<(), SharedError> {
        self.desc()?;
        self.files()?;
        self.mtree()?;
        Ok(())
    }

    /// Whether the `desc` file has already been read.
    #[must_use]
    pub fn is_desc_loaded(&self) -> bool {
        self.desc.is_loaded()
    }

    /// Whether the `files` file has already been read.
    #[must_use]
    pub fn is_files_loaded(&self) -> bool {
        self.files.is_loaded()
    }

    /// Whether the `mtree` file has already been read.
    #[must_use]
    pub fn is_mtree_loaded(&self) -> bool {
        self.mtree.is_loaded()
    }

    fn load_eager(&self) -> std::result::Result<&LoadedEager, SharedError> {
        self.eager.get_or_load(|| self.read_eager())
    }

    fn load_desc(&self) -> std::result::Result<&LoadedDesc, SharedError> {
        // The two tiers use separate `Lazy` slots, not one. Reading a dependency never pays
        // for the typed conversion of `%LICENSE%`, `%URL%` and the rest. `desc` borrows
        // `eager`'s retained text, so forcing `desc` also forces `eager`. Forcing `eager`
        // alone does not force `desc`.
        let eager = self.load_eager()?;
        let text = &eager.text;
        self.desc
            .get_or_load(|| {
                let path = || fs_util::join(&self.dir, DESC_FILE);
                let fields = |source| Error::DescFields { path: path(), source: Box::new(source) };
                let (desc, unknown) = LocalDesc::parse(text).map_err(fields)?;
                if self.policy == UnknownSectionPolicy::Reject
                    && let Some(section) = unknown.first()
                {
                    return Err(fields(crate::eager::DescFieldError::UnknownSection {
                        keyword: section.keyword.clone(),
                        line: section.line,
                    }));
                }

                let mut inconsistencies = Vec::new();
                if desc.name() != self.name() {
                    inconsistencies.push(Inconsistency::NameMismatch {
                        directory: self.name().clone(),
                        desc: desc.name().clone(),
                    });
                }
                if desc.version() != self.version() {
                    inconsistencies.push(Inconsistency::VersionMismatch {
                        directory: self.version().clone(),
                        desc: desc.version().clone(),
                    });
                }
                inconsistencies.extend(unknown.into_iter().map(Inconsistency::UnknownDescSection));
                inconsistencies.extend(
                    desc.invalid_fields()
                        .into_iter()
                        .map(|reason| Inconsistency::InvalidField { reason }),
                );

                Ok(Box::new(LoadedDesc { desc, inconsistencies }))
            })
            .map(|loaded| &**loaded)
    }

    fn read_eager(&self) -> Result<LoadedEager> {
        let path = fs_util::join(&self.dir, DESC_FILE);
        let text = fs_util::read_capped_utf8_in(
            &self.dir,
            DESC_FILE,
            Limit::Desc,
            self.limits.get(Limit::Desc),
        )?;

        // `%REASON%` is absent for an explicitly installed package. That is exactly what
        // libalpm writes (`if(info->reason)` at `be_local.c:1029`). So the default is not a
        // fallback for a malformed file. A malformed value is still an error.
        let mut install_reason = PackageInstallReason::Explicit;
        let mut installed_size = 0;
        // No relation budget. A local `desc` is read uncompressed and capped by
        // `Limits::desc_bytes`, so its text bounds what its parse builds. A repository archive
        // needs the budget because compression breaks that ratio.
        let relations = crate::eager::scan(&text, crate::eager::Depends::Eager, None, |section| {
            for line in section.values() {
                match section.keyword.as_bytes() {
                    b"REASON" => {
                        install_reason = match crate::eager::scalar::<u8>(line, "REASON")? {
                            0 => PackageInstallReason::Explicit,
                            1 => PackageInstallReason::Depend,
                            _ => {
                                return Err(crate::eager::DescFieldError::InvalidSize {
                                    section: "REASON",
                                    value: line.to_owned(),
                                });
                            }
                        };
                    }
                    b"SIZE" => installed_size = crate::eager::scalar(line, "SIZE")?,
                    _ => {}
                }
            }
            Ok(())
        })
        .map_err(|error| match error {
            crate::eager::ScanError::Field(source) => {
                Error::DescFields { path: path.clone(), source: Box::new(source) }
            }
            crate::eager::ScanError::Budget { max } => {
                Error::TooManyRelations { path: path.clone(), max }
            }
        })?;

        Ok(LoadedEager { text: text.into_boxed_str(), relations, install_reason, installed_size })
    }

    fn read_files(&self) -> Result<LocalFiles> {
        let path = fs_util::join(&self.dir, FILES_FILE);
        let text = fs_util::read_capped_utf8_in(
            &self.dir,
            FILES_FILE,
            Limit::Files,
            self.limits.get(Limit::Files),
        )?;

        crate::meta::files::parse(&text).map_err(|source| Error::Files { path, source })
    }

    /// Reads and parses `mtree`, decompressing it against a bound.
    ///
    /// `alpm-mtree`'s own `from_file` would inflate gzip internally with no limit. A
    /// compression bomb planted in the database would then be an unbounded allocation. piko
    /// therefore inflates the data itself and only ever hands the parser a plain string.
    fn read_mtree(&self) -> Result<Option<Mtree>> {
        use std::str::FromStr as _;

        let path = fs_util::join(&self.dir, MTREE_FILE);
        if !fs_util::exists_in(&self.dir, MTREE_FILE) {
            return Ok(None);
        }

        let raw = fs_util::read_capped_in(
            &self.dir,
            MTREE_FILE,
            Limit::MtreeCompressed,
            self.limits.get(Limit::MtreeCompressed),
        )?;

        let text = if raw.get(..2) == Some(GZIP_MAGIC.as_slice()) {
            self.inflate(&path, &raw)?
        } else {
            String::from_utf8(raw).map_err(|error| Error::NotUtf8 {
                path: path.clone(),
                source: error.utf8_error(),
            })?
        };

        Mtree::from_str(&text).map(Some).map_err(|source| Error::Mtree { path, source })
    }

    /// Gzip-decompresses `raw`, refusing output larger than the configured limit.
    fn inflate(&self, path: &Path, raw: &[u8]) -> Result<String> {
        let max = self.limits.get(Limit::MtreeInflated);
        let mut decoder = flate2::read::GzDecoder::new(raw).take(max.saturating_add(1));
        let mut inflated = Vec::new();

        decoder
            .read_to_end(&mut inflated)
            .map_err(|source| Error::io(path, IoAction::Decompress, source))?;

        if inflated.len() as u64 > max {
            return Err(Error::LimitExceeded {
                path: path.to_path_buf(),
                limit: Limit::MtreeInflated,
                max,
            });
        }

        String::from_utf8(inflated).map_err(|error| Error::NotUtf8 {
            path: path.to_path_buf(),
            source: error.utf8_error(),
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;
    use crate::fixture::{DbFixture, MINIMAL_DESC_V1, MINIMAL_FILES, MINIMAL_MTREE_V2, gzip_bomb};

    fn package_at(db: &DbFixture, entry: &str) -> LocalPackage {
        LocalPackage::new(
            EntryName::parse(entry).unwrap(),
            db.path().join(entry),
            Limits::default(),
            UnknownSectionPolicy::default(),
        )
    }

    /// A full `desc` is boxed inside its `Lazy`. A `Lazy` holds its value inline, read or not,
    /// and most entries are never asked for their full `desc`.
    #[test]
    fn an_unread_desc_costs_a_package_one_pointer() {
        assert!(
            std::mem::size_of::<LocalPackage>() < std::mem::size_of::<LoadedDesc>(),
            "LocalPackage is {} bytes, LoadedDesc {}",
            std::mem::size_of::<LocalPackage>(),
            std::mem::size_of::<LoadedDesc>()
        );
    }

    /// A package built by makepkg with no `PACKAGER` set stays fully readable, and its default
    /// packager is not reported as a defect.
    #[test]
    fn a_package_built_with_makepkgs_default_packager_is_readable() {
        let db = DbFixture::new();
        let body = MINIMAL_DESC_V1.replace(
            "Foobar McFooface <foobar@mcfooface.org>",
            crate::desc_compat::UNKNOWN_PACKAGER,
        );
        db.package("foo-1.0.0-1").desc(&body).files(MINIMAL_FILES).build();

        let package = package_at(&db, "foo-1.0.0-1");
        let desc = package.desc().unwrap();

        assert!(desc.packager().is_none());
        assert_eq!(desc.packager_raw(), Some(crate::desc_compat::UNKNOWN_PACKAGER));
        assert_eq!(desc.description().to_string(), "An example package");
        assert!(package.check_consistency().unwrap().is_empty());
    }

    #[test]
    fn is_send_and_sync() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LocalPackage>();
    }

    /// Identity is available before any file is touched.
    #[test]
    fn name_and_version_need_no_file_at_all() {
        let db = DbFixture::new();
        // Note: the entry directory is never created.
        let pkg = package_at(&db, "my-pkg-1:2.3.4-5");

        assert_eq!(pkg.name().as_ref(), "my-pkg");
        assert_eq!(pkg.version().to_string(), "1:2.3.4-5");
        assert!(!pkg.is_desc_loaded());
        assert!(!pkg.is_files_loaded());
        assert!(!pkg.is_mtree_loaded());
    }

    #[test]
    fn reads_desc_files_and_mtree_on_demand() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").with_defaults().build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        assert_eq!(pkg.desc().unwrap().description().to_string(), "An example package");
        assert!(pkg.is_desc_loaded());
        assert!(!pkg.is_files_loaded(), "reading desc must not read files");

        assert_eq!(
            pkg.file_list().unwrap().collect::<Vec<_>>(),
            ["usr/", "usr/bin/", "usr/bin/foo"]
        );
        assert!(pkg.mtree().unwrap().is_some());
    }

    /// Seven packages on a real system ship a zero-byte `files`.
    #[test]
    fn an_empty_files_file_is_an_empty_file_list() {
        let db = DbFixture::new();
        db.package("base-3-3").desc(MINIMAL_DESC_V1).files("").build();
        let pkg = package_at(&db, "base-3-3");

        assert_eq!(pkg.file_list().unwrap().len(), 0);
    }

    /// libalpm treats a missing `mtree` as absent, not as a failure.
    #[test]
    fn a_missing_mtree_is_absent_not_an_error() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).files(MINIMAL_FILES).build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        assert!(pkg.mtree().unwrap().is_none());
    }

    /// pacman gzips `mtree`; an uncompressed one is still accepted.
    #[test]
    fn reads_an_uncompressed_mtree() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1")
            .desc(MINIMAL_DESC_V1)
            .mtree_raw(MINIMAL_MTREE_V2.as_bytes())
            .build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        assert!(pkg.mtree().unwrap().is_some());
    }

    /// The reason piko inflates `mtree` itself instead of letting `alpm-mtree` do it.
    #[test]
    fn refuses_a_compression_bomb() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1")
            .desc(MINIMAL_DESC_V1)
            .mtree_raw(&gzip_bomb(4 * 1024 * 1024))
            .build();

        let pkg = LocalPackage::new(
            EntryName::parse("foo-1.0.0-1").unwrap(),
            db.path().join("foo-1.0.0-1"),
            Limits { mtree_inflated_bytes: 64 * 1024, ..Limits::default() },
            UnknownSectionPolicy::default(),
        );

        let err = pkg.mtree().unwrap_err();
        assert!(
            matches!(&*err, Error::LimitExceeded { limit: Limit::MtreeInflated, .. }),
            "got {err:?}"
        );
    }

    /// This is the point of the eager tier. Reading what the planner needs must not run
    /// `alpm-db`'s typed conversion of `%LICENSE%`, `%URL%`, `%PACKAGER%` and the checksums.
    #[test]
    fn the_eager_tier_does_not_force_the_typed_parse() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        let eager = pkg.eager().unwrap();
        let _ = eager.depends();
        let _ = eager.provides();
        let _ = eager.groups();
        let _ = eager.install_reason();
        let _ = eager.installed_size();

        assert!(!pkg.is_desc_loaded(), "the eager accessors must not force the typed parse");

        pkg.desc().unwrap();
        assert!(pkg.is_desc_loaded());
    }

    /// The eager tier and the typed parse must agree about the sections they both cover.
    /// Otherwise the split is a silent behaviour change rather than a cost one.
    #[test]
    fn the_eager_tier_agrees_with_the_typed_parse() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        let eager = pkg.eager().unwrap();
        let desc = pkg.desc().unwrap();

        let rendered = |values: &[RelationOrSoname]| {
            values.iter().map(ToString::to_string).collect::<Vec<_>>()
        };
        assert_eq!(rendered(eager.depends()), rendered(desc.depends()));
        assert_eq!(rendered(eager.provides()), rendered(desc.provides()));
        assert_eq!(eager.groups(), desc.groups());
        assert_eq!(eager.install_reason(), desc.install_reason());
        assert_eq!(eager.installed_size(), desc.installed_size());
    }

    /// `%REASON%` is absent for an explicitly installed package. That is not a parse failure,
    /// and must not be reported as one. A value that is neither 0 nor 1 still is.
    #[test]
    fn an_absent_reason_is_explicit_and_a_bogus_one_is_an_error() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).build();
        assert_eq!(
            package_at(&db, "foo-1.0.0-1").eager().unwrap().install_reason(),
            PackageInstallReason::Explicit,
        );

        let db = DbFixture::new();
        db.package("bar-1.0.0-1").desc(&format!("{MINIMAL_DESC_V1}%REASON%\n7\n\n")).build();
        let error = package_at(&db, "bar-1.0.0-1").eager().unwrap_err();
        assert!(matches!(&*error, Error::DescFields { .. }), "got {error:?}");
    }

    #[test]
    fn a_missing_desc_is_an_error_not_empty_metadata() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").files(MINIMAL_FILES).build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        let err = pkg.desc().unwrap_err();
        assert!(matches!(&*err, Error::Io { action: IoAction::Open, .. }), "got {err:?}");
        // `files` is independent and must still load.
        assert!(pkg.files().is_ok());
    }

    /// libalpm would return an empty dependency list here. That is the behaviour piko
    /// deliberately does not copy.
    #[test]
    fn a_corrupt_desc_reports_the_same_error_every_time() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").desc("this is not a desc file").build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        let first = pkg.desc().unwrap_err();
        let second = pkg.desc().unwrap_err();
        assert!(SharedError::ptr_eq(&first, &second), "the failure must be cached");
        assert!(first.to_string().contains("desc"));
    }

    /// This is the whole point of the `%URL%` split, end to end. pacman prints a `%URL%`
    /// that `url::Url` refuses. piko must still read the package it belongs to.
    #[test]
    fn an_unparsable_url_does_not_make_the_package_unreadable() {
        let db = DbFixture::new();
        let text = MINIMAL_DESC_V1.replace("https://example.org/", "www.example.org");
        db.package("foo-1.0.0-1").desc(&text).build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        let desc = pkg.desc().unwrap();
        assert_eq!(desc.url(), None);
        assert_eq!(desc.url_raw(), Some("www.example.org"));
        assert_eq!(desc.description().to_string(), "An example package");
        assert!(pkg.check_consistency().unwrap().is_empty(), "it is not an inconsistency");
    }

    #[test]
    fn consistency_check_passes_for_a_well_formed_entry() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").with_defaults().build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        assert_eq!(pkg.check_consistency().unwrap(), []);
    }

    /// The directory name wins; the disagreement is reported, not resolved.
    #[test]
    fn consistency_check_reports_a_name_mismatch_without_overriding() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).build();
        // MINIMAL_DESC_V1 declares %NAME% foo, so rename the directory's idea of it.
        let pkg = LocalPackage::new(
            EntryName::parse("bar-1.0.0-1").unwrap(),
            db.path().join("foo-1.0.0-1"),
            Limits::default(),
            UnknownSectionPolicy::default(),
        );

        let found = pkg.check_consistency().unwrap();
        assert!(matches!(found.first(), Some(Inconsistency::NameMismatch { .. })), "got {found:?}");
        assert_eq!(pkg.name().as_ref(), "bar", "the directory name stays authoritative");
    }

    #[test]
    fn consistency_check_reports_a_version_mismatch() {
        let db = DbFixture::new();
        db.package("foo-9.9.9-9").desc(MINIMAL_DESC_V1).build();
        let pkg = package_at(&db, "foo-9.9.9-9");

        let found = pkg.check_consistency().unwrap();
        assert!(
            matches!(found.first(), Some(Inconsistency::VersionMismatch { .. })),
            "got {found:?}"
        );
    }

    #[test]
    fn unknown_sections_are_reported_as_inconsistencies() {
        let db = DbFixture::new();
        let desc = format!("{MINIMAL_DESC_V1}%FUTURE%\nvalue\n\n");
        db.package("foo-1.0.0-1").desc(&desc).build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        let found = pkg.check_consistency().unwrap();
        assert!(
            found.iter().any(
                |i| matches!(i, Inconsistency::UnknownDescSection(s) if s.keyword == "FUTURE")
            ),
            "got {found:?}"
        );
    }

    #[test]
    fn the_reject_policy_refuses_an_unknown_section() {
        let db = DbFixture::new();
        let desc = format!("{MINIMAL_DESC_V1}%FUTURE%\nvalue\n\n");
        db.package("foo-1.0.0-1").desc(&desc).build();

        let pkg = LocalPackage::new(
            EntryName::parse("foo-1.0.0-1").unwrap(),
            db.path().join("foo-1.0.0-1"),
            Limits::default(),
            UnknownSectionPolicy::Reject,
        );

        assert!(pkg.desc().is_err(), "Reject must not tolerate an unknown section");
    }

    #[test]
    fn an_oversized_desc_is_refused() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).build();

        let pkg = LocalPackage::new(
            EntryName::parse("foo-1.0.0-1").unwrap(),
            db.path().join("foo-1.0.0-1"),
            Limits { desc_bytes: 8, ..Limits::default() },
            UnknownSectionPolicy::default(),
        );

        let err = pkg.desc().unwrap_err();
        assert!(matches!(&*err, Error::LimitExceeded { limit: Limit::Desc, .. }), "got {err:?}");
    }

    #[test]
    fn load_all_forces_every_slot() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").with_defaults().build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        pkg.load_all().unwrap();

        assert!(pkg.is_desc_loaded() && pkg.is_files_loaded() && pkg.is_mtree_loaded());
    }

    #[test]
    fn backups_are_exposed() {
        let db = DbFixture::new();
        // `alpm-db` requires a path's parent directory to be listed too, as pacman writes it.
        let files = "%FILES%\netc/\netc/foo.conf\n\n\
                     %BACKUP%\netc/foo.conf\td41d8cd98f00b204e9800998ecf8427e\n\n";
        db.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).files(files).build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        let backups = pkg.backups().unwrap();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups.first().map(|b| b.path.to_string()), Some("etc/foo.conf".to_owned()));
    }

    #[test]
    fn files_may_list_finds_a_listed_path_and_rules_out_an_absent_one() {
        let db = DbFixture::new();
        let files = "%FILES%\nsrv/\nsrv/shared/\n";
        db.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).files(files).build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        assert!(pkg.files_may_list(|line| line == "srv/shared/"));
        assert!(!pkg.files_may_list(|line| line == "srv/other/"));
        // The filter reads the text. It does not fill the parsed slot.
        assert!(!pkg.is_files_loaded());
    }

    /// The filter and the parse must agree on where a path ends. A `\r\n` line ending ends a
    /// path for both, and a false `false` would hide an owner the parse finds.
    #[test]
    fn files_may_list_splits_lines_as_the_parse_does() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).files("%FILES%\r\nsrv/\r\n").build();
        let pkg = package_at(&db, "foo-1.0.0-1");

        let parsed: Vec<String> = pkg.file_list().unwrap().map(str::to_owned).collect();
        assert_eq!(parsed, ["srv/"]);
        for path in &parsed {
            let fresh = package_at(&db, "foo-1.0.0-1");
            assert!(fresh.files_may_list(|line| line == path), "{path:?} was ruled out");
        }
    }

    /// An unreadable file is left for the parse to report, never ruled out.
    #[test]
    fn files_may_list_answers_true_when_the_file_cannot_be_read() {
        let db = DbFixture::new();
        db.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).files("%FILES%\nsrv/\n").build();
        let pkg = LocalPackage::new(
            EntryName::parse("foo-1.0.0-1").unwrap(),
            db.path().join("foo-1.0.0-1"),
            Limits { files_bytes: 4, ..Limits::default() },
            UnknownSectionPolicy::default(),
        );

        assert!(pkg.files_may_list(|_| false));
        assert!(pkg.file_list().is_err());
    }

    #[test]
    fn inconsistencies_render_readably() {
        let text = Inconsistency::UnknownDescSection(UnknownSection {
            keyword: "FUTURE".to_owned(),
            line: 7,
        })
        .to_string();
        assert_eq!(text, "unknown section %FUTURE% on line 7");
    }
}
