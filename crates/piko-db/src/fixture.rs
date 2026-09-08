//! Builders for throwaway local databases, for tests.
//!
//! The `alpm` repository ships no example database tree, only negative parser fixtures for
//! individual files. Tests here construct their own instead. Everything is written verbatim,
//! which lets a test express a *malformed* entry as easily as a well-formed one.
//!
//! Available to downstream crates behind the `fixture` feature.
//!
//! ```
//! use piko_db::fixture::DbFixture;
//!
//! let db = DbFixture::new();
//! db.package("foo-1.0.0-1").with_defaults().build();
//! // `db.path()` now holds a database with one package.
//! ```

use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use tempfile::TempDir;

use crate::local::schema_version::{ALPM_DB_VERSION, ALPM_DB_VERSION_FILE};

/// A minimal, well-formed `desc` body, in `alpm-db-descv1` form.
///
/// Derived from the example in `alpm-db`'s own documentation, so it is known to parse.
pub const MINIMAL_DESC_V1: &str = "\
%NAME%
foo

%VERSION%
1.0.0-1

%BASE%
foo

%DESC%
An example package

%URL%
https://example.org/

%ARCH%
x86_64

%BUILDDATE%
1733737242

%INSTALLDATE%
1733737243

%PACKAGER%
Foobar McFooface <foobar@mcfooface.org>

%SIZE%
123

%VALIDATION%
pgp

";

/// A minimal, well-formed `files` body.
pub const MINIMAL_FILES: &str = "\
%FILES%
usr/
usr/bin/
usr/bin/foo

";

/// A minimal, well-formed ALPM-MTREE v2 body, before compression.
pub const MINIMAL_MTREE_V2: &str = "\
#mtree
/set type=file uid=0 gid=0 mode=644
./usr type=dir time=1700000000.0 mode=755
./usr/bin type=dir time=1700000000.0 mode=755
./usr/bin/foo time=1700000000.0 size=4 \
sha256digest=b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c
";

/// A temporary local database directory.
///
/// The directory is removed when this value is dropped. A fixture must stay alive for as long
/// as the database opened from it is used.
#[derive(Debug)]
pub struct DbFixture {
    dir: TempDir,
}

impl DbFixture {
    /// Creates a database containing a valid `ALPM_DB_VERSION` and nothing else.
    ///
    /// # Panics
    ///
    /// If the temporary directory cannot be created or written to.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "a fixture that cannot set itself up has no useful error to report"
    )]
    pub fn new() -> Self {
        let fixture = Self::without_schema_version();
        fixture.write_schema_version(&ALPM_DB_VERSION.to_string());
        fixture
    }

    /// Creates a database with no `ALPM_DB_VERSION` file.
    ///
    /// # Panics
    ///
    /// If the temporary directory cannot be created.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "a fixture that cannot set itself up has no useful error to report"
    )]
    pub fn without_schema_version() -> Self {
        Self { dir: TempDir::new().expect("failed to create a temporary directory") }
    }

    /// Writes `contents` to `ALPM_DB_VERSION` verbatim. This lets a test express an invalid
    /// version.
    ///
    /// # Panics
    ///
    /// If the file cannot be written.
    #[allow(clippy::expect_used, reason = "fixture setup failures are not recoverable")]
    pub fn write_schema_version(&self, contents: &str) -> &Self {
        std::fs::write(self.path().join(ALPM_DB_VERSION_FILE), contents)
            .expect("failed to write the schema version file");
        self
    }

    /// Starts building an entry directory named `entry`.
    ///
    /// The name is used verbatim. This lets a test express an invalid entry name.
    pub fn package(&self, entry: &str) -> PackageFixture<'_> {
        PackageFixture { db: self, entry: entry.to_owned(), desc: None, files: None, mtree: None }
    }

    /// Creates a plain file, rather than a directory, directly in the database.
    ///
    /// # Panics
    ///
    /// If the file cannot be written.
    #[allow(clippy::expect_used, reason = "fixture setup failures are not recoverable")]
    pub fn stray_file(&self, name: &str, contents: &str) -> &Self {
        std::fs::write(self.path().join(name), contents).expect("failed to write a stray file");
        self
    }

    /// The database directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Takes ownership of the temporary directory, keeping it alive independently.
    #[must_use]
    pub fn into_temp_dir(self) -> TempDir {
        self.dir
    }
}

impl Default for DbFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// A pending entry directory. Call [`PackageFixture::build`] to write it.
#[derive(Debug)]
#[must_use = "a PackageFixture does nothing until `build` is called"]
pub struct PackageFixture<'a> {
    db: &'a DbFixture,
    entry: String,
    desc: Option<String>,
    files: Option<String>,
    mtree: Option<Vec<u8>>,
}

impl PackageFixture<'_> {
    /// Fills in a well-formed `desc`, `files` and `mtree`.
    ///
    /// The `desc` is [`MINIMAL_DESC_V1`] with its `%NAME%` and `%VERSION%` rewritten to agree
    /// with the entry directory name. This keeps the entry self-consistent.
    pub fn with_defaults(self) -> Self {
        let (name, version) = split_entry(&self.entry);
        let desc = MINIMAL_DESC_V1
            .replacen("%NAME%\nfoo", &format!("%NAME%\n{name}"), 1)
            .replacen("%VERSION%\n1.0.0-1", &format!("%VERSION%\n{version}"), 1)
            .replacen("%BASE%\nfoo", &format!("%BASE%\n{name}"), 1);

        self.desc(&desc).files(MINIMAL_FILES).mtree(MINIMAL_MTREE_V2)
    }

    /// Sets the `desc` body, written verbatim.
    pub fn desc(mut self, body: &str) -> Self {
        self.desc = Some(body.to_owned());
        self
    }

    /// Sets the `files` body, written verbatim.
    pub fn files(mut self, body: &str) -> Self {
        self.files = Some(body.to_owned());
        self
    }

    /// Sets the `mtree` body, gzip-compressed on write, as pacman stores it.
    pub fn mtree(mut self, body: &str) -> Self {
        self.mtree = Some(gzip(body.as_bytes()));
        self
    }

    /// Sets the `mtree` file's raw bytes, bypassing compression.
    pub fn mtree_raw(mut self, bytes: &[u8]) -> Self {
        self.mtree = Some(bytes.to_vec());
        self
    }

    /// Writes the entry directory and its files, returning the directory's path.
    ///
    /// # Panics
    ///
    /// If the directory or any of its files cannot be written.
    #[allow(clippy::expect_used, reason = "fixture setup failures are not recoverable")]
    pub fn build(self) -> PathBuf {
        let dir = self.db.path().join(&self.entry);
        std::fs::create_dir_all(&dir).expect("failed to create an entry directory");

        if let Some(desc) = &self.desc {
            std::fs::write(dir.join("desc"), desc).expect("failed to write desc");
        }
        if let Some(files) = &self.files {
            std::fs::write(dir.join("files"), files).expect("failed to write files");
        }
        if let Some(mtree) = &self.mtree {
            std::fs::write(dir.join("mtree"), mtree).expect("failed to write mtree");
        }

        dir
    }
}

/// Splits an entry name for the purpose of generating a matching `desc`.
///
/// Intentionally naive — this is the fixture side, not the parser under test.
fn split_entry(entry: &str) -> (&str, &str) {
    match entry.rmatch_indices('-').nth(1).map(|(index, _)| index) {
        Some(index) => {
            let name = entry.get(..index).unwrap_or(entry);
            let version = entry.get(index..).unwrap_or("").trim_start_matches('-');
            (name, version)
        }
        None => (entry, "1.0.0-1"),
    }
}

/// Gzip-compresses `bytes`, as pacman does when storing an `mtree`.
///
/// # Panics
///
/// If compression fails, which for an in-memory writer means an allocation failure.
#[allow(clippy::expect_used, reason = "fixture setup failures are not recoverable")]
#[must_use]
pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).expect("failed to gzip fixture data");
    encoder.finish().expect("failed to finish gzipping fixture data")
}

/// Builds a gzip stream that inflates to `size` bytes of zeroes.
///
/// Used to check that decompression is bounded: at the default limits this compresses to a
/// few kilobytes but inflates to hundreds of megabytes.
#[must_use]
pub fn gzip_bomb(size: usize) -> Vec<u8> {
    gzip(&vec![b'\n'; size])
}

/// A minimal, well-formed `alpm-repo-descv2` body.
///
/// Unlike the local `desc` format, a repository `desc` also carries the package file name,
/// its checksum and its compressed/installed sizes — see
/// [alpm-repo-db](https://alpm.archlinux.page/specifications/alpm-repo-db.7.html).
pub const MINIMAL_REPO_DESC_V2: &str = "\
%FILENAME%
foo-1.0.0-1-x86_64.pkg.tar.zst

%NAME%
foo

%BASE%
foo

%VERSION%
1.0.0-1

%DESC%
An example package

%CSIZE%
1234

%ISIZE%
5678

%SHA256SUM%
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

%URL%
https://example.org/

%ARCH%
x86_64

%BUILDDATE%
1733737242

%PACKAGER%
Foobar McFooface <foobar@mcfooface.org>

";

/// A minimal, well-formed `alpm-repo-files` body.
pub const MINIMAL_REPO_FILES: &str = "\
%FILES%
usr/
usr/bin/
usr/bin/foo
";

/// Builds a gzip-compressed tar archive from `(path, content)` pairs, laid out the way a real
/// `alpm-repo-db` archive is: no compression suffix on the outer file name, gzip only inside.
///
/// # Panics
///
/// If building the tar or gzip stream fails, which for an in-memory writer means an
/// allocation failure.
#[must_use]
#[allow(clippy::expect_used, reason = "fixture setup failures are not recoverable")]
pub fn gzip_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, *content).expect("failed to append a tar entry");
    }
    let tar_bytes = builder.into_inner().expect("failed to finish the tar archive");
    gzip(&tar_bytes)
}

/// A temporary directory for repository archive fixtures.
///
/// Unlike [`DbFixture`], this does not itself hold a database — it is a plain scratch
/// directory that [`RepoFixture::write_archive`] writes named archive files into, since a
/// repository database is a single file rather than a directory tree.
#[derive(Debug)]
pub struct RepoFixture {
    dir: TempDir,
}

impl RepoFixture {
    /// Creates an empty scratch directory.
    ///
    /// # Panics
    ///
    /// If the temporary directory cannot be created.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "a fixture that cannot set itself up has no useful error to report"
    )]
    pub fn new() -> Self {
        Self { dir: TempDir::new().expect("failed to create a temporary directory") }
    }

    /// The scratch directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Writes `bytes` to `name` inside the scratch directory, returning the full path.
    ///
    /// # Panics
    ///
    /// If the file cannot be written.
    #[allow(clippy::expect_used, reason = "fixture setup failures are not recoverable")]
    pub fn write_archive(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, bytes).expect("failed to write an archive fixture");
        path
    }

    /// Writes a gzip-compressed tar archive built from `(path, content)` pairs to `name`.
    ///
    /// # Panics
    ///
    /// As [`RepoFixture::write_archive`] and [`gzip_tar`].
    pub fn write_gzip_archive(&self, name: &str, entries: &[(&str, &[u8])]) -> PathBuf {
        self.write_archive(name, &gzip_tar(entries))
    }
}

impl Default for RepoFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// One package, described by the fields dependency resolution actually reads.
///
/// [`DbFixture`]/[`RepoFixture`] write bodies verbatim, which lets a test express a
/// *malformed* entry. That is the wrong trade for a resolver test, where every package is
/// well-formed by construction and only its relations vary. Spelling out a fifteen-section
/// `desc` per package would bury the one line under test. This renders both the local `desc`
/// and the repository `desc` from the same spec instead, so a scenario cannot state a
/// package's dependencies one way to the local database and another way to a repository.
///
/// Everything not named here (description, URL, architecture, packager, dates, checksum)
/// is filled with the same constants [`MINIMAL_DESC_V1`] and [`MINIMAL_REPO_DESC_V2`] use.
#[derive(Clone, Debug)]
pub struct PackageSpec {
    name: String,
    version: String,
    depends: Vec<String>,
    provides: Vec<String>,
    conflicts: Vec<String>,
    replaces: Vec<String>,
    optdepends: Vec<String>,
    groups: Vec<String>,
    reason: alpm_types::PackageInstallReason,
    installed_size: u64,
    compressed_size: u64,
}

impl PackageSpec {
    /// A package named `name` at `version`, with no relations and no groups.
    ///
    /// `version` must be a full `pkgver-pkgrel` (optionally epoch-prefixed). An entry
    /// directory name that [`crate::EntryName`] rejects would make the package invisible.
    #[must_use]
    pub fn new(name: &str, version: &str) -> Self {
        Self {
            name: name.to_owned(),
            version: version.to_owned(),
            depends: Vec::new(),
            provides: Vec::new(),
            conflicts: Vec::new(),
            replaces: Vec::new(),
            optdepends: Vec::new(),
            groups: Vec::new(),
            reason: alpm_types::PackageInstallReason::Explicit,
            installed_size: 123,
            compressed_size: 45,
        }
    }

    /// Sets `%DEPENDS%`, e.g. `["bar>=2.0", "lib:libfoo.so.1"]`.
    #[must_use]
    pub fn depends<I: IntoIterator<Item = S>, S: Into<String>>(mut self, items: I) -> Self {
        self.depends = items.into_iter().map(Into::into).collect();
        self
    }

    /// Sets `%PROVIDES%`, e.g. `["python=3.12", "libfoo.so=1-64"]`.
    #[must_use]
    pub fn provides<I: IntoIterator<Item = S>, S: Into<String>>(mut self, items: I) -> Self {
        self.provides = items.into_iter().map(Into::into).collect();
        self
    }

    /// Sets `%CONFLICTS%`.
    #[must_use]
    pub fn conflicts<I: IntoIterator<Item = S>, S: Into<String>>(mut self, items: I) -> Self {
        self.conflicts = items.into_iter().map(Into::into).collect();
        self
    }

    /// Sets `%REPLACES%`.
    #[must_use]
    pub fn replaces<I: IntoIterator<Item = S>, S: Into<String>>(mut self, items: I) -> Self {
        self.replaces = items.into_iter().map(Into::into).collect();
        self
    }

    /// Sets `%OPTDEPENDS%`, e.g. `["cups: printing support"]`.
    #[must_use]
    pub fn optdepends<I: IntoIterator<Item = S>, S: Into<String>>(mut self, items: I) -> Self {
        self.optdepends = items.into_iter().map(Into::into).collect();
        self
    }

    /// Sets `%GROUPS%`: what `IgnoreGroup` matches against, and what a target naming a
    /// group expands through.
    #[must_use]
    pub fn groups<I: IntoIterator<Item = S>, S: Into<String>>(mut self, items: I) -> Self {
        self.groups = items.into_iter().map(Into::into).collect();
        self
    }

    /// Sets `%REASON%`. Only meaningful for an installed package; a repository `desc` has no
    /// such field.
    #[must_use]
    pub const fn reason(mut self, reason: alpm_types::PackageInstallReason) -> Self {
        self.reason = reason;
        self
    }

    /// Sets `%SIZE%` (local) / `%ISIZE%` (repository).
    #[must_use]
    pub const fn installed_size(mut self, bytes: u64) -> Self {
        self.installed_size = bytes;
        self
    }

    /// Sets `%CSIZE%`, the download size a plan reports. Repository-only.
    #[must_use]
    pub const fn compressed_size(mut self, bytes: u64) -> Self {
        self.compressed_size = bytes;
        self
    }

    /// The entry directory name this package is stored under, in both database layouts.
    #[must_use]
    pub fn entry(&self) -> String {
        format!("{}-{}", self.name, self.version)
    }

    /// Renders the local database's `desc`, in `alpm-db-descv1` form.
    ///
    /// Section order follows `_alpm_local_db_write` (`be_local.c`). `%REASON%` is written
    /// only for a dependency, because libalpm omits the field entirely when the reason is
    /// `Explicit` (the zero value). A fixture that always wrote it would not exercise the
    /// absent-means-explicit path real entries take.
    #[must_use]
    pub fn local_desc(&self) -> String {
        let mut desc = String::new();
        desc.push_str(&section("NAME", std::slice::from_ref(&self.name)));
        desc.push_str(&section("VERSION", std::slice::from_ref(&self.version)));
        desc.push_str(&section("BASE", std::slice::from_ref(&self.name)));
        desc.push_str("%DESC%\nAn example package\n\n");
        desc.push_str("%URL%\nhttps://example.org/\n\n");
        desc.push_str("%ARCH%\nx86_64\n\n");
        desc.push_str("%BUILDDATE%\n1733737242\n\n");
        desc.push_str("%INSTALLDATE%\n1733737243\n\n");
        desc.push_str("%PACKAGER%\nFoobar McFooface <foobar@mcfooface.org>\n\n");
        desc.push_str(&format!("%SIZE%\n{}\n\n", self.installed_size));
        if self.reason == alpm_types::PackageInstallReason::Depend {
            desc.push_str("%REASON%\n1\n\n");
        }
        desc.push_str(&section("GROUPS", &self.groups));
        desc.push_str("%VALIDATION%\npgp\n\n");
        desc.push_str(&section("REPLACES", &self.replaces));
        desc.push_str(&section("DEPENDS", &self.depends));
        desc.push_str(&section("OPTDEPENDS", &self.optdepends));
        desc.push_str(&section("CONFLICTS", &self.conflicts));
        desc.push_str(&section("PROVIDES", &self.provides));
        desc
    }

    /// Renders a repository database's `desc`, in `alpm-repo-descv2` form.
    ///
    /// v2 rather than v1, because v1 mandates `%MD5SUM%`. Its presence is exactly what
    /// distinguishes the two schemas. See [`crate::repo::RepoDescView::md5_checksum`].
    #[must_use]
    pub fn repo_desc(&self) -> String {
        let file_name = format!("{}-{}-x86_64.pkg.tar.zst", self.name, self.version);
        let mut desc = String::new();
        desc.push_str(&section("FILENAME", std::slice::from_ref(&file_name)));
        desc.push_str(&section("NAME", std::slice::from_ref(&self.name)));
        desc.push_str(&section("BASE", std::slice::from_ref(&self.name)));
        desc.push_str(&section("VERSION", std::slice::from_ref(&self.version)));
        desc.push_str("%DESC%\nAn example package\n\n");
        desc.push_str(&section("GROUPS", &self.groups));
        desc.push_str(&format!("%CSIZE%\n{}\n\n", self.compressed_size));
        desc.push_str(&format!("%ISIZE%\n{}\n\n", self.installed_size));
        desc.push_str(
            "%SHA256SUM%\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n",
        );
        desc.push_str("%URL%\nhttps://example.org/\n\n");
        desc.push_str("%ARCH%\nx86_64\n\n");
        desc.push_str("%BUILDDATE%\n1733737242\n\n");
        desc.push_str("%PACKAGER%\nFoobar McFooface <foobar@mcfooface.org>\n\n");
        desc.push_str(&section("REPLACES", &self.replaces));
        desc.push_str(&section("CONFLICTS", &self.conflicts));
        desc.push_str(&section("PROVIDES", &self.provides));
        desc.push_str(&section("DEPENDS", &self.depends));
        desc.push_str(&section("OPTDEPENDS", &self.optdepends));
        desc
    }

    /// A `files` body owning one path unique to this package, so two packages in a scenario
    /// never collide by accident.
    #[must_use]
    fn files_body(&self) -> String {
        format!("%FILES%\nusr/\nusr/bin/\nusr/bin/{}\n\n", self.name)
    }
}

/// Renders one `%KEY%` section, or nothing at all when `values` is empty.
///
/// An empty section is not the same as an absent one to every parser. libalpm writes nothing
/// rather than a bare header, so this omits the section entirely too.
fn section(key: &str, values: &[String]) -> String {
    if values.is_empty() {
        return String::new();
    }
    let mut out = format!("%{key}%\n");
    for value in values {
        out.push_str(value);
        out.push('\n');
    }
    out.push('\n');
    out
}

/// A whole resolver scenario: an installed set plus any number of repositories, in priority
/// order.
///
/// ```
/// use piko_db::fixture::{PackageSpec, Scenario};
///
/// let scenario = Scenario::new()
///     .installed(PackageSpec::new("bar", "1.0.0-1"))
///     .repo("core", [PackageSpec::new("foo", "2.0.0-1").depends(["bar"])])
///     .build();
///
/// assert_eq!(scenario.local().len(), 1);
/// assert_eq!(scenario.repos().len(), 1);
/// ```
#[derive(Debug, Default)]
#[must_use = "a Scenario does nothing until `build` is called"]
pub struct Scenario {
    installed: Vec<PackageSpec>,
    repos: Vec<(String, Vec<PackageSpec>)>,
}

impl Scenario {
    /// An empty scenario: nothing installed, no repositories.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one installed package.
    pub fn installed(mut self, package: PackageSpec) -> Self {
        self.installed.push(package);
        self
    }

    /// Adds a repository named `name` carrying `packages`.
    ///
    /// Repositories are opened in the order they are added here, which is the order
    /// `pacman.conf` would list them in. That order **is** priority.
    pub fn repo<I: IntoIterator<Item = PackageSpec>>(mut self, name: &str, packages: I) -> Self {
        self.repos.push((name.to_owned(), packages.into_iter().collect()));
        self
    }

    /// Writes both database layouts to temporary directories and opens them.
    ///
    /// # Panics
    ///
    /// If a directory or archive cannot be written, or if either database fails to open.
    /// Every package a scenario describes is well-formed by construction, so a failure here
    /// is a bug in this builder, not a condition a test could meaningfully assert on.
    #[allow(clippy::expect_used, reason = "fixture setup failures are not recoverable")]
    pub fn build(self) -> BuiltScenario {
        let local_fixture = DbFixture::new();
        for package in &self.installed {
            local_fixture
                .package(&package.entry())
                .desc(&package.local_desc())
                .files(&package.files_body())
                .build();
        }

        let repo_fixture = RepoFixture::new();
        let mut repos = Vec::with_capacity(self.repos.len());
        for (name, packages) in &self.repos {
            // `gzip_tar` borrows. The rendered bodies must outlive the call.
            let bodies: Vec<(String, Vec<u8>)> = packages
                .iter()
                .map(|package| {
                    (format!("{}/desc", package.entry()), package.repo_desc().into_bytes())
                })
                .collect();
            let entries: Vec<(&str, &[u8])> =
                bodies.iter().map(|(path, body)| (path.as_str(), body.as_slice())).collect();
            repo_fixture.write_gzip_archive(&format!("{name}.db"), &entries);

            let repo_name = crate::repo::RepoName::parse(name).expect("invalid repository name");
            repos.push(
                crate::repo::RepoDatabase::open_repo(repo_fixture.path(), &repo_name)
                    .expect("failed to open a scenario repository"),
            );
        }

        let local = crate::LocalDatabase::open(local_fixture.path())
            .expect("failed to open the scenario local database");

        BuiltScenario { _local_fixture: local_fixture, _repo_fixture: repo_fixture, local, repos }
    }
}

/// The opened databases a [`Scenario`] describes.
///
/// This owns the temporary directories, so it must outlive every borrow taken from
/// [`BuiltScenario::local`] or [`BuiltScenario::repos`]. A lazily-loaded `desc` is read from
/// disk on first access, long after `build` returned.
#[derive(Debug)]
pub struct BuiltScenario {
    _local_fixture: DbFixture,
    _repo_fixture: RepoFixture,
    local: crate::LocalDatabase,
    repos: Vec<crate::repo::RepoDatabase>,
}

impl BuiltScenario {
    /// The installed set.
    #[must_use]
    pub const fn local(&self) -> &crate::LocalDatabase {
        &self.local
    }

    /// Every repository, in the order [`Scenario::repo`] added them — priority order.
    #[must_use]
    pub fn repos(&self) -> &[crate::repo::RepoDatabase] {
        &self.repos
    }

    /// One repository by name.
    #[must_use]
    pub fn repo(&self, name: &str) -> Option<&crate::repo::RepoDatabase> {
        self.repos.iter().find(|repo| repo.name().as_ref() == name)
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

    #[test]
    fn a_new_fixture_has_a_valid_schema_version() {
        let db = DbFixture::new();
        let contents = std::fs::read_to_string(db.path().join(ALPM_DB_VERSION_FILE)).unwrap();
        assert_eq!(contents, "9");
    }

    #[test]
    fn build_writes_all_three_metadata_files() {
        let db = DbFixture::new();
        let dir = db.package("foo-1.0.0-1").with_defaults().build();

        assert!(dir.join("desc").is_file());
        assert!(dir.join("files").is_file());
        assert!(dir.join("mtree").is_file());
    }

    /// The generated `desc` must agree with the directory name. Otherwise every consistency
    /// test built on the fixture would be testing the fixture's bug instead.
    #[test]
    fn defaults_agree_with_the_entry_name() {
        let db = DbFixture::new();
        let dir = db.package("my-pkg-2:3.4.5-6").with_defaults().build();
        let desc = std::fs::read_to_string(dir.join("desc")).unwrap();

        assert!(desc.contains("%NAME%\nmy-pkg\n"), "{desc}");
        assert!(desc.contains("%VERSION%\n2:3.4.5-6\n"), "{desc}");
        assert!(desc.contains("%BASE%\nmy-pkg\n"), "{desc}");
    }

    /// pacman stores `mtree` gzip-compressed. A fixture that did not would not exercise the
    /// decompression path.
    #[test]
    fn mtree_is_gzip_compressed() {
        let db = DbFixture::new();
        let dir = db.package("foo-1.0.0-1").with_defaults().build();
        let bytes = std::fs::read(dir.join("mtree")).unwrap();
        assert_eq!(bytes.get(..2), Some([0x1f, 0x8b].as_slice()), "mtree must be gzip");
    }

    #[test]
    fn bodies_are_written_verbatim_so_invalid_input_is_expressible() {
        let db = DbFixture::new();
        let dir = db.package("foo-1.0.0-1").desc("not a desc at all").build();
        assert_eq!(std::fs::read_to_string(dir.join("desc")).unwrap(), "not a desc at all");
        assert!(!dir.join("files").exists(), "unset files must not be written");
    }

    #[test]
    fn a_gzip_bomb_is_much_smaller_than_its_output() {
        let bomb = gzip_bomb(64 * 1024 * 1024);
        assert!(bomb.len() < 128 * 1024, "bomb was {} bytes", bomb.len());
    }

    #[test]
    fn split_entry_handles_the_shapes_the_fixture_needs() {
        assert_eq!(split_entry("foo-1.0.0-1"), ("foo", "1.0.0-1"));
        assert_eq!(split_entry("my-pkg-2:3.4.5-6"), ("my-pkg", "2:3.4.5-6"));
        assert_eq!(split_entry("nonsense"), ("nonsense", "1.0.0-1"));
    }

    /// The reason [`PackageSpec`] renders both layouts from one value. A scenario must not be
    /// able to tell the local database one set of dependencies and a repository another.
    #[test]
    fn one_spec_describes_a_package_identically_to_both_databases() {
        let spec = PackageSpec::new("foo", "1.0.0-1")
            .depends(["bar>=2.0"])
            .provides(["virtual"])
            .conflicts(["baz"])
            .replaces(["old-foo"]);

        let scenario = Scenario::new().installed(spec.clone()).repo("core", [spec]).build();

        let local = scenario.local().get_str("foo").unwrap();
        let local_desc = local.desc().unwrap();
        let repo = scenario.repo("core").unwrap().get_str("foo").unwrap();

        // The repository side reads these straight off the package. They are the eager tier.
        assert_eq!(join_display(local_desc.depends()), join_display(repo.depends().unwrap()));
        assert_eq!(join_display(local_desc.provides()), join_display(repo.provides()));
        assert_eq!(join_display(local_desc.conflicts()), join_display(repo.conflicts()));
        assert_eq!(join_display(local_desc.replaces()), join_display(repo.replaces()));
        assert_eq!(join_display(local_desc.depends()), "bar>=2.0");
    }

    /// Repository order is priority order. A builder that reordered them would silently
    /// invert the outcome of every priority test built on it.
    #[test]
    fn repositories_keep_the_order_they_were_added_in() {
        let scenario = Scenario::new()
            .repo("core", [PackageSpec::new("foo", "1.0.0-1")])
            .repo("extra", [PackageSpec::new("foo", "2.0.0-1")])
            .build();

        let names: Vec<_> =
            scenario.repos().iter().map(|repo| repo.name().as_ref().to_owned()).collect();
        assert_eq!(names, ["core", "extra"]);
        assert_eq!(
            scenario.repo("extra").unwrap().get_str("foo").unwrap().version().to_string(),
            "2.0.0-1"
        );
    }

    /// libalpm omits `%REASON%` entirely when the reason is `Explicit`. A fixture that always
    /// wrote it would never exercise the absent-means-explicit path real entries take.
    #[test]
    fn install_reason_is_written_the_way_libalpm_writes_it() {
        let explicit = PackageSpec::new("foo", "1.0.0-1");
        assert!(!explicit.local_desc().contains("%REASON%"), "{}", explicit.local_desc());

        let dependency =
            PackageSpec::new("foo", "1.0.0-1").reason(alpm_types::PackageInstallReason::Depend);
        assert!(dependency.local_desc().contains("%REASON%\n1\n"), "{}", dependency.local_desc());

        let scenario = Scenario::new().installed(dependency).build();
        let desc = scenario.local().get_str("foo").unwrap().desc().unwrap();
        assert_eq!(desc.install_reason(), alpm_types::PackageInstallReason::Depend);
    }

    /// An unset relation must produce no section at all, not an empty header.
    #[test]
    fn unset_sections_are_omitted_entirely() {
        let spec = PackageSpec::new("foo", "1.0.0-1");
        for body in [spec.local_desc(), spec.repo_desc()] {
            assert!(!body.contains("%DEPENDS%"), "{body}");
            assert!(!body.contains("%PROVIDES%"), "{body}");
            assert!(!body.contains("%CONFLICTS%"), "{body}");
            assert!(!body.contains("%GROUPS%"), "{body}");
        }
    }

    /// Two packages in one scenario must not appear to fight over the same file. Otherwise a
    /// future file-conflict test would be asserting on an artefact of the builder.
    #[test]
    fn each_package_owns_a_distinct_file() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("foo", "1.0.0-1"))
            .installed(PackageSpec::new("bar", "1.0.0-1"))
            .build();

        let foo = scenario.local().get_str("foo").unwrap().file_list().unwrap().to_vec();
        let bar = scenario.local().get_str("bar").unwrap().file_list().unwrap().to_vec();
        assert!(foo.iter().any(|path| path.ends_with("usr/bin/foo")), "{foo:?}");
        assert!(bar.iter().any(|path| path.ends_with("usr/bin/bar")), "{bar:?}");
        assert!(!foo.iter().any(|path| path.ends_with("usr/bin/bar")), "{foo:?}");
    }

    /// Renders a relation list the way both `DescView` and `RepoDescView` would print it. The
    /// two can then be compared without caring that their element types differ.
    fn join_display<T: std::fmt::Display>(items: &[T]) -> String {
        items.iter().map(ToString::to_string).collect::<Vec<_>>().join(" ")
    }
}
