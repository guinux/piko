//! Package files named on the command line: reading them, checking them, fetching them.
//!
//! This is the library half of `pacman -U`. A package file is a candidate the solver has never
//! seen, addressed by a path rather than by a repository, and governed by its own `SigLevel`
//! directive. Each of those three is decided here, once, so that any frontend gets the same
//! answers.
//!
//! What is *not* here: the solving, which is `piko_db::solve`'s, and the verification, which
//! happens in [`crate::Transaction::verify`] exactly as it does for a repository package. A
//! file target is checked in the same place, by the same code, under a different policy —
//! not on a path of its own.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use alpm_types::{
    Architecture, CompressionAlgorithmFileExtension, PackageFileName, RelationOrSoname,
};
use piko_db::EntryName;
use piko_db::solve::FilePackage;
use piko_sig::Policy;

use crate::extract::PackageLimits;
use crate::source::{CacheDirSource, PackageSource};
use crate::{Error, Result};

/// One package file a transaction will install, read far enough to plan with.
#[derive(Debug)]
pub struct FileTarget {
    path: PathBuf,
    architecture: Architecture,
    candidate: FilePackage,
    policy: Policy,
}

impl FileTarget {
    /// Where the file is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The name this package is addressed by inside a transaction.
    ///
    /// Built from the `.PKGINFO`, not from the file's own name. The two usually agree, and
    /// when they do not it is the metadata that describes the archive — a file renamed on
    /// disk is still the package it was built as. Nothing downloads this name; it is the key
    /// [`crate::source::FileSource`] maps back to [`FileTarget::path`].
    #[must_use]
    pub const fn file_name(&self) -> &PackageFileName {
        self.candidate.file_name()
    }

    /// The candidate the solver sees.
    #[must_use]
    pub const fn candidate(&self) -> &FilePackage {
        &self.candidate
    }

    /// The signature policy this file is held to.
    #[must_use]
    pub const fn policy(&self) -> Policy {
        self.policy
    }

    /// The architecture its `.PKGINFO` declares.
    #[must_use]
    pub const fn architecture(&self) -> &Architecture {
        &self.architecture
    }
}

/// Reads `path` far enough to plan with it, under `policy`.
///
/// Only `.PKGINFO` is read here — see [`crate::conflict::load_pkginfo`] for why the archive is
/// read again later rather than cached.
///
/// # Errors
///
/// [`Error::UnusableSource`] if the archive has no usable `.PKGINFO`, or if its name and
/// version do not form an entry name piko's own reader would accept.
pub fn load(path: &Path, policy: Policy, limits: &PackageLimits) -> Result<FileTarget> {
    let (info, _raw) = crate::conflict::load_pkginfo(path, limits)?;
    let fields = Fields::of(&info);

    let entry = EntryName::new(fields.name, fields.version).map_err(|error| {
        Error::UnusableSource { path: path.to_path_buf(), reason: error.to_string() }
    })?;
    let file_name = PackageFileName::new(
        fields.name.clone(),
        fields.version.clone(),
        fields.architecture.clone(),
        compression_of(path),
    );

    Ok(FileTarget {
        path: path.to_path_buf(),
        architecture: fields.architecture.clone(),
        candidate: FilePackage::new(
            entry,
            file_name,
            fields.depends.to_vec(),
            fields.provides.to_vec(),
            fields.conflicts.to_vec(),
            fields.replaces.to_vec(),
            fields.groups.to_vec(),
            fields.installed_size,
        ),
        policy,
    })
}

/// The `.PKGINFO` fields a candidate is built from, read through one match on the schema
/// version rather than one per field.
struct Fields<'a> {
    name: &'a alpm_types::Name,
    version: &'a alpm_types::FullVersion,
    architecture: &'a Architecture,
    installed_size: u64,
    depends: &'a [RelationOrSoname],
    provides: &'a [RelationOrSoname],
    conflicts: &'a [alpm_types::PackageRelation],
    replaces: &'a [alpm_types::PackageRelation],
    groups: &'a [alpm_types::Group],
}

impl<'a> Fields<'a> {
    /// Both `.PKGINFO` schema versions carry every field read here. V2 adds `xdata`, which
    /// nothing in a plan needs.
    fn of(info: &'a alpm_pkginfo::PackageInfo) -> Self {
        macro_rules! fields {
            ($v:expr) => {
                Self {
                    name: &$v.pkgname,
                    version: &$v.pkgver,
                    architecture: &$v.arch,
                    installed_size: u64::from($v.size),
                    depends: &$v.depend,
                    provides: &$v.provides,
                    conflicts: &$v.conflict,
                    replaces: &$v.replaces,
                    groups: &$v.group,
                }
            };
        }
        match info {
            alpm_pkginfo::PackageInfo::V1(v1) => fields!(v1),
            alpm_pkginfo::PackageInfo::V2(v2) => fields!(v2),
        }
    }
}

/// The compression a file's own name declares, for [`PackageFileName`].
///
/// Best effort, and deliberately so. This affects only the string a package is addressed by
/// inside the transaction; the archive itself is decompressed by sniffing its magic bytes
/// (`extract::archive::sniff_file`), never by trusting an extension. An unrecognised name
/// yields an uncompressed-looking key, which still round-trips.
fn compression_of(path: &Path) -> Option<CompressionAlgorithmFileExtension> {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(|extension| extension.parse::<CompressionAlgorithmFileExtension>().ok())
}

/// Refuses a file built for an architecture this machine is not configured to run.
///
/// This is `check_arch` (`trans.c:69`), which libalpm runs over the whole add list before
/// preparing a transaction. It has never had anything to do in piko: a repository serves the
/// architecture its `Server` URL named. A file named on the command line is the case it exists
/// for.
///
/// Skipped entirely when no `Architecture` is configured, as libalpm skips it. `any` always
/// passes. Otherwise the match is literal — `x86_64` does not admit `i686`.
///
/// # Errors
///
/// [`Error::WrongArchitecture`] naming every refused file.
pub fn check_architecture(targets: &[FileTarget], configured: &[Architecture]) -> Result<()> {
    if configured.is_empty() {
        return Ok(());
    }
    let refused: Vec<String> = targets
        .iter()
        .filter(|target| {
            target.architecture != Architecture::Any && !configured.contains(&target.architecture)
        })
        .map(|target| format!("{} ({})", target.file_name(), target.architecture))
        .collect();
    if refused.is_empty() {
        return Ok(());
    }
    Err(Error::WrongArchitecture {
        packages: refused,
        configured: configured.iter().map(ToString::to_string).collect(),
    })
}

/// Refuses two targets that would install the same package.
///
/// `alpm_add_pkg` (`add.c:49`) refuses a duplicate name with `ALPM_ERR_TRANS_DUP_TARGET`, and
/// `_alpm_sync_prepare` (`sync.c:470`) refuses a duplicate file name with
/// `ALPM_ERR_TRANS_DUP_FILENAME`. Both reduce to one question here, because a file target's
/// name *is* its `PackageFileName`: two files that render the same key would have to be the
/// same package, and [`crate::source::FileSource`] could only serve one of them.
///
/// # Errors
///
/// [`Error::DuplicateTarget`] naming the two paths.
pub fn check_duplicates(targets: &[FileTarget]) -> Result<()> {
    let mut seen: HashMap<String, &Path> = HashMap::new();
    for target in targets {
        let key = target.file_name().to_string();
        if let Some(first) = seen.insert(key.clone(), &target.path) {
            return Err(Error::DuplicateTarget {
                package: key,
                first: first.to_path_buf(),
                second: target.path.clone(),
            });
        }
    }
    Ok(())
}

/// Fetches a package named by URL, and returns where it landed.
///
/// This is `alpm_fetch_pkgurl` (`dload.c:1324`), including its cache rule: a copy already in a
/// cache directory is used, unless `policy` asks for a signature and no `.sig` sits beside it
/// — in which case the hit is discarded and the file is fetched again, so that the signature
/// arrives with it.
///
/// The URL is split at its last `/` into a server and a file name, and handed to the same
/// `piko-net` download every repository package uses. That is what makes the `.sig` fetch, the
/// size bound, the atomic write and the cancellation check identical on both paths. It also
/// means the last component must be a name `alpm_types::PackageFileName` accepts.
///
/// # Where the file lands
///
/// [`select_download_dir`] runs here, which is the second place it runs — the other being
/// `DownloadingSource::new`. It has to: this download happens before a plan exists, so there
/// is no transaction source yet to borrow one from. It runs *after* the URL is parsed and
/// after the cache is asked, so a malformed URL is reported as a malformed URL rather than as
/// a cache problem, and a URL already in the cache needs no writable directory at all.
///
/// Nothing is verified here. The file joins the transaction as an ordinary file target and is
/// checked in [`crate::Transaction::verify`], under `policy`.
///
/// # Errors
///
/// [`Error::InvalidPackageUrl`] if the URL has no usable last component.
/// [`Error::NoWritableCacheDir`] if the download has nowhere to go.
/// [`Error::Download`] if no server could supply it, or the download was cancelled.
pub fn fetch_url(
    url: &str,
    cache: &CacheDirSource,
    policy: Policy,
    cancel: &piko_net::Cancel,
    progress: &(dyn Fn(piko_net::Event) + Sync),
) -> Result<PathBuf> {
    let (server, last) = url.rsplit_once('/').ok_or_else(|| Error::InvalidPackageUrl {
        url: url.to_owned(),
        reason: "it has no path component".to_owned(),
    })?;
    let file_name: PackageFileName = last.parse().map_err(|error| Error::InvalidPackageUrl {
        url: url.to_owned(),
        reason: format!("{last:?} is not a package file name: {error}"),
    })?;

    if let Ok(location) = cache.locate(&file_name)
        && (!policy.check || piko_sig::signature_path(location.path()).is_file())
    {
        return Ok(location.path().to_path_buf());
    }

    let download_dir = crate::source::select_download_dir(cache.directories())?;
    piko_net::Refresher::default()
        .fetch_package_with_progress(
            download_dir.path(),
            &file_name,
            url,
            std::slice::from_ref(&server.to_owned()),
            policy,
            cancel,
            progress,
        )
        .map_err(Error::Download)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// Builds an uncompressed package archive carrying `pkginfo`, and returns its path.
    fn package(dir: &Path, name: &str, pkginfo: &str) -> PathBuf {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(pkginfo.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, ".PKGINFO", pkginfo.as_bytes()).unwrap();

        let path = dir.join(name);
        std::fs::write(&path, builder.into_inner().unwrap()).unwrap();
        path
    }

    /// A `.PKGINFO` with every section a candidate is built from.
    fn pkginfo(name: &str, version: &str, arch: &str) -> String {
        format!(
            "pkgname = {name}\n\
             pkgbase = {name}\n\
             pkgver = {version}\n\
             pkgdesc = An example package\n\
             url = https://example.org/\n\
             builddate = 1733737242\n\
             packager = Foobar McFooface <foobar@mcfooface.org>\n\
             size = 4096\n\
             arch = {arch}\n\
             license = MIT\n\
             depend = glibc\n\
             depend = libfoo.so=1-64\n\
             provides = foo-api=2\n\
             conflict = oldfoo\n\
             replaces = ancientfoo\n\
             group = base\n"
        )
    }

    fn arch(spelled: &str) -> Architecture {
        spelled.parse().unwrap()
    }

    fn policy() -> Policy {
        Policy::for_package(piko_db::config::SigLevel::default())
    }

    #[test]
    fn every_section_a_candidate_needs_comes_out_of_the_pkginfo() {
        let dir = tempfile::tempdir().unwrap();
        let path = package(dir.path(), "foo.pkg.tar", &pkginfo("foo", "1.0.0-1", "x86_64"));

        let target = load(&path, policy(), &PackageLimits::default()).unwrap();
        let candidate = target.candidate();

        assert_eq!(candidate.name().to_string(), "foo");
        assert_eq!(candidate.version().to_string(), "1.0.0-1");
        assert_eq!(candidate.installed_size(), 4096);
        assert_eq!(candidate.depends().len(), 2);
        assert_eq!(candidate.provides().len(), 1);
        assert_eq!(candidate.conflicts().len(), 1);
        assert_eq!(candidate.replaces().len(), 1);
        assert_eq!(candidate.groups().len(), 1);
    }

    /// The addressing name is rebuilt from the metadata, not taken from the file. A renamed
    /// archive is still the package it was built as, and `FileSource` maps that name back to
    /// wherever the file actually is.
    #[test]
    fn the_addressing_name_comes_from_the_metadata_not_the_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = package(dir.path(), "renamed.pkg.tar", &pkginfo("foo", "1.0.0-1", "x86_64"));

        let target = load(&path, policy(), &PackageLimits::default()).unwrap();
        assert_eq!(target.file_name().to_string(), "foo-1.0.0-1-x86_64.pkg.tar");
        assert_eq!(target.path(), path);
    }

    #[test]
    fn an_architecture_this_machine_cannot_run_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = package(dir.path(), "foo.pkg.tar", &pkginfo("foo", "1.0.0-1", "aarch64"));
        let targets = vec![load(&path, policy(), &PackageLimits::default()).unwrap()];

        let error = check_architecture(&targets, &[arch("x86_64")]).unwrap_err();
        assert!(matches!(error, Error::WrongArchitecture { .. }), "got {error:?}");

        // libalpm skips the check entirely when nothing is configured (`trans.c:69`).
        check_architecture(&targets, &[]).unwrap();
        check_architecture(&targets, &[arch("aarch64")]).unwrap();
    }

    #[test]
    fn an_any_package_runs_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        let path = package(dir.path(), "foo.pkg.tar", &pkginfo("foo", "1.0.0-1", "any"));
        let targets = vec![load(&path, policy(), &PackageLimits::default()).unwrap()];
        check_architecture(&targets, &[arch("x86_64")]).unwrap();
    }

    /// Two paths, one package. `FileSource` could serve only one of them, so the transaction
    /// refuses rather than silently picking.
    #[test]
    fn two_files_naming_one_package_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let info = pkginfo("foo", "1.0.0-1", "x86_64");
        let first = package(dir.path(), "one.pkg.tar", &info);
        let second = package(dir.path(), "two.pkg.tar", &info);
        let targets = vec![
            load(&first, policy(), &PackageLimits::default()).unwrap(),
            load(&second, policy(), &PackageLimits::default()).unwrap(),
        ];

        let error = check_duplicates(&targets).unwrap_err();
        assert!(matches!(error, Error::DuplicateTarget { .. }), "got {error:?}");
    }

    #[test]
    fn two_different_packages_are_not_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let first = package(dir.path(), "a.pkg.tar", &pkginfo("foo", "1.0.0-1", "x86_64"));
        let second = package(dir.path(), "b.pkg.tar", &pkginfo("bar", "1.0.0-1", "x86_64"));
        let targets = vec![
            load(&first, policy(), &PackageLimits::default()).unwrap(),
            load(&second, policy(), &PackageLimits::default()).unwrap(),
        ];
        check_duplicates(&targets).unwrap();
    }

    /// A URL whose last component is not a package file name has nothing to fetch. This is
    /// refused before anything touches the network or the cache directories.
    #[test]
    fn a_url_that_names_no_package_is_refused_before_any_io() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheDirSource::new([dir.path().to_path_buf()]).unwrap();
        let cancel = piko_net::Cancel::new();

        for url in ["https://host/notapackage", "https://host/"] {
            let error = fetch_url(url, &cache, policy(), &cancel, &|_| {}).unwrap_err();
            assert!(matches!(error, Error::InvalidPackageUrl { .. }), "{url}: got {error:?}");
        }
    }

    /// `alpm_fetch_pkgurl`'s cache rule: a cached copy is used, but only if the signature the
    /// policy asks for is cached with it.
    #[test]
    fn a_cached_url_is_used_only_when_its_signature_is_there_too() {
        let dir = tempfile::tempdir().unwrap();
        let name = "foo-1.0.0-1-x86_64.pkg.tar.zst";
        std::fs::write(dir.path().join(name), b"cached bytes").unwrap();
        let cache = CacheDirSource::new([dir.path().to_path_buf()]).unwrap();
        let cancel = piko_net::Cancel::new();
        let url = format!("https://host.invalid/{name}");

        // Nothing to check: the hit stands.
        let unchecked = Policy { check: false, ..policy() };
        assert_eq!(
            fetch_url(&url, &cache, unchecked, &cancel, &|_| {}).unwrap(),
            dir.path().join(name)
        );

        // A signature is wanted and none is beside it, so the hit is discarded and the fetch
        // is attempted — against a host that does not resolve, which is how this test knows
        // the hit was rejected without needing a server.
        let checked = Policy { check: true, ..policy() };
        assert!(fetch_url(&url, &cache, checked, &cancel, &|_| {}).is_err());

        // With the signature there, the hit stands again.
        std::fs::write(dir.path().join(format!("{name}.sig")), b"not a real signature").unwrap();
        assert_eq!(
            fetch_url(&url, &cache, checked, &cancel, &|_| {}).unwrap(),
            dir.path().join(name)
        );
    }
}
