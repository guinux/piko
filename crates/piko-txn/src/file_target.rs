//! Package files named on the command line: reading them, checking them, fetching them.
//!
//! This is the library half of `pacman -U`. A package file is a candidate the solver has
//! never seen. A path addresses it rather than a repository, and its own `SigLevel` directive
//! governs it. Each of those three is decided here, once, so any frontend gets the same
//! answers.
//!
//! Two things are *not* here. The solving belongs to `piko_db::solve`. The verification
//! happens in [`crate::Transaction::verify`], exactly as it does for a repository package. A
//! file target is checked in the same place, by the same code, under a different policy. It
//! takes no path of its own.

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
    problems: Vec<crate::pkginfo::Problem>,
}

impl FileTarget {
    /// Where the file is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The name this package is addressed by inside a transaction.
    ///
    /// Built from the `.PKGINFO`, not from the file's own name. The two usually agree. When
    /// they do not, the metadata is what describes the archive. A file renamed on disk is
    /// still the package it was built as. Nothing downloads this name. It is the key
    /// `crate::source::FileSource` maps back to [`FileTarget::path`].
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

    /// What its `.PKGINFO` holds that piko reads past, as [`crate::pkginfo::PkgInfo::problems`]
    /// lists it. A frontend shows these before it asks to install the file.
    #[must_use]
    pub fn problems(&self) -> &[crate::pkginfo::Problem] {
        &self.problems
    }
}

/// Reads `path` far enough to plan with it, under `policy`.
///
/// Only `.PKGINFO` is read here — see [`crate::conflict::load_pkginfo`] for why the archive is
/// read again later rather than cached.
///
/// # Errors
///
/// [`Error::UnusableSource`] covers two cases. The archive has no usable `.PKGINFO`, or its
/// name and version do not form an entry name piko's own reader would accept.
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
        problems: info.problems(),
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
    /// The fields of a `.PKGINFO` a plan reads, every one a key that decides something.
    fn of(info: &'a crate::pkginfo::PkgInfo) -> Self {
        Self {
            name: &info.name,
            version: &info.version,
            architecture: &info.architecture,
            installed_size: info.size,
            depends: &info.depends,
            provides: &info.provides,
            conflicts: &info.conflicts,
            replaces: &info.replaces,
            groups: &info.groups,
        }
    }
}

/// The compression a file's own name declares, for [`PackageFileName`].
///
/// Best effort, and deliberately so. This affects only the string a package is addressed by
/// inside the transaction. The archive itself is decompressed by sniffing its magic bytes
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
/// preparing a transaction. This half covers the files named on the command line.
/// [`crate::plan::check_architecture`] covers the repository packages a plan installs.
///
/// Skipped entirely when no `Architecture` is configured, as libalpm skips it. `any` always
/// passes. Otherwise the match is literal — `x86_64` does not admit `i686`.
///
/// # Errors
///
/// [`Error::WrongArchitecture`] naming every refused file.
pub fn check_architecture(targets: &[FileTarget], configured: &[Architecture]) -> Result<()> {
    let refused: Vec<String> = targets
        .iter()
        .filter(|target| !is_admitted(configured, &target.architecture))
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

/// Whether a package built for `architecture` may be installed under `configured`.
///
/// `check_arch`'s rule (`trans.c:69`): an empty list admits everything, `any` is always
/// admitted, and otherwise the name must be one of `configured`.
pub(crate) fn is_admitted(configured: &[Architecture], architecture: &Architecture) -> bool {
    configured.is_empty() || *architecture == Architecture::Any || configured.contains(architecture)
}

/// Refuses two targets that would install the same package.
///
/// `alpm_add_pkg` (`add.c:49`) refuses a duplicate name with `ALPM_ERR_TRANS_DUP_TARGET`, and
/// `_alpm_sync_prepare` (`sync.c:470`) refuses a duplicate file name with
/// `ALPM_ERR_TRANS_DUP_FILENAME`. Both reduce to one question here, because a file target's
/// name *is* its `PackageFileName`. Two files that render the same key would have to be the
/// same package, and [`crate::source::FileSource`] could serve only one of them.
///
/// # Errors
///
/// [`Error::DuplicateTarget`] naming the two paths.
pub(crate) fn check_duplicates(targets: &[FileTarget]) -> Result<()> {
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

/// The signature policies a package file named as a target is loaded under.
///
/// pacman's `-U` splits its targets on `strstr(i->data, "://")` and loads each half under its
/// own directive (`upgrade.c`). [`crate::classify`] makes the same split.
#[derive(Clone, Copy, Debug)]
pub struct FilePolicies {
    /// `LocalFileSigLevel`: the policy for a file named by path.
    pub local: Policy,
    /// `RemoteFileSigLevel`: the policy for a file named by URL.
    pub remote: Policy,
}

/// What [`load_targets`] does with a target that names a URL.
pub enum Urls<'a> {
    /// Refuse it with [`Error::UrlNotLoaded`]. A command that must not reach the network,
    /// such as a preview, takes this.
    Refuse,
    /// Fetch it through the callback, which returns where the file landed.
    ///
    /// The caller owns the download: its progress, its cancellation, and what it prints. The
    /// callback is expected to call [`fetch_url`].
    Fetch(&'a mut dyn FnMut(&str) -> Result<PathBuf>),
}

impl std::fmt::Debug for Urls<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refuse => f.write_str("Refuse"),
            Self::Fetch(_) => f.write_str("Fetch(..)"),
        }
    }
}

/// The targets of an install, split into what the solver resolves and what was read from a
/// file.
#[derive(Debug, Default)]
pub struct Targets {
    /// Targets to resolve through the repositories, in the order they were given.
    pub names: Vec<String>,
    /// Every package file named, path and URL alike, in the order they were given.
    pub files: Vec<FileTarget>,
}

impl Targets {
    /// The solver's view of each named file, in the order they were given.
    ///
    /// A `Universe` borrows these for as long as it lives. So the caller collects them once and
    /// keeps them beside it.
    #[must_use]
    pub fn candidates(&self) -> Vec<&FilePackage> {
        self.files.iter().map(FileTarget::candidate).collect()
    }
}

/// Reads every target that names a package file, and keeps every other target as a name.
///
/// `kinds` is each target as [`crate::classify`] read it, in the order given. A path is loaded
/// under `policies.local`. A URL is refused or fetched, as `urls` says, and the file it
/// fetched is loaded under `policies.remote`. The files are then checked together:
/// `check_duplicates` first, [`check_architecture`] second.
///
/// `piko plan` and `piko install` both read their targets through this function. So a preview
/// refuses what the install refuses, in the same order. A preview that plans what the install
/// refuses is a wrong answer.
///
/// # Errors
///
/// [`Error::UrlNotLoaded`] for a URL under [`Urls::Refuse`]. Whatever [`load`], the fetch
/// callback, `check_duplicates` or [`check_architecture`] return, from the first target that
/// fails.
pub fn load_targets(
    kinds: &[crate::TargetKind],
    policies: FilePolicies,
    architecture: &[Architecture],
    mut urls: Urls<'_>,
    limits: &PackageLimits,
) -> Result<Targets> {
    let mut targets = Targets { names: Vec::new(), files: Vec::new() };
    for kind in kinds {
        match kind {
            crate::TargetKind::Name(name) => targets.names.push(name.clone()),
            crate::TargetKind::File(path) => {
                targets.files.push(load(path, policies.local, limits)?)
            }
            crate::TargetKind::Url(url) => {
                let Urls::Fetch(fetch) = &mut urls else {
                    return Err(Error::UrlNotLoaded {
                        url: piko_net::without_credentials(url).into_owned(),
                    });
                };
                let path = fetch(url)?;
                targets.files.push(load(&path, policies.remote, limits)?);
            }
        }
    }
    check_duplicates(&targets.files)?;
    check_architecture(&targets.files, architecture)?;
    Ok(targets)
}

/// Fetches a package named by URL, and returns where it landed.
///
/// This is `alpm_fetch_pkgurl` (`dload.c:1324`), including its cache rule. A copy already in
/// a cache directory is used. The exception is a `policy` asking for a signature with no
/// `.sig` beside the copy. The hit is then discarded and the file is fetched again, so the
/// signature arrives with it.
///
/// The URL is split at its last `/` into a server and a file name. That pair goes to the same
/// `piko-net` download every repository package uses. That is what makes the `.sig` fetch, the
/// size bound, the atomic write and the cancellation check identical on both paths. It also
/// means the last component must be a name `alpm_types::PackageFileName` accepts.
///
/// # Where the file lands
///
/// [`crate::select_download_dir`] runs here, the second place it runs. The other is
/// `DownloadingSource::new`. It has to run here, because this download happens before a plan
/// exists. There is no transaction source yet to borrow one from.
///
/// It runs *after* the URL is parsed and after the cache is asked. So a malformed URL is
/// reported as a malformed URL rather than as a cache problem. And a URL already in the cache
/// needs no writable directory at all.
///
/// The download is confined and bounded by `downloads`, as every repository package's is.
///
/// Nothing is verified here. The file joins the transaction as an ordinary file target and is
/// checked in [`crate::Transaction::verify`], under `policy`.
///
/// # Errors
///
/// [`Error::InvalidPackageUrl`] if the URL has no usable last component.
/// [`Error::UnsupportedPackageCompression`] if that component's suffix declares a compression
/// piko does not decode.
/// [`Error::NoWritableCacheDir`] if the download has nowhere to go.
/// [`Error::Download`] if no server could supply it, or the download was cancelled.
pub fn fetch_url(
    url: &str,
    cache: &CacheDirSource,
    policy: Policy,
    downloads: piko_net::DownloadSettings,
    cancel: &piko_net::Cancel,
    progress: &(dyn Fn(piko_net::Event) + Sync),
) -> Result<PathBuf> {
    let shown = || piko_net::without_credentials(url).into_owned();
    let (server, last) = url.rsplit_once('/').ok_or_else(|| Error::InvalidPackageUrl {
        url: shown(),
        reason: "it has no path component".to_owned(),
    })?;
    let file_name: PackageFileName = last.parse().map_err(|error| Error::InvalidPackageUrl {
        url: shown(),
        reason: format!("{last:?} is not a package file name: {error}"),
    })?;
    // Refused before the download, as `plan::check_compression` refuses a repository package.
    if let Err(format) = piko_db::compression::from_extension(file_name.compression()) {
        return Err(Error::UnsupportedPackageCompression {
            packages: vec![(file_name.to_string(), format)],
        });
    }

    if let Ok(location) = cache.locate(&file_name)
        && (!policy.check || piko_sig::signature_path(location.path()).is_file())
    {
        return Ok(location.path().to_path_buf());
    }

    let download_dir = crate::source::select_download_dir(cache.directories())?;
    piko_net::Refresher::from_settings(downloads)
        .fetch_package_with_progress(
            download_dir.path(),
            // No repository describes a URL target, so `max_package_bytes` alone bounds it.
            piko_net::PackageFetch::new(
                &file_name,
                url,
                std::slice::from_ref(&server.to_owned()),
                policy,
            ),
            cancel,
            progress,
        )
        .map_err(Error::Download)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
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
    /// archive is still the package it was built as. `FileSource` maps that name back to
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

    fn policies() -> FilePolicies {
        FilePolicies {
            local: Policy::for_package(piko_db::config::SigLevel::default()),
            remote: Policy { check: true, optional: false, marginal_ok: false, unknown_ok: false },
        }
    }

    /// Names stay names, files are read, and both keep the order they were given in.
    #[test]
    fn load_targets_splits_names_from_files_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let foo = package(dir.path(), "foo.pkg.tar", &pkginfo("foo", "1.0.0-1", "x86_64"));
        let bar = package(dir.path(), "bar.pkg.tar", &pkginfo("bar", "1.0.0-1", "x86_64"));
        let kinds = [
            crate::TargetKind::Name("vim".to_owned()),
            crate::TargetKind::File(foo.clone()),
            crate::TargetKind::Name("git".to_owned()),
            crate::TargetKind::File(bar.clone()),
        ];

        let targets =
            load_targets(&kinds, policies(), &[], Urls::Refuse, &PackageLimits::default()).unwrap();

        assert_eq!(targets.names, ["vim", "git"]);
        let paths: Vec<&Path> = targets.files.iter().map(FileTarget::path).collect();
        assert_eq!(paths, [foo.as_path(), bar.as_path()]);
        assert_eq!(targets.candidates().len(), 2);
    }

    /// A preview must not reach the network, so a URL is refused rather than fetched.
    #[test]
    fn load_targets_refuses_a_url_under_refuse() {
        let kinds = [crate::TargetKind::Url("https://host/foo-1.0.0-1-x86_64.pkg.tar".to_owned())];

        let error = load_targets(&kinds, policies(), &[], Urls::Refuse, &PackageLimits::default())
            .unwrap_err();
        assert!(matches!(error, Error::UrlNotLoaded { .. }), "got {error:?}");
    }

    /// A fetched file is read from where the callback put it, under the remote policy.
    #[test]
    fn load_targets_reads_a_fetched_url_under_the_remote_policy() {
        let dir = tempfile::tempdir().unwrap();
        let fetched = package(dir.path(), "foo.pkg.tar", &pkginfo("foo", "1.0.0-1", "x86_64"));
        let url = "https://host/foo-1.0.0-1-x86_64.pkg.tar";
        let kinds = [crate::TargetKind::Url(url.to_owned())];
        let mut asked = Vec::new();
        let mut fetch = |requested: &str| {
            asked.push(requested.to_owned());
            Ok(fetched.clone())
        };

        let targets = load_targets(
            &kinds,
            policies(),
            &[],
            Urls::Fetch(&mut fetch),
            &PackageLimits::default(),
        )
        .unwrap();

        assert_eq!(asked, [url]);
        let file = targets.files.first().unwrap();
        assert_eq!(file.path(), fetched);
        assert!(file.policy().check, "a URL target takes RemoteFileSigLevel");
    }

    /// The same checks as on their own, after every file is read.
    #[test]
    fn load_targets_refuses_duplicates_and_foreign_architectures() {
        let dir = tempfile::tempdir().unwrap();
        let info = pkginfo("foo", "1.0.0-1", "x86_64");
        let first = package(dir.path(), "one.pkg.tar", &info);
        let second = package(dir.path(), "two.pkg.tar", &info);
        let twice = [crate::TargetKind::File(first.clone()), crate::TargetKind::File(second)];
        let error = load_targets(&twice, policies(), &[], Urls::Refuse, &PackageLimits::default())
            .unwrap_err();
        assert!(matches!(error, Error::DuplicateTarget { .. }), "got {error:?}");

        let once = [crate::TargetKind::File(first)];
        let error = load_targets(
            &once,
            policies(),
            &[arch("aarch64")],
            Urls::Refuse,
            &PackageLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::WrongArchitecture { .. }), "got {error:?}");
    }

    /// A URL whose last component is not a package file name has nothing to fetch. This is
    /// refused before anything touches the network or the cache directories.
    #[test]
    fn a_url_that_names_no_package_is_refused_before_any_io() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheDirSource::new([dir.path().to_path_buf()]).unwrap();
        let cancel = piko_net::Cancel::new();

        for url in ["https://host/notapackage", "https://host/"] {
            let error = fetch_url(
                url,
                &cache,
                policy(),
                piko_net::DownloadSettings::unconfined(),
                &cancel,
                &|_| {},
            )
            .unwrap_err();
            assert!(matches!(error, Error::InvalidPackageUrl { .. }), "{url}: got {error:?}");
        }
    }

    /// A URL naming an xz package is refused before the download, even when a copy is
    /// already cached: the bytes would be refused after it anyway.
    #[test]
    fn a_url_naming_an_xz_package_is_refused_before_any_io() {
        let dir = tempfile::tempdir().unwrap();
        let name = "foo-1.0.0-1-x86_64.pkg.tar.xz";
        std::fs::write(dir.path().join(name), b"cached").unwrap();
        let cache = CacheDirSource::new([dir.path().to_path_buf()]).unwrap();
        let cancel = piko_net::Cancel::new();

        let url = format!("https://host.invalid/{name}");
        let error = fetch_url(
            &url,
            &cache,
            policy(),
            piko_net::DownloadSettings::unconfined(),
            &cancel,
            &|_| {},
        )
        .unwrap_err();
        let Error::UnsupportedPackageCompression { packages } = &error else {
            panic!("got {error:?}");
        };
        assert_eq!(packages, &[(name.to_owned(), piko_db::compression::Unsupported::Xz)]);
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
            fetch_url(
                &url,
                &cache,
                unchecked,
                piko_net::DownloadSettings::unconfined(),
                &cancel,
                &|_| {}
            )
            .unwrap(),
            dir.path().join(name)
        );

        // A signature is wanted and none is beside it, so the hit is discarded and the fetch
        // is attempted. The host does not resolve. That is how this test knows the hit was
        // rejected, without needing a server.
        let checked = Policy { check: true, ..policy() };
        assert!(
            fetch_url(
                &url,
                &cache,
                checked,
                piko_net::DownloadSettings::unconfined(),
                &cancel,
                &|_| {}
            )
            .is_err()
        );

        // With the signature there, the hit stands again.
        std::fs::write(dir.path().join(format!("{name}.sig")), b"not a real signature").unwrap();
        assert_eq!(
            fetch_url(
                &url,
                &cache,
                checked,
                piko_net::DownloadSettings::unconfined(),
                &cancel,
                &|_| {}
            )
            .unwrap(),
            dir.path().join(name)
        );
    }
}
