//! Where package files come from.
//!
//! A commit needs the `.pkg.tar.*` file behind every install step. [`PackageSource`] is the
//! seam that supplies it. It decouples the transaction engine from where the file comes from.
//! Everything the engine sees is a [`Location`] — a path to a regular file that exists right
//! now. It may come from a cache or a fresh download.
//!
//! [`CacheDirSource`] is the *offline* implementation. It reads what pacman already downloaded
//! into `CacheDir`. That is enough to build and exercise the whole engine against real
//! packages — 1872 of them on a real system — without piko fetching anything.
//! [`DownloadingSource`] is the second implementation. It wraps a [`CacheDirSource`] and, on a
//! genuine miss, downloads the file through `piko-net` before answering.

use std::{
    collections::HashMap,
    fmt,
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use alpm_types::PackageFileName;

use crate::error::{Error, IoAction, Result};

/// Why a candidate package file was not usable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SkipReason {
    /// The path exists but is a directory, FIFO, socket or device node.
    ///
    /// libalpm logs this as a warning and keeps searching (`util.c:869`). piko also keeps
    /// searching, but returns the fact instead of logging it. This follows piko-db's
    /// principle 7.
    NotARegularFile,
    /// The path could not be stat'ed for a reason other than not existing.
    Unreadable,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotARegularFile => "not a regular file",
            Self::Unreadable => "unreadable",
        })
    }
}

/// A candidate package file that existed but could not be used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Skipped {
    /// The candidate's path.
    pub path: PathBuf,
    /// Why it was skipped.
    pub reason: SkipReason,
}

impl fmt::Display for Skipped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.path.display(), self.reason)
    }
}

/// A package file that exists and is usable.
///
/// # This is a snapshot, not a promise
///
/// Nothing holds a lock over the cache. The file can be removed or replaced between this
/// value's creation and its use. This is not a flaw to fix — it is the same staleness
/// [`piko_db::solve::Plan`] has. The same answer applies: whatever consumes this must open
/// the path and handle failure, rather than trust `size` to still be true. `size` exists for
/// progress reporting, not for allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Location {
    path: PathBuf,
    size: u64,
    skipped: Vec<Skipped>,
}

impl Location {
    /// The package file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The file's size in bytes as of the lookup.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Candidates that were found before this one and rejected.
    ///
    /// Usually empty. When it is not, it explains why the package came from a later source
    /// than expected. That is the difference between "piko used the wrong cache" and "your
    /// first cache directory has a broken entry".
    #[must_use]
    pub fn skipped(&self) -> &[Skipped] {
        &self.skipped
    }
}

/// Supplies the package files a transaction needs.
///
/// Implementations must work from several threads at once. Extraction will eventually run in
/// parallel, and adding a lock to this trait later would change every implementation.
pub trait PackageSource: fmt::Debug + Send + Sync {
    /// Locates the package file named `file_name`.
    ///
    /// # Errors
    ///
    /// [`Error::NotAvailable`] if no source can supply it. It carries every location searched
    /// and everything rejected.
    fn locate(&self, file_name: &PackageFileName) -> Result<Location>;

    /// Whether `file_name` can be supplied, without reporting why not.
    ///
    /// This is the equivalent of `_alpm_filecache_exists` (`util.c:891`). It is implemented in
    /// terms of [`PackageSource::locate`], for the same reason libalpm implements it in terms
    /// of `_alpm_filecache_find`: two lookup paths that can disagree are a bug waiting to
    /// happen.
    fn contains(&self, file_name: &PackageFileName) -> bool {
        self.locate(file_name).is_ok()
    }

    /// Fetches whatever in `file_names` is not already on hand, ahead of the per-file
    /// [`PackageSource::locate`] calls that follow.
    ///
    /// This makes downloads parallel without moving any verification. The loops that follow
    /// stay unchanged; they simply find their packages already in the cache.
    ///
    /// # Every failure but cancellation is deliberately dropped
    ///
    /// This is an optimization, not a lookup. A file it could not fetch is still missing. The
    /// `locate` that follows retries it and reports the same error it would report had this
    /// method never run — same code path, same message, same position in the caller's ordered
    /// output. Surfacing failures here would create a second place that can refuse a package,
    /// and two such places eventually disagree.
    ///
    /// Cancellation is the exception. It is not a fact about one package. There is no point
    /// letting `locate` retry each file to rediscover that the user asked to stop.
    ///
    /// The default does nothing. That is right for a source that only checks what already
    /// exists, and it keeps [`PackageSource::locate`] the only path that can download.
    ///
    /// # Errors
    ///
    /// [`Error::Download`] wrapping `piko_net::Error::Cancelled`, and nothing else.
    fn prefetch(&self, _file_names: &[PackageFileName]) -> Result<()> {
        Ok(())
    }
}

/// Why a configured cache directory cannot receive a download.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RejectionReason {
    /// The path exists and is not a directory.
    NotADirectory,
    /// The path is a directory this process may not write into.
    NotWritable,
    /// The directory carries none of the owner, group or other write bits.
    NoWriteBits,
    /// The path did not exist and could not be created.
    CreateFailed(std::io::ErrorKind),
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotADirectory => f.write_str("not a directory"),
            Self::NotWritable => f.write_str("not writable"),
            Self::NoWriteBits => f.write_str("no write bits set"),
            Self::CreateFailed(kind) => write!(f, "could not be created: {kind}"),
        }
    }
}

/// A configured cache directory a download cannot be written into.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedCacheDir {
    /// The directory as it was configured.
    pub path: PathBuf,
    /// Why it cannot receive a download.
    pub reason: RejectionReason,
}

impl fmt::Display for RejectedCacheDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "skipping cache directory {} ({})", self.path.display(), self.reason)
    }
}

/// The cache directory a download will be written into.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadDir {
    path: PathBuf,
    created: bool,
    rejected: Vec<RejectedCacheDir>,
}

impl DownloadDir {
    /// The chosen directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this directory did not exist and was created.
    #[must_use]
    pub const fn created(&self) -> bool {
        self.created
    }

    /// The directories passed over to reach this one, in configured order.
    ///
    /// Empty in the ordinary case. When it is not, it explains why a download landed
    /// somewhere other than the first configured directory.
    #[must_use]
    pub fn rejected(&self) -> &[RejectedCacheDir] {
        &self.rejected
    }
}

/// Chooses the cache directory a download is written into, creating it if it is absent.
///
/// This transcribes `_alpm_filecache_setup` (`util.c:904`). `directories` is walked in order
/// and the first usable entry wins: an absent one is created, while a non-directory, one this
/// process may not write into, and one with no write bit set are all passed over.
///
/// The *search* list is a different question and stays complete. [`CacheDirSource`] reads
/// every configured directory, including the ones passed over here, so a read-only cache is
/// still read and a package already in one is never fetched again.
///
/// This creates a directory, so it belongs to a caller that is about to download. Keep it out
/// of [`CacheDirSource::new`], which `piko plan` and `piko remove` both build without ever
/// fetching anything.
///
/// # Errors
///
/// [`Error::NoWritableCacheDir`] when no entry is usable. It names every directory and why
/// each one was refused.
pub fn select_download_dir(directories: &[PathBuf]) -> Result<DownloadDir> {
    let mut rejected = Vec::new();

    for directory in directories {
        // The stat follows a final symlink, as libalpm's does, and for the reason
        // `CacheDirSource` documents: the path comes from configuration, not from an
        // untrusted directory entry.
        let metadata = match std::fs::metadata(directory) {
            Ok(metadata) => metadata,
            // libalpm does not separate "absent" from "unstatable" here either: both mean
            // there is nothing usable yet, and creating is the only way to find out.
            Err(_) => match create_cache_dir(directory) {
                Ok(()) => {
                    return Ok(DownloadDir { path: directory.clone(), created: true, rejected });
                }
                Err(source) => {
                    let reason = RejectionReason::CreateFailed(source.kind());
                    rejected.push(RejectedCacheDir { path: directory.clone(), reason });
                    continue;
                }
            },
        };

        if !metadata.is_dir() {
            let reason = RejectionReason::NotADirectory;
            rejected.push(RejectedCacheDir { path: directory.clone(), reason });
            continue;
        }
        if rustix::fs::access(directory, rustix::fs::Access::WRITE_OK).is_err() {
            let reason = RejectionReason::NotWritable;
            rejected.push(RejectedCacheDir { path: directory.clone(), reason });
            continue;
        }
        // A separate question from the access check above, and libalpm asks both
        // (`util.c:925` then `:928`). The access check answers "may this process write
        // here", which root and `CAP_DAC_OVERRIDE` answer yes to whatever the mode says.
        // This one is a fact about the directory.
        if metadata.permissions().mode() & 0o222 == 0 {
            let reason = RejectionReason::NoWriteBits;
            rejected.push(RejectedCacheDir { path: directory.clone(), reason });
            continue;
        }

        return Ok(DownloadDir { path: directory.clone(), created: false, rejected });
    }

    Err(Error::NoWritableCacheDir { rejected })
}

/// Creates a cache directory and every missing parent, mode `0755` before the umask.
///
/// `_alpm_makepath_mode` (`util.c:111`) sets the umask to zero around the `mkdir` to land on
/// exactly `0755`. This does not: the umask is process-global state, and piko downloads in
/// parallel, so clearing it opens a window where a file another thread creates becomes
/// world-accessible. A permission difference in the restrictive direction does not pay for
/// that race.
fn create_cache_dir(directory: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    builder.mode(0o755);
    builder.create(directory)
}

/// Finds packages in pacman's own download cache.
///
/// This mirrors `_alpm_filecache_find` (`util.c:857`). The configured cache directories are
/// searched in order, and the first regular file wins. A candidate that exists but is not a
/// regular file does not stop the search.
///
/// # Symlinks are followed
///
/// The stat follows a final symlink, as libalpm's does. This matches the judgment made for
/// repository archives in `piko-db` (see `fs_util::open_following_symlinks`). The path comes
/// from configuration, not an untrusted directory entry, and a cache directory of symlinks
/// into shared storage is a real deployment, not an attack. What the symlink resolves to must
/// still be a regular file.
#[derive(Clone, Debug)]
pub struct CacheDirSource {
    directories: Vec<PathBuf>,
}

impl CacheDirSource {
    /// Builds a source over `directories`, searched in the given order.
    ///
    /// The order matters and comes from the caller: it is `CacheDir`'s order in `pacman.conf`,
    /// a priority just as repository order is.
    ///
    /// # Errors
    ///
    /// [`Error::UnusableSource`] if no directories are given. An empty source would report
    /// every package missing, with an error naming nothing searched. Catching this
    /// configuration mistake here is far cheaper than catching it at the first install step.
    pub fn new(directories: impl IntoIterator<Item = PathBuf>) -> Result<Self> {
        let directories: Vec<PathBuf> = directories.into_iter().collect();
        if directories.is_empty() {
            return Err(Error::UnusableSource {
                path: PathBuf::new(),
                reason: "no cache directories were configured".to_owned(),
            });
        }
        Ok(Self { directories })
    }

    /// The directories this source searches, in order.
    #[must_use]
    pub fn directories(&self) -> &[PathBuf] {
        &self.directories
    }
}

impl PackageSource for CacheDirSource {
    fn locate(&self, file_name: &PackageFileName) -> Result<Location> {
        let name = file_name.to_string();
        let mut skipped = Vec::new();

        for directory in &self.directories {
            let candidate = directory.join(&name);
            match std::fs::metadata(&candidate) {
                Ok(metadata) if metadata.is_file() => {
                    return Ok(Location { path: candidate, size: metadata.len(), skipped });
                }
                Ok(_) => {
                    skipped.push(Skipped { path: candidate, reason: SkipReason::NotARegularFile })
                }
                // Absence is the ordinary case and says nothing worth reporting.
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    skipped.push(Skipped { path: candidate, reason: SkipReason::Unreadable });
                }
            }
        }

        Err(Error::NotAvailable { file_name: name, searched: self.directories.clone(), skipped })
    }
}

/// The oracle [`piko_db::solve::Plan::assemble`] asks how many bytes a plan will really move.
///
/// This is implemented for this source and deliberately not for [`DownloadingSource`]. The
/// latter answers a miss by downloading it, so using it to compute a download size would
/// download everything the size was meant to measure. Leaving the impl off turns that mistake
/// into a compile error instead of a comment nobody reads.
impl piko_db::solve::PackageCache for CacheDirSource {
    fn is_cached(&self, file_name: &PackageFileName) -> bool {
        self.contains(file_name)
    }
}

/// Opens a located package file, refusing anything that is not a regular file.
///
/// The check repeats here even though [`PackageSource::locate`] already made it. The file can
/// be replaced between the two calls — the staleness [`Location`] documents this.
/// Re-checking on the open descriptor with `fstat`, rather than on the path, makes the answer
/// describe the bytes actually about to be read.
///
/// # Errors
///
/// [`Error::Io`] if the file cannot be opened or stat'ed. [`Error::UnusableSource`] if it is
/// no longer a regular file.
pub fn open(location: &Location) -> Result<std::fs::File> {
    let file = std::fs::File::open(location.path())
        .map_err(|source| Error::io(location.path(), IoAction::Open, source))?;
    let metadata =
        file.metadata().map_err(|source| Error::io(location.path(), IoAction::Metadata, source))?;
    if !metadata.is_file() {
        return Err(Error::UnusableSource {
            path: location.path().to_path_buf(),
            reason: "not a regular file".to_owned(),
        });
    }
    Ok(file)
}

/// Serves the package files named on the command line, and delegates everything else.
///
/// A `pacman -U` target is not in any cache directory and has no repository to download from.
/// It is addressed the same way every other package is — by
/// [`PackageFileName`](alpm_types::PackageFileName), built from its own `.PKGINFO` — and this
/// source is what turns that name back into the path the user typed.
///
/// # Why a wrapper rather than a step in `Transaction`
///
/// Everything downstream of [`PackageSource::locate`] works on a path: signature checking,
/// the archive walk, conflict detection, extraction. Making a file target a *source* rather
/// than a second kind of step means none of that has to learn about it, and means a file
/// target cannot accidentally take a shorter route through verification than a downloaded
/// package does.
///
/// A named file wins over a cached or downloadable package of the same name. That is the same
/// precedence [`piko_db::solve::UniverseOptions::files`] gives it when solving, and it must be
/// the same in both places: a plan that chose the file and a source that served the cache
/// copy would install something the user was never shown.
#[derive(Debug)]
pub struct FileSource {
    files: HashMap<String, PathBuf>,
    inner: Box<dyn PackageSource>,
}

impl FileSource {
    /// Wraps `inner`, serving `files` — keyed by the name each one is addressed by — ahead of
    /// it.
    #[must_use]
    pub fn new(files: HashMap<String, PathBuf>, inner: Box<dyn PackageSource>) -> Self {
        Self { files, inner }
    }
}

impl PackageSource for FileSource {
    fn locate(&self, file_name: &PackageFileName) -> Result<Location> {
        let Some(path) = self.files.get(&file_name.to_string()) else {
            return self.inner.locate(file_name);
        };
        // Stat'ed rather than trusted. The file was read once at planning time and can have
        // been replaced since, exactly as a cache entry can — see `Location`.
        let metadata = std::fs::metadata(path)
            .map_err(|source| Error::io(path, IoAction::Metadata, source))?;
        if !metadata.is_file() {
            return Err(Error::UnusableSource {
                path: path.clone(),
                reason: "not a regular file".to_owned(),
            });
        }
        Ok(Location { path: path.clone(), size: metadata.len(), skipped: Vec::new() })
    }

    fn contains(&self, file_name: &PackageFileName) -> bool {
        self.files.contains_key(&file_name.to_string()) || self.inner.contains(file_name)
    }

    /// Fetches only what this source does not already hold.
    ///
    /// A file named on the command line is never downloaded. Passing its name through would
    /// send `DownloadingSource` looking for a repository it has no target for — harmless, but
    /// it would report a download that is not going to happen.
    fn prefetch(&self, file_names: &[PackageFileName]) -> Result<()> {
        let remaining: Vec<PackageFileName> = file_names
            .iter()
            .filter(|file_name| !self.files.contains_key(&file_name.to_string()))
            .cloned()
            .collect();
        if remaining.is_empty() {
            return Ok(());
        }
        self.inner.prefetch(&remaining)
    }
}

/// A file already on disk contributes nothing to a plan's download size.
///
/// [`piko_db::solve::Solvable::download_size`] already answers `None` for a file candidate, so
/// this is never the reason a file counts zero. It exists so that a caller which wraps its
/// cache in a `FileSource` and passes the result as the size oracle gets a consistent answer
/// either way.
impl piko_db::solve::PackageCache for FileSource {
    fn is_cached(&self, file_name: &PackageFileName) -> bool {
        self.contains(file_name)
    }
}

/// Where one package file can be downloaded from, and under what policy.
#[derive(Clone, Debug)]
pub struct DownloadTarget {
    /// The repository this file belongs to, for naming it in an error.
    pub repo_name: String,
    /// `Server`/`CacheServer`, tried in order.
    pub servers: Vec<String>,
    /// Whether — and how — the package's signature should be checked.
    ///
    /// This only decides whether it is worth downloading a `.sig` alongside the package. The
    /// actual check happens later, in [`crate::transaction::Transaction::verify`]'s own
    /// `policy_overrides`. See that module for why the two stay separate instead of verifying
    /// here too.
    pub policy: piko_sig::Policy,
    /// `%CSIZE%`, used only to download the largest packages first.
    ///
    /// This is never a bound. A repository's claimed size is only a claim.
    /// `piko_net::refresh::Limits` still enforces against the bytes that actually arrive, so a
    /// wrong value here only costs a worse download schedule.
    pub size: u64,
}

/// Finds package files in the cache; downloads a miss before reporting one.
///
/// This wraps a [`CacheDirSource`]. A cache hit is served exactly as before, with unchanged
/// behavior. A miss is looked up in `targets` and, if found, downloaded through `piko-net`
/// into the first *usable* configured cache directory ([`select_download_dir`], pacman's own
/// convention for a download's destination). It comes back as an ordinary [`Location`].
/// **Nothing is verified here** — see
/// `piko_net::refresh::Refresher::fetch_package_with_progress`'s documentation for why that
/// responsibility stays with whoever calls `Keyring::check` afterward.
pub struct DownloadingSource {
    cache: CacheDirSource,
    download_dir: DownloadDir,
    refresher: piko_net::Refresher,
    targets: HashMap<String, DownloadTarget>,
    cancel: piko_net::Cancel,
    concurrency: piko_net::Concurrency,
    progress: Box<dyn Fn(piko_net::Event) + Send + Sync>,
}

impl fmt::Debug for DownloadingSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownloadingSource")
            .field("cache", &self.cache)
            .field("download_dir", &self.download_dir)
            .field("targets", &self.targets)
            .field("cancel", &self.cancel)
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}

impl DownloadingSource {
    /// Builds a source over `directories` (searched in order, exactly as [`CacheDirSource`]
    /// would), downloading a miss named in `targets` into the first usable one.
    ///
    /// This is where [`select_download_dir`] runs, and the only place it does. The directory
    /// it may create is created here rather than in [`CacheDirSource::new`], so a command that
    /// only reads the cache never writes to disk.
    ///
    /// `progress` is called synchronously for every download event. This is the same narrow
    /// exception `piko-net` documents on [`piko_net::Event`].
    ///
    /// # Errors
    ///
    /// [`Error::UnusableSource`] if `directories` is empty, for the same reason
    /// [`CacheDirSource::new`] refuses it. [`Error::NoWritableCacheDir`] if none of them can
    /// receive a download.
    pub fn new(
        directories: impl IntoIterator<Item = PathBuf>,
        targets: HashMap<String, DownloadTarget>,
        cancel: piko_net::Cancel,
        concurrency: piko_net::Concurrency,
        progress: impl Fn(piko_net::Event) + Send + Sync + 'static,
    ) -> Result<Self> {
        // `CacheDirSource::new` refuses an empty list, so the selection never sees one.
        let cache = CacheDirSource::new(directories)?;
        let download_dir = select_download_dir(cache.directories())?;
        Ok(Self {
            cache,
            download_dir,
            refresher: piko_net::Refresher::default(),
            targets,
            cancel,
            concurrency,
            progress: Box::new(progress),
        })
    }

    /// Where a download will be written, and what was passed over to get there.
    #[must_use]
    pub const fn download_dir(&self) -> &DownloadDir {
        &self.download_dir
    }
}

impl PackageSource for DownloadingSource {
    fn locate(&self, file_name: &PackageFileName) -> Result<Location> {
        let skipped = match self.cache.locate(file_name) {
            Ok(location) => return Ok(location),
            Err(Error::NotAvailable { skipped, .. }) => skipped,
            Err(other) => return Err(other),
        };

        let name = file_name.to_string();
        let Some(target) = self.targets.get(&name) else {
            return Err(Error::NotAvailable {
                file_name: name,
                searched: self.cache.directories().to_vec(),
                skipped,
            });
        };

        let path = self
            .refresher
            .fetch_package_with_progress(
                self.download_dir.path(),
                file_name,
                &target.repo_name,
                &target.servers,
                target.policy,
                &self.cancel,
                self.progress.as_ref(),
            )
            .map_err(Error::Download)?;
        let metadata = std::fs::metadata(&path)
            .map_err(|source| Error::io(&path, IoAction::Metadata, source))?;
        Ok(Location { path, size: metadata.len(), skipped })
    }

    /// Whether the package is *already* available, without fetching it.
    ///
    /// The inherited default is `locate(...).is_ok()`. That is right for a source that only
    /// looks, and wrong here, because [`DownloadingSource::locate`] answers a miss by
    /// downloading it. A question about what is on hand would transfer the file it asked about
    /// — the opposite of what `_alpm_filecache_exists` (`util.c:891`) means. So this asks the
    /// cache and nothing else.
    fn contains(&self, file_name: &PackageFileName) -> bool {
        self.cache.contains(file_name)
    }

    /// Downloads every cache miss in `file_names` at once, so the `locate` calls that follow
    /// find them already there.
    ///
    /// A name with no [`DownloadTarget`] is skipped rather than reported. `locate` says what is
    /// wrong with it far better, and avoiding that duplicate report is why this method exists.
    /// See the trait's documentation for why nothing but cancellation comes back from here.
    fn prefetch(&self, file_names: &[PackageFileName]) -> Result<()> {
        // Deduplicated: a batch refuses to fetch one destination twice. Two workers would
        // otherwise race for the same atomic-write temporary.
        let mut seen = std::collections::HashSet::new();
        let wanted: Vec<piko_net::PackageFetch<'_>> = file_names
            .iter()
            .filter(|file_name| !self.cache.contains(file_name))
            .filter_map(|file_name| {
                let name = file_name.to_string();
                let target = self.targets.get(&name)?;
                seen.insert(name).then_some(piko_net::PackageFetch {
                    file_name,
                    repo_name: &target.repo_name,
                    servers: &target.servers,
                    policy: target.policy,
                    size: target.size,
                })
            })
            .collect();
        if wanted.is_empty() {
            return Ok(());
        }

        let results = self.refresher.fetch_packages(
            self.download_dir.path(),
            &wanted,
            self.concurrency,
            &self.cancel,
            self.progress.as_ref(),
        );
        for result in results {
            if let Err(error @ piko_net::Error::Cancelled) = result {
                return Err(Error::Download(error));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::str::FromStr as _;

    use super::*;

    const PACKAGE: &str = "foo-1.0.0-1-x86_64.pkg.tar.zst";

    /// A named file wins over a copy of the same package in a cache directory.
    ///
    /// The plan chose the file, so the source has to serve the file. If the two ever
    /// disagreed, `piko install ./foo.pkg.tar.zst` would install the cached build while
    /// showing the user the one they named.
    #[test]
    fn a_named_file_wins_over_a_cache_copy_of_the_same_package() {
        let cache_dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(cache_dir.path().join(PACKAGE), b"the cached build").unwrap();
        let named = elsewhere.path().join("renamed-on-disk.pkg.tar.zst");
        std::fs::write(&named, b"the build the user named").unwrap();

        let inner = CacheDirSource::new([cache_dir.path().to_path_buf()]).unwrap();
        let source =
            FileSource::new(HashMap::from([(PACKAGE.to_owned(), named.clone())]), Box::new(inner));

        let located = source.locate(&file_name()).unwrap();
        assert_eq!(located.path(), named);
        assert!(source.contains(&file_name()));
    }

    /// Anything not named falls through unchanged, so wrapping a source costs nothing when no
    /// file was named.
    #[test]
    fn an_unnamed_package_falls_through_to_the_inner_source() {
        let cache_dir = tempfile::tempdir().unwrap();
        std::fs::write(cache_dir.path().join(PACKAGE), b"the cached build").unwrap();

        let inner = CacheDirSource::new([cache_dir.path().to_path_buf()]).unwrap();
        let source = FileSource::new(HashMap::new(), Box::new(inner));

        assert_eq!(source.locate(&file_name()).unwrap().path(), cache_dir.path().join(PACKAGE));
    }

    /// A named file that has since been deleted is reported against its own path, not as a
    /// cache miss listing directories the user never mentioned.
    #[test]
    fn a_named_file_that_vanished_is_reported_against_its_own_path() {
        let cache_dir = tempfile::tempdir().unwrap();
        let inner = CacheDirSource::new([cache_dir.path().to_path_buf()]).unwrap();
        let gone = cache_dir.path().join("gone.pkg.tar.zst");
        let source =
            FileSource::new(HashMap::from([(PACKAGE.to_owned(), gone.clone())]), Box::new(inner));

        let error = source.locate(&file_name()).unwrap_err();
        let Error::Io { path, .. } = &error else {
            panic!("expected an I/O error naming the file, got {error:?}");
        };
        assert_eq!(path, &gone);
    }

    /// Sets `path`'s mode, so a test can build a directory the selection must pass over.
    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn the_first_usable_cache_directory_is_chosen() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();

        let chosen =
            select_download_dir(&[first.path().to_path_buf(), second.path().to_path_buf()])
                .unwrap();

        assert_eq!(chosen.path(), first.path());
        assert!(!chosen.created());
        assert!(chosen.rejected().is_empty());
    }

    /// `_alpm_makepath` creates every missing parent, so this does too.
    #[test]
    fn a_missing_cache_directory_is_created_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let wanted = dir.path().join("var/cache/pacman/pkg");

        let chosen = select_download_dir(std::slice::from_ref(&wanted)).unwrap();

        assert_eq!(chosen.path(), wanted);
        assert!(chosen.created());
        assert!(wanted.is_dir());
        let mode = std::fs::metadata(&wanted).unwrap().permissions().mode() & 0o777;
        // `0o755` before the umask, which only takes bits away.
        assert_eq!(mode & !0o755, 0, "{mode:o} has a bit 0o755 does not");
    }

    #[test]
    fn a_cache_directory_that_is_a_file_is_passed_over() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"").unwrap();
        let good = tempfile::tempdir().unwrap();

        let chosen = select_download_dir(&[file.clone(), good.path().to_path_buf()]).unwrap();

        assert_eq!(chosen.path(), good.path());
        assert_eq!(
            chosen.rejected(),
            [RejectedCacheDir { path: file, reason: RejectionReason::NotADirectory }]
        );
    }

    /// libalpm asks two questions about write access, in this order: may this process write
    /// here (`util.c:925`), then does the directory carry any write bit at all
    /// (`util.c:928`). The order decides which reason a `0o500` directory reports. An
    /// ordinary process is refused by the first, while root and anything holding
    /// `CAP_DAC_OVERRIDE` pass it and are refused by the second. Either way the directory is
    /// passed over, which is the property that matters, so this pins the skip and accepts
    /// the reason the running process implies.
    #[test]
    fn a_cache_directory_that_cannot_be_written_into_is_passed_over() {
        let locked = tempfile::tempdir().unwrap();
        chmod(locked.path(), 0o500);
        let writable_anyway = std::fs::File::create(locked.path().join("probe")).is_ok();
        let good = tempfile::tempdir().unwrap();

        let chosen =
            select_download_dir(&[locked.path().to_path_buf(), good.path().to_path_buf()]).unwrap();

        assert_eq!(chosen.path(), good.path());
        assert_eq!(chosen.rejected().len(), 1);
        let rejected = chosen.rejected().first().unwrap();
        assert_eq!(rejected.path, locked.path());
        let expected = if writable_anyway {
            RejectionReason::NoWriteBits
        } else {
            RejectionReason::NotWritable
        };
        assert_eq!(rejected.reason, expected);
        chmod(locked.path(), 0o700);
    }

    #[test]
    fn a_cache_directory_that_cannot_be_created_is_passed_over() {
        let parent = tempfile::tempdir().unwrap();
        chmod(parent.path(), 0o500);
        let wanted = parent.path().join("pkg");
        if std::fs::create_dir(&wanted).is_ok() {
            chmod(parent.path(), 0o700);
            return;
        }
        let good = tempfile::tempdir().unwrap();

        let chosen = select_download_dir(&[wanted.clone(), good.path().to_path_buf()]).unwrap();

        assert_eq!(chosen.path(), good.path());
        assert_eq!(chosen.rejected().len(), 1);
        assert!(matches!(
            chosen.rejected().first().map(|r| r.reason),
            Some(RejectionReason::CreateFailed(_))
        ));
        chmod(parent.path(), 0o700);
    }

    /// `_alpm_makepath` treats `EEXIST` as success, so libalpm accepts a dangling symlink and
    /// fails at the first transfer instead. `create_dir_all` re-checks `is_dir`, so this is
    /// passed over.
    #[test]
    fn a_dangling_symlink_cache_directory_is_passed_over() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("cache");
        std::os::unix::fs::symlink(dir.path().join("absent"), &link).unwrap();
        let good = tempfile::tempdir().unwrap();

        let chosen = select_download_dir(&[link, good.path().to_path_buf()]).unwrap();

        assert_eq!(chosen.path(), good.path());
        assert_eq!(chosen.rejected().len(), 1);
    }

    /// Only the chosen directory is created. A later one is never touched.
    #[test]
    fn a_directory_after_the_chosen_one_is_never_created() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");

        let chosen = select_download_dir(&[first.clone(), second.clone()]).unwrap();

        assert_eq!(chosen.path(), first);
        assert!(first.is_dir());
        assert!(!second.exists());
    }

    #[test]
    fn no_usable_cache_directory_is_an_error_naming_every_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a-file");
        std::fs::write(&file, b"").unwrap();
        let locked = tempfile::tempdir().unwrap();
        chmod(locked.path(), 0o500);

        let error = select_download_dir(&[file.clone(), locked.path().to_path_buf()]).unwrap_err();

        let message = error.to_string();
        assert!(message.contains(&file.display().to_string()), "{message}");
        assert!(message.contains(&locked.path().display().to_string()), "{message}");
        assert!(message.contains("not a directory"), "{message}");
        // "not writable" for an ordinary process, "no write bits set" under
        // `CAP_DAC_OVERRIDE`; both name the same refusal.
        assert!(
            message.contains("not writable") || message.contains("no write bits set"),
            "{message}"
        );
        chmod(locked.path(), 0o700);
    }

    /// The search list is a different question from the write destination. A cache that
    /// cannot receive a download is still read, so a package already in it is never fetched
    /// again.
    #[test]
    fn the_search_list_keeps_every_directory_when_one_is_not_writable() {
        let locked = tempfile::tempdir().unwrap();
        write(locked.path(), PACKAGE, b"cached");
        chmod(locked.path(), 0o500);
        let good = tempfile::tempdir().unwrap();

        let source = DownloadingSource::new(
            [locked.path().to_path_buf(), good.path().to_path_buf()],
            HashMap::new(),
            piko_net::Cancel::default(),
            piko_net::Concurrency::new(1),
            |_| {},
        )
        .unwrap();

        assert_eq!(source.download_dir().path(), good.path());
        assert_eq!(source.cache.directories().len(), 2);
        // The unwritable directory is still searched, so the cached package is found there.
        assert_eq!(source.locate(&file_name()).unwrap().path(), locked.path().join(PACKAGE));
        chmod(locked.path(), 0o700);
    }

    #[test]
    fn an_empty_cache_directory_list_is_still_refused() {
        let error = CacheDirSource::new([]).unwrap_err();

        assert!(matches!(error, Error::UnusableSource { .. }), "{error}");
    }

    fn file_name() -> PackageFileName {
        PackageFileName::from_str(PACKAGE).unwrap()
    }

    fn write(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn finds_a_cached_package() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), PACKAGE, b"not really a package");

        let source = CacheDirSource::new([dir.path().to_path_buf()]).unwrap();
        let location = source.locate(&file_name()).unwrap();
        assert_eq!(location.path(), path);
        assert_eq!(location.size(), 20);
        assert!(location.skipped().is_empty());
        assert!(source.contains(&file_name()));
    }

    #[test]
    fn reports_where_it_looked_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([dir.path().to_path_buf()]).unwrap();

        let err = source.locate(&file_name()).unwrap_err();
        assert!(matches!(err, Error::NotAvailable { .. }), "got {err:?}");
        assert!(err.to_string().contains(&dir.path().display().to_string()));
        assert!(!source.contains(&file_name()));
    }

    /// Cache directories are a priority list, exactly like repositories.
    #[test]
    fn searches_directories_in_order() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        write(first.path(), PACKAGE, b"first");
        write(second.path(), PACKAGE, b"second");

        let source =
            CacheDirSource::new([first.path().to_path_buf(), second.path().to_path_buf()]).unwrap();
        assert_eq!(source.locate(&file_name()).unwrap().path(), first.path().join(PACKAGE));
    }

    #[test]
    fn falls_through_to_a_later_directory() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        write(second.path(), PACKAGE, b"second");

        let source =
            CacheDirSource::new([first.path().to_path_buf(), second.path().to_path_buf()]).unwrap();
        assert_eq!(source.locate(&file_name()).unwrap().path(), second.path().join(PACKAGE));
    }

    /// A directory named like a package must not stop the search. It must also be reported, or
    /// the user sees "not found" while staring at something with the right name.
    #[test]
    fn skips_a_non_regular_candidate_and_says_so() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::create_dir(first.path().join(PACKAGE)).unwrap();
        write(second.path(), PACKAGE, b"second");

        let source =
            CacheDirSource::new([first.path().to_path_buf(), second.path().to_path_buf()]).unwrap();
        let location = source.locate(&file_name()).unwrap();
        assert_eq!(location.path(), second.path().join(PACKAGE));
        assert_eq!(
            location.skipped(),
            [Skipped { path: first.path().join(PACKAGE), reason: SkipReason::NotARegularFile }]
        );
    }

    #[test]
    fn a_non_regular_candidate_alone_is_not_found_but_is_explained() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(PACKAGE)).unwrap();

        let source = CacheDirSource::new([dir.path().to_path_buf()]).unwrap();
        let err = source.locate(&file_name()).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
    }

    /// This matches libalpm, which stats rather than lstats.
    #[cfg(unix)]
    #[test]
    fn follows_a_symlink_to_a_real_package() {
        let dir = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let target = write(store.path(), "real.pkg.tar.zst", b"payload");
        std::os::unix::fs::symlink(&target, dir.path().join(PACKAGE)).unwrap();

        let source = CacheDirSource::new([dir.path().to_path_buf()]).unwrap();
        assert_eq!(source.locate(&file_name()).unwrap().size(), 7);
    }

    /// A dangling symlink is absence, not a usable file.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_is_not_a_package() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dir.path().join("nowhere"), dir.path().join(PACKAGE)).unwrap();

        let source = CacheDirSource::new([dir.path().to_path_buf()]).unwrap();
        assert!(source.locate(&file_name()).is_err());
    }

    /// An empty source would report every package missing with an error naming nothing.
    #[test]
    fn refuses_to_be_built_with_no_directories() {
        let err = CacheDirSource::new(Vec::new()).unwrap_err();
        assert!(matches!(err, Error::UnusableSource { .. }), "got {err:?}");
    }

    #[test]
    fn open_reads_the_located_file() {
        use std::io::Read as _;

        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), PACKAGE, b"payload");
        let source = CacheDirSource::new([dir.path().to_path_buf()]).unwrap();
        let location = source.locate(&file_name()).unwrap();

        let mut contents = Vec::new();
        open(&location).unwrap().read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"payload");
    }

    /// The file can be swapped between locating and opening. The open must not trust the
    /// earlier check.
    #[test]
    fn open_rechecks_the_file_type() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), PACKAGE, b"payload");
        let source = CacheDirSource::new([dir.path().to_path_buf()]).unwrap();
        let location = source.locate(&file_name()).unwrap();

        std::fs::remove_file(location.path()).unwrap();
        std::fs::create_dir(location.path()).unwrap();
        assert!(open(&location).is_err());
    }

    /// The trait is object-safe and thread-safe, both of which the engine above relies on.
    #[test]
    fn the_trait_is_usable_as_an_object() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), PACKAGE, b"payload");
        let source: Box<dyn PackageSource> =
            Box::new(CacheDirSource::new([dir.path().to_path_buf()]).unwrap());
        assert!(source.contains(&file_name()));

        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CacheDirSource>();
    }

    /// Like `conditional.rs`/`package.rs` in `piko-net`, this is the crudest HTTP server that
    /// works: one response per connection.
    fn serve(response: Vec<u8>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read as _, Write as _};
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    fn ok_response(body: &[u8]) -> Vec<u8> {
        let mut out =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn target(url: String) -> DownloadTarget {
        DownloadTarget {
            size: 0,
            repo_name: "core".to_owned(),
            servers: vec![url],
            policy: piko_sig::Policy::for_package(piko_db::config::SigLevel::default()),
        }
    }

    /// A cache hit is served exactly as `CacheDirSource` would — no download attempted, no
    /// server needed at all.
    #[test]
    fn a_cache_hit_is_served_without_downloading() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), PACKAGE, b"already cached");

        let source = DownloadingSource::new(
            [dir.path().to_path_buf()],
            HashMap::new(),
            piko_net::Cancel::new(),
            piko_net::Concurrency::default(),
            |_| {},
        )
        .unwrap();
        let location = source.locate(&file_name()).unwrap();
        assert_eq!(std::fs::read(location.path()).unwrap(), b"already cached");
    }

    /// A miss with a matching download target is fetched and lands in the first configured
    /// cache directory — pacman's own convention for where a download goes.
    #[test]
    fn a_miss_downloads_into_the_first_cache_directory() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let url = serve(ok_response(b"downloaded just now"));

        let targets = HashMap::from([(PACKAGE.to_owned(), target(url))]);
        let source = DownloadingSource::new(
            [first.path().to_path_buf(), second.path().to_path_buf()],
            targets,
            piko_net::Cancel::new(),
            piko_net::Concurrency::default(),
            |_| {},
        )
        .unwrap();

        let location = source.locate(&file_name()).unwrap();
        assert_eq!(location.path(), first.path().join(PACKAGE));
        assert_eq!(std::fs::read(location.path()).unwrap(), b"downloaded just now");
        assert!(!second.path().join(PACKAGE).exists());
    }

    /// `prefetch` fills the cache, so the `locate` that follows never touches the network.
    /// This is why the serial verification loops stay unchanged.
    #[test]
    fn a_prefetch_fills_the_cache_so_locate_never_downloads() {
        let dir = tempfile::tempdir().unwrap();
        let url = serve(ok_response(b"fetched ahead of time"));

        let targets = HashMap::from([(PACKAGE.to_owned(), target(url))]);
        let source = DownloadingSource::new(
            [dir.path().to_path_buf()],
            targets,
            piko_net::Cancel::new(),
            piko_net::Concurrency::new(4),
            |_| {},
        )
        .unwrap();

        source.prefetch(&[file_name()]).unwrap();
        assert!(dir.path().join(PACKAGE).exists(), "prefetch should have downloaded it");

        // The one-response server is spent, so a `locate` that downloaded would fail here.
        let location = source.locate(&file_name()).unwrap();
        assert_eq!(std::fs::read(location.path()).unwrap(), b"fetched ahead of time");
    }

    /// A prefetch that could not fetch a package is **not** an error. The package is simply
    /// still missing, and the `locate` that follows reports it as it always did. Two places
    /// that can refuse a package eventually disagree with each other.
    #[test]
    fn a_prefetch_failure_is_left_for_locate_to_report() {
        let dir = tempfile::tempdir().unwrap();
        // A port with nothing behind it: every attempt fails, immediately.
        let dead = "http://127.0.0.1:1".to_owned();
        let targets = HashMap::from([(PACKAGE.to_owned(), target(dead))]);
        let source = DownloadingSource::new(
            [dir.path().to_path_buf()],
            targets,
            piko_net::Cancel::new(),
            piko_net::Concurrency::new(4),
            |_| {},
        )
        .unwrap();

        // Not an error: the package is still missing, and `locate` is what says so.
        source.prefetch(&[file_name()]).unwrap();
        let error = source.locate(&file_name()).unwrap_err();
        assert!(matches!(error, Error::Download(_)), "{error:?}");
    }

    /// Cancellation is the one thing a prefetch does report. It is not a fact about any single
    /// package, and letting `locate` rediscover it one file at a time would be pointless.
    #[test]
    fn a_cancelled_prefetch_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let url = serve(ok_response(b"never arrives"));
        let cancel = piko_net::Cancel::new();
        cancel.request();

        let targets = HashMap::from([(PACKAGE.to_owned(), target(url))]);
        let source = DownloadingSource::new(
            [dir.path().to_path_buf()],
            targets,
            cancel,
            piko_net::Concurrency::new(4),
            |_| {},
        )
        .unwrap();

        let error = source.prefetch(&[file_name()]).unwrap_err();
        assert!(matches!(error, Error::Download(piko_net::Error::Cancelled)), "{error:?}");
    }

    /// A name with no download target is skipped rather than reported. `locate` says what is
    /// wrong with it far better, and avoiding that duplicate report is why `prefetch` exists.
    #[test]
    fn a_prefetch_ignores_a_name_it_has_no_target_for() {
        let dir = tempfile::tempdir().unwrap();
        let source = DownloadingSource::new(
            [dir.path().to_path_buf()],
            HashMap::new(),
            piko_net::Cancel::new(),
            piko_net::Concurrency::new(4),
            |_| {},
        )
        .unwrap();
        // An unknown name is skipped, not reported.
        source.prefetch(&[file_name()]).unwrap();
        assert!(matches!(source.locate(&file_name()), Err(Error::NotAvailable { .. })));
    }

    /// A repeated name must not reach the batch. The batch refuses a duplicate destination
    /// outright, because two workers would otherwise race for one atomic-write temporary.
    #[test]
    fn a_prefetch_deduplicates_before_it_reaches_the_batch() {
        let dir = tempfile::tempdir().unwrap();
        let url = serve(ok_response(b"downloaded once"));
        let targets = HashMap::from([(PACKAGE.to_owned(), target(url))]);
        let source = DownloadingSource::new(
            [dir.path().to_path_buf()],
            targets,
            piko_net::Cancel::new(),
            piko_net::Concurrency::new(4),
            |_| {},
        )
        .unwrap();

        source.prefetch(&[file_name(), file_name(), file_name()]).unwrap();
        assert_eq!(std::fs::read(dir.path().join(PACKAGE)).unwrap(), b"downloaded once");
    }

    /// A miss with no matching download target reports the same `NotAvailable` a pure
    /// `CacheDirSource` would, rather than pretending a download was possible.
    #[test]
    fn a_miss_with_no_target_reports_not_available() {
        let dir = tempfile::tempdir().unwrap();
        let source = DownloadingSource::new(
            [dir.path().to_path_buf()],
            HashMap::new(),
            piko_net::Cancel::new(),
            piko_net::Concurrency::default(),
            |_| {},
        )
        .unwrap();

        let error = source.locate(&file_name()).unwrap_err();
        assert!(matches!(error, Error::NotAvailable { .. }), "{error:?}");
    }

    /// Asking whether a package is on hand must not put it there.
    ///
    /// The inherited `PackageSource::contains` is `locate(...).is_ok()`. This source's `locate`
    /// downloads a miss, so without the override this would return `true` *and* leave the
    /// package in the cache directory. Both halves are asserted: the answer, and the absence of
    /// the file a wrong answer would have created.
    #[test]
    fn asking_a_downloading_source_what_it_has_downloads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let url = serve(ok_response(b"downloaded just now"));

        let targets = HashMap::from([(PACKAGE.to_owned(), target(url))]);
        let source = DownloadingSource::new(
            [dir.path().to_path_buf()],
            targets,
            piko_net::Cancel::new(),
            piko_net::Concurrency::default(),
            |_| {},
        )
        .unwrap();

        assert!(!source.contains(&file_name()));
        assert!(!dir.path().join(PACKAGE).exists());

        // The download itself still works: the miss above was answered from the cache, not by
        // a server that was somehow unreachable.
        assert!(source.locate(&file_name()).is_ok());
        assert!(source.contains(&file_name()));
    }

    /// The trait is object-safe and thread-safe, both of which the engine above relies on.
    #[test]
    fn downloading_source_is_usable_as_an_object() {
        let dir = tempfile::tempdir().unwrap();
        let source: Box<dyn PackageSource> = Box::new(
            DownloadingSource::new(
                [dir.path().to_path_buf()],
                HashMap::new(),
                piko_net::Cancel::new(),
                piko_net::Concurrency::default(),
                |_| {},
            )
            .unwrap(),
        );
        assert!(!source.contains(&file_name()));

        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DownloadingSource>();
    }
}
