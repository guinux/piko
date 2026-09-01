//! Whether a package file has already been downloaded.
//!
//! [`Plan::download_size`](crate::solve::Plan::download_size) answers "how many bytes will
//! cross the network", not "how big are these packages". libalpm's `compute_download_size`
//! (`sync.c:310`) sets a package's download size to zero once `_alpm_filecache_find` reports
//! it as already downloaded.
//!
//! Answering that question needs a look at the cache directories. piko-db has no business
//! doing that: it only reads databases. The code that owns cache lookup
//! (`piko_txn::CacheDirSource`, the equivalent of `_alpm_filecache_find`) lives in a crate
//! that depends on this one, so the dependency cannot run the other way.
//!
//! [`PackageCache`] is therefore a seam, not a probe. The planner stays a pure function of its
//! inputs, testable with a fake. The one implementation that touches a disk lives next to the
//! rest of the cache handling.

use alpm_types::PackageFileName;

/// Answers whether a package file is already in the download cache.
///
/// libalpm spells this seam `_alpm_filecache_exists` (`util.c:891`).
///
/// The method is named `is_cached`, not `contains`. The type that implements it,
/// `piko_txn::CacheDirSource`, already has a `PackageSource::contains`. Two identically named
/// methods on one type would force every call site to disambiguate.
pub trait PackageCache: std::fmt::Debug {
    /// Whether `file_name` can be used from the cache without downloading it.
    fn is_cached(&self, file_name: &PackageFileName) -> bool;
}

/// A cache that holds nothing: every candidate counts as a full download.
///
/// The correct default for a caller with no cache to consult: a removal plan, whose steps
/// download nothing at all, or a test that is not about download sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCache;

impl PackageCache for NoCache {
    fn is_cached(&self, _file_name: &PackageFileName) -> bool {
        false
    }
}

impl<T: PackageCache + ?Sized> PackageCache for &T {
    fn is_cached(&self, file_name: &PackageFileName) -> bool {
        (**self).is_cached(file_name)
    }
}
