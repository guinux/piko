//! A compact store for every package's file list in a repository database.
//!
//! `RepoFilesV1` (via [`alpm_repo_db::files::RepoFilesV1`]) hands back a `Vec<PathBuf>` per
//! package. A full `.files` archive holds millions of paths — 7 639 616 measured on the real
//! `extra` repository, 509 MiB of path bytes. Storing one `Vec<PathBuf>` per package would
//! cost roughly 800 MiB for that repository, once allocator overhead is counted. Concatenating
//! every path into one `String` and indexing into it with `u32` offsets measures at 538 MiB
//! for the same data: smaller, with far fewer allocations.
//!
//! # Why the index is keyed by name, not shared with the package list positionally
//!
//! `<repo>.db` and `<repo>.files` are refreshed independently by pacman (`-Sy` versus `-Fy`).
//! They routinely describe different builds of the same package — measured at 12 of `core`'s
//! 296 packages disagreeing on this machine, right now. A positional index would silently
//! serve one package's file list under another package's name whenever the two archives
//! drift, with no error at all. Keying by [`Name`] and checking the [`FullVersion`] at lookup
//! time turns that into [`Error::FilesVersionSkew`]. This is the whole reason this module
//! exists in this shape, rather than as a plain `Vec<Vec<PathBuf>>`.

use std::{collections::HashMap, ops::Range, path::Path};

use alpm_types::{FullVersion, Name};

use crate::{
    error::{Error, Result},
    limits::Limit,
};

/// Every path for every package, concatenated, indexed by `u32` byte offsets.
///
/// Built once per repository database — see [`crate::repo::RepoDatabase`] — and read many
/// times. [`Self::insert`] is the only way to grow it; nothing after construction removes or
/// rewrites an entry.
#[derive(Debug, Default)]
pub(crate) struct FilesArena {
    /// Every path's bytes, back to back, with no separators.
    data: String,
    /// `starts[i]..ends[i]` is the byte range of the `i`-th path in `data`.
    starts: Vec<u32>,
    /// See `starts`.
    ends: Vec<u32>,
    /// Package name to (its version, the range of path indices belonging to it).
    index: HashMap<Name, (FullVersion, Range<u32>)>,
}

/// What [`FilesArena::insert`] did with the package it was handed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Inserted {
    /// The package was appended; it is the only one under that name.
    Yes,
    /// A package of that name was already present, so this one was discarded. It carries the
    /// version of the entry that was **kept**. A diagnostic needs to name that version; the
    /// caller only knows the one it just tried to insert.
    Duplicate {
        /// The version of the entry already in the arena.
        kept: FullVersion,
    },
}

impl FilesArena {
    /// Creates an empty arena.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Appends one package's paths, keyed by `name`.
    ///
    /// `name` can already be present: the same package name appearing twice in one `.files`
    /// archive. The spec's uniqueness guarantee rules this out, but a corrupt archive could
    /// still contain it. In that case the existing entry is kept and [`Inserted::Duplicate`]
    /// is returned, carrying the kept version so the caller can record a diagnostic naming
    /// both sides. This is a same-archive duplicate, not the cross-archive version skew
    /// [`Self::file_list`] detects.
    ///
    /// # Errors
    ///
    /// [`Error::LimitExceeded`] if appending would exceed `max_bytes`, or would need more
    /// than [`u32::MAX`] path entries or bytes to address. The arena is left exactly as it was
    /// before the call: a package is appended whole or not at all, so no path bytes are ever
    /// left behind with no index entry pointing at them.
    pub(crate) fn insert(
        &mut self,
        archive_path: &Path,
        name: Name,
        version: FullVersion,
        paths: &[std::path::PathBuf],
        max_bytes: u64,
    ) -> Result<Inserted> {
        if let Some((kept, _)) = self.index.get(&name) {
            return Ok(Inserted::Duplicate { kept: kept.clone() });
        }

        let range_start = self.path_count_as_u32(archive_path, max_bytes)?;

        for path in paths {
            if let Err(error) = self.push_path(archive_path, path, max_bytes) {
                // Roll back the partial append. Every caller currently aborts the whole open
                // on this error, so nothing would observe the debris — but the type's
                // invariant is that `data` holds only bytes some index entry addresses, and
                // an invariant that only holds because no one looks is not one.
                self.truncate_to(range_start);
                return Err(error);
            }
        }

        let range_end = self.path_count_as_u32(archive_path, max_bytes)?;
        self.index.insert(name, (version, range_start..range_end));
        Ok(Inserted::Yes)
    }

    /// Discards every path from index `count` onwards, along with its bytes.
    fn truncate_to(&mut self, count: u32) {
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        // The byte offset to cut `data` at is where the first discarded path started; if
        // nothing is being discarded, `data` is already the right length.
        let cut = self
            .starts
            .get(count)
            .copied()
            .map(|start| usize::try_from(start).unwrap_or(usize::MAX));
        self.starts.truncate(count);
        self.ends.truncate(count);
        if let Some(cut) = cut
            && self.data.is_char_boundary(cut)
        {
            self.data.truncate(cut);
        }
    }

    /// Appends one path's bytes and records its offsets.
    fn push_path(
        &mut self,
        archive_path: &Path,
        path: &std::path::Path,
        max_bytes: u64,
    ) -> Result<()> {
        // Every path here was parsed by `RepoFilesV1::from_str` out of a UTF-8 `&str`, so
        // `to_str` cannot fail in practice. `to_string_lossy` is used anyway rather than an
        // `unwrap`: if that invariant is ever violated, degrading to replacement characters
        // is safer than a panic or a fabricated error variant with no real source.
        let text = path.to_string_lossy();

        let start = self.byte_len_as_u32(archive_path, max_bytes)?;

        let new_len = self
            .data
            .len()
            .checked_add(text.len())
            .ok_or_else(|| limit_exceeded(archive_path, max_bytes))?;
        if new_len as u64 > max_bytes {
            return Err(limit_exceeded(archive_path, max_bytes));
        }
        let end = u32::try_from(new_len).map_err(|_| limit_exceeded(archive_path, max_bytes))?;

        self.data.push_str(&text);
        self.starts.push(start);
        self.ends.push(end);
        Ok(())
    }

    fn byte_len_as_u32(&self, archive_path: &Path, max_bytes: u64) -> Result<u32> {
        u32::try_from(self.data.len()).map_err(|_| limit_exceeded(archive_path, max_bytes))
    }

    fn path_count_as_u32(&self, archive_path: &Path, max_bytes: u64) -> Result<u32> {
        u32::try_from(self.starts.len()).map_err(|_| limit_exceeded(archive_path, max_bytes))
    }

    /// Looks up the file list for a specific `name` at a specific `version`.
    ///
    /// # Errors
    ///
    /// - [`Error::FilesMissingForPackage`] if `name` has no entry in this arena at all.
    /// - [`Error::FilesVersionSkew`] if `name` is present but at a different version — the
    ///   `.db`/`.files` drift documented on this type.
    pub(crate) fn file_list(&self, name: &Name, version: &FullVersion) -> Result<PathIter<'_>> {
        match self.index.get(name) {
            None => Err(Error::FilesMissingForPackage { name: name.clone() }),
            Some((files_version, range)) if files_version == version => {
                Ok(self.iter_range(range.clone()))
            }
            Some((files_version, _)) => Err(Error::FilesVersionSkew {
                name: name.clone(),
                db_version: Box::new(version.clone()),
                files_version: Box::new(files_version.clone()),
            }),
        }
    }

    fn iter_range(&self, range: Range<u32>) -> PathIter<'_> {
        let start = usize::try_from(range.start).unwrap_or(usize::MAX);
        let end = usize::try_from(range.end).unwrap_or(usize::MAX);
        PathIter {
            data: &self.data,
            starts: self.starts.get(start..end).unwrap_or(&[]).iter(),
            ends: self.ends.get(start..end).unwrap_or(&[]).iter(),
        }
    }
}

/// Builds a [`Error::LimitExceeded`] against [`Limit::RepoInflated`].
fn limit_exceeded(archive_path: &Path, max_bytes: u64) -> Error {
    Error::LimitExceeded {
        path: archive_path.to_path_buf(),
        limit: Limit::RepoInflated,
        max: max_bytes,
    }
}

/// Iterates over the paths of one package's file list.
#[derive(Debug)]
pub struct PathIter<'a> {
    data: &'a str,
    starts: std::slice::Iter<'a, u32>,
    ends: std::slice::Iter<'a, u32>,
}

impl<'a> Iterator for PathIter<'a> {
    type Item = &'a Path;

    fn next(&mut self) -> Option<Self::Item> {
        let start = *self.starts.next()?;
        let end = *self.ends.next()?;
        let start = usize::try_from(start).ok()?;
        let end = usize::try_from(end).ok()?;
        self.data.get(start..end).map(Path::new)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.starts.size_hint()
    }
}

impl ExactSizeIterator for PathIter<'_> {
    fn len(&self) -> usize {
        self.starts.len()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::{path::PathBuf, str::FromStr as _};

    use super::*;

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    fn version(s: &str) -> FullVersion {
        FullVersion::from_str(s).unwrap()
    }

    fn paths(items: &[&str]) -> Vec<PathBuf> {
        items.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn inserts_and_looks_up_a_package() {
        let mut arena = FilesArena::new();
        arena
            .insert(
                Path::new("extra.files"),
                name("foo"),
                version("1.0.0-1"),
                &paths(&["usr/", "usr/bin/", "usr/bin/foo"]),
                1024,
            )
            .unwrap();

        let found: Vec<_> = arena.file_list(&name("foo"), &version("1.0.0-1")).unwrap().collect();
        assert_eq!(found, [Path::new("usr/"), Path::new("usr/bin/"), Path::new("usr/bin/foo")]);
    }

    #[test]
    fn an_absent_package_is_missing_not_empty() {
        let arena = FilesArena::new();
        let err = arena.file_list(&name("absent"), &version("1.0.0-1")).unwrap_err();
        assert!(matches!(err, Error::FilesMissingForPackage { .. }), "got {err:?}");
    }

    /// The property this whole module exists for: a `.db`/`.files` disagreement about which
    /// build is current must be an error. It must never produce a silently wrong file list.
    #[test]
    fn a_different_version_is_a_skew_error_not_a_silent_substitution() {
        let mut arena = FilesArena::new();
        arena
            .insert(
                Path::new("core.files"),
                name("linux-lts"),
                version("6.18.42-1"),
                &paths(&["boot/vmlinuz"]),
                1024,
            )
            .unwrap();

        let err = arena.file_list(&name("linux-lts"), &version("6.18.43-1")).unwrap_err();
        assert!(
            matches!(
                &err,
                Error::FilesVersionSkew { db_version, files_version, .. }
                    if db_version.to_string() == "6.18.43-1" && files_version.to_string() == "6.18.42-1"
            ),
            "got {err:?}"
        );
    }

    /// Two packages' path ranges must never bleed into each other.
    #[test]
    fn multiple_packages_do_not_overlap() {
        let mut arena = FilesArena::new();
        arena
            .insert(Path::new("x"), name("foo"), version("1-1"), &paths(&["a", "b"]), 1024)
            .unwrap();
        arena.insert(Path::new("x"), name("bar"), version("1-1"), &paths(&["c"]), 1024).unwrap();

        let foo: Vec<_> = arena.file_list(&name("foo"), &version("1-1")).unwrap().collect();
        let bar: Vec<_> = arena.file_list(&name("bar"), &version("1-1")).unwrap().collect();
        assert_eq!(foo, [Path::new("a"), Path::new("b")]);
        assert_eq!(bar, [Path::new("c")]);
    }

    #[test]
    fn a_package_with_no_paths_is_an_empty_iterator() {
        let mut arena = FilesArena::new();
        arena.insert(Path::new("x"), name("foo"), version("1-1"), &[], 1024).unwrap();

        let found = arena.file_list(&name("foo"), &version("1-1")).unwrap();
        assert_eq!(found.len(), 0);
        assert_eq!(found.count(), 0);
    }

    /// A duplicate name within one archive keeps the first entry and reports it, mirroring
    /// `LocalDatabase`'s duplicate-entry handling.
    #[test]
    fn a_duplicate_name_keeps_the_first_and_signals_it() {
        let mut arena = FilesArena::new();
        let first = arena
            .insert(Path::new("x"), name("foo"), version("1-1"), &paths(&["a"]), 1024)
            .unwrap();
        let second = arena
            .insert(Path::new("x"), name("foo"), version("2-1"), &paths(&["b"]), 1024)
            .unwrap();

        assert_eq!(first, Inserted::Yes, "the first insert must succeed");
        assert_eq!(
            second,
            Inserted::Duplicate { kept: version("1-1") },
            "the second must be reported as a duplicate naming the version that was kept, \
             not silently override"
        );

        let found: Vec<_> = arena.file_list(&name("foo"), &version("1-1")).unwrap().collect();
        assert_eq!(found, [Path::new("a")], "the first entry must be the one kept");
    }

    /// The duplicate report must name the entry that **won**, not the one that was discarded.
    /// The caller only knows the discarded one — that is why `kept` is returned at all.
    #[test]
    fn a_duplicate_reports_the_kept_version_not_the_discarded_one() {
        let mut arena = FilesArena::new();
        arena
            .insert(Path::new("x"), name("foo"), version("1.0.0-1"), &paths(&["a"]), 1024)
            .unwrap();

        let second = arena
            .insert(Path::new("x"), name("foo"), version("2.0.0-1"), &paths(&["b"]), 1024)
            .unwrap();

        let Inserted::Duplicate { kept } = second else {
            panic!("expected a duplicate, got {second:?}")
        };
        assert_eq!(kept.to_string(), "1.0.0-1");
    }

    /// A package is appended whole or not at all. Tripping the byte limit part-way through
    /// must not leave path bytes behind that no index entry addresses.
    #[test]
    fn a_partial_append_is_rolled_back_when_the_limit_trips() {
        let mut arena = FilesArena::new();
        arena.insert(Path::new("x"), name("first"), version("1-1"), &paths(&["aaaa"]), 64).unwrap();

        // "bbbb" fits, the 100-byte path that follows does not — so the whole of `second` is
        // discarded, "bbbb" included.
        let huge = "x".repeat(100);
        let err = arena
            .insert(Path::new("x"), name("second"), version("1-1"), &paths(&["bbbb", &huge]), 64)
            .unwrap_err();
        assert!(matches!(&err, Error::LimitExceeded { .. }), "got {err:?}");

        assert_eq!(arena.data, "aaaa", "the rejected package's bytes must be gone");
        assert_eq!(arena.starts.len(), 1);
        assert_eq!(arena.ends.len(), 1);

        // The arena must still be usable, and a later insert must land at the right offset.
        arena.insert(Path::new("x"), name("third"), version("1-1"), &paths(&["cccc"]), 64).unwrap();
        let first: Vec<_> = arena.file_list(&name("first"), &version("1-1")).unwrap().collect();
        let third: Vec<_> = arena.file_list(&name("third"), &version("1-1")).unwrap().collect();
        assert_eq!(first, [Path::new("aaaa")]);
        assert_eq!(third, [Path::new("cccc")]);
    }

    /// The reason this module exists instead of `Vec<Vec<PathBuf>>`.
    #[test]
    fn refuses_to_exceed_the_configured_byte_limit() {
        let mut arena = FilesArena::new();
        let huge = "x".repeat(100);
        let err = arena
            .insert(Path::new("extra.files"), name("foo"), version("1-1"), &paths(&[&huge]), 64)
            .unwrap_err();
        assert!(
            matches!(&err, Error::LimitExceeded { limit: Limit::RepoInflated, max: 64, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn an_iterator_reports_an_accurate_length() {
        let mut arena = FilesArena::new();
        arena
            .insert(Path::new("x"), name("foo"), version("1-1"), &paths(&["a", "b", "c"]), 1024)
            .unwrap();

        let iter = arena.file_list(&name("foo"), &version("1-1")).unwrap();
        assert_eq!(iter.len(), 3);
        assert_eq!(iter.count(), 3);
    }
}
