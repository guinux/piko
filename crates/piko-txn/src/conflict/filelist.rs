//! A package's file list, and the three set operations conflict detection is built from.
//!
//! This module is transcribed from `filelist.c`, with one deliberate difference in
//! [`FileList::intersection`].
//!
//! # Two comparisons, not one
//!
//! libalpm compares paths two different ways, and the difference is load-bearing:
//!
//! - **exactly**, byte for byte (`_alpm_files_cmp`, a plain `strcmp`) — used by
//!   `alpm_filelist_contains` and by `_alpm_filelist_difference`;
//! - **ignoring a trailing slash** (`_alpm_filelist_pathcmp`) — used only by
//!   `_alpm_filelist_intersection`.
//!
//! The second comparison is what lets the intersection see that one package ships
//! `usr/lib/foo` as a file while another ships `usr/lib/foo/` as a directory. That is a real
//! conflict, and an exact comparison would miss it entirely. Everywhere else the exact
//! comparison is the right one, because the question there is "does this package own
//! precisely this entry".
//!
//! This module keeps both comparisons, under names that say which is which.

use std::collections::HashMap;

/// A package's file list, sorted, as `%FILES%` and a package archive both spell it.
///
/// Directories carry a trailing `/`; files do not. That convention comes from the archive and
/// pacman preserves it into the database, so it is what both sides of a comparison see.
#[derive(Clone, Debug, Default)]
pub struct FileList {
    /// Sorted by bytes, matching `_alpm_filelist_sort`.
    entries: Box<[Box<str>]>,
}

/// A path with one trailing `/` removed, which is how [`pathcmp`] compares.
///
/// Exactly one slash, not all of them: `_alpm_filelist_pathcmp` advances a single character
/// past the end of the shorter string, so `a` equals `a/` but not `a//`. Real archives never
/// spell a doubled slash, so this detail only matters for staying honest about what is
/// transcribed.
#[must_use]
pub fn strip_dir(path: &str) -> &str {
    path.strip_suffix('/').unwrap_or(path)
}

/// Whether `path` names a directory, by the trailing-slash convention.
#[must_use]
pub fn is_directory(path: &str) -> bool {
    path.ends_with('/')
}

/// Compares two paths ignoring a trailing slash, as `_alpm_filelist_pathcmp` does.
#[must_use]
pub fn pathcmp(left: &str, right: &str) -> std::cmp::Ordering {
    strip_dir(left).cmp(strip_dir(right))
}

impl FileList {
    /// Builds a list from `paths`, sorting it.
    ///
    /// This sorts rather than requiring sorted input, matching libalpm's `_alpm_filelist_sort`.
    /// A `%FILES%` section written by another tool need not be ordered, and every operation
    /// below is a merge that assumes it is.
    pub fn new<S: Into<Box<str>>>(paths: impl IntoIterator<Item = S>) -> Self {
        let mut entries: Vec<Box<str>> = paths.into_iter().map(Into::into).collect();
        entries.sort_unstable();
        Self { entries: entries.into_boxed_slice() }
    }

    /// Every entry, in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(AsRef::as_ref)
    }

    /// How many entries the list has.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the list holds exactly `path`, trailing slash and all.
    ///
    /// This uses the exact comparison, matching `alpm_filelist_contains`. A caller asking "is
    /// `etc/foo` one of this package's files" must not get a yes from an entry `etc/foo/`,
    /// which is a different object.
    #[must_use]
    pub fn contains(&self, path: &str) -> bool {
        self.entries.binary_search_by(|entry| (**entry).cmp(path)).is_ok()
    }

    /// Entries of `self` that are not in `other`, compared exactly, in sorted order.
    ///
    /// This is `_alpm_filelist_difference`. It reduces an upgrade to the paths that are new,
    /// which is why the comparison must be exact: a path present in both versions is not new.
    ///
    /// The result stays sorted, and the caller depends on that. The filesystem check walks it
    /// relying on a directory's contents following the directory itself.
    #[must_use]
    pub fn difference<'a>(&'a self, other: &Self) -> Vec<&'a str> {
        self.iter().filter(|entry| !other.contains(entry)).collect()
    }

    /// Entries present in both lists, ignoring a trailing slash, except where both are
    /// directories.
    ///
    /// Two packages owning the same directory is normal and not a conflict. Anything else —
    /// file against file, or file against directory — is a conflict.
    ///
    /// # Difference from libalpm
    ///
    /// `_alpm_filelist_intersection` merges the two lists in one pass, comparing with
    /// `pathcmp` while the lists are sorted by `strcmp`. Those two orders disagree, so the
    /// merge can step past a matching pair and miss it. The test
    /// `the_libalpm_merge_can_step_past_a_conflict` in this module demonstrates a concrete
    /// case. piko matches on the stripped path instead, so the order entries arrive in cannot
    /// hide a pair.
    #[must_use]
    pub fn intersection<'a>(&'a self, other: &Self) -> Vec<&'a str> {
        // Whether `other` holds a non-directory under this stripped path. A pair is skipped
        // only when both sides are directories, so one non-directory on the other side makes
        // every match a conflict.
        let mut other_has_file: HashMap<&str, bool> = HashMap::new();
        for entry in other.iter() {
            let slot = other_has_file.entry(strip_dir(entry)).or_insert(false);
            *slot = *slot || !is_directory(entry);
        }

        self.iter()
            .filter(|entry| match other_has_file.get(strip_dir(entry)) {
                Some(other_is_file) => !is_directory(entry) || *other_is_file,
                None => false,
            })
            .collect()
    }
}

impl<S: Into<Box<str>>> FromIterator<S> for FileList {
    fn from_iter<T: IntoIterator<Item = S>>(iter: T) -> Self {
        Self::new(iter)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn list(paths: &[&str]) -> FileList {
        FileList::new(paths.iter().copied())
    }

    #[test]
    fn a_list_is_sorted_however_it_is_built() {
        let sorted = list(&["usr/bin/z", "usr/bin/a", "etc/foo"]);
        assert_eq!(sorted.iter().collect::<Vec<_>>(), ["etc/foo", "usr/bin/a", "usr/bin/z"]);
    }

    /// `contains` is exact. A directory entry does not answer for the file of the same name.
    #[test]
    fn contains_does_not_confuse_a_file_with_a_directory() {
        let files = list(&["usr/lib/foo/"]);
        assert!(files.contains("usr/lib/foo/"));
        assert!(!files.contains("usr/lib/foo"));
    }

    #[test]
    fn difference_keeps_only_what_is_new_and_keeps_it_sorted() {
        let new = list(&["usr/bin/a", "usr/bin/b", "usr/bin/c"]);
        let old = list(&["usr/bin/b"]);
        assert_eq!(new.difference(&old), ["usr/bin/a", "usr/bin/c"]);
    }

    /// `difference` uses exact comparison. An upgrade that turns a file into a directory must
    /// report the directory as new, because it is a different object on disk.
    #[test]
    fn difference_treats_a_file_and_a_directory_of_one_name_as_distinct() {
        let new = list(&["usr/lib/foo/"]);
        let old = list(&["usr/lib/foo"]);
        assert_eq!(new.difference(&old), ["usr/lib/foo/"]);
    }

    #[test]
    fn two_packages_shipping_the_same_file_intersect() {
        let a = list(&["usr/bin/foo"]);
        let b = list(&["usr/bin/foo"]);
        assert_eq!(a.intersection(&b), ["usr/bin/foo"]);
    }

    /// The ordinary case that must not be reported: every package owns `usr/bin/`.
    #[test]
    fn two_packages_sharing_a_directory_do_not_intersect() {
        let a = list(&["usr/", "usr/bin/", "usr/bin/a"]);
        let b = list(&["usr/", "usr/bin/", "usr/bin/b"]);
        assert!(a.intersection(&b).is_empty());
    }

    /// The case the trailing-slash-insensitive comparison exists for.
    #[test]
    fn a_file_and_a_directory_of_the_same_name_intersect() {
        let a = list(&["usr/lib/foo"]);
        let b = list(&["usr/lib/foo/", "usr/lib/foo/bar"]);
        assert_eq!(a.intersection(&b), ["usr/lib/foo"]);
        // And from the other side, since the caller checks only one direction per pair.
        assert_eq!(b.intersection(&a), ["usr/lib/foo/"]);
    }

    /// libalpm's own merge, transcribed exactly. This demonstrates the divergence below
    /// against the real algorithm, not against a description of it.
    fn libalpm_intersection<'a>(left: &'a FileList, right: &FileList) -> Vec<&'a str> {
        let (a, b) = (left.entries.as_ref(), right.entries.as_ref());
        let (mut i, mut j) = (0_usize, 0_usize);
        let mut out = Vec::new();
        while i < a.len() && j < b.len() {
            match pathcmp(&a[i], &b[j]) {
                std::cmp::Ordering::Less => i = i.saturating_add(1),
                std::cmp::Ordering::Greater => j = j.saturating_add(1),
                std::cmp::Ordering::Equal => {
                    if !is_directory(&a[i]) || !is_directory(&b[j]) {
                        out.push(a[i].as_ref());
                    }
                    i = i.saturating_add(1);
                    j = j.saturating_add(1);
                }
            }
        }
        out
    }

    /// The reason `intersection` is not a merge.
    ///
    /// The lists are sorted by bytes, where `usr/lib/foo` < `usr/lib/foo!` < `usr/lib/foo/`
    /// (`!` is 0x21, `/` is 0x2f, and the terminator sorts before both). The merge compares
    /// with `pathcmp`, which calls the first and the third equal. Meeting `usr/lib/foo!` in
    /// between advances the left cursor past `usr/lib/foo`, so the file-against-directory
    /// conflict is never reported.
    ///
    /// This test asserts both halves — that libalpm misses the conflict and that piko does
    /// not — so it fails if either behavior changes.
    #[test]
    fn the_libalpm_merge_can_step_past_a_conflict() {
        let a = list(&["usr/lib/foo"]);
        let b = list(&["usr/lib/foo!", "usr/lib/foo/"]);

        assert_eq!(b.iter().collect::<Vec<_>>(), ["usr/lib/foo!", "usr/lib/foo/"]);
        assert!(
            libalpm_intersection(&a, &b).is_empty(),
            "the premise of §53 no longer holds: the merge found the pair"
        );
        assert_eq!(a.intersection(&b), ["usr/lib/foo"]);
    }

    /// Where the two orders agree — which covers every ordinary file list — the two
    /// intersections must not differ.
    #[test]
    fn the_two_intersections_agree_on_ordinary_lists() {
        let a = list(&["etc/x", "usr/", "usr/bin/", "usr/bin/a", "usr/share/doc/"]);
        let b = list(&["etc/x", "usr/", "usr/bin/", "usr/bin/b", "usr/share/doc"]);
        assert_eq!(a.intersection(&b), libalpm_intersection(&a, &b));
        assert_eq!(a.intersection(&b), ["etc/x", "usr/share/doc/"]);
    }

    #[test]
    fn an_empty_list_intersects_with_nothing() {
        let empty = FileList::default();
        assert!(empty.intersection(&list(&["usr/bin/a"])).is_empty());
        assert!(list(&["usr/bin/a"]).intersection(&empty).is_empty());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn pathcmp_ignores_exactly_one_trailing_slash() {
        assert_eq!(pathcmp("a", "a/"), std::cmp::Ordering::Equal);
        assert_eq!(pathcmp("a/", "a"), std::cmp::Ordering::Equal);
        assert_eq!(pathcmp("a", "a//"), std::cmp::Ordering::Less);
        assert_eq!(pathcmp("a/b", "a"), std::cmp::Ordering::Greater);
    }
}
