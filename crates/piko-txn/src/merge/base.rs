//! The common ancestor a three-way merge needs.
//!
//! A `.pacnew` exists because an upgrade landed. The version that landed is the installed one,
//! and it is one side of the merge. The user's file descends from the version installed before
//! it. So the common ancestor is the newest cached build strictly below the installed version.
//!
//! # Why not the second-newest file in the cache
//!
//! `pacdiff` takes `pacsort --files --reverse | sed -ne '2p'`, a proxy for "the version before"
//! chosen because a shell script has no cheap way to ask which version is installed. The proxy
//! is wrong whenever the cache holds a build *newer* than the installed one, which `-Sw`, an
//! interrupted upgrade and a downgrade all produce. The merge program is then handed the
//! installed version as the ancestor. `diff3 -m mine theirs theirs` returns `mine`: a merge
//! that changed nothing and looks like it worked. The proxy is wrong again when the installed
//! build has been cleaned from the cache, where the ancestor lands two versions back.
//!
//! Versions are ordered by [`FullVersion`]'s `Ord`, which is `alpm_pkg_vercmp`. A string
//! comparison sorts `1.10-1` below `1.9-1`.
//!
//! # No fallback
//!
//! `None` means no older build is cached, which is ordinary: a cache gets cleaned. A caller
//! falls back to a two-way view. Using the installed version as the ancestor would be a merge
//! that cannot be justified.

use std::{
    io::Read as _,
    path::{Component, Path, PathBuf},
    str::FromStr as _,
};

use alpm_types::{FullVersion, Name, PackageFileName};

use crate::{
    error::{Error, IoAction, Result},
    extract::{
        archive::{Flow, PackageLimits, walk_until},
        decision::EntryKind,
    },
    hash::MAX_BACKUP_BYTES,
};

/// A cached package file a three-way ancestor can be read from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaseCandidate {
    /// Where the file sits.
    pub path: PathBuf,
    /// Its parsed name, so a caller can say which version it picked.
    pub file_name: PackageFileName,
}

/// Bounds on the cache search and on one member's extraction.
#[derive(Clone, Copy, Debug)]
pub struct BaseLimits {
    /// Largest number of entries examined per cache directory.
    pub max_cache_entries: usize,
    /// Largest member read into memory.
    pub max_member_bytes: u64,
    /// What the archive walk itself is bounded by.
    pub package: PackageLimits,
}

impl Default for BaseLimits {
    fn default() -> Self {
        Self {
            // A real cache holds a few thousand packages. This machine's holds 1872.
            max_cache_entries: 200_000,
            max_member_bytes: MAX_BACKUP_BYTES,
            package: PackageLimits::default(),
        }
    }
}

/// Picks the cached build of `package` a three-way merge should use as its ancestor.
///
/// That is the newest build strictly older than `installed`. `None` means no such build is
/// cached.
///
/// `directories` are searched in `CacheDir` order. Two directories holding the same version
/// resolve to the first one, as [`crate::source::CacheDirSource`] resolves a package file.
/// Nothing is created: this reads the directories it is given, and passes over one it cannot.
///
/// # Errors
///
/// This does not fail on a cache directory it cannot read. Such a directory contributes
/// nothing, the way an unparsable file name does. The signature returns a [`Result`] so a
/// future bound can refuse.
pub fn find_base(
    directories: &[PathBuf],
    package: &Name,
    installed: &FullVersion,
    limits: &BaseLimits,
) -> Result<Option<BaseCandidate>> {
    let mut best: Option<BaseCandidate> = None;

    for directory in directories {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        let mut seen = 0_usize;
        for entry in entries {
            seen = seen.saturating_add(1);
            if seen > limits.max_cache_entries {
                break;
            }
            let Ok(entry) = entry else {
                continue;
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            // A cache holds signatures, partial downloads and whatever else landed there. A
            // name that does not parse is noise, not a problem worth reporting.
            if name.ends_with(".sig") {
                continue;
            }
            let Ok(file_name) = PackageFileName::from_str(name) else {
                continue;
            };
            if file_name.name() != package {
                continue;
            }
            if file_name.version() >= installed {
                continue;
            }
            if !entry.metadata().is_ok_and(|metadata| metadata.is_file()) {
                continue;
            }
            // A later directory only wins by being strictly newer, so the first directory
            // keeps a version both hold.
            let better = best
                .as_ref()
                .is_none_or(|current| file_name.version() > current.file_name.version());
            if better {
                best = Some(BaseCandidate { path: entry.path(), file_name });
            }
        }
    }

    Ok(best)
}

/// Reads one member of a package archive into memory.
///
/// `member` is root-relative, the spelling `%BACKUP%` and the archive share. A leading `./` or
/// `/` is normalised away on both sides, so a producer that writes either is matched.
///
/// `Ok(None)` when the archive holds no such member, or holds it as something other than a
/// regular file. Both are ordinary: a package can stop shipping a file, or ship it as a
/// symlink.
///
/// The walk stops at the member, so a configuration file near the front of a large archive
/// costs only what precedes it.
///
/// # Errors
///
/// As [`walk_until`], plus [`Error::PackageLimitExceeded`] if the member is larger than
/// `limits.max_member_bytes`.
pub fn extract_member(
    package: &Path,
    member: &Path,
    limits: &BaseLimits,
) -> Result<Option<Vec<u8>>> {
    let wanted = self::normalise(member);
    let mut found: Option<Vec<u8>> = None;

    walk_until(package, &limits.package, |entry, contents| {
        if self::normalise(&entry.path) != wanted {
            return Ok(Flow::Continue);
        }
        // Only a regular file has contents to merge. A directory or a link at this path means
        // the package stopped shipping a file here, which is an answer rather than a failure.
        if entry.entry != EntryKind::Other || entry.link.is_some() {
            return Ok(Flow::Stop);
        }
        if entry.size > limits.max_member_bytes {
            return Err(Error::PackageLimitExceeded {
                path: member.to_path_buf(),
                limit: "merge base size",
                max: limits.max_member_bytes,
            });
        }

        let mut buffer = Vec::new();
        // One byte past the cap tells "exactly at the limit" from "truncated". The header's
        // size is the archive's claim, not a fact.
        contents
            .take(limits.max_member_bytes.saturating_add(1))
            .read_to_end(&mut buffer)
            .map_err(|source| Error::io(package, IoAction::Read, source))?;
        if buffer.len() as u64 > limits.max_member_bytes {
            return Err(Error::PackageLimitExceeded {
                path: member.to_path_buf(),
                limit: "merge base size",
                max: limits.max_member_bytes,
            });
        }

        found = Some(buffer);
        Ok(Flow::Stop)
    })?;

    Ok(found)
}

/// The components of `path`, with a leading `/` or `.` dropped.
///
/// Comparing two spellings component by component matches `etc/foo.conf` against
/// `./etc/foo.conf`, which a string comparison does not.
fn normalise(path: &Path) -> Vec<&std::ffi::OsStr> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect()
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

    /// A gzip-compressed tar holding one regular file per entry.
    ///
    /// Written here rather than reused from `piko_db::fixture`, because that builder leaves the
    /// uid and gid fields blank and this crate's reader reads both.
    fn gzip_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, path, *contents).unwrap();
        }
        let bytes = builder.into_inner().unwrap();
        piko_db::fixture::gzip(&bytes)
    }

    fn version(raw: &str) -> FullVersion {
        raw.parse().unwrap()
    }

    fn name(raw: &str) -> Name {
        raw.parse().unwrap()
    }

    /// A cache directory holding an empty file per name given.
    fn cache(names: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for entry in names {
            std::fs::write(dir.path().join(entry), b"not a real package").unwrap();
        }
        dir
    }

    fn base(dirs: &[PathBuf], package: &str, installed: &str) -> Option<String> {
        find_base(dirs, &name(package), &version(installed), &BaseLimits::default())
            .unwrap()
            .map(|candidate| candidate.file_name.to_string())
    }

    #[test]
    fn picks_the_newest_build_below_the_installed_version() {
        let dir = cache(&[
            "foo-1.0.0-1-x86_64.pkg.tar.zst",
            "foo-2.0.0-1-x86_64.pkg.tar.zst",
            "foo-3.0.0-1-x86_64.pkg.tar.zst",
        ]);
        let dirs = vec![dir.path().to_path_buf()];
        assert_eq!(
            base(&dirs, "foo", "3.0.0-1").as_deref(),
            Some("foo-2.0.0-1-x86_64.pkg.tar.zst")
        );
    }

    /// The case `pacdiff` gets wrong. Its "second newest file in the cache" is the installed
    /// build itself here, which makes `diff3 -m mine theirs theirs` return `mine`.
    #[test]
    fn never_picks_a_build_newer_than_the_installed_one() {
        let dir = cache(&[
            "foo-1.0.0-1-x86_64.pkg.tar.zst",
            "foo-2.0.0-1-x86_64.pkg.tar.zst",
            "foo-3.0.0-1-x86_64.pkg.tar.zst",
        ]);
        let dirs = vec![dir.path().to_path_buf()];
        assert_eq!(
            base(&dirs, "foo", "2.0.0-1").as_deref(),
            Some("foo-1.0.0-1-x86_64.pkg.tar.zst")
        );
    }

    /// The installed build itself is never the ancestor: it is one side of the merge.
    #[test]
    fn never_picks_the_installed_version() {
        let dir = cache(&["foo-2.0.0-1-x86_64.pkg.tar.zst"]);
        assert_eq!(base(&[dir.path().to_path_buf()], "foo", "2.0.0-1"), None);
    }

    #[test]
    fn nothing_older_is_none() {
        let dir = cache(&["foo-9.0.0-1-x86_64.pkg.tar.zst"]);
        assert_eq!(base(&[dir.path().to_path_buf()], "foo", "1.0.0-1"), None);
    }

    /// Versions are ordered by `alpm_pkg_vercmp`. A string comparison sorts `1.10-1` below
    /// `1.9-1`.
    #[test]
    fn orders_versions_the_way_pacman_does() {
        let dir = cache(&["foo-1.9-1-x86_64.pkg.tar.zst", "foo-1.10-1-x86_64.pkg.tar.zst"]);
        assert_eq!(
            base(&[dir.path().to_path_buf()], "foo", "2.0-1").as_deref(),
            Some("foo-1.10-1-x86_64.pkg.tar.zst")
        );
    }

    #[test]
    fn ignores_signatures_and_unparsable_names() {
        let dir = cache(&[
            "foo-1.0.0-1-x86_64.pkg.tar.zst",
            "foo-9.0.0-1-x86_64.pkg.tar.zst.sig",
            "foo-partial.part",
            "not a package at all",
        ]);
        assert_eq!(
            base(&[dir.path().to_path_buf()], "foo", "2.0.0-1").as_deref(),
            Some("foo-1.0.0-1-x86_64.pkg.tar.zst")
        );
    }

    #[test]
    fn ignores_another_package_of_the_same_version() {
        let dir = cache(&["bar-1.0.0-1-x86_64.pkg.tar.zst"]);
        assert_eq!(base(&[dir.path().to_path_buf()], "foo", "2.0.0-1"), None);
    }

    /// A later directory wins only by being strictly newer, so the first keeps a version both
    /// hold. That is the order `CacheDirSource` resolves a package file in.
    #[test]
    fn the_first_directory_keeps_a_version_both_hold() {
        let first = cache(&["foo-1.0.0-1-x86_64.pkg.tar.zst"]);
        let second = cache(&["foo-1.0.0-1-x86_64.pkg.tar.zst"]);
        let dirs = vec![first.path().to_path_buf(), second.path().to_path_buf()];

        let picked = find_base(&dirs, &name("foo"), &version("2.0.0-1"), &BaseLimits::default())
            .unwrap()
            .unwrap();
        assert!(picked.path.starts_with(first.path()), "{:?}", picked.path);
    }

    #[test]
    fn a_directory_that_cannot_be_read_contributes_nothing() {
        let dir = cache(&["foo-1.0.0-1-x86_64.pkg.tar.zst"]);
        let dirs = vec![PathBuf::from("/nonexistent"), dir.path().to_path_buf()];
        assert_eq!(
            base(&dirs, "foo", "2.0.0-1").as_deref(),
            Some("foo-1.0.0-1-x86_64.pkg.tar.zst")
        );
    }

    /// A cache directory filled while it is read must not cost an unbounded walk. The bound
    /// is set to zero so the answer does not depend on the order the entries arrive in.
    #[test]
    fn the_cache_bound_stops_the_walk() {
        let dir = cache(&["foo-1.0.0-1-x86_64.pkg.tar.zst"]);
        let limits = BaseLimits { max_cache_entries: 0, ..BaseLimits::default() };
        let found =
            find_base(&[dir.path().to_path_buf()], &name("foo"), &version("2.0-1"), &limits)
                .unwrap();
        assert!(found.is_none());
    }

    /// The archive spells a payload path without a leading separator. Some producers write
    /// `./etc/foo.conf` instead, and both must match the same `%BACKUP%` entry.
    #[test]
    fn finds_a_member_however_the_archive_spells_it() {
        let dir = tempfile::tempdir().unwrap();
        for (index, spelling) in ["etc/foo.conf", "./etc/foo.conf"].iter().enumerate() {
            let path = dir.path().join(format!("p{index}.tar.gz"));
            std::fs::write(&path, gzip_tar(&[(spelling, b"contents")])).unwrap();
            let found =
                extract_member(&path, Path::new("etc/foo.conf"), &BaseLimits::default()).unwrap();
            assert_eq!(found.as_deref(), Some(b"contents".as_slice()), "{spelling}");
        }
    }

    #[test]
    fn a_member_the_archive_does_not_hold_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.tar.gz");
        std::fs::write(&path, gzip_tar(&[("etc/other.conf", b"contents")])).unwrap();
        assert!(
            extract_member(&path, Path::new("etc/foo.conf"), &BaseLimits::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn refuses_a_member_over_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.tar.gz");
        std::fs::write(&path, gzip_tar(&[("etc/foo.conf", &[b'x'; 200])])).unwrap();

        let limits = BaseLimits { max_member_bytes: 10, ..BaseLimits::default() };
        let error = extract_member(&path, Path::new("etc/foo.conf"), &limits).unwrap_err();
        assert!(
            matches!(error, Error::PackageLimitExceeded { limit: "merge base size", .. }),
            "got {error:?}"
        );
    }

    /// The walk stops at the member, so what follows is never decompressed. A tail the reader
    /// would choke on proves it directly.
    #[test]
    fn stops_at_the_member_and_never_reads_the_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.tar.gz");
        let mut bytes = gzip_tar(&[("etc/foo.conf", b"contents")]);
        bytes.extend_from_slice(b"this is not gzip and never will be");
        std::fs::write(&path, &bytes).unwrap();

        let found =
            extract_member(&path, Path::new("etc/foo.conf"), &BaseLimits::default()).unwrap();
        assert_eq!(found.as_deref(), Some(b"contents".as_slice()));
    }
}
