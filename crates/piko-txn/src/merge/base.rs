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
use piko_db::config::SigLevel;
use piko_sig::{Keyring, Policy, Verdict};

use crate::source::distrust;
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
#[non_exhaustive]
pub struct BaseCandidate {
    /// Where the file sits.
    pub path: PathBuf,
    /// Its parsed name, so a caller can say which version it picked.
    pub file_name: PackageFileName,
}

/// A cached build that was not used as the ancestor, and why.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RefusedBase {
    /// The package file.
    pub path: PathBuf,
    /// Why its bytes cannot reach a merge.
    pub reason: String,
}

/// What [`find_base`] found.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct BaseSearch {
    /// The ancestor to merge against. `None` means a two-way view.
    pub base: Option<BaseCandidate>,
    /// Newer builds passed over on the way to it, newest first.
    pub refused: Vec<RefusedBase>,
}

/// The ancestor a three-way merge of one pending file can use.
#[derive(Debug)]
#[non_exhaustive]
pub enum BaseContents {
    /// No accepted cached build is older than the installed version: a two-way view.
    NoBase,
    /// The chosen build does not ship the file.
    NotShipped {
        /// The build.
        base: BaseCandidate,
    },
    /// The chosen build could not be read.
    Unreadable {
        /// The build.
        base: BaseCandidate,
        /// Why.
        error: Error,
    },
    /// The file as the chosen build ships it.
    Found {
        /// The build.
        base: BaseCandidate,
        /// The file's contents.
        contents: Vec<u8>,
    },
}

/// What [`base_contents`] found, and the builds it passed over on the way.
#[derive(Debug)]
#[non_exhaustive]
pub struct BaseLookup {
    /// Newer builds passed over on the way to the base, newest first, as [`BaseSearch`] lists
    /// them. Reported on every outcome.
    pub refused: Vec<RefusedBase>,
    /// The ancestor, or why there is none.
    pub contents: BaseContents,
}

/// The ancestor of `pending`, read out of the cache: [`find_base`], then `extract_member`.
///
/// The build is the newest one strictly below the installed version whose signature `check`
/// accepts, and the member is `pending.target`. A failure to read the chosen build is
/// [`BaseContents::Unreadable`] rather than an error, so the builds passed over on the way are
/// still reported.
///
/// # Errors
///
/// As [`find_base`].
pub fn base_contents(
    directories: &[PathBuf],
    pending: &crate::merge::Pending,
    limits: &BaseLimits,
    check: &BaseCheck,
) -> Result<BaseLookup> {
    let search =
        find_base(directories, &pending.package, &pending.installed_version, limits, check)?;
    let contents = match search.base {
        None => BaseContents::NoBase,
        Some(base) => match extract_member(&base.path, &pending.target, limits) {
            Ok(Some(contents)) => BaseContents::Found { base, contents },
            Ok(None) => BaseContents::NotShipped { base },
            Err(error) => BaseContents::Unreadable { base, error },
        },
    };
    Ok(BaseLookup { refused: search.refused, contents })
}

/// How a cached build's signature is checked before its bytes can reach a merge.
///
/// A base is read out of a cache, and every cache holds whatever was downloaded into it: a
/// package fetched by URL and then refused for having no signature stays there, under the name
/// its URL gave it. Its bytes then decide which side of a three-way merge wins, in a file root
/// reads as configuration. So a base must carry a signature the keyring accepts, as a package
/// must before it is installed.
#[derive(Clone, Debug)]
pub enum BaseCheck {
    /// Check each candidate's `.sig` against `keyring`, under `policy`.
    Signed {
        /// The keyring, `GPGDir`.
        keyring: Keyring,
        /// What a signature must satisfy. Never optional: see [`BaseCheck::new`].
        policy: Policy,
    },
    /// Check nothing, because the configuration checks no package signature (`SigLevel = Never`).
    Unchecked,
}

impl BaseCheck {
    /// The check `level`, the global `SigLevel`, asks of a package file, against the keyring at
    /// `gpg_dir`.
    ///
    /// The keyring is opened only when `level` checks package signatures. `...Optional` is not
    /// honoured: a base is optional itself, so a build with no signature is passed over, and
    /// the merge falls back to a two-way view rather than to unchecked bytes.
    ///
    /// # Errors
    ///
    /// [`Error::KeyringUnusable`] if a keyring is needed and cannot be opened.
    pub fn new(level: SigLevel, gpg_dir: &Path) -> Result<Self> {
        let policy = Policy { optional: false, ..Policy::for_package(level) };
        if !policy.check {
            return Ok(Self::Unchecked);
        }
        let keyring = Keyring::open(gpg_dir)
            .map_err(|source| Error::KeyringUnusable { path: gpg_dir.to_path_buf(), source })?;
        Ok(Self::Signed { keyring, policy })
    }

    /// Why `path` cannot be a base, or `None` when it can.
    fn refusal(&self, path: &Path) -> Option<String> {
        let Self::Signed { keyring, policy } = self else { return None };
        match keyring.check(path, *policy) {
            Ok(Verdict::Accepted { .. }) => None,
            Ok(Verdict::Rejected(rejection)) => Some(rejection.to_string()),
            Err(error) => Some(error.to_string()),
        }
    }
}

/// Bounds on the cache search and on one member's extraction.
#[derive(Clone, Copy, Debug)]
pub struct BaseLimits {
    /// Largest number of entries examined per cache directory.
    pub max_cache_entries: usize,
    /// Largest member read into memory.
    pub max_member_bytes: u64,
    /// Largest number of builds whose signature is checked in one search.
    ///
    /// A check hashes the whole package, and a cache that was never cleaned can hold dozens of
    /// older builds, each refused for the same reason.
    pub max_signature_checks: usize,
    /// What the archive walk itself is bounded by.
    pub package: PackageLimits,
}

impl Default for BaseLimits {
    fn default() -> Self {
        Self {
            // A real cache holds a few thousand packages. This machine's holds 1872.
            max_cache_entries: 200_000,
            max_member_bytes: MAX_BACKUP_BYTES,
            max_signature_checks: 8,
            package: PackageLimits::default(),
        }
    }
}

/// Picks the cached build of `package` a three-way merge should use as its ancestor.
///
/// That is the newest build strictly older than `installed` whose signature `check` accepts.
/// A newer build that fails the check is passed over, and named in [`BaseSearch::refused`].
/// No base means a two-way view.
///
/// `directories` are searched in `CacheDir` order. Two directories holding the same version
/// resolve to the first one, as [`crate::source::CacheDirSource`] resolves a package file.
/// Nothing is created: this reads the directories it is given, and passes over one it cannot.
///
/// A directory or a file another user could change is passed over too
/// ([`crate::source::Distrust`]), and so is a directory with an ancestor another user could
/// write ([`piko_db::fs_util::ensure_trusted_directory`]).
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
    check: &BaseCheck,
) -> Result<BaseSearch> {
    let mut candidates: Vec<BaseCandidate> = Vec::new();

    for directory in directories {
        if piko_db::fs_util::ensure_trusted_directory(directory).is_err() {
            continue;
        }
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
            if !entry
                .metadata()
                .is_ok_and(|metadata| metadata.is_file() && distrust(&metadata).is_none())
            {
                continue;
            }
            candidates.push(BaseCandidate { path: entry.path(), file_name });
        }
    }

    // Newest first. The sort is stable, so of two directories holding one version, the first
    // is tried first.
    candidates.sort_by(|left, right| right.file_name.version().cmp(left.file_name.version()));

    let mut search = BaseSearch::default();
    for candidate in candidates.into_iter().take(limits.max_signature_checks) {
        match check.refusal(&candidate.path) {
            None => {
                search.base = Some(candidate);
                break;
            }
            Some(reason) => search.refused.push(RefusedBase { path: candidate.path, reason }),
        }
    }
    Ok(search)
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
/// As `walk_until`, plus [`Error::PackageLimitExceeded`] if the member is larger than
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
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
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
        find_base(
            dirs,
            &name(package),
            &version(installed),
            &BaseLimits::default(),
            &BaseCheck::Unchecked,
        )
        .unwrap()
        .base
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

    /// An ancestor is never signature-checked, and its bytes reach the merged file. So a build
    /// another user could have planted is passed over: in a directory others can write, or as a
    /// file others can write.
    #[test]
    fn an_ancestor_another_user_could_change_is_passed_over() {
        use std::os::unix::fs::PermissionsExt as _;
        let chmod = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };

        let shared = cache(&["foo-2.0.0-1-x86_64.pkg.tar.zst"]);
        let trusted = cache(&["foo-1.0.0-1-x86_64.pkg.tar.zst", "foo-2.5.0-1-x86_64.pkg.tar.zst"]);
        chmod(shared.path(), 0o1777);
        chmod(&trusted.path().join("foo-2.5.0-1-x86_64.pkg.tar.zst"), 0o646);

        let dirs = vec![shared.path().to_path_buf(), trusted.path().to_path_buf()];
        assert_eq!(
            base(&dirs, "foo", "3.0.0-1").as_deref(),
            Some("foo-1.0.0-1-x86_64.pkg.tar.zst")
        );
        chmod(shared.path(), 0o700);
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

        let picked = find_base(
            &dirs,
            &name("foo"),
            &version("2.0.0-1"),
            &BaseLimits::default(),
            &BaseCheck::Unchecked,
        )
        .unwrap()
        .base
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
        let found = find_base(
            &[dir.path().to_path_buf()],
            &name("foo"),
            &version("2.0-1"),
            &limits,
            &BaseCheck::Unchecked,
        )
        .unwrap();
        assert!(found.base.is_none());
    }

    /// A keyring holding one fresh, fully trusted signing key, or `None` without `gpg`.
    fn signing_keyring() -> Option<tempfile::TempDir> {
        use std::os::unix::fs::PermissionsExt as _;
        let home = tempfile::tempdir().ok()?;
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).ok()?;
        let output = std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(home.path())
            .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--quick-generate-key", "piko test <test@example.invalid>", "ed25519"])
            .args(["sign", "never"])
            .output()
            .ok()?;
        if !output.status.success() {
            eprintln!("skipping: no test key: {}", String::from_utf8_lossy(&output.stderr));
            return None;
        }
        Some(home)
    }

    /// Writes `file.sig`, a detached signature of `file` by the key in `home`.
    fn sign(home: &Path, file: &Path) {
        let status = std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(home)
            .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
            .arg("--output")
            .arg(piko_sig::signature_path(file))
            .arg("--detach-sign")
            .arg(file)
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// A build with no signature, or with one that does not verify, is never a base. The
    /// newest build that verifies is, and the ones passed over are named, newest first.
    #[test]
    fn a_base_needs_a_signature_the_keyring_accepts() {
        let Some(home) = signing_keyring() else { return };
        let dir = cache(&[
            "foo-1.0.0-1-x86_64.pkg.tar.zst",
            "foo-1.5.0-1-x86_64.pkg.tar.zst",
            "foo-1.8.0-1-x86_64.pkg.tar.zst",
        ]);
        sign(home.path(), &dir.path().join("foo-1.0.0-1-x86_64.pkg.tar.zst"));
        // A signature over other bytes: the file was replaced after it was signed.
        let replaced = dir.path().join("foo-1.8.0-1-x86_64.pkg.tar.zst");
        sign(home.path(), &replaced);
        std::fs::write(&replaced, b"other bytes").unwrap();

        let check = BaseCheck::new(SigLevel::PACKAGE, home.path()).unwrap();
        let search = find_base(
            &[dir.path().to_path_buf()],
            &name("foo"),
            &version("2.0.0-1"),
            &BaseLimits::default(),
            &check,
        )
        .unwrap();

        assert_eq!(
            search.base.map(|candidate| candidate.file_name.to_string()).as_deref(),
            Some("foo-1.0.0-1-x86_64.pkg.tar.zst")
        );
        let refused: Vec<_> =
            search.refused.iter().map(|refused| refused.path.file_name().unwrap()).collect();
        assert_eq!(refused, ["foo-1.8.0-1-x86_64.pkg.tar.zst", "foo-1.5.0-1-x86_64.pkg.tar.zst"]);
    }

    /// `PackageOptional` does not let an unsigned build through: a base is optional itself.
    #[test]
    fn an_optional_policy_still_refuses_an_unsigned_base() {
        let Some(home) = signing_keyring() else { return };
        let dir = cache(&["foo-1.0.0-1-x86_64.pkg.tar.zst"]);
        let level = SigLevel::PACKAGE.union(SigLevel::PACKAGE_OPTIONAL);
        let check = BaseCheck::new(level, home.path()).unwrap();
        let search = find_base(
            &[dir.path().to_path_buf()],
            &name("foo"),
            &version("2.0.0-1"),
            &BaseLimits::default(),
            &check,
        )
        .unwrap();
        assert!(search.base.is_none(), "{search:?}");
        assert_eq!(search.refused.len(), 1);
    }

    /// A level that checks no package signature needs no keyring at all.
    #[test]
    fn a_policy_that_checks_nothing_opens_no_keyring() {
        let check = BaseCheck::new(SigLevel::DATABASE, Path::new("/nonexistent-keyring")).unwrap();
        assert!(matches!(check, BaseCheck::Unchecked));
    }

    /// The signature checks are bounded: each one hashes a whole package.
    #[test]
    fn the_signature_checks_are_bounded() {
        let Some(home) = signing_keyring() else { return };
        let dir = cache(&[
            "foo-1.0.0-1-x86_64.pkg.tar.zst",
            "foo-1.1.0-1-x86_64.pkg.tar.zst",
            "foo-1.2.0-1-x86_64.pkg.tar.zst",
        ]);
        sign(home.path(), &dir.path().join("foo-1.0.0-1-x86_64.pkg.tar.zst"));
        let check = BaseCheck::new(SigLevel::PACKAGE, home.path()).unwrap();
        let limits = BaseLimits { max_signature_checks: 2, ..BaseLimits::default() };
        let search = find_base(
            &[dir.path().to_path_buf()],
            &name("foo"),
            &version("2.0.0-1"),
            &limits,
            &check,
        )
        .unwrap();
        assert!(search.base.is_none(), "{search:?}");
        assert_eq!(search.refused.len(), 2);
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

    fn pending_for(target: &str, installed: &str) -> crate::merge::Pending {
        crate::merge::Pending {
            pacfile: PathBuf::from(format!("{target}.pacnew")),
            target: PathBuf::from(target),
            kind: crate::merge::PendingKind::Pacnew,
            package: name("foo"),
            installed_version: version(installed),
            verdict: crate::merge::Verdict::Differs,
        }
    }

    /// The three outcomes a merge tells apart: no older build, a build without the file, and
    /// the file itself.
    #[test]
    fn base_contents_reads_the_member_out_of_the_chosen_build() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("foo-1.0.0-1-x86_64.pkg.tar.gz"),
            gzip_tar(&[("etc/foo.conf", b"ancestor")]),
        )
        .unwrap();
        let dirs = vec![dir.path().to_path_buf()];
        let lookup = |target: &str, installed: &str| {
            base_contents(
                &dirs,
                &pending_for(target, installed),
                &BaseLimits::default(),
                &BaseCheck::Unchecked,
            )
            .unwrap()
            .contents
        };

        assert!(matches!(
            lookup("etc/foo.conf", "2.0.0-1"),
            BaseContents::Found { contents, .. } if contents == b"ancestor"
        ));
        assert!(matches!(lookup("etc/bar.conf", "2.0.0-1"), BaseContents::NotShipped { .. }));
        assert!(matches!(lookup("etc/foo.conf", "1.0.0-1"), BaseContents::NoBase));
    }

    /// A build that cannot be read is an outcome, not an error.
    #[test]
    fn an_unreadable_base_is_reported_as_such() {
        let dir = cache(&["foo-1.0.0-1-x86_64.pkg.tar.gz"]);
        let dirs = vec![dir.path().to_path_buf()];

        let lookup = base_contents(
            &dirs,
            &pending_for("etc/foo.conf", "2.0.0-1"),
            &BaseLimits::default(),
            &BaseCheck::Unchecked,
        )
        .unwrap();
        assert!(matches!(lookup.contents, BaseContents::Unreadable { .. }), "{lookup:?}");
    }
}
