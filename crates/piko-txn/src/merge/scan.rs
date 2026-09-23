//! Finding the pending files a local database can account for.
//!
//! The scan starts from `%BACKUP%` rather than from the filesystem. Every entry names a path
//! the package manager may have left a second copy of, so testing three suffixes beside it
//! finds every pending file a package declared. `pacdiff` walks the same list in its default
//! mode, then asks `pacman -Qoq` which package owns each hit. Starting from the package
//! answers that for free.
//!
//! # What the direction buys
//!
//! `pacdiff` finds `<path>.pacnew` and strips the suffix to get the target (`${pacfile%.pac*}`).
//! This module adds the suffix to a `%BACKUP%` entry instead. The two agree on every ordinary
//! name. They disagree on a configuration file whose own name contains `.pac`, where stripping
//! names a file that was never the target.
//!
//! # Two ways of looking
//!
//! `.pacnew` and `.pacsave` are tested by name, with one `statat` each. `.pacsave.N` cannot be
//! tested that way, because `N` is unbounded, so those need the parent directory listed. The
//! listing is bounded and the by-name tests are not. A directory too large to list therefore
//! still yields its two mergeable kinds. A bound that hid a `.pacnew` would be a bound that
//! opens a hole.

use std::{
    collections::{BTreeSet, HashMap},
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
};

use piko_db::LocalDatabase;

use crate::{
    hash::{self, MAX_BACKUP_BYTES},
    merge::{PACSAVE_SUFFIX, Pending, PendingKind, Problem, Verdict},
    rootfs::{Resolved, RootDir},
};

/// Bounds on what one scan may cost.
#[derive(Clone, Copy, Debug)]
pub struct ScanLimits {
    /// Largest pair compared. A larger one is [`Verdict::Unreadable`].
    pub compare_bytes: u64,
    /// Largest number of directory entries read while looking for numbered `.pacsave` files.
    pub max_dir_entries: usize,
    /// Largest number of pending files returned. The overflow is counted, not dropped in
    /// silence.
    pub max_pending: usize,
    /// Largest number of problems returned.
    pub max_problems: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            compare_bytes: MAX_BACKUP_BYTES,
            // A real `/etc` holds a few thousand entries. This is far above that, and far
            // below what a directory built to stall a scan would hold.
            max_dir_entries: 100_000,
            // A real system declares a few hundred `%BACKUP%` entries in total.
            max_pending: 100_000,
            max_problems: 100,
        }
    }
}

/// Everything one scan found.
#[derive(Clone, Debug, Default)]
pub struct Scan {
    pending: Vec<Pending>,
    problems: Vec<Problem>,
    pending_dropped: usize,
    problems_dropped: usize,
}

impl Scan {
    /// The pending files, in database order, then in `%BACKUP%` order within a package.
    #[must_use]
    pub fn pending(&self) -> &[Pending] {
        &self.pending
    }

    /// What went wrong, in the order it was met.
    #[must_use]
    pub fn problems(&self) -> &[Problem] {
        &self.problems
    }

    /// How many pending files the bound withheld.
    #[must_use]
    pub const fn pending_dropped(&self) -> usize {
        self.pending_dropped
    }

    /// How many problems the bound withheld.
    #[must_use]
    pub const fn problems_dropped(&self) -> usize {
        self.problems_dropped
    }

    /// Records a pending file, or counts it as withheld.
    fn push(&mut self, pending: Pending, limits: &ScanLimits) {
        if self.pending.len() >= limits.max_pending {
            self.pending_dropped = self.pending_dropped.saturating_add(1);
            return;
        }
        self.pending.push(pending);
    }

    /// Records a problem, or counts it as withheld.
    fn note(&mut self, problem: Problem, limits: &ScanLimits) {
        if self.problems.len() >= limits.max_problems {
            self.problems_dropped = self.problems_dropped.saturating_add(1);
            return;
        }
        self.problems.push(problem);
    }
}

/// Finds every pending file the local database can account for.
///
/// This returns rather than fails. One unreadable package must not cost the rest of the scan,
/// so what went wrong comes back on [`Scan::problems`].
#[must_use]
pub fn scan(root: &RootDir, db: &LocalDatabase, limits: &ScanLimits) -> Scan {
    let mut found = Scan::default();
    // One listing per distinct parent directory, not one per `%BACKUP%` entry. A real system
    // spreads a few hundred entries over a few dozen directories.
    let mut listings: HashMap<PathBuf, Option<BTreeSet<OsString>>> = HashMap::new();

    for package in db.iter() {
        let backups = match package.backups() {
            Ok(backups) => backups,
            Err(error) => {
                found.note(
                    Problem::UnreadableEntry {
                        package: package.entry().as_str().to_owned(),
                        reason: error.to_string(),
                    },
                    limits,
                );
                continue;
            }
        };

        for backup in backups {
            let target = backup.path.inner();
            let resolved = match root.resolve_parent(target) {
                Ok(resolved) => resolved,
                Err(error) => {
                    found.note(
                        Problem::OutsideRoot {
                            path: target.to_path_buf(),
                            reason: error.to_string(),
                        },
                        limits,
                    );
                    continue;
                }
            };

            self::collect(
                &mut found,
                &mut listings,
                &resolved,
                target,
                package.name(),
                package.version(),
                limits,
            );
        }
    }

    found
}

/// Records every pending file sitting beside `target`.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct input; bundling them would only hide the count"
)]
fn collect(
    found: &mut Scan,
    listings: &mut HashMap<PathBuf, Option<BTreeSet<OsString>>>,
    resolved: &Resolved,
    target: &Path,
    package: &alpm_types::Name,
    version: &alpm_types::FullVersion,
    limits: &ScanLimits,
) {
    for kind in [PendingKind::Pacnew, PendingKind::Pacsave] {
        let candidate = self::with_suffix(resolved.name(), &kind.suffix());
        if !hash::exists_at(resolved.dir(), &candidate) {
            continue;
        }
        let pending = self::describe(found, resolved, target, package, version, kind, limits);
        found.push(pending, limits);
    }

    for number in self::numbered(found, listings, resolved, target, limits) {
        let kind = PendingKind::NumberedPacsave(number);
        let pending = self::describe(found, resolved, target, package, version, kind, limits);
        found.push(pending, limits);
    }
}

/// Builds the record for one pending file, comparing it with its target.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct input; bundling them would only hide the count"
)]
fn describe(
    found: &mut Scan,
    resolved: &Resolved,
    target: &Path,
    package: &alpm_types::Name,
    version: &alpm_types::FullVersion,
    kind: PendingKind,
    limits: &ScanLimits,
) -> Pending {
    let suffix = kind.suffix();
    let candidate = self::with_suffix(resolved.name(), &suffix);
    let pacfile = self::append_suffix(target, &suffix);

    let verdict = if hash::exists_at(resolved.dir(), resolved.name()) {
        match hash::same_contents_at(
            resolved.dir(),
            resolved.name(),
            &candidate,
            limits.compare_bytes,
        ) {
            Ok(Some(true)) => Verdict::Identical,
            Ok(Some(false)) => Verdict::Differs,
            // One of the two vanished between the test above and the comparison. Nothing is
            // left to decide, and saying so is closer than claiming a difference.
            Ok(None) => Verdict::TargetMissing,
            Err(error) => {
                found.note(
                    Problem::Uncomparable { path: pacfile.clone(), reason: error.to_string() },
                    limits,
                );
                Verdict::Unreadable
            }
        }
    } else {
        Verdict::TargetMissing
    };

    Pending {
        pacfile,
        target: target.to_path_buf(),
        kind,
        package: package.clone(),
        installed_version: version.clone(),
        verdict,
    }
}

/// The `N`s of the `<target>.pacsave.N` files beside `target`.
fn numbered(
    found: &mut Scan,
    listings: &mut HashMap<PathBuf, Option<BTreeSet<OsString>>>,
    resolved: &Resolved,
    target: &Path,
    limits: &ScanLimits,
) -> Vec<u32> {
    let parent = target.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
    let listing = listings.entry(parent.clone()).or_insert_with(|| {
        match self::list_directory(resolved, limits.max_dir_entries) {
            Ok(names) => Some(names),
            Err(reason) => {
                // Recorded once per directory, not once per entry in it.
                found.note(Problem::UnlistableDirectory { path: parent.clone(), reason }, limits);
                None
            }
        }
    });
    let Some(names) = listing.as_ref() else {
        return Vec::new();
    };

    let prefix = self::with_suffix(resolved.name(), &format!("{PACSAVE_SUFFIX}."));
    let mut numbers = Vec::new();
    for name in names {
        let Some(digits) = self::strip_prefix(name, &prefix) else {
            continue;
        };
        let Some(digits) = digits.to_str() else {
            continue;
        };
        // The number must round-trip. `.pacsave.01` reads as `1`, and acting on that would
        // rename `.pacsave.1` to `.pacsave.2` while `.pacsave.01` stayed put, leaving two
        // files that claim one rank.
        match digits.parse::<u32>() {
            Ok(number) if number.to_string() == digits => numbers.push(number),
            _ => found.note(
                Problem::UnusableNumber {
                    path: self::append_suffix(target, &format!("{PACSAVE_SUFFIX}.{digits}")),
                },
                limits,
            ),
        }
    }
    numbers.sort_unstable();
    numbers
}

/// Lists the directory `resolved` names, through the descriptor that resolved it.
///
/// The bound fires while the entries arrive, so an oversized directory costs the bound rather
/// than the whole listing.
fn list_directory(
    resolved: &Resolved,
    max_entries: usize,
) -> std::result::Result<BTreeSet<OsString>, String> {
    let handle = rustix::fs::openat(
        resolved.dir(),
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| source.to_string())?;

    let mut names = BTreeSet::new();
    let mut seen = 0_usize;
    for entry in rustix::fs::Dir::read_from(&handle).map_err(|source| source.to_string())? {
        let entry = entry.map_err(|source| source.to_string())?;
        seen = seen.saturating_add(1);
        if seen > max_entries {
            return Err(format!("it holds more than {max_entries} entries"));
        }
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name == "." || name == ".." {
            continue;
        }
        names.insert(name.to_os_string());
    }
    Ok(names)
}

/// `name` with `suffix` appended.
fn with_suffix(name: &OsStr, suffix: &str) -> OsString {
    let mut joined = name.to_os_string();
    joined.push(suffix);
    joined
}

/// `path` with `suffix` appended to its final component.
fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut joined = path.as_os_str().to_os_string();
    joined.push(suffix);
    PathBuf::from(joined)
}

/// What follows `prefix` in `name`, if `name` starts with it.
fn strip_prefix(name: &OsStr, prefix: &OsStr) -> Option<OsString> {
    let bytes = name.as_bytes();
    let head = prefix.as_bytes();
    let rest = bytes.strip_prefix(head)?;
    Some(OsStr::from_bytes(rest).to_os_string())
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
    use piko_db::fixture::DbFixture;

    /// A well-formed MD5, so a `%BACKUP%` line parses. Its value is never compared.
    const SOME_HASH: &str = "615a81e46afa8d939f47824e83e9d444";

    /// A `files` body declaring `backups` as both shipped files and `%BACKUP%` entries.
    ///
    /// `%FILES%` lists each parent directory too. `alpm-db` refuses a list that names a file
    /// under a directory the list does not hold.
    fn files_body(backups: &[&str]) -> String {
        let mut listed: BTreeSet<String> = BTreeSet::new();
        for path in backups {
            let mut prefix = String::new();
            for part in Path::new(path).parent().into_iter().flat_map(Path::components) {
                prefix.push_str(&part.as_os_str().to_string_lossy());
                prefix.push('/');
                listed.insert(prefix.clone());
            }
            listed.insert((*path).to_owned());
        }

        let mut body = String::from("%FILES%\n");
        for path in &listed {
            body.push_str(path);
            body.push('\n');
        }
        body.push_str("\n%BACKUP%\n");
        for path in backups {
            body.push_str(&format!("{path}\t{SOME_HASH}\n"));
        }
        body.push('\n');
        body
    }

    /// A local database whose packages declare the `%BACKUP%` paths given.
    fn database(packages: &[(&str, &[&str])]) -> (DbFixture, LocalDatabase) {
        let fixture = DbFixture::new();
        for (entry, backups) in packages {
            fixture.package(entry).with_defaults().files(&files_body(backups)).build();
        }
        let local = LocalDatabase::open(fixture.path()).unwrap();
        (fixture, local)
    }

    /// An installation root holding the files named, with the contents given.
    fn root(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, contents) in files {
            let full = dir.path().join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&full, contents).unwrap();
        }
        dir
    }

    fn run(dir: &tempfile::TempDir, db: &LocalDatabase) -> Scan {
        let root = RootDir::open(dir.path()).unwrap();
        scan(&root, db, &ScanLimits::default())
    }

    #[test]
    fn finds_a_pacnew_with_its_target_package_and_version() {
        let (_fixture, db) = database(&[("foo-1.0.0-1", &["etc/foo.conf"])]);
        let dir = root(&[("etc/foo.conf", b"mine"), ("etc/foo.conf.pacnew", b"theirs")]);

        let found = run(&dir, &db);
        assert_eq!(found.pending().len(), 1, "{:?}", found.pending());
        let pending = found.pending().first().unwrap();
        assert_eq!(pending.pacfile, Path::new("etc/foo.conf.pacnew"));
        assert_eq!(pending.target, Path::new("etc/foo.conf"));
        assert_eq!(pending.kind, PendingKind::Pacnew);
        assert_eq!(pending.package.as_ref(), "foo");
        assert_eq!(pending.installed_version.to_string(), "1.0.0-1");
        assert_eq!(pending.verdict, Verdict::Differs);
        assert!(found.problems().is_empty(), "{:?}", found.problems());
    }

    #[test]
    fn a_backup_entry_with_nothing_beside_it_yields_nothing() {
        let (_fixture, db) = database(&[("foo-1.0.0-1", &["etc/foo.conf"])]);
        let dir = root(&[("etc/foo.conf", b"mine")]);
        assert!(run(&dir, &db).pending().is_empty());
    }

    #[test]
    fn a_pacnew_holding_the_same_bytes_is_identical() {
        let (_fixture, db) = database(&[("foo-1.0.0-1", &["etc/foo.conf"])]);
        let dir = root(&[("etc/foo.conf", b"same"), ("etc/foo.conf.pacnew", b"same")]);
        assert_eq!(run(&dir, &db).pending().first().unwrap().verdict, Verdict::Identical);
    }

    #[test]
    fn a_pacsave_whose_target_is_gone_says_so() {
        let (_fixture, db) = database(&[("foo-1.0.0-1", &["etc/foo.conf"])]);
        let dir = root(&[("etc/foo.conf.pacsave", b"mine")]);

        let found = run(&dir, &db);
        let pending = found.pending().first().unwrap();
        assert_eq!(pending.kind, PendingKind::Pacsave);
        assert_eq!(pending.verdict, Verdict::TargetMissing);
    }

    /// The verdict that deletes a file without asking must never come from a file the scan
    /// could not read.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_pacnew_is_unreadable_and_is_not_followed() {
        let (_fixture, db) = database(&[("foo-1.0.0-1", &["etc/foo.conf"])]);
        let dir = root(&[("etc/foo.conf", b"mine")]);
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret");
        std::fs::write(&secret, b"mine").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("etc/foo.conf.pacnew")).unwrap();

        let found = run(&dir, &db);
        assert_eq!(found.pending().first().unwrap().verdict, Verdict::Unreadable);
        assert!(
            matches!(found.problems().first(), Some(Problem::Uncomparable { .. })),
            "{:?}",
            found.problems()
        );
        assert!(secret.exists(), "the symlink target must be untouched");
    }

    /// A parent component that has become a symlink is a path piko will not act inside. So
    /// nothing is listed for it at all.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_parent_lists_nothing_and_is_reported() {
        let (_fixture, db) = database(&[("foo-1.0.0-1", &["etc/foo.conf"])]);
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("foo.conf"), b"mine").unwrap();
        std::fs::write(outside.path().join("foo.conf.pacnew"), b"theirs").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("etc")).unwrap();

        let found = run(&dir, &db);
        assert!(found.pending().is_empty(), "{:?}", found.pending());
        assert!(
            matches!(found.problems().first(), Some(Problem::OutsideRoot { .. })),
            "{:?}",
            found.problems()
        );
    }

    /// Reading a FIFO would block the scan forever.
    #[cfg(unix)]
    #[test]
    fn a_fifo_target_is_unreadable_and_never_blocks() {
        let (_fixture, db) = database(&[("foo-1.0.0-1", &["etc/foo.conf"])]);
        let dir = root(&[("etc/foo.conf.pacnew", b"theirs")]);
        let fifo = dir.path().join("etc/foo.conf");
        let path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            path.as_c_str(),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();

        let found = run(&dir, &db);
        assert_eq!(found.pending().first().unwrap().verdict, Verdict::Unreadable);
    }

    #[test]
    fn numbered_pacsaves_are_listed_and_are_not_mergeable() {
        let (_fixture, db) = database(&[("foo-1.0.0-1", &["etc/foo.conf"])]);
        let dir = root(&[
            ("etc/foo.conf", b"mine"),
            ("etc/foo.conf.pacsave", b"older"),
            ("etc/foo.conf.pacsave.1", b"older still"),
            ("etc/foo.conf.pacsave.2", b"oldest"),
        ]);

        let found = run(&dir, &db);
        let kinds: Vec<PendingKind> = found.pending().iter().map(|p| p.kind).collect();
        assert_eq!(
            kinds,
            vec![
                PendingKind::Pacsave,
                PendingKind::NumberedPacsave(1),
                PendingKind::NumberedPacsave(2)
            ]
        );
        assert!(!PendingKind::NumberedPacsave(1).is_mergeable());
        assert!(PendingKind::Pacsave.is_mergeable());
    }

    #[test]
    fn a_number_too_large_for_a_u32_is_reported_and_not_listed() {
        let (_fixture, db) = database(&[("foo-1.0.0-1", &["etc/foo.conf"])]);
        let dir =
            root(&[("etc/foo.conf", b"mine"), ("etc/foo.conf.pacsave.99999999999999", b"huge")]);

        let found = run(&dir, &db);
        assert!(found.pending().is_empty(), "{:?}", found.pending());
        assert!(
            matches!(found.problems().first(), Some(Problem::UnusableNumber { .. })),
            "{:?}",
            found.problems()
        );
    }

    /// `.pacsave.01` reads as `1`. Acting on that would rename `.pacsave.1` over `.pacsave.2`
    /// while `.pacsave.01` stayed put, leaving two files claiming one rank.
    #[test]
    fn a_number_that_does_not_round_trip_is_reported_and_not_listed() {
        let (_fixture, db) = database(&[("foo-1.0.0-1", &["etc/foo.conf"])]);
        let dir = root(&[("etc/foo.conf", b"mine"), ("etc/foo.conf.pacsave.01", b"padded")]);

        let found = run(&dir, &db);
        assert!(found.pending().is_empty(), "{:?}", found.pending());
        assert!(
            matches!(found.problems().first(), Some(Problem::UnusableNumber { .. })),
            "{:?}",
            found.problems()
        );
    }

    /// The by-name tests do not depend on the listing, so a directory the bound refuses still
    /// yields the two kinds that can be merged.
    #[test]
    fn a_directory_over_the_listing_bound_still_yields_its_pacnew() {
        let (_fixture, db) = database(&[("foo-1.0.0-1", &["etc/foo.conf"])]);
        let dir = root(&[("etc/foo.conf", b"mine"), ("etc/foo.conf.pacnew", b"theirs")]);
        for index in 0..20 {
            std::fs::write(dir.path().join(format!("etc/filler{index}")), b"x").unwrap();
        }

        let root_dir = RootDir::open(dir.path()).unwrap();
        let limits = ScanLimits { max_dir_entries: 3, ..ScanLimits::default() };
        let found = scan(&root_dir, &db, &limits);

        assert_eq!(found.pending().len(), 1);
        assert_eq!(found.pending().first().unwrap().kind, PendingKind::Pacnew);
        assert!(
            matches!(found.problems().first(), Some(Problem::UnlistableDirectory { .. })),
            "{:?}",
            found.problems()
        );
    }

    #[test]
    fn the_pending_bound_truncates_and_counts_what_it_withheld() {
        let (_fixture, db) =
            database(&[("foo-1.0.0-1", &["etc/a.conf", "etc/b.conf", "etc/c.conf"])]);
        let dir = root(&[
            ("etc/a.conf", b"mine"),
            ("etc/a.conf.pacnew", b"theirs"),
            ("etc/b.conf", b"mine"),
            ("etc/b.conf.pacnew", b"theirs"),
            ("etc/c.conf", b"mine"),
            ("etc/c.conf.pacnew", b"theirs"),
        ]);

        let root_dir = RootDir::open(dir.path()).unwrap();
        let limits = ScanLimits { max_pending: 2, ..ScanLimits::default() };
        let found = scan(&root_dir, &db, &limits);

        assert_eq!(found.pending().len(), 2);
        assert_eq!(found.pending_dropped(), 1);
    }

    /// One unreadable package must not cost the rest of the scan.
    #[test]
    fn an_unreadable_entry_is_reported_and_the_scan_continues() {
        let fixture = DbFixture::new();
        fixture
            .package("broken-1.0.0-1")
            .with_defaults()
            .files("%BACKUP%\nnot a backup line\n")
            .build();
        fixture
            .package("foo-1.0.0-1")
            .with_defaults()
            .files(&files_body(&["etc/foo.conf"]))
            .build();
        let db = LocalDatabase::open(fixture.path()).unwrap();
        let dir = root(&[("etc/foo.conf", b"mine"), ("etc/foo.conf.pacnew", b"theirs")]);

        let found = run(&dir, &db);
        assert_eq!(found.pending().len(), 1, "{:?}", found.pending());
        assert!(
            matches!(found.problems().first(), Some(Problem::UnreadableEntry { .. })),
            "{:?}",
            found.problems()
        );
    }
}
