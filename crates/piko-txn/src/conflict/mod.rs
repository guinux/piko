//! File-conflict detection: does this transaction try to write a file that is not its own?
//!
//! `_alpm_db_find_fileconflicts` (`conflict.c:404`) performs two checks. piko keeps the same
//! two names because they answer genuinely different questions:
//!
//! 1. **target against target** — two packages in the same transaction both ship a path;
//! 2. **target against the filesystem** — something is already at a path a package will
//!    write, and no rule explains it.
//!
//! Check 1 is pure set arithmetic and lives in [`filelist`]. Check 2's rules are pure and
//! live in [`decision`]. What is left here is the part that has to touch a disk: `lstat`ing
//! each path inside the root, and asking the local database who owns what.
//!
//! # Why this is not optional
//!
//! Everything else in this crate refuses to leave the installation root, refuses to follow a
//! symlink, and refuses to put a file where a directory is. None of that helps against a
//! package that simply ships `usr/bin/ls`. Extraction would write it, the local database
//! would record two owners for one path, and removing either package would delete a file the
//! other still needs. This check is the only safeguard against that outcome, which is why it
//! runs during [`crate::Transaction::verify`] — the last state from which abandoning the
//! transaction leaves the system untouched.
//!
//! # What it costs
//!
//! Two of the rules ask the whole local database who owns a path. That forces every installed
//! package's `files` to be read. libalpm has the same data resident for other reasons; piko
//! does not. The load is deferred to the first query that actually needs one ([`Owners`]) and
//! then shared. A transaction whose packages ship no backup files and hit no conflicts never
//! pays it.
//!
//! Deferring the load is not the whole cost, and the rest is easy to miss. Most of
//! [`Owners`]'s accessors ask "who owns this path", which genuinely has to consider every
//! installed package — but they run rarely: once per reported conflict, or only for a backup
//! file. [`Owners::files_of`] is the opposite. It asks "what does *this named package* own".
//! [`examine`] calls it once per path **per other target in the transaction**, so a linear
//! scan of the installed set sits inside two nested loops. The check becomes quadratic in the
//! size of the plan.
//!
//! Measured against this machine's database, 85 677 paths held constant while the target count
//! varied: 1 target 5.1 s, 16 targets 7.0 s, 64 targets 13.7 s, 200 targets **32.0 s**. With
//! `files_of` indexed by name, the same runs are 6.5 / 5.1 / 5.5 / **7.1** s. The target count
//! nearly stops mattering, and the remaining ~5 s is the `lstat` of every path — the work the
//! check exists to do. Both versions report the same 72 516 conflicts.
//!
//! Indexing `files_of` left one scan of the target list per path: [`examine`]'s "is this path
//! changing hands between two targets" question. That question is now answered from
//! [`Handover`], built once per [`check`]. Measured on the case that exercises it hardest,
//! targets rotated so that *every* path is new to its target and owned by another target's
//! installed version:
//!
//! | targets | paths | per-path scan | indexed |
//! | --- | --- | --- | --- |
//! | 20 | 6 201 | 0.73 s | 0.70 s |
//! | 50 | 15 024 | 1.10 s | 1.02 s |
//! | 100 | 49 757 | 3.34 s | 2.80 s |
//! | 200 | 85 677 | 5.75 s | 4.55 s |
//! | 400 | 140 181 | **11.29 s** | **6.68 s** |
//!
//! No size is slower. That was the thing worth checking rather than assuming: the index has to
//! be built before it can save anything, and a plan of twenty packages is the ordinary case
//! while four hundred is `kde-applications-meta`. It costs one entry per distinct path across
//! the targets' installed file lists. Every row above produces byte-identical output,
//! `skip_remove` included (115 256 entries in the last one), checked by digest.

pub mod decision;
pub mod filelist;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use piko_db::LocalDatabase;

use crate::{
    conflict::{
        decision::{FilesystemContext, Resolution, Verdict, decide},
        filelist::{FileList, is_directory, strip_dir},
    },
    error::Result,
    extract::decision::Existing,
    rootfs::RootDir,
    scriptlet::MAX_SCRIPTLET_BYTES,
};

/// A package this transaction will install, as far as conflict detection is concerned.
#[derive(Clone, Debug)]
pub struct Target {
    /// The package name, as `%NAME%` spells it.
    pub name: String,
    /// The package version, as `.PKGINFO`'s `pkgver` spells it.
    ///
    /// Read here because `.PKGINFO` is already being parsed for the name. A scriptlet that
    /// runs *before* extraction needs the version without a second pass over the archive.
    pub version: String,
    /// Every path the package ships, directories with their trailing `/`.
    pub files: FileList,
    /// Paths the package declares as `%BACKUP%`.
    pub backups: BTreeSet<String>,
    /// The package's `.INSTALL` scriptlet, if it ships one.
    ///
    /// Not a conflict-detection concern. It is carried here for one measurable reason: the
    /// `pre_install`/`pre_upgrade` function must run **before** the package is extracted, so it
    /// cannot come from the extraction that follows. Reading it needs a full pass over an
    /// archive this function is already making. A second pass would mean decompressing every
    /// package twice. libalpm pays that cost — `_alpm_unpack_single` re-opens the archive
    /// (`trans.c:379`) — and piko does not have to.
    ///
    /// `None` for a package with no scriptlet, which is most of them.
    pub install_script: Option<Vec<u8>>,
}

/// What is in the way, and who put it there.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Blocker {
    /// Another package in this same transaction ships the path.
    Target {
        /// Its name.
        other: String,
    },
    /// Something is already on the filesystem.
    Filesystem {
        /// The installed package that owns it, if any owns it.
        ///
        /// `None` means the path is unowned — a file some other tool or the user put there.
        owner: Option<String>,
    },
}

impl std::fmt::Display for Blocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Target { other } => write!(f, "also in {other}"),
            Self::Filesystem { owner: Some(owner) } => write!(f, "owned by {owner}"),
            Self::Filesystem { owner: None } => f.write_str("exists in filesystem"),
        }
    }
}

/// One path this transaction cannot write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileConflict {
    /// The package that wanted to write it.
    pub package: String,
    /// The path, relative to the installation root.
    pub path: PathBuf,
    /// What is in the way.
    pub blocker: Blocker,
}

impl std::fmt::Display for FileConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} ({})", self.package, self.path.display(), self.blocker)
    }
}

/// The result of checking a transaction.
#[derive(Clone, Debug, Default)]
pub struct Check {
    /// Every conflict found, in target order then path order.
    pub conflicts: Vec<FileConflict>,
    /// Paths that must not be deleted by a removal step in this transaction.
    ///
    /// libalpm's `trans->skip_remove` (`conflict.c:591`). A path that changes owner between
    /// two packages being upgraded together is installed by its new owner. Without this
    /// entry, the old owner's removal then deletes it — leaving the file missing and the new
    /// package's database entry claiming it.
    pub skip_remove: BTreeSet<PathBuf>,
}

impl Check {
    /// Whether the transaction may proceed.
    #[must_use]
    pub fn is_clear(&self) -> bool {
        self.conflicts.is_empty()
    }
}

/// Bounds on the directory walk the "emptied by this transaction" rule performs.
///
/// That rule is the only part of conflict detection that reads a directory it was not told
/// about. It is therefore the only part whose cost is not a function of the packages
/// involved. Without these bounds, a deep or wide tree under a single conflicting path would
/// decide how long the check takes.
#[derive(Clone, Copy, Debug)]
pub struct WalkLimits {
    /// How deep the walk may recurse below the directory it starts at.
    pub max_depth: u32,
    /// How many entries the walk may examine in total.
    pub max_entries: usize,
}

impl Default for WalkLimits {
    fn default() -> Self {
        // These bounds are generous against real trees: the deepest path in this machine's
        // database is well under 20 components. They are also small enough that neither bound
        // funds a stall.
        Self { max_depth: 64, max_entries: 100_000 }
    }
}

/// Which paths the user has released piko from protecting — pacman's `--overwrite`.
///
/// This is a predicate rather than a pattern list, for the same reason [`crate::Filters`]
/// holds predicates: this crate does not need an opinion about glob syntax. A test can supply
/// an exact answer instead of a pattern that has to be right twice.
pub struct Overwrite(Box<dyn Fn(&Path) -> bool + Send + Sync>);

impl Overwrite {
    /// Releases the paths `matches` accepts.
    #[must_use]
    pub fn new(matches: impl Fn(&Path) -> bool + Send + Sync + 'static) -> Self {
        Self(Box::new(matches))
    }

    /// Whether `path` is released.
    #[must_use]
    pub fn matches(&self, path: &Path) -> bool {
        (self.0)(path)
    }
}

impl Default for Overwrite {
    /// Releases nothing, which is pacman's default and the only safe one.
    fn default() -> Self {
        Self::new(|_| false)
    }
}

impl std::fmt::Debug for Overwrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Overwrite").finish_non_exhaustive()
    }
}

/// The installed set, in database order, with a name index beside it.
///
/// The two are **not** redundant. Collapsing them into a `HashMap` alone would be a
/// behavioural change, not a simplification: [`Owners::owner_of`] answers with the *first*
/// package owning a path, as `_alpm_find_file_owner` does. The order a walk sees has to be the
/// database's, not a hash's.
#[derive(Debug)]
struct Installed {
    /// Every installed package and its file list, in database order.
    packages: Vec<(String, FileList)>,
    /// Where each name sits in `packages`.
    by_name: std::collections::HashMap<String, usize>,
}

/// Who owns what, loaded from the local database only once something asks.
///
/// Deliberately not built in the constructor. Most transactions never reach a rule that needs
/// it, and building it forces every installed package's `files` to be read.
#[derive(Debug)]
struct Owners<'db> {
    local: &'db LocalDatabase,
    loaded: Option<Installed>,
}

impl<'db> Owners<'db> {
    const fn new(local: &'db LocalDatabase) -> Self {
        Self { local, loaded: None }
    }

    /// The installed set, reading it on the first call.
    fn installed(&mut self) -> &Installed {
        let local = self.local;
        self.loaded.get_or_insert_with(|| {
            let packages: Vec<(String, FileList)> = local
                .iter()
                .map(|package| {
                    // A package whose `files` cannot be read contributes an empty list. This is
                    // the safe direction: it makes paths look unowned, which produces a
                    // conflict rather than suppressing one.
                    let files = package
                        .file_list()
                        .map(|paths| {
                            FileList::new(
                                paths.iter().map(|path| path.to_string_lossy().into_owned()),
                            )
                        })
                        .unwrap_or_default();
                    (package.name().to_string(), files)
                })
                .collect();
            // First occurrence wins, so the index agrees with the ordered walk about which
            // package a name refers to. A local database cannot hold two entries of one name.
            // This choice only matters for staying honest about what the index means.
            let mut by_name = std::collections::HashMap::with_capacity(packages.len());
            for (index, (name, _)) in packages.iter().enumerate() {
                by_name.entry(name.clone()).or_insert(index);
            }
            Installed { packages, by_name }
        })
    }

    /// Every installed package and its file list, in database order.
    fn all(&mut self) -> &[(String, FileList)] {
        &self.installed().packages
    }

    /// The first installed package owning `path` exactly, as `_alpm_find_file_owner` does.
    fn owner_of(&mut self, path: &str) -> Option<String> {
        self.all().iter().find(|(_, files)| files.contains(path)).map(|(name, _)| name.clone())
    }

    /// Every installed package owning `path` exactly.
    fn owners_of(&mut self, path: &str) -> Vec<String> {
        self.all()
            .iter()
            .filter(|(_, files)| files.contains(path))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Whether any installed package owns `path` exactly.
    fn anyone_owns(&mut self, path: &str) -> bool {
        self.all().iter().any(|(_, files)| files.contains(path))
    }

    /// The file list of an installed package, if it is installed.
    ///
    /// Indexed rather than scanned. That is not premature: this is the one accessor asked per
    /// **path and per target** — [`examine`] consults it once for every other target in the
    /// transaction — so a linear scan would put the whole installed set inside two nested
    /// loops. See the module's "What it costs" note for the measurement.
    fn files_of(&mut self, name: &str) -> Option<&FileList> {
        let installed = self.installed();
        let index = *installed.by_name.get(name)?;
        installed.packages.get(index).map(|(_, files)| files)
    }
}

/// Checks `targets` against each other and against the filesystem under `root`.
///
/// `removals` names the packages this transaction removes. This is what lets a path being
/// vacated stop being a conflict. `overwrite` answers the `--overwrite` patterns. It is a
/// predicate rather than a pattern list for the same reason [`crate::Filters`] is.
///
/// # Errors
///
/// [`crate::Error`] only for a path that cannot be resolved inside the root. A path that
/// simply does not exist, or a directory that cannot be read, is an answer rather than a
/// failure.
pub fn check(
    root: &RootDir,
    local: &LocalDatabase,
    targets: &[Target],
    removals: &[String],
    overwrite: &Overwrite,
    limits: &WalkLimits,
) -> Result<Check> {
    let mut result = Check::default();
    let mut owners = Owners::new(local);

    check_targets(targets, overwrite, &mut result);
    check_filesystem(root, &mut owners, targets, removals, overwrite, limits, &mut result)?;

    Ok(result)
}

/// One target's entry, keyed by the path [`FileList::intersection`] compares on.
///
/// Ordered as `(stripped path, target, spelling)`. Sorting on this tuple groups every target
/// that ships one path together, and orders the group by target and then by spelling — the
/// same order the nested loops this replaces produced.
type Shipped<'a> = (&'a str, usize, &'a str);

/// Check 1: every target against every other target (`conflict.c:432`).
///
/// # Not a loop over pairs
///
/// `conflict.c:432` is a double loop calling `_alpm_filelist_intersection` on each pair. That is
/// quadratic in the number of targets *and* linear in the file lists: [`FileList::intersection`]
/// builds a map of the whole right-hand list every time it is called. A 500-package transaction
/// would take ~125 000 intersections, each rebuilding a map of a list it had already seen
/// hundreds of times.
///
/// A path can only collide if two targets ship it, so the work belongs to the *paths*, not to
/// the pairs. Every entry of every target is sorted once by stripped path. A run of equal
/// stripped paths that comes from a single target — which is almost all of them — is skipped
/// whole. Only a genuinely shared path is expanded into pairs, and there are few.
///
/// The second fast path is the one that is easy to leave out, and it would undo most of this. A
/// shared *directory* is not a conflict, and `usr/`, `usr/bin/`, and `usr/share/` are shipped by
/// nearly every package. Those groups hold one run per target, so expanding them into pairs
/// anyway would put the target count straight back inside a quadratic. A group whose entries
/// are all directories is therefore dropped in one linear scan.
///
/// The result is identical, ordering included. `found` is sorted by
/// `(first target, second target, spelling)` before anything is reported. That matches exactly
/// what the nested loops emitted: the outer loop ascending, the inner loop ascending, and each
/// intersection yielding the left-hand list in its own sorted order.
///
/// Measured against real package file lists, each duplicated under a second name so that every
/// path genuinely collides, timed with an empty root so that check 2 returns immediately:
///
/// | targets | paths | pairwise | indexed |
/// | --- | --- | --- | --- |
/// | 100 | 30 048 | 405 ms | 168 ms |
/// | 200 | 99 514 | 2.66 s | 551 ms |
/// | 400 | 171 354 | 7.30 s | 983 ms |
/// | 800 | 280 362 | **20.38 s** | **1.59 s** |
///
/// The pairwise column roughly triples per doubling; the indexed one tracks the path count.
/// Both produce the same conflicts in the same order: 115 257 of them in the last row, checked
/// by digest, and pinned for the small cases by
/// `the_indexed_check_agrees_with_the_pairwise_loop`.
fn check_targets(targets: &[Target], overwrite: &Overwrite, into: &mut Check) {
    let mut entries: Vec<Shipped<'_>> = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        entries.extend(target.files.iter().map(|entry| (strip_dir(entry), index, entry)));
    }
    entries.sort_unstable();

    let mut found: Vec<(usize, usize, &str)> = Vec::new();
    for group in entries.chunk_by(|left, right| left.0 == right.0) {
        // The entries are sorted by target within the group. First and last agreeing means one
        // target ships this path, so there is nothing for it to collide with. This holds for
        // very nearly every path, and it costs one comparison and no allocation.
        let (Some(first), Some(last)) = (group.first(), group.last()) else { continue };
        if first.1 == last.1 {
            continue;
        }

        // Two packages owning one directory is normal, and a pair is spared only when *both*
        // sides are directories. So a group that is all directories yields nothing whatever
        // its size. That case is worth a linear scan: `usr/`, `usr/bin/`, and `usr/share/` are
        // shipped by nearly every package on the system, so these groups hold one run per
        // target. Expanding them into pairs anyway would put the target count back inside a
        // quadratic, which is what this rewrite exists to remove.
        if group.iter().all(|(_, _, entry)| is_directory(entry)) {
            continue;
        }

        // `_alpm_filelist_intersection` asks whether the *other* side holds a non-directory
        // under this path. This is answered once per run here rather than once per pair, so a
        // group that does contain a file cannot make the walk cubic in the number of targets.
        let runs: Vec<(usize, &[Shipped<'_>], bool)> = group
            .chunk_by(|left, right| left.1 == right.1)
            .filter_map(|run| {
                let &(_, target, _) = run.first()?;
                Some((target, run, run.iter().any(|(_, _, entry)| !is_directory(entry))))
            })
            .collect();

        for (position, &(_, left, _)) in runs.iter().enumerate() {
            for &(other, _, right_has_file) in runs.iter().skip(position.saturating_add(1)) {
                for &(_, mine, entry) in left {
                    if !is_directory(entry) || right_has_file {
                        found.push((mine, other, entry));
                    }
                }
            }
        }
    }
    found.sort_unstable();

    for (first, second, path) in found {
        let (Some(first), Some(second)) = (targets.get(first), targets.get(second)) else {
            continue;
        };
        // `--overwrite` releases a file-against-file collision only. libalpm expresses that
        // by re-testing the path against the *other* package's list with an exact comparison
        // (`conflict.c:455`). The intersection returns the path as the first package spells
        // it, so an exact hit means both spell it the same way, and a file-against-directory
        // pair cannot match.
        if overwrite.matches(Path::new(path)) && second.files.contains(path) {
            continue;
        }
        into.conflicts.push(FileConflict {
            package: first.name.clone(),
            path: PathBuf::from(path),
            blocker: Blocker::Target { other: second.name.clone() },
        });
    }
}

/// Which targets' *installed* versions own one path — enough of them to answer [`examine`]'s
/// "is this changing hands" question without walking the target list per path.
///
/// # Two entries, and two is provably enough
///
/// The question is: the first target, in target order, whose name differs from the one being
/// examined and whose installed version owns this path. The only name that can ever be excluded
/// is the examined target's own, so exactly two cases arise:
///
/// - `first`'s name differs from it — `first` is the answer.
/// - `first`'s name *is* it — then every owner between `first` and [`Self::runner_up`] shares
///   that name by construction, so all of them are excluded too. `runner_up` (the first owner
///   with a name different from `first`'s) is the answer.
///
/// A third entry could never be reached: `runner_up`'s name differs from `first`'s, which in
/// that branch is the examined target's. So `runner_up` is never itself excluded.
#[derive(Clone, Copy, Debug)]
struct Handover {
    /// The lowest target index whose installed version owns the path.
    first: usize,
    /// The lowest target index after `first` whose *name* differs from `first`'s.
    runner_up: Option<usize>,
}

impl Handover {
    /// The first owner whose name is not `name`, in target order.
    fn other_than<'a>(&self, name: &str, targets: &'a [Target]) -> Option<&'a str> {
        let first = targets.get(self.first)?;
        if first.name != name {
            return Some(&first.name);
        }
        let runner_up = targets.get(self.runner_up?)?;
        Some(&runner_up.name)
    }
}

/// Indexes every target's installed file list by path, once per [`check`].
///
/// This replaces a scan of every target for every path, which made check 2 grow with the
/// product of the two. The keys are the paths **exactly as the installed package spells them**,
/// because the lookup it serves is `FileList::contains`, which compares exactly. A directory
/// recorded as `usr/lib/` is therefore never matched by a query for `usr/lib` — the same
/// behaviour the scan had.
fn handovers(owners: &mut Owners<'_>, targets: &[Target]) -> HashMap<String, Handover> {
    let mut index: HashMap<String, Handover> = HashMap::new();
    for (position, target) in targets.iter().enumerate() {
        let Some(files) = owners.files_of(&target.name) else { continue };
        for entry in files.iter() {
            index
                .entry(entry.to_owned())
                .and_modify(|handover| {
                    // Targets arrive in order, so the first differing name met is the lowest.
                    if handover.runner_up.is_none()
                        && targets.get(handover.first).is_some_and(|held| held.name != target.name)
                    {
                        handover.runner_up = Some(position);
                    }
                })
                .or_insert(Handover { first: position, runner_up: None });
        }
    }
    index
}

/// Check 2: every target against the filesystem (`conflict.c:477`).
fn check_filesystem(
    root: &RootDir,
    owners: &mut Owners<'_>,
    targets: &[Target],
    removals: &[String],
    overwrite: &Overwrite,
    limits: &WalkLimits,
    into: &mut Check,
) -> Result<()> {
    // This is built once for the whole check, not consulted per target per path. See
    // `handovers`.
    let handovers = self::handovers(owners, targets);

    for target in targets {
        // Only paths that are *new* need checking. This package may overwrite a path its own
        // installed version already owns.
        let installed = owners.files_of(&target.name).cloned();
        let new_paths: Vec<String> = match &installed {
            Some(old) => target.files.difference(old).into_iter().map(ToOwned::to_owned).collect(),
            None => target.files.iter().map(ToOwned::to_owned).collect(),
        };

        let mut index = 0_usize;
        while let Some(spelled) = new_paths.get(index) {
            index = index.saturating_add(1);
            let verdict = examine(
                root,
                owners,
                target,
                installed.as_ref(),
                spelled,
                targets,
                &handovers,
                removals,
                overwrite,
                limits,
            )?;

            if verdict.changes_owner_from().is_some() {
                into.skip_remove.insert(PathBuf::from(strip_dir(spelled)));
            }

            // libalpm advances past everything nested under a directory whose resolution
            // already covers its contents (`conflict.c:542`). Checking them anyway would
            // report conflicts the resolution has already answered.
            if verdict.skips_directory_contents() && is_directory(spelled) {
                while new_paths.get(index).is_some_and(|next| next.starts_with(spelled.as_str())) {
                    index = index.saturating_add(1);
                }
            }

            if verdict == Verdict::Conflict {
                let stripped = strip_dir(spelled).to_owned();
                into.conflicts.push(FileConflict {
                    package: target.name.clone(),
                    path: PathBuf::from(&stripped),
                    blocker: Blocker::Filesystem { owner: owners.owner_of(&stripped) },
                });
            }
        }
    }
    Ok(())
}

/// Answers every question [`decide`] asks about one path.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument answers one of the rules' inputs; bundling them into a struct \
              would only move the same list one line up"
)]
fn examine(
    root: &RootDir,
    owners: &mut Owners<'_>,
    target: &Target,
    installed: Option<&FileList>,
    spelled: &str,
    targets: &[Target],
    handovers: &HashMap<String, Handover>,
    removals: &[String],
    overwrite: &Overwrite,
    limits: &WalkLimits,
) -> Result<Verdict> {
    let packaged_directory = is_directory(spelled);
    // Every lookup below uses the path without its trailing slash, matching libalpm. libalpm
    // truncates it in place before the first of them (`conflict.c:530`).
    let stripped = strip_dir(spelled);
    let as_path = Path::new(stripped);

    let existing = crate::install::probe_existing(root, as_path);
    if existing == Existing::Absent {
        return Ok(Verdict::Resolved(Resolution::NotPresent));
    }

    let mut context = FilesystemContext {
        package_says_directory: packaged_directory,
        existing,
        resolves_to_directory: resolves_to_directory(root, as_path),
        old_version_owns_file: installed.is_some_and(|files| files.contains(stripped)),
        owned_by_removal: false,
        changing_owner_from: None,
        directory_emptied_by_transaction: false,
        // libalpm matches `--overwrite` against the path as the package spells it *and*
        // against the rooted path (`conflict.c:385`). The relative form is the one a user
        // writes a pattern for.
        new_is_backup: target.backups.contains(stripped),
        owned_by_anyone: false,
        overwrite: overwrite.matches(as_path),
    };

    // Does a package this transaction removes own it?
    for removed in removals {
        if owners.files_of(removed).is_some_and(|files| files.contains(stripped)) {
            context.owned_by_removal = true;
            break;
        }
    }

    // Is it changing hands between two packages this transaction upgrades? Only the *other*
    // targets matter; a collision between two targets is check 1's business. This is answered
    // from the precomputed index rather than by scanning every target. See `Handover`.
    let previous_owner = if context.owned_by_removal {
        None
    } else {
        handovers.get(stripped).and_then(|handover| handover.other_than(&target.name, targets))
    };
    context.changing_owner_from = previous_owner;

    // Only a directory needs the walk, and only once the rules above have all missed.
    if existing == Existing::Directory && !packaged_directory && previous_owner.is_none() {
        context.directory_emptied_by_transaction =
            directory_is_vacated(root, owners, stripped, &target.name, removals, limits);
    }

    if context.new_is_backup {
        context.owned_by_anyone = owners.anyone_owns(stripped);
    }

    Ok(decide(&context))
}

/// Whether `path` inside `root` is a directory once symlinks are followed.
fn resolves_to_directory(root: &RootDir, path: &Path) -> bool {
    let Ok(resolved) = root.resolve_parent(path) else { return false };
    rustix::fs::statat(resolved.dir(), resolved.name(), rustix::fs::AtFlags::empty()).is_ok_and(
        |stat| rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory,
    )
}

/// Whether every file under `dir` belongs to a package this transaction is getting rid of.
///
/// `conflict.c:613-642` states two rules in one. First its precondition: the directory must
/// have owners, and every one of them must be either the installed version of the package
/// being installed or a package being removed. Only then does it walk the directory
/// (`dir_belongsto_pkgs`, `conflict.c:308`) and require every entry inside to be owned by one
/// of them too.
///
/// A directory it cannot read answers `false`. That is the conservative direction, and it
/// matches libalpm.
fn directory_is_vacated(
    root: &RootDir,
    owners: &mut Owners<'_>,
    dir: &str,
    target_name: &str,
    removals: &[String],
    limits: &WalkLimits,
) -> bool {
    let with_slash = format!("{dir}/");
    let claimants = owners.owners_of(&with_slash);
    if claimants.is_empty() {
        return false;
    }

    let going_away: BTreeSet<&str> =
        removals.iter().map(String::as_str).chain(std::iter::once(target_name)).collect();
    if !claimants.iter().all(|owner| going_away.contains(owner.as_str())) {
        return false;
    }

    // The file lists to test entries against are exactly the claimants'. The precondition has
    // just shown this set to be a subset of what is going away.
    let lists: Vec<FileList> =
        claimants.iter().filter_map(|name| owners.files_of(name).cloned()).collect();

    let mut budget = limits.max_entries;
    everything_below_is_owned(root, &with_slash, &lists, limits.max_depth, &mut budget)
}

/// Recursive half of [`directory_is_vacated`], bounded in depth and in entries examined.
fn everything_below_is_owned(
    root: &RootDir,
    dir: &str,
    lists: &[FileList],
    depth_left: u32,
    budget: &mut usize,
) -> bool {
    if depth_left == 0 {
        return false;
    }
    let Some(entries) = read_directory(root, dir) else { return false };

    for (name, is_dir) in entries {
        let Some(next) = budget.checked_sub(1) else { return false };
        *budget = next;

        let child = if is_dir { format!("{dir}{name}/") } else { format!("{dir}{name}") };
        if !lists.iter().any(|files| files.contains(&child)) {
            return false;
        }
        if is_dir
            && !everything_below_is_owned(root, &child, lists, depth_left.saturating_sub(1), budget)
        {
            return false;
        }
    }
    true
}

/// The entries of `dir` inside `root`, as `(name, is_directory)`, or `None` if unreadable.
///
/// This opens `O_NOFOLLOW | O_DIRECTORY` from the parent's descriptor, so the directory read is
/// the one that was resolved, not whatever the path names by the time it is opened.
fn read_directory(root: &RootDir, dir: &str) -> Option<Vec<(String, bool)>> {
    let resolved = root.resolve_parent(Path::new(strip_dir(dir))).ok()?;
    let handle = rustix::fs::openat(
        resolved.dir(),
        resolved.name(),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .ok()?;

    let mut listing = Vec::new();
    for entry in rustix::fs::Dir::read_from(&handle).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name().to_str().ok()?;
        if name == "." || name == ".." {
            continue;
        }
        // `d_type` is unavailable on some filesystems, so an `fstatat` settles it. An
        // assumption instead could make an unowned subdirectory look like an owned file.
        let is_dir = match entry.file_type() {
            rustix::fs::FileType::Directory => true,
            rustix::fs::FileType::Unknown => rustix::fs::statat(
                &handle,
                entry.file_name(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .is_ok_and(|stat| {
                rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory
            }),
            _ => false,
        };
        listing.push((name.to_owned(), is_dir));
    }
    Some(listing)
}

/// A package archive read once: its conflict-detection view, and its validated `.PKGINFO`.
///
/// The two travel together because they come from one walk of one archive, and because both
/// must be known before [`crate::Transaction::verify`] returns. A `.PKGINFO` the typed parse
/// rejects is a package piko cannot record. Discovering that after extraction has run would
/// leave a mutated root behind, which is exactly what `Verified` promises it will not.
#[derive(Clone, Debug)]
pub struct LoadedPackage {
    /// Everything file-conflict detection asks about the package.
    pub target: Target,
    /// The parsed `.PKGINFO`.
    pub info: alpm_pkginfo::PackageInfo,
    /// Its text, verbatim.
    ///
    /// [`crate::record::desc`] needs both the bytes and the interpretation, for the fields
    /// that must survive byte-for-byte.
    pub raw: String,
}

/// Reads a package archive: its member list, its `.INSTALL`, and its `.PKGINFO`.
///
/// The file list must come from the archive: the package is not installed yet, so there is no
/// `%FILES%` to read, and the repository's `.files` database describes a build that may not be
/// the one in the cache. pacman resolves this the same way, loading the package files before
/// checking (`sync.c`'s `load_packages` ahead of `_alpm_sync_check`).
///
/// # Errors
///
/// [`crate::Error::UnusableSource`] if the archive has no readable `.PKGINFO`, or one that
/// `alpm-pkginfo` refuses; otherwise [`crate::Error`] if the archive cannot be read.
pub fn load_package(
    package: &Path,
    limits: &crate::extract::PackageLimits,
) -> Result<LoadedPackage> {
    let mut paths: Vec<String> = Vec::new();
    let mut pkginfo: Option<String> = None;
    let mut install_script: Option<Vec<u8>> = None;

    crate::extract::archive::walk(package, limits, |member, contents| {
        if member.kind == crate::extract::archive::MemberKind::Metadata {
            if member.path == Path::new(".PKGINFO") {
                let mut text = String::new();
                // A `.PKGINFO` that is not valid UTF-8 leaves nothing to parse. It is reported
                // below as the absence it amounts to.
                let mut limited = std::io::Read::take(contents, MAX_PKGINFO_BYTES);
                if std::io::Read::read_to_string(&mut limited, &mut text).is_ok() {
                    pkginfo = Some(text);
                }
            } else if member.path == Path::new(".INSTALL") {
                let mut bytes = Vec::new();
                let mut limited = std::io::Read::take(contents, MAX_SCRIPTLET_BYTES);
                if std::io::Read::read_to_end(&mut limited, &mut bytes).is_ok() {
                    install_script = Some(bytes);
                }
            }
            return Ok(());
        }
        let mut spelled = member.path.to_string_lossy().into_owned();
        if member.entry == crate::extract::decision::EntryKind::Directory && !spelled.ends_with('/')
        {
            // `%FILES%` and this check both use the trailing slash to mean "directory". A tar
            // writer is not obliged to include it.
            spelled.push('/');
        }
        paths.push(spelled);
        Ok(())
    })?;

    let Some(raw) = pkginfo else {
        return Err(crate::Error::UnusableSource {
            path: package.to_path_buf(),
            reason: "the package has no readable .PKGINFO".to_owned(),
        });
    };
    let info = crate::pkginfo::parse(&raw).map_err(|error| crate::Error::UnusableSource {
        path: package.to_path_buf(),
        reason: format!("its .PKGINFO is unreadable: {error}"),
    })?;

    let (name, version) = match &info {
        alpm_pkginfo::PackageInfo::V1(v1) => (v1.pkgname.to_string(), v1.pkgver.to_string()),
        alpm_pkginfo::PackageInfo::V2(v2) => (v2.pkgname.to_string(), v2.pkgver.to_string()),
    };
    // `%BACKUP%` paths are taken from the text rather than from the parsed `Backup` values,
    // because they are compared against the paths the *archive* spells. A round trip through
    // a typed path that normalises anything could make that comparison miss — the same hazard
    // `record::desc` avoids for `%URL%`.
    let backups: BTreeSet<String> = raw
        .lines()
        .filter_map(|line| line.strip_prefix("backup = "))
        .map(|value| value.trim().to_owned())
        .collect();

    Ok(LoadedPackage {
        target: Target { name, version, files: FileList::new(paths), backups, install_script },
        info,
        raw,
    })
}

/// Largest `.PKGINFO` this reads. It is a few kilobytes in practice.
const MAX_PKGINFO_BYTES: u64 = 4 * 1024 * 1024;

/// Builds the [`Target`] view of an already-installed package, for a removal step.
///
/// [`Target::version`] is left empty. Conflict detection never reads it, and the only caller
/// that does — the scriptlet sequence — takes the version from the database entry it is
/// removing rather than from here.
#[must_use]
pub fn target_from_installed(name: &str, files: &[PathBuf]) -> Target {
    Target {
        name: name.to_owned(),
        version: String::new(),
        files: FileList::new(files.iter().map(|path| path.to_string_lossy().into_owned())),
        backups: BTreeSet::new(),
        // The removal side reads its scriptlet from the database entry, not from an archive.
        install_script: None,
    }
}

/// The installed packages' file lists, keyed by name — exposed for tests and for callers that
/// want to report ownership themselves.
#[must_use]
pub fn installed_file_lists(local: &LocalDatabase) -> BTreeMap<String, FileList> {
    let mut owners = Owners::new(local);
    owners.all().iter().cloned().collect()
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

    /// A local database holding `packages`, each with the file list given.
    fn database(packages: &[(&str, &[&str])]) -> (DbFixture, LocalDatabase) {
        let fixture = DbFixture::new();
        for (entry, files) in packages {
            let body = std::iter::once("%FILES%".to_owned())
                .chain(files.iter().map(|path| (*path).to_owned()))
                .collect::<Vec<_>>()
                .join("\n");
            fixture.package(entry).with_defaults().files(&format!("{body}\n")).build();
        }
        let local = LocalDatabase::open(fixture.path()).unwrap();
        (fixture, local)
    }

    /// An installation root with the given entries already in it.
    fn filesystem(entries: &[(&str, Entry)]) -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().unwrap();
        for (path, kind) in entries {
            let full = dir.path().join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            match kind {
                Entry::File => std::fs::write(&full, b"contents").unwrap(),
                Entry::Dir => std::fs::create_dir_all(&full).unwrap(),
                Entry::SymlinkTo(target) => {
                    std::os::unix::fs::symlink(target, &full).unwrap();
                }
            }
        }
        let root = RootDir::open(dir.path()).unwrap();
        (dir, root)
    }

    enum Entry {
        File,
        Dir,
        SymlinkTo(&'static str),
    }

    fn target(name: &str, files: &[&str]) -> Target {
        Target {
            name: name.to_owned(),
            version: "1.0.0-1".to_owned(),
            files: FileList::new(files.iter().copied()),
            backups: BTreeSet::new(),
            install_script: None,
        }
    }

    fn run(
        root: &RootDir,
        local: &LocalDatabase,
        targets: &[Target],
        removals: &[String],
    ) -> Check {
        check(root, local, targets, removals, &Overwrite::default(), &WalkLimits::default())
            .unwrap()
    }

    /// Nothing installed, nothing on disk: the ordinary install.
    #[test]
    fn a_clean_install_has_no_conflicts() {
        let (_keep, local) = database(&[]);
        let (_dir, root) = filesystem(&[]);
        let result =
            run(&root, &local, &[target("foo", &["usr/", "usr/bin/", "usr/bin/foo"])], &[]);
        assert!(result.is_clear(), "{:?}", result.conflicts);
    }

    /// The per-path scan `Handover` replaces, kept as the reference.
    ///
    /// This is the rule verbatim: the first target, in target order, whose name differs from
    /// the one being examined and whose *installed* version owns `stripped` exactly.
    fn scan_previous_owner<'a>(
        owners: &mut Owners<'_>,
        targets: &'a [Target],
        target: &Target,
        stripped: &str,
    ) -> Option<&'a str> {
        for other in targets {
            if other.name == target.name {
                continue;
            }
            if owners.files_of(&other.name).is_some_and(|files| files.contains(stripped)) {
                return Some(&other.name);
            }
        }
        None
    }

    /// The index must answer identically to the scan for **every** target and every path, not
    /// merely for the paths a conflict is reported on: the answer feeds `changing_owner_from`,
    /// which decides `skip_remove` and names a package in the resolution.
    fn assert_handovers_agree(packages: &[(&str, &[&str])], targets: &[Target], probes: &[&str]) {
        let (_keep, local) = database(packages);
        let mut owners = Owners::new(&local);
        let index = handovers(&mut owners, targets);

        for target in targets {
            for path in probes {
                let indexed = index
                    .get(*path)
                    .and_then(|handover| handover.other_than(&target.name, targets));
                let scanned = scan_previous_owner(&mut owners, targets, target, path);
                assert_eq!(
                    indexed, scanned,
                    "target {} path {path}: index said {indexed:?}, scan said {scanned:?}",
                    target.name
                );
            }
        }
    }

    /// Every shape the two-entry `Handover` has to get right, including the ones that make two
    /// entries necessary rather than one.
    #[test]
    fn the_handover_index_agrees_with_the_per_target_scan() {
        // A path owned only by the examined target's own installed version. The scan filters
        // it out by name and finds nothing, so the index must not offer it either.
        assert_handovers_agree(
            &[("foo-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/only-foo"])],
            &[target("foo", &["usr/bin/only-foo"])],
            &["usr/bin/only-foo", "usr/bin/absent"],
        );

        // Owned by the examined target *and* another. `first` is the examined one, so the
        // answer must come from `runner_up`. This is the case one entry cannot serve.
        assert_handovers_agree(
            &[
                ("foo-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/shared"]),
                ("bar-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/shared"]),
            ],
            &[target("foo", &["usr/bin/shared"]), target("bar", &["usr/bin/shared"])],
            &["usr/bin/shared"],
        );

        // Three targets, two of them sharing a name. When `foo` is examined, both `foo` entries
        // are filtered, so the answer is the third — which is exactly why `runner_up` is keyed
        // on a differing *name* rather than simply being the second index seen.
        assert_handovers_agree(
            &[
                ("foo-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/shared"]),
                ("baz-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/shared"]),
            ],
            &[
                target("foo", &["usr/bin/shared"]),
                target("foo", &["usr/bin/shared"]),
                target("baz", &["usr/bin/shared"]),
            ],
            &["usr/bin/shared"],
        );

        // A target that is not installed at all contributes nothing. It must not shift the
        // indices of the ones that are.
        assert_handovers_agree(
            &[("bar-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/shared"])],
            &[
                target("new", &["usr/bin/shared"]),
                target("bar", &["usr/bin/shared"]),
                target("other", &["usr/bin/shared"]),
            ],
            &["usr/bin/shared"],
        );

        // Directory spellings. The lookup is exact, so an installed `usr/lib/` must not answer
        // a query for `usr/lib` — the scan's `contains` does not, and neither may the index.
        assert_handovers_agree(
            &[("dirs-1.0.0-1", &["usr/", "usr/lib/", "usr/lib/thing"])],
            &[target("other", &["usr/lib/thing"]), target("dirs", &["usr/lib/thing"])],
            &["usr/lib", "usr/lib/", "usr/", "usr", "usr/lib/thing"],
        );

        // Order: the answer is the *lowest* qualifying index, so reversing the targets must
        // change the answer in the same way for both.
        for targets in [
            vec![
                target("a", &["usr/bin/shared"]),
                target("b", &["usr/bin/shared"]),
                target("c", &["usr/bin/shared"]),
            ],
            vec![
                target("c", &["usr/bin/shared"]),
                target("b", &["usr/bin/shared"]),
                target("a", &["usr/bin/shared"]),
            ],
        ] {
            assert_handovers_agree(
                &[
                    ("a-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/shared"]),
                    ("b-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/shared"]),
                    ("c-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/shared"]),
                ],
                &targets,
                &["usr/bin/shared"],
            );
        }
    }

    /// `conflict.c:432`'s double loop, transcribed, so the rewrite above is checked against the
    /// algorithm it replaced rather than against a description of it.
    ///
    /// This is the same technique `filelist.rs` uses to pin `_alpm_filelist_intersection`.
    fn paired_check_targets(targets: &[Target], overwrite: &Overwrite, into: &mut Check) {
        for (index, first) in targets.iter().enumerate() {
            for second in targets.iter().skip(index.saturating_add(1)) {
                for path in first.files.intersection(&second.files) {
                    if overwrite.matches(Path::new(path)) && second.files.contains(path) {
                        continue;
                    }
                    into.conflicts.push(FileConflict {
                        package: first.name.clone(),
                        path: PathBuf::from(path),
                        blocker: Blocker::Target { other: second.name.clone() },
                    });
                }
            }
        }
    }

    /// The rewrite must agree with the pairwise loop **entry for entry and in order**, not
    /// merely as a set. `Check::conflicts` is printed to the user in the order it is built.
    fn assert_agrees(targets: &[Target], overwrite: &Overwrite) {
        let (mut fast, mut paired) = (Check::default(), Check::default());
        check_targets(targets, overwrite, &mut fast);
        paired_check_targets(targets, overwrite, &mut paired);
        assert_eq!(fast.conflicts, paired.conflicts);
    }

    /// The cases the rewrite could plausibly get wrong, each stated on purpose.
    #[test]
    fn the_indexed_check_agrees_with_the_pairwise_loop() {
        let cases: Vec<Vec<Target>> = vec![
            // Nothing at all, and a single target. These are the empty and one-run groups.
            vec![],
            vec![target("solo", &["usr/bin/a", "usr/"])],
            // The ordinary shared-directory case, which must stay silent.
            vec![
                target("a", &["usr/", "usr/bin/", "usr/bin/a"]),
                target("b", &["usr/", "usr/bin/", "usr/bin/b"]),
            ],
            // A file against a directory of the same name: the pair `strip_dir` exists for.
            vec![target("a", &["usr/lib/foo"]), target("b", &["usr/lib/foo/", "usr/lib/foo/x"])],
            // The same, with the file on the *right*. The rule is not symmetric in how it is
            // computed, even though the answer is.
            vec![target("a", &["usr/lib/foo/", "usr/lib/foo/x"]), target("b", &["usr/lib/foo"])],
            // Three targets sharing one path: every pair must be reported, in order.
            vec![
                target("a", &["usr/bin/tool"]),
                target("b", &["usr/bin/tool"]),
                target("c", &["usr/bin/tool"]),
            ],
            // One target shipping both spellings while another ships only one. The left-hand
            // list is what is walked, so the count depends on which side is which.
            vec![target("a", &["usr/lib/foo", "usr/lib/foo/"]), target("b", &["usr/lib/foo"])],
            vec![target("a", &["usr/lib/foo"]), target("b", &["usr/lib/foo", "usr/lib/foo/"])],
            // The byte-order trap: `!` sorts between a name and its trailing slash.
            vec![target("a", &["usr/lib/foo"]), target("b", &["usr/lib/foo!", "usr/lib/foo/"])],
            // Many paths per target, so the sort has runs longer than one to group.
            vec![
                target("a", &["etc/x", "usr/", "usr/bin/", "usr/bin/a", "usr/share/"]),
                target("b", &["etc/x", "usr/", "usr/bin/", "usr/bin/a", "usr/share"]),
                target("c", &["etc/y", "usr/", "usr/bin/"]),
            ],
            // Two targets of one name, which the check distinguishes by position only.
            vec![target("same", &["usr/bin/tool"]), target("same", &["usr/bin/tool"])],
            // A mixed group in which one pair must *still* be spared. Two targets ship the
            // directory and a third ships a file of the same name, so the group is not all
            // directories and the fast path does not apply. The directory-against-directory
            // pair inside it is still not a conflict. Without this case the both-are-
            // directories rule could be deleted outright and every other case here would still
            // pass, because the fast path answers them first.
            vec![
                target("a", &["usr/lib/foo/", "usr/lib/foo/x"]),
                target("b", &["usr/lib/foo/", "usr/lib/foo/y"]),
                target("c", &["usr/lib/foo"]),
            ],
            // The ordering case, and the only one here that fails if `found` is not sorted.
            //
            // The pairwise loop walks targets and reports `z` (shared with the *second*
            // target) before `a` (shared with the third). The rewrite walks paths, so it meets
            // `a` first. Without the final sort, the two disagree on order while agreeing on
            // content. A set comparison would miss exactly that kind of difference, and
            // `Check::conflicts` is printed in order.
            vec![
                target("p0", &["usr/bin/a", "usr/bin/z"]),
                target("p1", &["usr/bin/z"]),
                target("p2", &["usr/bin/a"]),
            ],
        ];

        for targets in &cases {
            assert_agrees(targets, &Overwrite::default());
            // `--overwrite` filters at the end, so it must not disturb the ordering either.
            assert_agrees(targets, &Overwrite::new(|path| path.starts_with("usr/lib")));
            assert_agrees(targets, &Overwrite::new(|_| true));
        }
    }

    /// Check 1: two packages in one transaction shipping the same file.
    #[test]
    fn two_targets_shipping_one_file_conflict() {
        let (_keep, local) = database(&[]);
        let (_dir, root) = filesystem(&[]);
        let result = run(
            &root,
            &local,
            &[target("foo", &["usr/bin/tool"]), target("bar", &["usr/bin/tool"])],
            &[],
        );
        assert_eq!(result.conflicts.len(), 1, "{:?}", result.conflicts);
        let conflict = result.conflicts.first().unwrap();
        assert_eq!(conflict.package, "foo");
        assert_eq!(conflict.path, PathBuf::from("usr/bin/tool"));
        assert_eq!(conflict.blocker, Blocker::Target { other: "bar".to_owned() });
    }

    /// And the shared directories they both ship are not reported. This is what makes the
    /// check usable at all — every package on the system ships `usr/bin/`.
    #[test]
    fn two_targets_sharing_directories_do_not_conflict() {
        let (_keep, local) = database(&[]);
        let (_dir, root) = filesystem(&[]);
        let result = run(
            &root,
            &local,
            &[
                target("foo", &["usr/", "usr/bin/", "usr/bin/foo"]),
                target("bar", &["usr/", "usr/bin/", "usr/bin/bar"]),
            ],
            &[],
        );
        assert!(result.is_clear(), "{:?}", result.conflicts);
    }

    /// Check 2, and the reason the whole module exists: a file another installed package owns.
    #[test]
    fn a_file_owned_by_an_installed_package_conflicts_and_names_the_owner() {
        let (_keep, local) = database(&[("other-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/tool"])]);
        let (_dir, root) = filesystem(&[("usr/bin/tool", Entry::File)]);

        let result = run(&root, &local, &[target("foo", &["usr/bin/tool"])], &[]);
        assert_eq!(result.conflicts.len(), 1, "{:?}", result.conflicts);
        assert_eq!(
            result.conflicts.first().unwrap().blocker,
            Blocker::Filesystem { owner: Some("other".to_owned()) }
        );
    }

    /// An unowned file is still a conflict, and says so rather than naming a package.
    #[test]
    fn an_unowned_file_conflicts_without_an_owner() {
        let (_keep, local) = database(&[]);
        let (_dir, root) = filesystem(&[("usr/bin/tool", Entry::File)]);

        let result = run(&root, &local, &[target("foo", &["usr/bin/tool"])], &[]);
        assert_eq!(result.conflicts.first().unwrap().blocker, Blocker::Filesystem { owner: None });
    }

    /// Upgrading a package over its own files is not a conflict. This is the common case, and
    /// getting it wrong would make every upgrade fail.
    #[test]
    fn upgrading_a_package_over_its_own_files_is_not_a_conflict() {
        let (_keep, local) = database(&[("foo-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/foo"])]);
        let (_dir, root) = filesystem(&[("usr/bin/foo", Entry::File)]);

        let result =
            run(&root, &local, &[target("foo", &["usr/", "usr/bin/", "usr/bin/foo"])], &[]);
        assert!(result.is_clear(), "{:?}", result.conflicts);
    }

    /// A path a package being removed owns is free by the time it is needed.
    #[test]
    fn a_path_vacated_by_a_removal_is_not_a_conflict() {
        let (_keep, local) = database(&[("old-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/tool"])]);
        let (_dir, root) = filesystem(&[("usr/bin/tool", Entry::File)]);

        let result = run(&root, &local, &[target("foo", &["usr/bin/tool"])], &["old".to_owned()]);
        assert!(result.is_clear(), "{:?}", result.conflicts);
    }

    /// The rule with the side effect. `bar` hands `usr/bin/tool` to `foo`. Without the
    /// `skip_remove` entry, `bar`'s removal deletes the file `foo` just installed.
    #[test]
    fn a_file_changing_owner_is_recorded_in_skip_remove() {
        let (_keep, local) = database(&[("bar-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/tool"])]);
        let (_dir, root) = filesystem(&[("usr/bin/tool", Entry::File)]);

        let result = run(
            &root,
            &local,
            &[target("foo", &["usr/bin/tool"]), target("bar", &["usr/bin/other"])],
            &[],
        );
        assert!(result.is_clear(), "{:?}", result.conflicts);
        assert!(result.skip_remove.contains(Path::new("usr/bin/tool")), "{:?}", result.skip_remove);
    }

    /// A config file the user wrote by hand, which the package now manages.
    #[test]
    fn an_unowned_backup_file_is_adopted_rather_than_refused() {
        let (_keep, local) = database(&[]);
        let (_dir, root) = filesystem(&[("etc/foo.conf", Entry::File)]);

        let mut foo = target("foo", &["etc/", "etc/foo.conf"]);
        foo.backups.insert("etc/foo.conf".to_owned());
        let result = run(&root, &local, &[foo], &[]);
        assert!(result.is_clear(), "{:?}", result.conflicts);
    }

    /// But not one another package owns. Being a backup file is not a licence to take it.
    #[test]
    fn a_backup_file_owned_by_another_package_still_conflicts() {
        let (_keep, local) = database(&[("other-1.0.0-1", &["etc/", "etc/foo.conf"])]);
        let (_dir, root) = filesystem(&[("etc/foo.conf", Entry::File)]);

        let mut foo = target("foo", &["etc/", "etc/foo.conf"]);
        foo.backups.insert("etc/foo.conf".to_owned());
        let result = run(&root, &local, &[foo], &[]);
        assert_eq!(result.conflicts.len(), 1, "{:?}", result.conflicts);
    }

    /// The symlinked-directory case. `usr/lib/foo -> bar` is a directory as far as a package
    /// shipping `usr/lib/foo/` is concerned, and reporting it would break real layouts.
    #[test]
    fn a_packaged_directory_over_a_symlink_to_a_directory_is_not_a_conflict() {
        let (_keep, local) = database(&[]);
        let (_dir, root) =
            filesystem(&[("usr/lib/bar", Entry::Dir), ("usr/lib/foo", Entry::SymlinkTo("bar"))]);

        let result =
            run(&root, &local, &[target("pkg", &["usr/", "usr/lib/", "usr/lib/foo/"])], &[]);
        assert!(result.is_clear(), "{:?}", result.conflicts);
    }

    /// And the case libalpm's `ENOTDIR` hides from it: a plain file where a package wants a
    /// directory. Extraction would replace the file, so it must be reported.
    #[test]
    fn a_packaged_directory_over_a_plain_file_conflicts() {
        let (_keep, local) = database(&[("other-1.0.0-1", &["usr/", "usr/lib/", "usr/lib/foo"])]);
        let (_dir, root) = filesystem(&[("usr/lib/foo", Entry::File)]);

        let result =
            run(&root, &local, &[target("pkg", &["usr/", "usr/lib/", "usr/lib/foo/"])], &[]);
        assert_eq!(result.conflicts.len(), 1, "{:?}", result.conflicts);
        assert_eq!(result.conflicts.first().unwrap().path, PathBuf::from("usr/lib/foo"));
    }

    /// `--overwrite` releases a file-against-file collision on the filesystem.
    #[test]
    fn overwrite_releases_a_filesystem_conflict() {
        let (_keep, local) = database(&[("other-1.0.0-1", &["usr/", "usr/bin/", "usr/bin/tool"])]);
        let (_dir, root) = filesystem(&[("usr/bin/tool", Entry::File)]);

        let all = Overwrite::new(|_| true);
        let result = check(
            &root,
            &local,
            &[target("foo", &["usr/bin/tool"])],
            &[],
            &all,
            &WalkLimits::default(),
        )
        .unwrap();
        assert!(result.is_clear(), "{:?}", result.conflicts);
    }

    /// And a target-against-target one.
    #[test]
    fn overwrite_releases_a_target_conflict() {
        let (_keep, local) = database(&[]);
        let (_dir, root) = filesystem(&[]);

        let all = Overwrite::new(|_| true);
        let result = check(
            &root,
            &local,
            &[target("foo", &["usr/bin/tool"]), target("bar", &["usr/bin/tool"])],
            &[],
            &all,
            &WalkLimits::default(),
        )
        .unwrap();
        assert!(result.is_clear(), "{:?}", result.conflicts);
    }

    /// `--overwrite` must not release a file-against-directory pair between two targets. The
    /// exact re-test at `conflict.c:455` is what stops it. Dropping that test would let a
    /// package silently replace another's directory.
    #[test]
    fn overwrite_does_not_release_a_file_against_directory_pair() {
        let (_keep, local) = database(&[]);
        let (_dir, root) = filesystem(&[]);

        let all = Overwrite::new(|_| true);
        let result = check(
            &root,
            &local,
            &[
                target("foo", &["usr/lib/thing"]),
                target("bar", &["usr/lib/thing/", "usr/lib/thing/inner"]),
            ],
            &[],
            &all,
            &WalkLimits::default(),
        )
        .unwrap();
        assert_eq!(result.conflicts.len(), 1, "{:?}", result.conflicts);
    }

    /// A directory whose every entry belongs to a package being removed is free to become
    /// whatever the new package puts there.
    #[test]
    fn a_directory_emptied_by_the_transaction_is_not_a_conflict() {
        let (_keep, local) = database(&[(
            "old-1.0.0-1",
            &["usr/", "usr/share/", "usr/share/thing/", "usr/share/thing/inner"],
        )]);
        let (_dir, root) = filesystem(&[("usr/share/thing/inner", Entry::File)]);

        let result = run(
            &root,
            &local,
            &[target("pkg", &["usr/", "usr/share/", "usr/share/thing"])],
            &["old".to_owned()],
        );
        assert!(result.is_clear(), "{:?}", result.conflicts);
    }

    /// The same directory with one file nobody is removing stays a conflict. This is the
    /// precondition and the walk both doing their job.
    #[test]
    fn a_directory_with_a_surviving_file_is_a_conflict() {
        let (_keep, local) = database(&[(
            "old-1.0.0-1",
            &["usr/", "usr/share/", "usr/share/thing/", "usr/share/thing/inner"],
        )]);
        let (_dir, root) = filesystem(&[
            ("usr/share/thing/inner", Entry::File),
            ("usr/share/thing/stray", Entry::File),
        ]);

        let result = run(
            &root,
            &local,
            &[target("pkg", &["usr/", "usr/share/", "usr/share/thing"])],
            &["old".to_owned()],
        );
        assert_eq!(result.conflicts.len(), 1, "{:?}", result.conflicts);
    }

    /// The walk is bounded. With no budget, it must answer "not vacated" — the conservative
    /// direction — rather than run out of budget silently in the permissive one.
    #[test]
    fn an_exhausted_walk_budget_reports_a_conflict() {
        let (_keep, local) = database(&[(
            "old-1.0.0-1",
            &["usr/", "usr/share/", "usr/share/thing/", "usr/share/thing/inner"],
        )]);
        let (_dir, root) = filesystem(&[("usr/share/thing/inner", Entry::File)]);

        let result = check(
            &root,
            &local,
            &[target("pkg", &["usr/", "usr/share/", "usr/share/thing"])],
            &["old".to_owned()],
            &Overwrite::default(),
            &WalkLimits { max_depth: 64, max_entries: 0 },
        )
        .unwrap();
        assert_eq!(result.conflicts.len(), 1, "{:?}", result.conflicts);
    }

    /// A `.PKGINFO` `alpm-pkginfo` accepts, with a `%BACKUP%` path.
    const PKGINFO: &str = "\
pkgname = foo
pkgbase = foo
pkgver = 1.0.0-1
pkgdesc = An example package
url = https://example.org/
builddate = 1733737242
packager = Foobar McFooface <foobar@mcfooface.org>
size = 123
arch = x86_64
license = MIT
backup = etc/foo.conf
";

    /// A package's own file list is read from the archive. The package is not installed yet,
    /// so there is nothing else to read it from.
    #[test]
    fn a_target_is_built_from_a_package_archive() {
        let mut builder = tar::Builder::new(Vec::new());
        let pkginfo = PKGINFO;

        let mut add = |path: &str, contents: &[u8], dir: bool| {
            let mut header = tar::Header::new_gnu();
            header.set_mode(if dir { 0o755 } else { 0o644 });
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(contents.len() as u64);
            if dir {
                header.set_entry_type(tar::EntryType::Directory);
            }
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        };
        add(".PKGINFO", pkginfo.as_bytes(), false);
        add("usr", &[][..], true);
        add("usr/bin/foo", b"binary", false);
        add("etc/foo.conf", b"setting", false);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo-1.0.0-1-x86_64.pkg.tar");
        std::fs::write(&path, builder.into_inner().unwrap()).unwrap();

        let loaded = load_package(&path, &crate::extract::PackageLimits::default()).unwrap();
        let built = loaded.target;

        assert_eq!(built.name, "foo");
        assert_eq!(built.version, "1.0.0-1");
        // `.PKGINFO` is metadata and never part of the file list.
        assert_eq!(built.files.iter().collect::<Vec<_>>(), ["etc/foo.conf", "usr/", "usr/bin/foo"]);
        // The trailing slash is added for a directory member that lacked one.
        assert!(built.files.contains("usr/"));
        assert!(built.backups.contains("etc/foo.conf"));
        // And the typed parse came back from the same walk. The caller never reads the archive
        // a second time to get it.
        assert_eq!(loaded.raw, PKGINFO);
        let alpm_pkginfo::PackageInfo::V1(v1) = &loaded.info else {
            panic!("expected a PKGINFOv1, got {:?}", loaded.info);
        };
        assert_eq!(v1.pkgname.to_string(), "foo");
    }

    /// A `.PKGINFO` the typed parse rejects fails here, where nothing has been changed yet.
    /// It must not fail later, from inside a commit that has already written into the root.
    #[test]
    fn an_unparseable_pkginfo_fails_the_load() {
        let mut builder = tar::Builder::new(Vec::new());
        // `packager` without an `<email>`. Everything else is valid.
        let pkginfo = PKGINFO
            .replace("packager = Foobar McFooface <foobar@mcfooface.org>", "packager = test");

        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(pkginfo.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, ".PKGINFO", pkginfo.as_bytes()).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo-1.0.0-1-x86_64.pkg.tar");
        std::fs::write(&path, builder.into_inner().unwrap()).unwrap();

        let error = load_package(&path, &crate::extract::PackageLimits::default()).unwrap_err();
        assert!(
            matches!(&error, crate::Error::UnusableSource { reason, .. }
                     if reason.contains(".PKGINFO is unreadable")),
            "got {error:?}"
        );
    }

    /// An archive with no `.PKGINFO` at all fails the same way.
    #[test]
    fn a_package_without_a_pkginfo_fails_the_load() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(6);
        header.set_cksum();
        builder.append_data(&mut header, "usr/bin/foo", &b"binary"[..]).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo-1.0.0-1-x86_64.pkg.tar");
        std::fs::write(&path, builder.into_inner().unwrap()).unwrap();

        let error = load_package(&path, &crate::extract::PackageLimits::default()).unwrap_err();
        assert!(
            matches!(&error, crate::Error::UnusableSource { reason, .. }
                     if reason.contains("no readable .PKGINFO")),
            "got {error:?}"
        );
    }
}
