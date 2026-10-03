//! The transaction itself: a typestate that cannot be committed out of order.
//!
//! ```text
//! Transaction<Planned> --verify--> Transaction<Verified> --stage--> Transaction<Staged> --commit--> Report
//! ```
//!
//! libalpm enforces the same sequence with a runtime `ASSERT` on `trans->state`. It returns
//! `ALPM_ERR_TRANS_NOT_INITIALIZED` when a caller gets it wrong (`trans.c`). Here each step
//! consumes the previous value and returns the next. Getting it wrong does not compile.
//!
//! The states are not decoration. Each is a point where something is guaranteed:
//!
//! - **`Planned`** — the steps are known. Nothing has been read or written.
//! - **`Verified`** — the database lock is held, and has been since before the first check.
//!   Every package the transaction needs has been located *and read*, every `.PKGINFO` is one
//!   piko can record, and every entry it will remove exists. The commit can still fail, but not
//!   for want of a package file or its metadata.
//! - **`Staged`** — the journal is on disk and fsynced. This is the last state in which
//!   abandoning the transaction leaves the system untouched.
//! - committing consumes `Staged` and mutates.
//!
//! # This is where piko can change a real system
//!
//! Every other module reads, decides, or writes somewhere the caller named. This one is handed
//! a root and a dbpath and applies a whole plan to them. The tests here use a
//! `tempfile::TempDir` for both.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use crate::pkginfo::PkgInfo;
use alpm_types::{PackageFileName, PackageInstallReason, PackageValidation};
use piko_db::{EntryName, LocalDatabase, LocalPackage, resolve::PatternList};
use piko_db_write::DbLock;
use piko_sig::{Keyring, Policy, Verdict};

use crate::{
    conflict::{self, Overwrite, WalkLimits, filelist::FileList},
    error::{Error, Result},
    exec::Runner,
    extract::{Ownership, PackageLimits},
    history::{Outcome as HistoryOutcome, Recorder, Recording},
    hook::{self, Hooks, When},
    install::Extraction,
    journal::{Intent, Journal},
    parallel,
    progress::{Event, StepOutcome, VerifyEvent},
    rootfs::RootDir,
    scriptlet::{self, MAX_SCRIPTLET_BYTES},
};

mod expected;
mod published;
mod step;

pub use expected::Expected;
pub use published::Published;

use step::{InstallStep, RemoveStep, install_step, remove_step};

/// One thing a transaction will do.
#[derive(Clone, Debug)]
pub enum Step {
    /// Install a package file.
    Install {
        /// Which package, by cache file name.
        package: PackageFileName,
        /// Whether the user asked for it or a dependency pulled it in.
        reason: PackageInstallReason,
    },
    /// Remove an installed package.
    Remove {
        /// The installed entry, `<name>-<version>`.
        entry: EntryName,
        /// Whether to skip `.pacsave` files (`-Rn`).
        no_save: bool,
    },
}

impl Step {
    /// The journal line for this step.
    fn intent(&self) -> Intent {
        match self {
            Self::Install { package, reason } => {
                Intent::Install { package: package.to_string(), reason: Some(*reason) }
            }
            Self::Remove { entry, .. } => Intent::Remove { entry: entry.as_str().to_owned() },
        }
    }
}

/// What a committed transaction did.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Packages installed, with what their extraction did.
    pub installed: Vec<(String, Extraction)>,
    /// Packages removed, and how many files each removal touched.
    pub removed: Vec<(String, usize)>,
    /// `.pacnew` files left on disk, by root-relative path, in step order.
    ///
    /// The package shipped a version of a backup file the user had edited, so both are on
    /// disk now. libalpm reports this through `ALPM_EVENT_PACNEW_CREATED`, fired mid-extraction
    /// and kept nowhere; a front end that wants to act on it afterwards has to read its own log
    /// back. See [`crate::merge`] for what acts on this.
    pub pacnews: Vec<PathBuf>,
    /// `.pacsave` files created, by root-relative path, in step order.
    ///
    /// A file rotated out of the way to make room for one of these is not here. It was already
    /// the user's to resolve before this transaction ran.
    pub pacsaves: Vec<PathBuf>,
    /// Every scriptlet function that ran, in order, with how it ended.
    ///
    /// A scriptlet that failed lands here rather than in an error. libalpm discards the return
    /// value at every call site, and piko matches that — see [`crate::scriptlet`]. Unlike
    /// libalpm, piko does not *drop* the outcome: what happened comes back to the caller.
    pub scriptlets: Vec<ScriptletRun>,
    /// Every hook that ran, before and after, in order.
    pub hooks: Vec<hook::Run>,
    /// Every hook file that could not be read or parsed, in the order they were met.
    ///
    /// Collected per phase rather than once up front. A file broken for the whole transaction is
    /// reported twice, once for each phase that read the directory. libalpm does the same:
    /// `_alpm_hook_run` re-runs `_alpm_hook_validate` on every call, so pacman prints such a
    /// warning twice too.
    pub hook_problems: Vec<hook::Problem>,
    /// Everything that went wrong recording the transaction.
    ///
    /// Returned rather than raised: neither `pacman.log` nor the history store may fail a
    /// transaction. See [`crate::history`].
    pub history_problems: Vec<crate::history::Problem>,
    /// Everything that stopped a backup file from being preserved.
    ///
    /// Returned rather than raised. The package is going away either way, so a file left in
    /// place is a warning about that file rather than a broken transaction.
    pub backup_problems: Vec<BackupProblem>,
}

/// Why a backup file could not be preserved the way a removal intended.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum BackupProblem {
    /// The file was left where it is, because the `.pacsave` beside it could not be rotated.
    #[error("{} was left in place: {}", piko_db::printable_path(path), piko_db::printable(reason))]
    RotationImpossible {
        /// The file that is still there.
        path: PathBuf,
        /// What stopped the rotation.
        reason: String,
    },
}

/// One scriptlet function that piko ran.
#[derive(Clone, Debug)]
pub struct ScriptletRun {
    /// The package whose scriptlet it was.
    pub package: String,
    /// Which of the six functions.
    pub kind: scriptlet::Kind,
    /// How it ended.
    pub outcome: crate::exec::Outcome,
}

/// Steps are known; nothing has been touched.
#[derive(Debug)]
pub struct Planned {
    steps: Vec<Step>,
}

/// How package signatures are checked.
///
/// A transaction a solver planned takes its verification from its
/// [`crate::TransactionPlan`], built from `pacman.conf`'s `SigLevel`. It cannot be set apart
/// from that configuration: `SigLevel = Never` is how such a transaction checks nothing.
///
/// [`Transaction::new`], for steps no solver planned, takes one as an argument. It has no
/// default: a caller that checks nothing writes [`Verification::Disabled`], and the choice is
/// then in its code rather than in a default it never read. `Disabled` keeps this crate usable
/// without a keyring, and a chroot built from scratch has none. libalpm's handle is zeroed
/// instead (`handle.c:46`), so nothing is checked until the frontend sets a `SigLevel`.
///
/// Neither constructor lets a caller change the verification afterwards. A setter would also
/// apply to [`Transaction::from_plan`], and remove the check its plan decided.
#[derive(Debug)]
pub enum Verification {
    /// Do not check signatures. `%VALIDATION%` will record `none`, truthfully.
    Disabled,
    /// Check every package against `keyring`, under `policy`.
    Enabled {
        /// The GnuPG keyring to verify against — pacman's is `/etc/pacman.d/gnupg`.
        keyring: Keyring,
        /// What the configured `SigLevel` demands of a package.
        policy: Policy,
    },
}

/// What a package's validation checked. `%VALIDATION%` records it.
///
/// The distinction between "accepted having verified" and "accepted because the policy asked
/// for nothing" is not cosmetic. It is exactly what `%VALIDATION%` records. Conflating them
/// would write `pgp` into the database for a package nobody checked.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Validation {
    /// The file's SHA-256 matched the one its repository database publishes.
    pub sha256: bool,
    /// A signature over the file was checked and accepted.
    pub signature: bool,
}

impl Validation {
    /// The `%VALIDATION%` values, in the order libalpm writes them (`be_local.c:1058`).
    #[must_use]
    pub fn recorded(self) -> Vec<PackageValidation> {
        let mut recorded = Vec::new();
        if self.sha256 {
            recorded.push(PackageValidation::Sha256);
        }
        if self.signature {
            recorded.push(PackageValidation::Pgp);
        }
        if recorded.is_empty() {
            recorded.push(PackageValidation::None);
        }
        recorded
    }
}

/// Validates one package file, as `_alpm_pkg_validate_internal` does (`be_package.c:279`).
///
/// `published` is what the package's repository database says about its file. It is `None` for
/// a package file named on the command line, which has no repository. The checks are libalpm's:
///
/// - When the policy checks signatures and the database publishes a `%PGPSIG%`, the file is
///   verified against that signature alone. The `.sig` beside the file is not read.
/// - Otherwise, when the policy checks signatures, the `.sig` beside the file is verified.
/// - When `published` is known, `%SHA256SUM%` is compared in every case except the first.
///   So under `SigLevel = Never` a repository package is still compared with its database. A
///   signature from the database covers the whole file, so the checksum adds nothing there.
///
/// A database signature binds the file to the database that planned it, as the checksum does.
/// A `.sig` from the mirror binds the file to its signer only.
///
/// The policy applied is `policy_overrides`' entry for `file_name`, keyed by cache file name —
/// a repository's `SigLevel` can differ from another's. It falls back to
/// [`Verification::Enabled`]'s own `policy` when `file_name` has no more specific answer. In
/// current practice that is only a candidate whose repository could not be resolved.
///
/// This is a free function rather than a method, because `piko install -w` verifies what it
/// downloaded without ever building a [`Transaction`]. libalpm checks under `-Sw` too:
/// `check_validity` (`sync.c:1275`) runs before `_alpm_sync_load`'s
/// `ALPM_TRANS_FLAG_DOWNLOADONLY` return. One shared function keeps the two answers from
/// drifting. [`Transaction::verify`] and the download path share `Keyring::check` for the same
/// reason, rather than each deciding what a missing `.sig` means.
///
/// # Errors
///
/// [`Error::ChecksumMismatch`] if the file is not the one the database publishes.
/// [`Error::SignatureUncheckable`] if the keyring could not answer at all, or
/// [`Error::SignatureRejected`] if it answered and the policy refuses the result.
pub fn validate_package(
    verification: &Verification,
    policy_overrides: &HashMap<String, Policy>,
    published: Option<&Published>,
    file_name: &PackageFileName,
    package: &Path,
) -> Result<Validation> {
    let checking = match verification {
        Verification::Enabled { keyring, policy } => {
            let policy = policy_overrides.get(&file_name.to_string()).copied().unwrap_or(*policy);
            policy.check.then_some((keyring, policy))
        }
        Verification::Disabled => None,
    };
    let from_database = checking.is_some() && published.is_some_and(Published::has_signature);

    let mut validation = Validation::default();
    if let Some(published) = published
        && !from_database
    {
        published.check_checksum(package)?;
        validation.sha256 = true;
    }
    let Some((keyring, policy)) = checking else { return Ok(validation) };

    let embedded = match published {
        Some(published) => published.decoded_signature(package)?,
        None => None,
    };
    // `Keyring::check` owns the rule that a missing `.sig` is the policy's problem, not an
    // error. The repository-database check shares it, so the two cannot drift.
    let verdict = match &embedded {
        Some(signature) => keyring.check_bytes(package, signature, policy),
        None => keyring.check(package, policy),
    }
    .map_err(|source| Error::SignatureUncheckable {
        package: package.to_path_buf(),
        reason: source.to_string(),
    })?;

    match verdict {
        Verdict::Accepted { verified } => {
            validation.signature = verified;
            Ok(validation)
        }
        Verdict::Rejected(rejection) => Err(Error::SignatureRejected {
            package: package.to_path_buf(),
            reason: rejection.to_string(),
            unsigned: rejection == piko_sig::Rejection::MissingRequired,
        }),
    }
}

/// One install step's package, with everything `verify` learned about it.
///
/// Gathered while the archive is open for conflict detection, rather than re-read at commit
/// time. The archive is decompressed once, and what a scriptlet runs is what was verified.
#[derive(Clone, Debug)]
struct Prepared {
    /// Where the package file is.
    path: PathBuf,
    /// Its `pkgname`, from the `.PKGINFO` already read.
    name: String,
    /// Its `pkgver`, likewise. The `pre_*` scriptlet needs it before extraction happens.
    version: String,
    /// The database entry it will become.
    ///
    /// Built at verify time, from [`Self::info`]. A name and version that do not form an entry
    /// mean the package cannot be recorded. That has to be known before anything is written.
    entry: EntryName,
    /// Its `.PKGINFO`, parsed.
    ///
    /// Parsed here rather than during the commit, and that placement is the point. A parse
    /// after [`crate::install::install`] has run would fail the step on a `.PKGINFO` the
    /// parser refuses. The package's payload would already be written into the root.
    info: PkgInfo,
    /// What its validation checked.
    ///
    /// Carried rather than recomputed. This is what `%VALIDATION%` records. Re-deriving it at
    /// write time would let the database claim a verification that never happened.
    validation: Validation,
    /// The bounds its archive is read under, its declared size included. Extraction reads the
    /// archive a second time, under the same bounds.
    limits: PackageLimits,
    /// Its `.INSTALL`, if it ships one.
    script: Option<Vec<u8>>,
    /// Every path it ships, as its archive spells them.
    ///
    /// libalpm's `newpkg` file list. The fake removal consults it to decide what it must not
    /// delete.
    files: FileList,
    /// Every path it declares `backup =` in its `.PKGINFO`.
    ///
    /// Two things need it. Extraction diverts the path to a `.pacnew` rather than overwrite
    /// the user's copy. The fake removal leaves that copy alone.
    backups: BTreeSet<String>,
    /// The version already installed under this package's name, if any.
    ///
    /// Five things read it:
    ///
    /// - it decides `pre_install` against `pre_upgrade`,
    /// - it supplies the scriptlet's second argument,
    /// - it names the entry the install must replace,
    /// - it drives the fake removal,
    /// - it supplies the `%BACKUP%` baseline extraction compares against.
    replaces: Option<Superseded>,
    /// What each of its payload members will occupy, for the disk-space estimate.
    ///
    /// Collected during the same archive walk that built [`Self::files`]. The package is not
    /// installed yet, so the archive is the only place its per-file sizes exist.
    footprint: Vec<crate::space::MemberFootprint>,
}

impl Prepared {
    /// What this package ships, as a removal asks about it — libalpm's `newpkg`.
    const fn as_replacement(&self) -> Replacement<'_> {
        Replacement { files: &self.files, backups: &self.backups }
    }
}

/// The installed version an install replaces, read while its entry is still there.
///
/// This is libalpm's `oldpkg`. Carrying it is what lets [`install_step`] run the "fake remove
/// transaction" of `add.c:508`, spelled
/// `_alpm_remove_single_package(handle, oldpkg, newpkg, 0, 0)`. That deletes the old version's
/// files before the new version is extracted. Without it, a package that drops a file between
/// versions leaves that file on disk owned by nobody.
#[derive(Clone, Debug)]
struct Superseded {
    /// The installed entry, `<name>-<version>`.
    entry: EntryName,
    /// Its `%FILES%`, in database order — directories keep their trailing `/`.
    files: Vec<PathBuf>,
    /// Its `%BACKUP%` hashes, keyed by path.
    ///
    /// Two things need it, and they ask different questions. A `.pacsave` decision asks
    /// whether the user edited a file that is going away. Extraction asks what the *previous*
    /// package shipped, so it can tell an edited file from an untouched one.
    backups: BTreeMap<PathBuf, String>,
    /// The directories of [`Self::files`] that another installed package also lists, without
    /// their trailing `/`. Taking this entry apart leaves them in place, even when empty.
    ///
    /// Filled by `mark_shared_directories` once every step is known, since which packages still
    /// count as owners depends on what the transaction removes.
    shared_directories: BTreeSet<PathBuf>,
}

/// The `pacman.conf` path patterns a transaction obeys.
///
/// Shell globs, each list a [`PatternList`] — the same matcher the hook triggers use. That is the point. `NoExtract` decides both what extraction writes and what a
/// hook is told changed. Those two answers have to come from one matcher, or they will
/// eventually disagree about a `!` inversion.
///
/// This holds patterns rather than the predicates [`crate::Filters`] takes. This is the
/// *configured* policy, and it has to be handed on to [`hook::Summary`] as data. `Filters` stays
/// a predicate, so a test can supply an exact answer instead of a pattern that has to be right
/// twice.
#[derive(Clone, Debug, Default)]
pub struct Patterns {
    /// `NoExtract`: never written, and therefore never owned.
    ///
    /// libalpm consults this in exactly two places, and only one of them decides anything:
    /// extraction (`add.c:224`). The other suppresses a warning in the disk-space estimate,
    /// which charges for a `NoExtract` path regardless. piko does not count what it will not
    /// write. Neither implementation consults it in conflict detection, so a `NoExtract` path
    /// is still checked for conflicts.
    pub no_extract: PatternList,
    /// `NoUpgrade`: never overwritten; the packaged version lands beside it as `.pacnew`.
    ///
    /// Consulted by extraction (`add.c:303`) *and* by removal (`remove.c:592`). A file the
    /// user asked piko never to touch is not one a removal may delete either.
    pub no_upgrade: PatternList,
}

impl Patterns {
    /// Whether `path` is never extracted.
    pub(crate) fn skips(&self, path: &Path) -> bool {
        self.no_extract.matches(&path.to_string_lossy())
    }

    /// Whether `path` is never overwritten or removed.
    fn preserves(&self, path: &Path) -> bool {
        self.no_upgrade.matches(&path.to_string_lossy())
    }
}

/// What the package replacing a removed one ships — libalpm's `newpkg`.
#[derive(Clone, Copy, Debug)]
struct Replacement<'a> {
    files: &'a FileList,
    backups: &'a BTreeSet<String>,
}

impl Replacement<'_> {
    /// `should_skip_file`'s third clause (`remove.c:594`).
    ///
    /// The replacement ships this path *and* declares it a backup file. The user's copy stays
    /// where it is, and the packaged version lands beside it as a `.pacnew`. Deleting it here
    /// would throw away edits a moment before that happens.
    fn keeps(&self, stripped: &str) -> bool {
        self.backups.contains(stripped) && self.files.contains(stripped)
    }

    /// Whether the replacement ships the path exactly as spelled (`remove.c:487`).
    fn ships(&self, spelled: &str) -> bool {
        self.files.contains(spelled)
    }
}

/// Every package is available and verified, every entry to remove exists and is readable, and
/// no file is contested, all read under the database lock this state holds.
#[derive(Debug)]
pub struct Verified<'lock> {
    steps: Vec<Step>,
    /// Located packages, parallel to the install steps.
    packages: Vec<Prepared>,
    /// Entries to be removed, parallel to the removal steps.
    removals: Vec<Doomed>,
    /// Paths a removal step must leave alone because an install step now owns them.
    skip_remove: std::collections::BTreeSet<PathBuf>,
    /// What the hooks will be asked about.
    ///
    /// Built here, before anything changes, because it describes the *old* state as much as
    /// the new one. An upgrade's `old_files` and a removal's file list are only readable while
    /// the packages are still installed.
    summary: hook::Summary,
    /// What the disk-space estimate could not measure, if it ran at all.
    ///
    /// Returned rather than logged, like every other diagnostic this crate produces. Empty
    /// when `CheckSpace` is off, and empty on the ordinary system where everything measured.
    space_problems: Vec<crate::space::Problem>,
    /// The lock every check above was made under, held until the commit ends.
    lock: &'lock DbLock,
}

/// The lock is held, the journal is written, and the records are open.
#[derive(Debug)]
pub struct Staged<'lock> {
    steps: Vec<Step>,
    packages: Vec<Prepared>,
    removals: Vec<Doomed>,
    skip_remove: std::collections::BTreeSet<PathBuf>,
    summary: hook::Summary,
    /// The root every step writes into, opened before the journal.
    root: RootDir,
    /// What runs scriptlets and hooks. `None` when neither can run.
    ///
    /// Built before the journal, like `root`. A failure here leaves nothing behind.
    runner: Option<Runner>,
    journal: Journal,
    /// Where this transaction records what it does. Opened with the journal, before the
    /// first mutation, so an unwritable `LogFile` is reported while nothing has changed.
    ///
    /// An `Option` so the commit can take it out of the state. The ending is then written
    /// from one place, after the apply loop has returned however it returned.
    recorder: Option<Recorder>,
    lock: &'lock DbLock,
}

/// A transaction against one root and one database.
#[derive(Debug)]
pub struct Transaction<S> {
    root_path: PathBuf,
    dbpath: PathBuf,
    limits: PackageLimits,
    ownership: Ownership,
    overwrite: Overwrite,
    walk_limits: WalkLimits,
    verification: Verification,
    policy_overrides: HashMap<String, Policy>,
    expectations: HashMap<String, Expected>,
    published: HashMap<String, Published>,
    patterns: Patterns,
    scriptlets: bool,
    hook_dirs: Vec<PathBuf>,
    recording: Recording,
    check_space: bool,
    cancel: Option<piko_net::Cancel>,
    state: S,
}

impl<S> Transaction<S> {
    /// This transaction in the state `next` makes of its current one, with its configuration
    /// unchanged.
    fn map_state<T>(self, next: impl FnOnce(S) -> T) -> Transaction<T> {
        Transaction {
            root_path: self.root_path,
            dbpath: self.dbpath,
            limits: self.limits,
            ownership: self.ownership,
            overwrite: self.overwrite,
            walk_limits: self.walk_limits,
            verification: self.verification,
            policy_overrides: self.policy_overrides,
            expectations: self.expectations,
            published: self.published,
            patterns: self.patterns,
            scriptlets: self.scriptlets,
            hook_dirs: self.hook_dirs,
            recording: self.recording,
            check_space: self.check_space,
            cancel: self.cancel,
            state: next(self.state),
        }
    }
}

impl Transaction<Planned> {
    /// Plans a solved plan's steps against `root` and `dbpath`, with everything `verify`
    /// compares the incoming packages with.
    ///
    /// This is the constructor for a transaction a solver planned. [`TransactionPlan`] carries
    /// the steps, the fields each `.PKGINFO` must repeat, and each repository package's
    /// `%SHA256SUM%` and `%PGPSIG%`, built together from one plan. See there for what each
    /// adds.
    ///
    /// The signature check comes from `plan` too: the keyring, and each package's own policy,
    /// the repository's `SigLevel` or a named file's `LocalFileSigLevel`/`RemoteFileSigLevel`.
    /// So a caller cannot leave it off by forgetting it, or change it apart from the
    /// configuration the plan was built from.
    ///
    /// [`TransactionPlan`]: crate::TransactionPlan
    #[must_use]
    pub fn from_plan(root: &Path, dbpath: &Path, plan: crate::plan::TransactionPlan) -> Self {
        let parts = plan.into_parts();
        Self::new(root, dbpath, parts.steps, parts.verification)
            .policy_overrides(parts.policies)
            .expectations(parts.expectations)
            .published(parts.published)
    }

    /// Plans `steps` against `root` and `dbpath`, checking signatures as `verification` says.
    ///
    /// For steps that no solver planned. `verify` then checks each archive's name and version
    /// against its step, and its signature against the `.sig` beside it, under
    /// `verification`. It compares no other field, and no `%SHA256SUM%` or `%PGPSIG%`, because
    /// nothing here says what they should be. [`Verification::Disabled`] checks no signature;
    /// see [`Verification`]. A caller with a solved plan uses [`Transaction::from_plan`].
    #[must_use]
    pub fn new(root: &Path, dbpath: &Path, steps: Vec<Step>, verification: Verification) -> Self {
        Self {
            root_path: root.to_path_buf(),
            dbpath: dbpath.to_path_buf(),
            limits: PackageLimits::default(),
            ownership: Ownership::FromArchive,
            overwrite: Overwrite::default(),
            walk_limits: WalkLimits::default(),
            verification,
            policy_overrides: HashMap::new(),
            expectations: HashMap::new(),
            published: HashMap::new(),
            patterns: Patterns::default(),
            // Off by default, unlike pacman, for the same reason `--root` has no default: this
            // runs vendor shell code with piko's privileges. The CLI turns it on, so `piko
            // install` behaves like pacman. A library caller has to say so explicitly.
            scriptlets: false,
            hook_dirs: Vec::new(),
            // Records nothing by default, like `scriptlets`. A library caller opts in.
            recording: Recording::default(),
            // Off by default. libalpm's own default is off too; it is Arch's shipped
            // `pacman.conf` that turns `CheckSpace` on, and the CLI reads that directive.
            check_space: false,
            // No flag by default, so the commit runs to the end. A library caller opts in.
            cancel: None,
            state: Planned { steps },
        }
    }

    /// Runs each package's `.INSTALL` scriptlet at the six points libalpm does.
    ///
    /// Off by default — see [`Transaction::new`]. pacman's `--noscriptlet` is the CLI's way of
    /// turning it back off.
    #[must_use]
    pub const fn scriptlets(mut self, enabled: bool) -> Self {
        self.scriptlets = enabled;
        self
    }

    /// Refuses the transaction during [`Transaction::verify`] unless every filesystem it writes
    /// to can hold its peak occupancy — `pacman.conf`'s `CheckSpace`.
    ///
    /// Off by default, as it is in libalpm. Only the transaction's own writes are weighed here.
    /// The space a download needs is a separate question, asked by
    /// [`crate::DownloadingSource::check_space`] before anything is fetched.
    ///
    /// A transaction that installs nothing runs no check. A removal can only free space, and
    /// libalpm skips the whole check for one for that reason.
    #[must_use]
    pub const fn check_space(mut self, enabled: bool) -> Self {
        self.check_space = enabled;
        self
    }

    /// Runs the hooks found in `directories` before and after the transaction.
    ///
    /// The default is an empty list, which runs nothing. These are the configured `HookDir`s —
    /// **host** paths, not paths inside the root. See [`crate::hook`] for why that asymmetry is
    /// deliberate.
    ///
    /// The directories are taken rather than an already-collected [`Hooks`] **on purpose**. The
    /// set of hook files is read once per phase, at the moment that phase runs. So a hook file
    /// the transaction itself installs or deletes is seen exactly as libalpm sees it.
    #[must_use]
    pub fn hook_dirs(mut self, directories: Vec<PathBuf>) -> Self {
        self.hook_dirs = directories;
        self
    }

    /// Sets whether the archive's ownership is applied. Requires privilege when it is.
    #[must_use]
    pub const fn ownership(mut self, ownership: Ownership) -> Self {
        self.ownership = ownership;
        self
    }

    /// Sets the per-package bounds.
    #[must_use]
    pub const fn limits(mut self, limits: PackageLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Releases the paths `overwrite` accepts from file-conflict detection.
    ///
    /// pacman's `--overwrite`. It excuses a *file* whose owner disagrees. It never excuses a
    /// directory, and never a path a package would replace with a directory. See
    /// [`conflict::decision::Resolution::Overwritten`].
    #[must_use]
    pub fn overwrite(mut self, overwrite: Overwrite) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Overrides the verification's policy for specific package files, keyed by cache file
    /// name (matching [`crate::source::CacheDirSource`]'s own key — `PackageFileName` has no
    /// `Hash` impl).
    ///
    /// A repository's `SigLevel` can differ from another's, unlike a database's single value.
    /// So a package is checked against the policy that governs *its* repository, rather than
    /// against one value for the whole transaction. The verification's own `policy` remains the
    /// fallback for a file this map has no answer for. [`Transaction::from_plan`] sets it from
    /// the plan. It is not public, for the reason [`Verification`] gives.
    #[must_use]
    pub(crate) fn policy_overrides(mut self, overrides: HashMap<String, Policy>) -> Self {
        self.policy_overrides = overrides;
        self
    }

    /// What the plan says each incoming package is, keyed by cache file name.
    ///
    /// `verify` compares every archive's `.PKGINFO` with its entry: the installed size and the
    /// five relation lists `check_pkg_matches_db` compares (`sync.c:1113`). The name and the
    /// version are compared for every install, from the step's own file name. A file with no
    /// entry here gets only that half. [`Transaction::from_plan`] sets it; the default is empty.
    #[must_use]
    pub(crate) fn expectations(mut self, expectations: HashMap<String, Expected>) -> Self {
        self.expectations = expectations;
        self
    }

    /// What each incoming package's repository database publishes about its file, keyed by
    /// cache file name.
    ///
    /// `verify` checks every file with an entry here against its `%SHA256SUM%`, and against its
    /// `%PGPSIG%` in place of the `.sig` beside it. See [`validate_package`] for which check
    /// runs when. A file with no entry gets the `.sig` check alone, as a named file does.
    /// [`Transaction::from_plan`] sets it; the default is empty.
    #[must_use]
    pub(crate) fn published(mut self, published: HashMap<String, Published>) -> Self {
        self.published = published;
        self
    }

    /// Applies `pacman.conf`'s `NoExtract` and `NoUpgrade` patterns.
    ///
    /// The default is empty, which treats no path specially. The `NoExtract` half also reaches
    /// [`hook::Summary`], so hooks and extraction cannot disagree about what was written. That
    /// is why this is one setting rather than two.
    #[must_use]
    pub fn patterns(mut self, patterns: Patterns) -> Self {
        self.patterns = patterns;
        self
    }

    /// Records what the transaction does, into `pacman.log` and the history store.
    ///
    /// The default records nothing, the same posture [`Transaction::scriptlets`] takes: a
    /// library caller says where its records go, or gets none. Neither record can fail a
    /// transaction — see [`crate::history`].
    #[must_use]
    pub fn recording(mut self, recording: Recording) -> Self {
        self.recording = recording;
        self
    }

    /// Lets `cancel` stop the commit between two steps.
    ///
    /// The default is no flag, which runs every step.
    ///
    /// [`Transaction::verify_with_progress`] reads the flag at each phase boundary and once
    /// per package. It applies nothing, so it stops with [`Error::Cancelled`] and leaves no
    /// journal.
    ///
    /// [`Transaction::commit_with_progress`] reads it once per step, before that step starts.
    /// The step already running therefore finishes. The commit then stops with the same error
    /// and leaves the journal in place. The journal names what was applied. A stop before the
    /// first step applied nothing, and removes the journal instead.
    ///
    /// This is the same flag a download reads, so one Ctrl+C covers every phase. Each read
    /// sits on a boundary. A flag raised inside one long extraction waits for that
    /// extraction.
    #[must_use]
    pub fn cancel(mut self, cancel: piko_net::Cancel) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Returns [`Error::Cancelled`] when [`Transaction::cancel`]'s flag is raised.
    ///
    /// [`Transaction::verify_with_progress`] calls this at each phase boundary, and once per
    /// package inside its loops. Verification reads whole package files, so one phase can run
    /// for a long time on a large transaction. A flag read only at the end of a phase leaves
    /// the user waiting. Nothing on screen says the stop was taken.
    ///
    /// Nothing is applied during verification, so `completed` is always zero here.
    fn stop_if_cancelled(&self, total: usize) -> Result<()> {
        if self.cancel.as_ref().is_some_and(piko_net::Cancel::is_requested) {
            return Err(Error::Cancelled { completed: 0, total });
        }
        Ok(())
    }

    /// Locates and reads every package, verifies its signature, checks every entry to be
    /// removed, and finds file conflicts.
    ///
    /// This up-front pass shortens the commit's failure modes. Three failures are found before
    /// anything has changed, rather than half-way through:
    ///
    /// - a missing package file,
    /// - a `.PKGINFO` that cannot be recorded,
    /// - a file two packages both claim.
    ///
    /// It runs under `lock`, the `db.lck` of this transaction's `dbpath`. The checks read the
    /// local database: which files each installed package owns, which entries exist. Another
    /// package manager changing that database between this check and the commit would make
    /// every answer stale, and a conflict check would then clear a write over a file it never
    /// saw. So the lock is taken first, and the transaction holds it until the commit ends.
    ///
    /// # Errors
    ///
    /// [`Error::Database`] wrapping `WrongLock` if `lock` is not this `dbpath`'s.
    /// [`Error::UnfinishedTransaction`] or [`Error::JournalUnreadable`] if a previous transaction
    /// left its journal. [`Error::NotAvailable`] if a package cannot be supplied.
    /// [`Error::UnusableSource`] if an entry to be removed is not installed, or a package's
    /// `.PKGINFO` cannot be read.
    /// [`Error::FileConflicts`] if the transaction would write a file it does not own.
    pub fn verify<'lock>(
        self,
        lock: &'lock DbLock,
        source: &dyn crate::source::PackageSource,
    ) -> Result<Transaction<Verified<'lock>>> {
        self.verify_with_progress(lock, source, &mut |_| {})
    }

    /// As [`Transaction::verify`], reporting progress through `progress` as it runs.
    ///
    /// `progress` is the same narrow, deliberate exception to "diagnostics are returned, not
    /// logged" as [`Transaction::commit_with_progress`]. See [`crate::progress`]'s
    /// documentation. It takes `FnMut` rather than `Fn` for the same reason
    /// `commit_with_progress` does. A caller driving a terminal UI needs a mutable borrow of
    /// whatever it draws with.
    ///
    /// # Errors
    ///
    /// As [`Transaction::verify`].
    pub fn verify_with_progress<'lock>(
        self,
        lock: &'lock DbLock,
        source: &dyn crate::source::PackageSource,
        progress: &mut dyn FnMut(VerifyEvent),
    ) -> Result<Transaction<Verified<'lock>>> {
        // A lock over another database protects nothing this transaction reads.
        if lock.path().parent() != Some(self.dbpath.as_path()) {
            return Err(Error::Database(piko_db_write::Error::WrongLock {
                lock: lock.path().to_path_buf(),
                dbpath: self.dbpath,
            }));
        }
        // First, before anything is downloaded or read. `stage` refuses again, under `db.lck`,
        // when it writes the journal.
        crate::journal::refuse_if_present(&self.dbpath)?;
        let local = LocalDatabase::open(self.dbpath.join("local"))
            .map_err(|error| Error::local_db(self.dbpath.join("local"), error))?;

        // Fetched up front, `ParallelDownloads` at a time, so the loop below finds every
        // package already in the cache. The verification order does not change. A download
        // that failed here is simply still missing, and `locate` reports it in its usual place.
        // See `PackageSource::prefetch`.
        let incoming: Vec<PackageFileName> = self
            .state
            .steps
            .iter()
            .filter_map(|step| match step {
                Step::Install { package, .. } => Some(package.clone()),
                Step::Remove { .. } => None,
            })
            .collect();
        source.prefetch(&incoming)?;

        let mut located: Vec<(&PackageFileName, crate::source::Location)> = Vec::new();
        let mut removals = Vec::new();
        let mut doomed_entries: Vec<Doomed> = Vec::new();
        // The same list extraction obeys, handed to the hooks as data. A hook told a path
        // changed that `NoExtract` stopped anyone from writing would be a lie. The two answers
        // stay consistent only because they come from one setting and one matcher.
        let mut summary =
            hook::Summary { no_extract: self.patterns.no_extract.clone(), ..Default::default() };
        // Known up front, so `SignatureChecked` can report a total before a single package is
        // checked. Signature checking hashes the whole file, and can be the slowest step here
        // for a large package.
        let total_installs =
            self.state.steps.iter().filter(|step| matches!(step, Step::Install { .. })).count();
        let total_steps = self.state.steps.len();

        // The steps in order, for what reads the local database or asks the package source.
        // The first step that fails stops this pass. Its error waits until the packages located
        // before it are validated, so that the failure of an earlier step still comes first.
        let mut stopped = None;
        for step in &self.state.steps {
            let taken = self.stop_if_cancelled(total_steps).and_then(|()| match step {
                Step::Install { package, .. } => {
                    // Before the download: a stale plan is refused without fetching anything.
                    if let Some(expected) = self.expectations.get(&package.to_string()) {
                        self::check_installed(&local, package.name(), expected.replaced())?;
                    }
                    located.push((package, source.locate(package)?));
                    Ok(())
                }
                Step::Remove { entry, .. } => {
                    let Some(package) = self::check_installed(&local, entry.name(), Some(entry))?
                    else {
                        return Err(Error::PlanStale {
                            name: entry.name().to_string(),
                            planned: Some(entry.as_str().to_owned()),
                            installed: None,
                        });
                    };
                    // Read here rather than left to the removal step, so the step needs no
                    // database of its own. Forcing the file list here also forces the backup
                    // list — see [`Doomed`].
                    let doomed = self::doomed(entry, package, self.scriptlets)?;
                    summary.removed.push(hook::trigger::Removed {
                        name: entry.name().to_string(),
                        files: spell(&doomed.installed.files),
                    });
                    removals.push(entry.name().to_string());
                    doomed_entries.push(doomed);
                    Ok(())
                }
            });
            if let Err(error) = taken {
                stopped = Some(error);
                break;
            }
        }

        // Every package is validated before any archive is opened for another purpose. A
        // package that fails this is not read further, so a hostile archive gets no chance to
        // exercise the extractor. The packages are independent, so they are checked on a few
        // threads, and the failure returned is the first one in step order.
        let threads = self::verify_threads();
        let cancel = self.cancel.as_ref();
        let cancelled = || cancel.is_some_and(piko_net::Cancel::is_requested);
        let mut signature_checked = 0_usize;
        let validated = parallel::map_ordered(
            &located,
            threads,
            |(package, location)| {
                if cancelled() {
                    return Err(Error::Cancelled { completed: 0, total: total_steps });
                }
                validate_package(
                    &self.verification,
                    &self.policy_overrides,
                    self.published.get(&package.to_string()),
                    package,
                    location.path(),
                )
            },
            || {
                signature_checked = signature_checked.saturating_add(1);
                progress(VerifyEvent::SignatureChecked {
                    index: signature_checked,
                    total: total_installs,
                });
            },
        );
        let validations = match validated {
            Ok(validations) => validations,
            Err((
                index,
                refusal @ (Error::ChecksumMismatch { .. }
                | Error::SignatureRejected { unsigned: false, .. }),
            )) => {
                return Err(match located.get(index) {
                    Some((_, location)) => self::discard(source, location, refusal),
                    None => refusal,
                });
            }
            Err((_, error)) => return Err(error),
        };
        if let Some(error) = stopped {
            return Err(error);
        }

        // Reading each archive answers two questions, and nothing else can answer either. What
        // will a package not yet installed write? And is its `.PKGINFO` one piko can record?
        // pacman loads the same files for the same reason before its own check, so this is not
        // a cost piko added. One walk answers both questions. Everything else that concerns one
        // package alone runs on the same thread, so the first failure in step order is still
        // the one returned.
        let validated: Vec<_> = located
            .iter()
            .zip(validations)
            .map(|((package, location), validation)| (*package, location, validation))
            .collect();
        let mut verified_installs = 0_usize;
        let prepared = parallel::map_ordered(
            &validated,
            threads,
            |&(package, location, validation)| {
                if cancelled() {
                    return Err((Error::Cancelled { completed: 0, total: total_steps }, false));
                }
                self::prepare(
                    &local,
                    &self.expectations,
                    self.limits,
                    package,
                    location,
                    validation,
                )
            },
            || {
                verified_installs = verified_installs.saturating_add(1);
                progress(VerifyEvent::PackageVerified {
                    index: verified_installs,
                    total: total_installs,
                });
            },
        );
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err((index, (refusal, true))) => {
                return Err(match validated.get(index) {
                    Some((_, location, _)) => self::discard(source, location, refusal),
                    None => refusal,
                });
            }
            Err((_, (error, false))) => return Err(error),
        };

        let mut targets = Vec::with_capacity(prepared.len());
        let mut packages = Vec::with_capacity(prepared.len());
        for (package, target) in prepared {
            let old_files =
                package.replaces.as_ref().map(|old| spell(&old.files)).unwrap_or_default();
            summary.added.push(hook::trigger::Added {
                name: target.name.clone(),
                files: target.files.iter().map(str::to_owned).collect(),
                old_files,
                replaces_installed: package.replaces.is_some(),
            });
            packages.push(package);
            targets.push(target);
        }

        {
            let removed: BTreeSet<&str> = removals.iter().map(String::as_str).collect();
            // Every entry a step takes apart, removed or replaced, in one pass over the file
            // lists.
            let mut taken_apart: Vec<(&mut Superseded, Option<Replacement<'_>>)> = doomed_entries
                .iter_mut()
                .map(|doomed| (&mut doomed.installed, None))
                .chain(packages.iter_mut().filter_map(|package| {
                    let Prepared { replaces, files, backups, .. } = package;
                    let replacement = Replacement { files, backups };
                    replaces.as_mut().map(|old| (old, Some(replacement)))
                }))
                .collect();
            self::mark_shared_directories(&local, &mut taken_apart, &removed);
        }

        // The last read before the conflict check. That check walks the filesystem once for
        // the whole plan, so it cannot be interrupted part-way.
        self.stop_if_cancelled(total_steps)?;
        let root = RootDir::open(&self.root_path)?;
        progress(VerifyEvent::ConflictCheckStarted);
        let check =
            conflict::check(&root, &local, &targets, &removals, &self.overwrite, &self.walk_limits);
        if !check.is_clear() {
            return Err(Error::FileConflicts { conflicts: check.conflicts });
        }

        // Where `_alpm_sync_check` asks it, and the last point at which refusing costs nothing:
        // `stage` writes the journal. An install-free transaction is not asked at all, matching
        // libalpm, which keeps the whole of `_alpm_sync_check` behind `if(trans->add)`.
        let space_problems = if self.check_space && total_installs > 0 {
            progress(VerifyEvent::DiskSpaceCheckStarted);
            self.weigh_space(&root, &packages, &doomed_entries)?
        } else {
            Vec::new()
        };

        Ok(self.map_state(|planned| Verified {
            steps: planned.steps,
            packages,
            removals: doomed_entries,
            skip_remove: check.skip_remove,
            summary,
            space_problems,
            lock,
        }))
    }

    /// Weighs what this transaction will write against what each filesystem has free.
    ///
    /// The root is canonicalized once. The mount table is the host's. So a relative `--root`,
    /// or one reached through a symlink, would match no mount point at all. It would then fail
    /// the coherence check for a reason that has nothing to do with disk space. libalpm
    /// resolves only its cache directory, and would mis-attribute such a root.
    fn weigh_space(
        &self,
        root: &RootDir,
        packages: &[Prepared],
        removals: &[Doomed],
    ) -> Result<Vec<crate::space::Problem>> {
        let canonical =
            std::fs::canonicalize(&self.root_path).unwrap_or_else(|_| self.root_path.clone());
        let doomed: Vec<&[PathBuf]> =
            removals.iter().map(|entry| entry.installed.files.as_slice()).collect();
        let installs: Vec<crate::space::Install<'_>> = packages
            .iter()
            .map(|package| crate::space::Install {
                footprint: &package.footprint,
                replaced: package.replaces.as_ref().map(|old| old.files.as_slice()),
            })
            .collect();
        crate::space::check_install(
            crate::space::mounts::MountTable::load()?,
            &canonical,
            root,
            &doomed,
            &installs,
            // libalpm charges for `NoExtract` bytes although its own extraction then declines
            // to write them. piko does not count what it will not write.
            &|path| self.patterns.skips(path),
        )
    }
}

/// Fails unless the archive at `path` holds the package the plan named: by name and version,
/// and, when the plan supplied `expected`, by the fields `check_pkg_matches_db` compares.
///
/// The plan was built from a repository `desc`, or from a named file's `.PKGINFO` read before the
/// confirmation prompt. The archive read here can hold something else: a cache file under a
/// name it does not match, a mirror serving an older signed build under a newer file name, or a
/// named file replaced after the plan was shown. Each is signed by a trusted key, so the
/// signature check passes, and only this comparison refuses it.
///
/// This is `check_pkg_matches_db` (`sync.c:1113`): the name, the version, the installed size,
/// and `depend`, `conflict`, `replaces`, `provides` and `group`. libalpm runs it on every
/// repository package (`sync.c:1202`) and skips a named file, whose plan it built from that same
/// file. piko checks a named file too: the plan read it before the confirmation prompt, and the
/// transaction reads it again after.
///
/// # Errors
///
/// [`Error::UnusableSource`] naming what was planned and what the archive holds, or every
/// field that differs from the plan.
/// Refuses a step when the entry installed under `name` is not `planned`.
///
/// The plan is read and confirmed before `verify` takes `db.lck`, so another package manager
/// may have changed the database in between. A removal of a version no longer installed would
/// delete the files of the version that is, and then fail to remove its entry. An upgrade from a
/// version no longer installed could turn into a downgrade no one confirmed. `planned` is `None`
/// for a fresh install, which expects the name not to be installed. The entries are compared as
/// directory names, the local database's own source of truth.
///
/// Returns the installed package, which is `Some` whenever `planned` is.
///
/// # Errors
///
/// [`Error::PlanStale`] naming both entries.
fn check_installed<'a>(
    local: &'a LocalDatabase,
    name: &alpm_types::Name,
    planned: Option<&EntryName>,
) -> Result<Option<&'a LocalPackage>> {
    let installed = local.get(name);
    let entry = installed.map(LocalPackage::entry);
    if entry.map(EntryName::as_str) == planned.map(EntryName::as_str) {
        return Ok(installed);
    }
    Err(Error::PlanStale {
        name: name.to_string(),
        planned: planned.map(|entry| entry.as_str().to_owned()),
        installed: entry.map(|entry| entry.as_str().to_owned()),
    })
}

fn matches_plan(
    planned: &PackageFileName,
    expected: Option<&Expected>,
    path: &Path,
    info: &PkgInfo,
) -> Result<()> {
    let (name, version) = crate::pkginfo::name_and_version(info);
    if name != planned.name() || version != planned.version() {
        return Err(Error::UnusableSource {
            path: path.to_path_buf(),
            reason: format!(
                "it holds {name} {version}, but the plan installs {} {}",
                planned.name(),
                planned.version()
            ),
        });
    }
    let Some(expected) = expected else { return Ok(()) };
    let differences = expected.differences(&Expected::of_archive(info));
    if differences.is_empty() {
        return Ok(());
    }
    Err(Error::UnusableSource {
        path: path.to_path_buf(),
        reason: format!(
            "its .PKGINFO does not match the plan for {name} {version}: {} differ",
            differences.join(", ")
        ),
    })
}

/// Removes a cache file that was refused, through the source that served it, and says what
/// happened in `refusal`'s reason.
///
/// Three refusals remove a file: a `.PKGINFO` that does not match the plan, a SHA-256 that does
/// not match the database, and a signature that was read and refused. libalpm removes on all
/// three (`sync.c:1202`, and `sync.c:1055` for the other two). A package with no signature at
/// all is not removed, as libalpm's `ALPM_ERR_PKG_MISSING_SIG` is not. Neither is one whose
/// signature could not be checked: the keyring is at fault, not the file. libalpm asks
/// `ALPM_QUESTION_CORRUPTED_PKG` first (`sync.c:705`), and pacman answers yes by default. piko
/// removes without asking, which is that default. A file left in place is served again by the
/// next run and refused again, rather than downloaded afresh. A removal that fails is reported
/// beside the refusal and never replaces it: the refusal is the answer. Any other error is
/// returned as it is.
pub(crate) fn discard(
    source: &dyn crate::source::PackageSource,
    location: &crate::source::Location,
    mut refusal: Error,
) -> Error {
    if let Error::UnusableSource { reason, .. }
    | Error::ChecksumMismatch { reason, .. }
    | Error::SignatureRejected { reason, unsigned: false, .. } = &mut refusal
    {
        match source.discard(location) {
            Ok(true) => reason
                .push_str("; it was removed from the cache, so the next run downloads it again"),
            Ok(false) => {}
            Err(error) => {
                reason.push_str(&format!("; it could not be removed from the cache: {error}"));
            }
        }
    }
    refusal
}

/// The database entry a package will become, from its `.PKGINFO`.
///
/// Asked during [`Transaction::verify`], for the same reason the `.PKGINFO` is parsed there. A
/// name and version that do not form an entry mean the package cannot be recorded. That has to
/// be known before anything is written.
fn entry_name(package: &Path, info: &PkgInfo) -> Result<EntryName> {
    let (name, version) = crate::pkginfo::name_and_version(info);
    EntryName::new(name, version).map_err(|error| Error::UnusableSource {
        path: package.to_path_buf(),
        reason: format!("its name and version do not form an entry: {error}"),
    })
}

/// How many threads check signatures and read archives at `verify`.
///
/// Measured on 100 real packages (734 MB) on a machine with 4 cores and 8 threads. Signature
/// checks took 3.7 s on one thread, 1.8 s on two, 1.2 s on four and 1.0 s on eight. Reading the
/// archives took 5.0 s, 2.6 s, 1.6 s and 1.3 s. Past four, a thread gains little, and each one
/// holds a zstd window and runs its own `gpg`.
const VERIFY_THREADS: usize = 4;

/// [`VERIFY_THREADS`], or fewer on a machine with fewer threads.
fn verify_threads() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get).min(VERIFY_THREADS)
}

/// Reads one validated package, and checks it against the plan and the entry format.
///
/// This is all of `verify`'s work that concerns one package alone, so it can run on any thread.
/// It reads the archive, compares its `.PKGINFO` with the plan, checks that its entry can be
/// recorded, and reads the installed version it replaces.
///
/// # Errors
///
/// The error, with `true` when the package file must be removed from the cache: the archive is
/// not the one the plan showed. The caller removes it, because only the caller holds the
/// source.
fn prepare(
    local: &LocalDatabase,
    expectations: &HashMap<String, Expected>,
    limits: PackageLimits,
    package: &PackageFileName,
    location: &crate::source::Location,
    validation: Validation,
) -> std::result::Result<(Prepared, conflict::Target), (Error, bool)> {
    let plain = |error| (error, false);
    let path = location.path().to_path_buf();
    let expected = expectations.get(&package.to_string());
    // Bounded by the size the plan declares, so an archive that inflates past it is refused
    // near that size, on this read and on the extraction's.
    let limits =
        expected.map_or(limits, |expected| limits.with_declared_size(expected.installed_size()));
    let conflict::LoadedPackage { target, info, footprint, .. } =
        conflict::load_package(&path, &limits).map_err(plain)?;
    self::matches_plan(package, expected, &path, &info).map_err(|refusal| (refusal, true))?;
    let entry = self::entry_name(&path, &info).map_err(plain)?;
    // Before anything is extracted: a value the entry format cannot hold refuses the package
    // here, rather than after its files are already in the root.
    crate::record::check(&info, target.files.iter(), target.backups.iter().map(String::as_str))
        .map_err(|error| {
            plain(Error::UnusableSource {
                path: path.clone(),
                reason: format!("its entry cannot be recorded: {error}"),
            })
        })?;

    // The installed package of the same name, looked up once and used five ways. It decides
    // `pre_install` against `pre_upgrade`. It supplies the scriptlet's `oldver` argument. It
    // names the entry `install_step` has to replace. It supplies the file list its fake removal
    // deletes. And it supplies the `%BACKUP%` baseline extraction needs, to tell an edited
    // config file from an untouched one.
    let replaces = superseded(local.get_str(&target.name)).map_err(plain)?;

    let prepared = Prepared {
        path,
        name: target.name.clone(),
        version: target.version.clone(),
        entry,
        info,
        validation,
        limits,
        script: target.install_script.clone(),
        files: target.files.clone(),
        backups: target.backups.clone(),
        replaces,
        footprint,
    };
    Ok((prepared, target))
}

/// A file list as a hook trigger compares it: plain strings, directories keeping their `/`.
fn spell(files: &[PathBuf]) -> Vec<String> {
    files.iter().map(|path| path.to_string_lossy().into_owned()).collect()
}

/// What an install has to take apart first, gathered while the old entry is still readable.
///
/// `None` when nothing of this name is installed. That is the ordinary fresh install.
///
/// # Errors
///
/// [`Error::UnreadableEntry`] if the installed entry exists but its `%FILES%` or `%BACKUP%`
/// cannot be read. An empty list is not an acceptable default here. The install is about to
/// delete that entry. An empty list would then leave every file it owned on disk, with nothing
/// recording who put them there. That is the exact shape of the cached-emptiness bug, in the
/// one place where it destroys data. Raising it at `verify` also keeps the promise `Verified`
/// makes. The commit does not fail for something that could have been read up front.
fn superseded(installed: Option<&LocalPackage>) -> Result<Option<Superseded>> {
    let Some(package) = installed else { return Ok(None) };
    self::installed_state(package.entry(), package).map(Some)
}

/// One installed entry's `%FILES%` and `%BACKUP%`, read while it is still on disk.
///
/// Shared by the two things that take an installed entry apart, rather than written twice.
/// Those two are an upgrade's fake removal and a real removal. This way the rule that neither
/// list may be defaulted cannot be applied in one place and skipped in the other.
/// `remove_files` is one function with two callers for the same reason.
///
/// # Errors
///
/// [`Error::UnreadableEntry`] if either list cannot be read.
fn installed_state(entry: &EntryName, package: &LocalPackage) -> Result<Superseded> {
    let files = package
        .file_list()
        .map_err(|error| Error::UnreadableEntry {
            entry: entry.as_str().to_owned(),
            reason: format!("its file list is unreadable: {error}"),
        })?
        .map(PathBuf::from)
        .collect();
    let backups = package
        .backups()
        .map_err(|error| Error::UnreadableEntry {
            entry: entry.as_str().to_owned(),
            reason: format!("its backup list is unreadable: {error}"),
        })?
        .iter()
        // A `(null)` entry has no hash to compare against: it names a file the package does
        // not ship. So it gives neither a `.pacsave` nor a `.pacnew` decision a baseline.
        .filter_map(|backup| {
            Some((backup.path.inner().to_path_buf(), backup.md5.as_ref()?.to_string()))
        })
        .collect();

    Ok(Superseded { entry: entry.clone(), files, backups, shared_directories: BTreeSet::new() })
}

/// Records, for each installed entry a step takes apart, the directories it lists that another
/// installed package also lists.
///
/// This is the last check `unlink_file` makes before an `rmdir` (`remove.c:495-513`). A
/// directory another package owns stays, even when it is empty now: it is that package's
/// directory too, with the mode and owner that package gave it. libalpm walks the whole local
/// database per directory. This reads every file list once, for the whole transaction, and
/// only when some step takes an entry apart, so no step opens a database.
///
/// A package this transaction removes is not counted as an owner. libalpm takes a removed
/// package out of its database as it goes, so the last of several owners being removed sees
/// the directory unowned. The entry itself is not counted either, removed or upgraded.
///
/// A file list that cannot be read owns nothing, as in the conflict check's index.
///
/// Two filters keep the cost to the directories that the steps can remove. Neither one
/// changes an answer:
///
/// - A directory that the replacement ships is not looked up. `decide_removal` tests
///   `replacement_ships_it` before `directory_has_other_owner`, so the step never asks about
///   it. An upgrade keeps most of its directories: 5 of 261, 4 of 592 and 23 of 4413
///   directories were left to look up in upgrades of 5, 20 and 100 real packages.
/// - A package is parsed only if [`LocalPackage::files_may_list`] finds one of those
///   directories in its text. The parse sorts and validates every path of every installed
///   package, which took 0.66 s to 0.80 s on a system with 1245 packages. The text search
///   only rules out a package, and the parse still decides which directories a package owns.
fn mark_shared_directories(
    local: &LocalDatabase,
    entries: &mut [(&mut Superseded, Option<Replacement<'_>>)],
    removed: &BTreeSet<&str>,
) {
    let mut wanted: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, (entry, replacement)) in entries.iter().enumerate() {
        for path in &entry.files {
            let spelled = path.to_string_lossy();
            if spelled.ends_with('/') && !replacement.is_some_and(|new| new.ships(&spelled)) {
                wanted.entry(spelled.into_owned()).or_default().push(index);
            }
        }
    }
    if wanted.is_empty() {
        return;
    }
    let names: Vec<String> =
        entries.iter().map(|(entry, _)| entry.entry.name().to_string()).collect();

    let mut shared: Vec<(usize, PathBuf)> = Vec::new();
    for package in local.iter() {
        let owner = package.name().to_string();
        if removed.contains(owner.as_str()) {
            continue;
        }
        if !package.files_may_list(|line| wanted.contains_key(line)) {
            continue;
        }
        let Ok(files) = package.file_list() else { continue };
        for spelled in files {
            let Some(indices) = wanted.get(spelled) else { continue };
            for &index in indices {
                if names.get(index).is_some_and(|name| *name != owner) {
                    let directory = spelled.strip_suffix('/').unwrap_or(spelled);
                    shared.push((index, PathBuf::from(directory)));
                }
            }
        }
    }
    for (index, directory) in shared {
        if let Some((entry, _)) = entries.get_mut(index) {
            entry.shared_directories.insert(directory);
        }
    }
}

/// Everything a removal step needs, read while the entry is still installed.
///
/// The mirror of [`Prepared`]. It exists to stop the local database being re-opened once per
/// removal step. The step only ever wants one entry. Opening a database to reach it means a
/// `readdir` of every installed package, ~1200 of them on this machine. That `readdir`
/// repeats for every package a `-Rcs` removes.
///
/// **Reading `%BACKUP%` here rather than in the step buys the `readdir`, and nothing about
/// safety.** It looks like it closes a hole in what `Verified` promises. A step reads its
/// entry after `pre_remove` has already run. It closes nothing. `%FILES%` and `%BACKUP%` are one
/// `files` file behind a single `Lazy<DbFiles>` in `LocalPackage`. Forcing the file list, which
/// `verify` does, forces the backup list with it. So `backups()` cannot fail where
/// `file_list()` succeeded. See
/// `a_malformed_backup_hash_makes_the_whole_entry_unreadable_at_verify`, which pins that.
#[derive(Clone, Debug)]
struct Doomed {
    /// Its `%FILES%` and `%BACKUP%`, read exactly as an upgrade reads the version it replaces.
    installed: Superseded,
    /// Its `install` scriptlet, if it ships one and scriptlets are turned on.
    ///
    /// `post_remove` runs after the entry has been deleted, so the bytes have to be held
    /// somewhere regardless. They are held from `verify` rather than from the top of the step.
    /// That removes the last reason for that step to open a database.
    script: Option<Vec<u8>>,
}

/// Reads what [`remove_step`] will need from an entry that is still on disk.
///
/// # Errors
///
/// [`Error::UnreadableEntry`] if `%FILES%` or `%BACKUP%` cannot be read. Neither may be
/// defaulted. An empty file list would delete the entry. It would leave every file it owned on
/// disk, with nothing recording who put them there.
fn doomed(entry: &EntryName, package: &LocalPackage, want_script: bool) -> Result<Doomed> {
    Ok(Doomed {
        installed: self::installed_state(entry, package)?,
        // Only when something will run it. A missing or unreadable scriptlet is not an error
        // either way — see [`read_entry_scriptlet`].
        script: want_script.then(|| read_entry_scriptlet(package.path())).flatten(),
    })
}

impl<'lock> Transaction<Verified<'lock>> {
    /// What the disk-space estimate could not measure.
    ///
    /// Empty when `CheckSpace` is off, and empty on a system where every path mapped to a
    /// readable filesystem. A problem here means part of the estimate is missing. It does not
    /// mean the transaction was refused: a refusal is [`Error::DiskSpace`], raised by
    /// [`Transaction::verify`] in place of a return value.
    #[must_use]
    pub fn space_problems(&self) -> &[crate::space::Problem] {
        &self.state.space_problems
    }

    /// What each package's `.PKGINFO` holds that the install reads past, by `pkgname`.
    ///
    /// A package with no problem is not listed. A problem here never refuses the package:
    /// an invalid shown key is recorded as written, and an unknown key is not recorded.
    /// libalpm warns about each unknown key as it loads a package.
    #[must_use]
    pub fn package_problems(&self) -> Vec<(&str, Vec<crate::pkginfo::Problem>)> {
        self.state
            .packages
            .iter()
            .map(|package| (package.name.as_str(), package.info.problems()))
            .filter(|(_, problems)| !problems.is_empty())
            .collect()
    }

    /// Writes the journal under the lock `verify` was given, reaching the point of no return.
    ///
    /// The transaction's records are opened here too, beside the journal and for the same
    /// reason. An unwritable `LogFile` is worth reporting while nothing has changed yet.
    /// Unlike the journal, a record that cannot be opened does not stop the transaction. See
    /// [`crate::history`].
    ///
    /// The root and the exec helper are opened first, before the journal. A failure there is a
    /// refusal with nothing changed, and must not leave a journal that reads as an interrupted
    /// transaction. The exec helper is needed only when scriptlets or hooks can run.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the root or the exec helper cannot be opened,
    /// [`Error::UnfinishedTransaction`] if a journal appeared since `verify` checked, and
    /// [`Error::Io`] if the journal cannot be written.
    pub fn stage(self) -> Result<Transaction<Staged<'lock>>> {
        let root = RootDir::open(&self.root_path)?;
        let runner = if self.scriptlets || !self.hook_dirs.is_empty() {
            Some(Runner::new(&self.root_path)?)
        } else {
            None
        };
        let intents: Vec<Intent> = self.state.steps.iter().map(Step::intent).collect();
        let journal = Journal::begin(&self.dbpath, &self.root_path, &intents)?;
        let recorder =
            Recorder::open(&self.recording, &self.root_path, &self.dbpath, crate::history::now());

        Ok(self.map_state(|verified| Staged {
            steps: verified.steps,
            packages: verified.packages,
            removals: verified.removals,
            skip_remove: verified.skip_remove,
            summary: verified.summary,
            root,
            runner,
            journal,
            recorder: Some(recorder),
            lock: verified.lock,
        }))
    }
}

impl Transaction<Staged<'_>> {
    /// Abandons the transaction, removing the journal.
    ///
    /// Valid only because nothing has been mutated yet — which is exactly what the `Staged`
    /// state means.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the journal cannot be removed.
    pub fn abandon(self) -> Result<()> {
        // Nothing was applied, so nothing is recorded — not even a `transaction failed` line.
        // A refused transaction must not look like one that ran, in the log any more than in
        // the journal.
        drop(self.state.recorder.map(Recorder::abandon));
        self.state.journal.finish()
    }

    /// Applies every step, in order.
    ///
    /// # Errors
    ///
    /// Whatever the underlying step fails with. **The journal is deliberately left behind on
    /// failure.** A partly applied transaction is exactly the state it exists to record.
    /// Removing it would erase the only evidence.
    pub fn commit(self) -> Result<Report> {
        self.commit_with_progress(&mut |_| {})
    }

    /// As [`Transaction::commit`], reporting progress through `progress` as it happens.
    ///
    /// `progress` is a narrow, deliberate exception to "diagnostics are returned, not logged".
    /// Read [`crate::progress`]'s documentation before treating this as license to add another
    /// one. It fires only for [`Step::Install`]/[`Step::Remove`], not for hooks, which already
    /// report through [`Report::hooks`]. It takes `FnMut` rather than `Fn`. A caller printing a
    /// durable line per step needs a mutable borrow of whatever it writes to.
    ///
    /// # Errors
    ///
    /// As [`Transaction::commit`].
    pub fn commit_with_progress(mut self, progress: &mut dyn FnMut(Event<'_>)) -> Result<Report> {
        // Taken out of the state, so the ending is written from exactly one place however
        // `apply` returns. One ending per `?` is how an exit path eventually stops writing one
        // at all. A completed transaction then reads as an interrupted one.
        let mut recorder = self.state.recorder.take();
        if let Some(recorder) = recorder.as_mut() {
            recorder.started();
        }

        let mut result = {
            // Every event reaches the records and the caller alike. The event stream is what
            // keeps the records behind the journal. `StepFinished` is emitted only once
            // `journal.completed` has returned, so nothing can be recorded that the journal
            // does not already know.
            let mut observed = |event: Event<'_>| {
                if let Some(recorder) = recorder.as_mut() {
                    recorder.observe(&event);
                }
                progress(event);
            };
            self.apply(&mut observed)
        };

        let problems = recorder.map_or_else(Vec::new, |recorder| {
            let outcome = match &result {
                Ok(_) => HistoryOutcome::Completed,
                // A cancellation is not a failure. The steps it counts did run, and the user
                // asked for the stop. `piko history` renders the two differently.
                Err(Error::Cancelled { .. }) => HistoryOutcome::Cancelled,
                Err(error) => HistoryOutcome::Failed { reason: error.to_string() },
            };
            recorder.finish(outcome, crate::history::now())
        });
        if let Ok(report) = result.as_mut() {
            report.history_problems = problems;
        }
        result
    }

    /// Applies every step, reporting through `progress`.
    ///
    /// Split out of [`Staged::commit_with_progress`] so that its every `?` still passes
    /// through one place that writes the transaction's ending.
    fn apply(self, progress: &mut dyn FnMut(Event<'_>)) -> Result<Report> {
        let mut state = self.state;
        let root = &state.root;
        let runner = state.runner.as_ref();
        let mut report = Report::default();
        let mut next_package = 0_usize;
        let mut next_removal = 0_usize;

        // Runs before anything changes. A `PreTransaction` hook with `AbortOnFail` that fails
        // stops the transaction here, with the system still untouched. That is the whole reason
        // the flag is `PreTransaction`-only. A hook that cannot be run at all stops it the same
        // way.
        let refusal = match self::run_hooks(
            runner,
            &self.dbpath,
            &self.hook_dirs,
            When::PreTransaction,
            &state.summary,
            &mut report,
            progress,
        ) {
            Ok(aborted) => aborted,
            Err(error) => Some(error),
        };
        if let Some(error) = refusal {
            // The journal is removed. Nothing was applied, so leaving one behind would make a
            // refused transaction look like an interrupted one.
            state.journal.finish()?;
            return Err(error);
        }
        let scriptlet_runner = if self.scriptlets { runner } else { None };

        let total = state.steps.len();
        let mut completed = 0_usize;
        for (index, step) in state.steps.iter().enumerate() {
            // Read before the step starts, so a raised flag never splits one. The step
            // before it wrote its own journal line and fsynced. The journal left behind
            // therefore names exactly what was applied. The remaining steps stay unattempted.
            //
            // `PostTransaction` hooks are skipped by the early return. `alpm-hooks(5)`
            // requires that: they do not run when a transaction does not complete.
            //
            // A stop before the first step applied nothing, so the journal goes, as for a
            // refusal. Kept, it would refuse the next transaction and ask for a reinstall of
            // every target. The flag is often raised during a slow `PreTransaction` hook.
            if self.cancel.as_ref().is_some_and(piko_net::Cancel::is_requested) {
                if completed == 0 {
                    state.journal.finish()?;
                }
                return Err(Error::Cancelled { completed, total });
            }
            // Peeked, not consumed. `next_package` still advances only inside the
            // `Step::Install` arm below.
            let replaces = match step {
                Step::Install { .. } => state
                    .packages
                    .get(next_package)
                    .and_then(|package| package.replaces.as_ref().map(|old| &old.entry)),
                Step::Remove { .. } => None,
            };
            progress(Event::StepStarted { index, total, step, replaces });
            match step {
                Step::Install { reason, .. } => {
                    let Some(package) = state.packages.get(next_package) else {
                        return Err(Error::UnusableSource {
                            path: PathBuf::new(),
                            reason: "verification did not locate this package".to_owned(),
                        });
                    };
                    next_package = next_package.saturating_add(1);
                    let pacnews_before = report.pacnews.len();
                    let pacsaves_before = report.pacsaves.len();
                    let extraction = self::install_step(
                        &InstallStep {
                            root,
                            dbpath: &self.dbpath,
                            lock: state.lock,
                            package,
                            reason: *reason,
                            ownership: self.ownership,
                            skip_remove: &state.skip_remove,
                            patterns: &self.patterns,
                            runner: scriptlet_runner,
                        },
                        &mut report,
                        progress,
                    )?;
                    state.journal.completed(index)?;
                    completed = completed.saturating_add(1);
                    progress(Event::StepFinished {
                        step,
                        outcome: StepOutcome::Installed {
                            entry: &package.entry,
                            replaced: package.replaces.as_ref().map(|old| &old.entry),
                            extraction: &extraction,
                            pacnews: report.pacnews.get(pacnews_before..).unwrap_or_default(),
                            pacsaves: report.pacsaves.get(pacsaves_before..).unwrap_or_default(),
                        },
                    });
                    report.installed.push((
                        package.path.file_name().unwrap_or_default().to_string_lossy().into_owned(),
                        extraction,
                    ));
                }
                Step::Remove { entry, no_save } => {
                    let Some(doomed) = state.removals.get(next_removal) else {
                        return Err(Error::UnusableSource {
                            path: PathBuf::from(entry.as_str()),
                            reason: "verification did not read this entry".to_owned(),
                        });
                    };
                    next_removal = next_removal.saturating_add(1);
                    let (touched, pacsaves) = self::remove_step(
                        &RemoveStep {
                            root,
                            dbpath: &self.dbpath,
                            lock: state.lock,
                            entry,
                            doomed,
                            no_save: *no_save,
                            skip_remove: &state.skip_remove,
                            patterns: &self.patterns,
                            runner: scriptlet_runner,
                        },
                        &mut report,
                        progress,
                    )?;
                    state.journal.completed(index)?;
                    completed = completed.saturating_add(1);
                    progress(Event::StepFinished {
                        step,
                        outcome: StepOutcome::Removed { pacsaves: &pacsaves },
                    });
                    report.removed.push((entry.as_str().to_owned(), touched));
                    report.pacsaves.extend(pacsaves);
                }
            }
        }

        // `alpm-hooks(5)` says: "PostTransaction hooks will not run if the transaction
        // fails to complete for any reason." So this runs after the loop. The `?`s above skip
        // it entirely.
        // `AbortOnFail` is meaningless here and is ignored, as in libalpm.
        //
        // Every step is applied, so a phase that cannot run is reported, never returned.
        // Returned, it would keep the journal and record a failure for a transaction that
        // completed. `trans.c:238` ignores `_alpm_hook_run`'s result here too.
        if let Err(error) = self::run_hooks(
            runner,
            &self.dbpath,
            &self.hook_dirs,
            When::PostTransaction,
            &state.summary,
            &mut report,
            progress,
        ) {
            report
                .hook_problems
                .push(hook::Problem::PostTransactionNotRun { reason: error.to_string() });
        }

        state.journal.finish()?;
        Ok(report)
    }
}

/// Runs the hooks for one phase, appending each to `report`.
///
/// Returns the refusal a hook raises when it demands the transaction be abandoned, if one does.
/// The error is built here, where the [`hook::Run`] carrying the cause is still in hand.
///
/// # The hook files are read here, not once up front
///
/// `_alpm_hook_run` does its own `opendir`/`readdir` of every `HookDir` (`hook.c:536`). It runs
/// twice, before the transaction and after it (`trans.c:202` and `trans.c:238`). So the set of
/// hook files is whatever is on disk **at the moment the phase runs**. The two phases can
/// legitimately see different sets.
///
/// That is not a minor detail. Arch ships each hook in the same package as the program it runs.
/// 31 of this machine's 46 hooks name an `Exec` their own package owns. A removal deletes the
/// hook file together with the binary, and the `PostTransaction` pass simply never finds it.
/// Only 8 of those 46 declare a `Depends`, so `Depends` is *not* what protects them. Collecting
/// the hook set once before the transaction would run a hook whose file and command were both
/// just deleted.
fn run_hooks(
    runner: Option<&Runner>,
    dbpath: &Path,
    hook_dirs: &[PathBuf],
    when: When,
    summary: &hook::Summary,
    report: &mut Report,
    progress: &mut dyn FnMut(Event<'_>),
) -> Result<Option<Error>> {
    // `stage` builds the runner whenever a hook directory is configured, so `None` means
    // there is none.
    let Some(runner) = runner.filter(|_| !hook_dirs.is_empty()) else {
        return Ok(None);
    };

    let (hooks, problems) = Hooks::collect(hook_dirs);
    report.hook_problems.extend(problems);

    let triggered = hooks.triggered(when, summary);
    if triggered.is_empty() {
        return Ok(None);
    }

    // Re-opened per phase rather than held. A `PostTransaction` hook's `Depends` must be
    // judged against the database as the transaction left it. That is exactly what
    // `_alpm_hook_run_hook` reads (`hook.c:505`) at the moment it runs.
    let local = LocalDatabase::open(dbpath.join("local"))
        .map_err(|error| Error::local_db(dbpath.join("local"), error))?;

    let total = triggered.len();
    progress(Event::HooksStarted { total });
    for (index, (hook, targets)) in triggered.into_iter().enumerate() {
        progress(Event::HookStarted {
            index,
            total,
            name: &hook.name,
            description: hook.description.as_deref(),
        });
        let run = hook::run(runner, &local, hook, &targets, &mut |line| {
            progress(Event::HookOutputLine { index, total, line });
        })?;
        let fatal = run.fatal.then(|| Error::HookAborted {
            hook: run.name.clone(),
            reason: run.failure_reason(),
            output: run.outcome.as_ref().map_or_else(Vec::new, |outcome| outcome.output.clone()),
        });
        progress(Event::HookFinished { index, total, run: &run });
        report.hooks.push(run);
        if let Some(error) = fatal {
            return Ok(Some(error));
        }
    }
    Ok(None)
}

/// The `install` file inside a database entry, if it has one.
///
/// A missing scriptlet is the common case and not an error — `_alpm_runscriptlet` returns
/// success for a path it cannot read (`trans.c:346`). An unreadable one is treated the same
/// way. A removal must not be blocked by a file it is about to delete anyway.
///
/// Read as bytes, as the install read it out of the archive: a scriptlet that ran at install is
/// one its `pre_remove` runs from too, whatever its encoding.
fn read_entry_scriptlet(entry_path: &Path) -> Option<Vec<u8>> {
    piko_db::fs_util::read_capped_in(
        entry_path,
        "install",
        piko_db::Limit::Desc,
        MAX_SCRIPTLET_BYTES,
    )
    .ok()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::source::CacheDirSource;

    /// A `.PKGINFO` for `foo` at `version`, declaring `backups` as `%BACKUP%` paths.
    fn pkginfo(version: &str, backups: &[&str]) -> String {
        let mut text = format!(
            "pkgname = foo\npkgbase = foo\npkgver = {version}\n\
             pkgdesc = An example package\nurl = https://example.org/\n\
             builddate = 1733737242\n\
             packager = Foobar McFooface <foobar@mcfooface.org>\n\
             size = 123\narch = x86_64\nlicense = MIT\n"
        );
        for path in backups {
            text.push_str(&format!("backup = {path}\n"));
        }
        text
    }

    /// A cache holding one synthetic package at version `1.0.0-1` with no backup files.
    fn cache_with_package(name: &str, payload: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write_package(dir.path(), name, "1.0.0-1", &[], payload);
        dir
    }

    /// Writes one synthetic `foo` package into `dir`.
    fn write_package(
        dir: &Path,
        name: &str,
        version: &str,
        backups: &[&str],
        payload: &[(&str, &[u8])],
    ) {
        let mut builder = tar::Builder::new(Vec::new());

        fn add(builder: &mut tar::Builder<Vec<u8>>, path: &str, contents: &[u8]) {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        fn add_dir(builder: &mut tar::Builder<Vec<u8>>, path: &str) {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Directory);
            header.set_cksum();
            builder.append_data(&mut header, path, &[][..]).unwrap();
        }

        add(&mut builder, ".PKGINFO", pkginfo(version, backups).as_bytes());
        // A real package lists every parent directory it owns exactly once. The `files` reader
        // requires both halves of that, so the fixture does too.
        let mut listed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (path, contents) in payload {
            let mut prefix = String::new();
            let parts: Vec<&str> = path.split('/').collect();
            for part in parts.iter().take(parts.len().saturating_sub(1)) {
                prefix.push_str(part);
                prefix.push('/');
                if listed.insert(prefix.clone()) {
                    add_dir(&mut builder, &prefix);
                }
            }
            add(&mut builder, path, contents);
        }
        std::fs::write(dir.join(name), builder.into_inner().unwrap()).unwrap();
    }

    /// A cache holding one package whose `.PKGINFO` is spelled out rather than generated.
    fn cache_with_raw_pkginfo(
        name: &str,
        pkginfo: &str,
        payload: &[(&str, &[u8])],
    ) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut add = |path: &str, contents: &[u8], is_dir: bool| {
            let mut header = tar::Header::new_gnu();
            header.set_mode(if is_dir { 0o755 } else { 0o644 });
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(contents.len() as u64);
            if is_dir {
                header.set_entry_type(tar::EntryType::Directory);
            }
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        };

        add(".PKGINFO", pkginfo.as_bytes(), false);
        for (path, contents) in payload {
            let mut prefix = String::new();
            let parts: Vec<&str> = path.split('/').collect();
            for part in parts.iter().take(parts.len().saturating_sub(1)) {
                prefix.push_str(part);
                prefix.push('/');
                add(&prefix.clone(), &[][..], true);
            }
            add(path, contents, false);
        }
        std::fs::write(dir.path().join(name), builder.into_inner().unwrap()).unwrap();
        dir
    }

    fn dbpath() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("local")).unwrap();
        std::fs::write(dir.path().join("local/ALPM_DB_VERSION"), "9\n").unwrap();
        dir
    }

    #[test]
    fn installs_a_package_and_records_it() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();

        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };

        let lock = DbLock::acquire(db.path()).unwrap();
        let report = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap()
            .stage()
            .unwrap()
            .commit()
            .unwrap();

        assert_eq!(report.installed.len(), 1);
        assert_eq!(std::fs::read(root.path().join("usr/bin/foo")).unwrap(), b"binary");

        // The database entry is real: piko's own reader opens it.
        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        let package = local.get_str("foo").expect("the entry was not recorded");
        assert_eq!(package.version().to_string(), "1.0.0-1");
        assert_eq!(
            package.file_list().unwrap().collect::<Vec<_>>(),
            ["usr/", "usr/bin/", "usr/bin/foo"]
        );

        // And the journal is gone, so nothing looks interrupted.
        assert!(crate::journal::read(db.path()).unwrap().is_none());
    }

    /// The three metadata members `extract_db_file` redirects reach the entry, each carrying
    /// the time the archive gave it.
    ///
    /// The time is the load-bearing half. `ALPM-MTREE` records a time for `.INSTALL`, and
    /// `piko check` compares that record against the entry's own `install`. A member written
    /// with the time of the transaction reads as altered from the moment it lands.
    ///
    /// `changelog` is the member easiest to leave out, because nothing else in piko reads it.
    /// `pacman -Qc` does. So does `LocalPackage::verify_files`, against the same mtree data it
    /// checks `install` against.
    #[test]
    fn the_database_members_keep_the_archive_time() {
        /// Distinctive, and far enough from now that a fallback to the write time is obvious.
        const STAMPED: u64 = 1_700_000_000;

        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let mut add = |path: &str, contents: &[u8], is_dir: bool| {
            let mut header = tar::Header::new_gnu();
            header.set_mode(if is_dir { 0o755 } else { 0o644 });
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(STAMPED);
            header.set_size(contents.len() as u64);
            if is_dir {
                header.set_entry_type(tar::EntryType::Directory);
            }
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        };
        add(".PKGINFO", pkginfo("1.0.0-1", &[]).as_bytes(), false);
        add(".INSTALL", b"post_install() { :; }\n", false);
        add(".CHANGELOG", b"1.0.0-1 first release\n", false);
        // Never parsed here. This test is about where the bytes land, not what they mean.
        add(".MTREE", b"opaque\n", false);
        add("usr/", &[][..], true);
        add("usr/bin/", &[][..], true);
        add("usr/bin/foo", b"binary", false);
        std::fs::write(cache.path().join(name), builder.into_inner().unwrap()).unwrap();

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };

        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap()
            .stage()
            .unwrap()
            .commit()
            .unwrap();

        let entry = db.path().join("local/foo-1.0.0-1");
        assert_eq!(std::fs::read(entry.join("changelog")).unwrap(), b"1.0.0-1 first release\n");
        for member in ["install", "changelog", "mtree"] {
            let seen = std::fs::metadata(entry.join(member))
                .unwrap_or_else(|error| panic!("{member} is not in the entry: {error}"))
                .modified()
                .unwrap()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            assert_eq!(seen, STAMPED, "{member} was stamped with the write time");
        }
    }

    /// `CheckSpace` runs inside `verify`, reports itself, and lets a transaction that fits
    /// through.
    ///
    /// The unit tests in `space` prove the arithmetic and `space_hardening.rs` proves the
    /// refusal. What is left to pin is the wiring, in three parts:
    ///
    /// - the builder reaches the check at all,
    /// - the check runs against the transaction's own root rather than `/`,
    /// - the caller is told it started.
    ///
    /// A silent no-op would pass every other test in this crate.
    #[test]
    fn a_space_checked_transaction_reports_the_check_and_installs() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };

        let mut announced = false;
        let lock = DbLock::acquire(db.path()).unwrap();
        let verified = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .check_space(true)
            .verify_with_progress(&lock, &source, &mut |event| {
                if matches!(event, VerifyEvent::DiskSpaceCheckStarted) {
                    announced = true;
                }
            })
            .unwrap();
        assert!(announced, "the disk-space check ran without saying so");
        assert!(verified.space_problems().is_empty(), "{:?}", verified.space_problems());

        verified.stage().unwrap().commit().unwrap();
        assert!(root.path().join("usr/bin/foo").is_file());
    }

    /// A `.PKGINFO` with an invalid shown key and an unknown key installs, and `verify` names
    /// both. A package with neither is not listed.
    #[test]
    fn package_problems_name_what_the_install_reads_past() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let raw = pkginfo("1.0.0-1", &[]).replace("builddate = 1733737242", "builddate = soon")
            + "futurekey = 1\n";
        let cache = cache_with_raw_pkginfo(name, &raw, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };

        let lock = DbLock::acquire(db.path()).unwrap();
        let verified = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap();
        let problems = verified.package_problems();
        assert_eq!(problems.len(), 1, "{problems:?}");
        let (package, found) = problems.first().unwrap();
        assert_eq!(*package, "foo");
        assert!(
            matches!(
                found.as_slice(),
                [
                    crate::pkginfo::Problem::InvalidField(_),
                    crate::pkginfo::Problem::UnknownKey { .. }
                ]
            ),
            "{found:?}"
        );
        drop(problems);

        verified.stage().unwrap().commit().unwrap();
        assert!(root.path().join("usr/bin/foo").is_file());
    }

    /// An entry whose `files` lists a file without its parent directories is still removed.
    /// The file goes, and the directories it does not list stay, as libalpm leaves them.
    #[test]
    fn an_entry_without_its_parent_directories_is_removed() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();
        let install = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        Transaction::new(root.path(), db.path(), vec![install], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap()
            .stage()
            .unwrap()
            .commit()
            .unwrap();
        std::fs::write(db.path().join("local/foo-1.0.0-1/files"), "%FILES%\nusr/bin/foo\n\n")
            .unwrap();

        let removal =
            Step::Remove { entry: EntryName::parse("foo-1.0.0-1").unwrap(), no_save: false };
        Transaction::new(root.path(), db.path(), vec![removal], Verification::Disabled)
            .verify(&lock, &source)
            .unwrap()
            .stage()
            .unwrap()
            .commit()
            .unwrap();

        assert!(!root.path().join("usr/bin/foo").exists());
        assert!(root.path().join("usr/bin").is_dir(), "an unlisted directory is not the package's");
    }

    /// A transaction that installs nothing is not weighed, and says nothing about space.
    ///
    /// libalpm keeps the whole of `_alpm_sync_check` behind `if(trans->add)`, so `pacman -R`
    /// runs no check at all. A removal can only free space.
    #[test]
    fn a_removal_only_transaction_is_not_weighed() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap();

        let mut announced = false;
        let removal =
            Step::Remove { entry: EntryName::parse("foo-1.0.0-1").unwrap(), no_save: false };
        let verified =
            Transaction::new(root.path(), db.path(), vec![removal], Verification::Disabled)
                .check_space(true)
                .verify_with_progress(&lock, &source, &mut |event| {
                    if matches!(event, VerifyEvent::DiskSpaceCheckStarted) {
                        announced = true;
                    }
                })
                .unwrap();
        assert!(!announced, "a removal-only transaction must not be weighed");
        assert!(verified.space_problems().is_empty());
    }

    /// A cancellation is read between two steps, so the step already running finishes.
    ///
    /// This pins all three halves of [`Transaction::cancel`]'s contract. The step that was
    /// running is applied and recorded. The next one is not attempted. The journal stays
    /// behind, naming what was done.
    #[test]
    fn a_cancelled_commit_finishes_its_step_and_leaves_the_journal() {
        let foo = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(foo, &[("usr/bin/foo", b"binary")]);
        let bar = "bar-1.0.0-1-x86_64.pkg.tar";
        let bar_cache = cache_with_raw_pkginfo(
            bar,
            "pkgname = bar\npkgbase = bar\npkgver = 1.0.0-1\n\
             pkgdesc = An example package\nurl = https://example.org/\n\
             builddate = 1733737242\n\
             packager = Foobar McFooface <foobar@mcfooface.org>\n\
             size = 123\narch = x86_64\nlicense = MIT\n",
            &[("usr/bin/bar", b"bar")],
        );
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source =
            CacheDirSource::new([cache.path().to_path_buf(), bar_cache.path().to_path_buf()])
                .unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();

        // `bar` is installed first, so the cancelled transaction below has a second step that
        // is not an install. A step left unattempted must stay unattempted whatever it is.
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: bar.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap();

        let cancel = piko_net::Cancel::new();
        let steps = vec![
            Step::Install { package: foo.parse().unwrap(), reason: PackageInstallReason::Explicit },
            Step::Remove { entry: EntryName::parse("bar-1.0.0-1").unwrap(), no_save: false },
        ];
        // Raised from inside the commit, once the first step is over. This is the moment a
        // Ctrl+C lands in: a step has just been recorded, and the next has not started.
        let raise = cancel.clone();
        let error = Transaction::new(root.path(), db.path(), steps, Verification::Disabled)
            .ownership(Ownership::Inherit)
            .cancel(cancel)
            .verify(&lock, &source)
            .unwrap()
            .stage()
            .unwrap()
            .commit_with_progress(&mut |event| {
                if matches!(event, Event::StepFinished { .. }) {
                    raise.request();
                }
            })
            .unwrap_err();

        assert!(matches!(error, Error::Cancelled { completed: 1, total: 2 }), "{error:?}");

        // The first step is applied and recorded.
        assert_eq!(std::fs::read(root.path().join("usr/bin/foo")).unwrap(), b"binary");
        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        assert!(local.get_str("foo").is_some(), "the finished step was not recorded");
        // The second is untouched.
        assert!(local.get_str("bar").is_some(), "an unattempted step ran anyway");
        assert!(root.path().join("usr/bin/bar").exists());

        // And the journal stays, naming exactly the one step that ran.
        let record = crate::journal::read(db.path()).unwrap().expect("the journal was removed");
        assert_eq!(record.completed, [0]);
        assert_eq!(record.outstanding().len(), 1);
    }

    /// Verification reads the flag too, so a press there does not wait for the whole phase.
    ///
    /// Signature checking hashes every package file. A flag read only after that loop would
    /// leave a long wait between the press and the stop.
    #[test]
    fn a_cancelled_verification_stops_before_it_stages_anything() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let cancel = piko_net::Cancel::new();
        cancel.request();
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .cancel(cancel)
        .verify(&lock, &source)
        .unwrap_err();

        assert!(matches!(error, Error::Cancelled { completed: 0, total: 1 }), "{error:?}");
        // Verification stages nothing, so there is no journal to leave behind.
        assert!(crate::journal::read(db.path()).unwrap().is_none());
        assert!(!root.path().join("usr/bin/foo").exists());
    }

    /// A flag raised after verification stops the commit before its first step.
    ///
    /// This is the one window verification's own reads cannot cover. The press lands after
    /// verification's last read and before the first step. Nothing was applied, so the journal
    /// `stage` wrote is removed, as for a refusal.
    #[test]
    fn a_commit_cancelled_before_its_first_step_applies_nothing() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();

        let cancel = piko_net::Cancel::new();
        let verified = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .cancel(cancel.clone())
        .verify(&lock, &source)
        .unwrap();
        cancel.request();

        let error = verified.stage().unwrap().commit().unwrap_err();

        assert!(matches!(error, Error::Cancelled { completed: 0, total: 1 }), "{error:?}");
        assert!(!root.path().join("usr/bin/foo").exists());
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "a journal was left");
    }

    /// Verification reads the local database, so it runs under that database's own lock. A lock
    /// taken on another database protects none of what it reads.
    #[test]
    fn verification_refuses_the_lock_of_another_database() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let other = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(other.path()).unwrap();
        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let error = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap_err();
        assert!(
            matches!(error, Error::Database(piko_db_write::Error::WrongLock { .. })),
            "got {error:?}"
        );
    }

    #[test]
    fn removes_a_package_and_its_files() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap();

        let entry = EntryName::parse("foo-1.0.0-1").unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Remove { entry, no_save: false }],
            Verification::Disabled,
        )
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap();

        assert!(!root.path().join("usr/bin/foo").exists());
        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        assert!(local.get_str("foo").is_none(), "the entry survived removal");
    }

    /// A step planned against an installed state that changed before `verify` is refused,
    /// before any file is deleted: another package manager changed the database after the plan.
    #[test]
    fn a_step_planned_against_another_installed_state_is_refused() {
        let name = "foo-2.0.0-1-x86_64.pkg.tar";
        let cache = tempfile::tempdir().unwrap();
        write_package(cache.path(), name, "2.0.0-1", &[], &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap();

        let stale = EntryName::parse("foo-1.0.0-1").unwrap();
        let Err(error) = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Remove { entry: stale, no_save: false }],
            Verification::Disabled,
        )
        .verify(&lock, &source) else {
            panic!("a stale removal must be refused");
        };

        assert!(
            matches!(&error, Error::PlanStale { planned: Some(planned), installed: Some(installed), .. }
                if planned == "foo-1.0.0-1" && installed == "foo-2.0.0-1"),
            "got {error:?}"
        );
        assert!(root.path().join("usr/bin/foo").exists(), "no file may be removed");

        // The install side: a fresh install expects the name not to be installed, and an
        // upgrade expects the version it was planned from.
        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        let foo: alpm_types::Name = "foo".parse().unwrap();
        assert!(matches!(
            check_installed(&local, &foo, None),
            Err(Error::PlanStale { planned: None, installed: Some(_), .. })
        ));
        let current = EntryName::parse("foo-2.0.0-1").unwrap();
        assert!(check_installed(&local, &foo, Some(&current)).unwrap().is_some());
    }

    /// Writes package `name` at `version` into `dir`, with `members` spelled byte for byte.
    ///
    /// `tar::Builder::append_data` normalises a name, so a test of a spelling the reader must
    /// refuse cannot go through it.
    fn write_raw_package(
        dir: &Path,
        name: &str,
        version: &str,
        members: &[(&str, tar::EntryType)],
    ) -> PackageFileName {
        use crate::extract::archive::fixture::raw;

        let mut builder = tar::Builder::new(Vec::new());
        let info = pkginfo(version, &[]).replace("= foo\n", &format!("= {name}\n"));
        raw(&mut builder, ".PKGINFO", tar::EntryType::Regular, None, info.as_bytes());
        for (path, kind) in members {
            raw(&mut builder, path, *kind, None, name.as_bytes());
        }
        let file = format!("{name}-{version}-x86_64.pkg.tar");
        std::fs::write(dir.join(&file), builder.into_inner().unwrap()).unwrap();
        file.parse().unwrap()
    }

    /// Runs `steps` against `root` and `db`, from `cache`, without ownership.
    fn run_steps(cache: &Path, db: &Path, root: &Path, steps: Vec<Step>) -> Result<Report> {
        let source = CacheDirSource::new([cache.to_path_buf()]).unwrap();
        let lock = DbLock::acquire(db).unwrap();
        Transaction::new(root, db, steps, Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)?
            .stage()?
            .commit()
    }

    fn install_step(package: PackageFileName) -> Step {
        Step::Install { package, reason: PackageInstallReason::Explicit }
    }

    fn remove_step(entry: &str) -> Step {
        Step::Remove { entry: EntryName::parse(entry).unwrap(), no_save: false }
    }

    /// A member spelled `usr/./bin/tool` names the file another package in the same
    /// transaction ships as `usr/bin/tool`. Conflict detection compares the strings and would
    /// see two files, while extraction writes one: the second package would take the first
    /// one's file over, and removing it would delete a file the first still claims. So the
    /// spelling refuses the package before anything is written.
    #[test]
    fn a_second_spelling_of_another_package_s_file_is_refused_before_the_root_is_touched() {
        use tar::EntryType::{Directory, Regular};

        let cache = tempfile::tempdir().unwrap();
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let first = write_raw_package(
            cache.path(),
            "aaa",
            "1.0.0-1",
            &[("usr/", Directory), ("usr/bin/", Directory), ("usr/bin/tool", Regular)],
        );
        let second = write_raw_package(
            cache.path(),
            "bbb",
            "1.0.0-1",
            &[("usr/", Directory), ("usr/bin/", Directory), ("usr/./bin/tool", Regular)],
        );

        let error = run_steps(
            cache.path(),
            db.path(),
            root.path(),
            vec![install_step(first), install_step(second)],
        )
        .unwrap_err();
        assert!(matches!(error, Error::UnsafeArchivePath { .. }), "got {error:?}");
        assert!(!root.path().join("usr").exists(), "the root was touched");
    }

    /// An upgrade that moves a file beneath a symbolic link (`usr/sbin -> bin`) is refused at
    /// `verify`. Extraction never writes through the link, and by the time it would try, the
    /// upgrade has deleted the old version's files: the package would keep no binary, with its
    /// entry naming the old version.
    #[test]
    fn a_file_beneath_a_symlinked_directory_is_refused_before_the_old_version_is_removed() {
        use tar::EntryType::{Directory, Regular};

        let cache = tempfile::tempdir().unwrap();
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        std::os::unix::fs::symlink("bin", root.path().join("usr/sbin")).unwrap();

        let old = write_raw_package(
            cache.path(),
            "ccc",
            "1.0.0-1",
            &[("usr/", Directory), ("usr/bin/", Directory), ("usr/bin/ccc", Regular)],
        );
        run_steps(cache.path(), db.path(), root.path(), vec![install_step(old)]).unwrap();

        let new = write_raw_package(
            cache.path(),
            "ccc",
            "2.0.0-1",
            &[("usr/", Directory), ("usr/sbin/", Directory), ("usr/sbin/ccc", Regular)],
        );
        let error =
            run_steps(cache.path(), db.path(), root.path(), vec![install_step(new)]).unwrap_err();

        let Error::FileConflicts { conflicts } = &error else {
            panic!("expected a file conflict, got {error:?}");
        };
        assert!(
            matches!(
                conflicts.as_slice(),
                [conflict::FileConflict { blocker: conflict::Blocker::Unreachable { .. }, .. }]
            ),
            "{conflicts:?}"
        );
        assert_eq!(std::fs::read(root.path().join("usr/bin/ccc")).unwrap(), b"ccc");
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "a journal was left");
    }

    /// `verify` reads the archives on several threads. The failure it reports is still the first
    /// one in step order, as a serial loop reports it, and nothing is written.
    #[test]
    fn the_first_unreadable_package_in_step_order_is_the_one_reported() {
        use tar::EntryType::Directory;

        let cache = tempfile::tempdir().unwrap();
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let names = ["aaa", "bbb", "ccc", "ddd", "eee", "fff", "ggg", "hhh"];
        let mut steps = Vec::new();
        for (index, name) in names.into_iter().enumerate() {
            let package = if index == 2 || index == 5 {
                let file = format!("{name}-1.0.0-1-x86_64.pkg.tar");
                std::fs::write(cache.path().join(&file), b"not an archive").unwrap();
                file.parse().unwrap()
            } else {
                write_raw_package(cache.path(), name, "1.0.0-1", &[("srv/", Directory)])
            };
            steps.push(install_step(package));
        }

        let error = run_steps(cache.path(), db.path(), root.path(), steps).unwrap_err();
        let reported = format!("{error:?}");
        assert!(reported.contains("ccc-1.0.0-1"), "{reported}");
        assert!(!root.path().join("srv").exists(), "the root was touched");
    }

    /// An empty directory two packages own stays when one of them is removed, as libalpm
    /// keeps it (`remove.c:495`). It goes with the last owner.
    #[test]
    fn an_empty_directory_another_package_owns_survives_a_removal() {
        use tar::EntryType::Directory;

        let cache = tempfile::tempdir().unwrap();
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let members = [("srv/", Directory), ("srv/shared/", Directory)];
        let first = write_raw_package(cache.path(), "aaa", "1.0.0-1", &members);
        let second = write_raw_package(cache.path(), "bbb", "1.0.0-1", &members);
        let third = write_raw_package(cache.path(), "ccc", "1.0.0-1", &members);
        run_steps(
            cache.path(),
            db.path(),
            root.path(),
            vec![install_step(first), install_step(second), install_step(third)],
        )
        .unwrap();

        run_steps(cache.path(), db.path(), root.path(), vec![remove_step("bbb-1.0.0-1")]).unwrap();
        assert!(root.path().join("srv/shared").is_dir(), "a directory aaa owns was removed");

        // Removed together, the last two owners take it with them.
        run_steps(
            cache.path(),
            db.path(),
            root.path(),
            vec![remove_step("aaa-1.0.0-1"), remove_step("ccc-1.0.0-1")],
        )
        .unwrap();
        assert!(!root.path().join("srv").exists(), "a directory nobody owns was left");
    }

    /// The same rule during an upgrade's removal of the old version: a directory the new
    /// version drops stays while another package owns it.
    #[test]
    fn an_upgrade_keeps_an_empty_directory_another_package_owns() {
        use tar::EntryType::Directory;

        let cache = tempfile::tempdir().unwrap();
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let members = [("srv/", Directory), ("srv/shared/", Directory)];
        let other = write_raw_package(cache.path(), "aaa", "1.0.0-1", &members);
        let old = write_raw_package(cache.path(), "bbb", "1.0.0-1", &members);
        run_steps(
            cache.path(),
            db.path(),
            root.path(),
            vec![install_step(other), install_step(old)],
        )
        .unwrap();

        let new = write_raw_package(cache.path(), "bbb", "2.0.0-1", &[("srv/", Directory)]);
        run_steps(cache.path(), db.path(), root.path(), vec![install_step(new)]).unwrap();
        assert!(root.path().join("srv/shared").is_dir(), "a directory aaa owns was removed");
    }

    /// One bad `%BACKUP%` hash makes the whole entry unreadable, file list included.
    ///
    /// Not obvious, and worth pinning. `%FILES%` and `%BACKUP%` live in one `files` file, and
    /// `LocalPackage` parses it **once**, behind a single `Lazy<DbFiles>`. They are the same
    /// parse, so `backups()` cannot fail unless `file_list()` fails too. The error a corrupt
    /// backup hash produces names the *file list*.
    ///
    /// That is why reading the backup list at `verify` rather than inside the removal step buys
    /// no safety. Forcing the file list, which `verify` does, forces the backup list with it.
    /// This test is what proves that.
    ///
    /// The rest of the assertion checks *when* the refusal arrives. `verify` returns it, so
    /// `stage` is never reached and nothing has been touched.
    #[test]
    fn a_malformed_backup_hash_makes_the_whole_entry_unreadable_at_verify() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap();

        // `%BACKUP%` lives in the entry's `files`, beside `%FILES%`, as `path<TAB>md5`.
        // A hash that is not one is what a corrupt entry looks like.
        let files = db.path().join("local/foo-1.0.0-1/files");
        let mut text = std::fs::read_to_string(&files).unwrap();
        text.push_str("\n%BACKUP%\netc/foo\tnot-a-hash\n");
        std::fs::write(&files, text).unwrap();

        let entry = EntryName::parse("foo-1.0.0-1").unwrap();
        let error = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Remove { entry, no_save: false }],
            Verification::Disabled,
        )
        .verify(&lock, &source)
        .unwrap_err();

        // The reason names the file list, not the backup list, because one parse produced both.
        let Error::UnreadableEntry { ref reason, .. } = error else {
            panic!("got {error:?}");
        };
        assert!(reason.contains("file list"), "{reason}");
        // Nothing was staged, so the package's files are all still there.
        assert!(root.path().join("usr/bin/foo").exists());
        assert!(crate::journal::read(db.path()).unwrap().is_none());
    }

    /// An unopenable local database keeps its cause typed, rather than stringified.
    ///
    /// An `Error::Io` carrying `io::Error::other(error.to_string())` would read as `failed to
    /// open <path>`, which names the wrong failure. A commit engine that cannot open the
    /// database has not failed at I/O in any way the `IoAction::Open` verb describes. Such an
    /// error also flattens the `piko_db::Error` underneath into an opaque string, which no
    /// caller can match on at any depth.
    ///
    /// Asserted on shape rather than wording. The downcast is to `Box<piko_db::Error>`, not to
    /// `piko_db::Error`, because `#[source]` on a boxed field yields the box. See that
    /// variant's own documentation for why it is boxed at all.
    #[test]
    fn an_unopenable_local_database_keeps_its_cause_typed() {
        let cache = tempfile::tempdir().unwrap();
        let db = tempfile::tempdir().unwrap();
        // A `local` subdirectory that already holds something, but not `ALPM_DB_VERSION`.
        // A missing marker is tolerated on an empty or absent directory. See
        // `piko_db::local::schema_version::root_is_unpopulated`. So this needs an entry besides
        // the marker, to count as unreadable rather than as a fresh database.
        let local = db.path().join("local");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(local.join("stray-file"), b"").unwrap();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let step = Step::Install {
            package: "absent-1.0.0-1-x86_64.pkg.tar.zst".parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .verify(&lock, &source)
            .unwrap_err();

        assert!(
            matches!(error, Error::LocalDatabaseUnreadable { .. }),
            "expected LocalDatabaseUnreadable, got {error:?}"
        );
        // The top line says what failed, and does not pretend it was an `open` syscall.
        let message = error.to_string();
        assert!(message.contains("local database"), "{message}");

        let cause = std::error::Error::source(&error).expect("the cause must survive");
        let db_error = cause
            .downcast_ref::<Box<piko_db::Error>>()
            .expect("the cause must still be a piko_db::Error, not an opaque string");
        // Its own message reaches the user unmerged, on its own `caused by:` line.
        assert!(db_error.to_string().contains("ALPM_DB_VERSION"), "{db_error}");
    }

    /// A missing package is caught before anything is touched.
    #[test]
    fn verification_fails_before_the_system_is_changed() {
        let cache = tempfile::tempdir().unwrap();
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let step = Step::Install {
            package: "absent-1.0.0-1-x86_64.pkg.tar.zst".parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let planned = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled);
        assert!(planned.verify(&lock, &source).is_err());
        // No journal, because staging never happened.
        assert!(crate::journal::read(db.path()).unwrap().is_none());
    }

    /// A `.PKGINFO` piko cannot record fails at `verify`, not half-way through the commit.
    ///
    /// The parse must run before `install` extracts the payload. Otherwise a `size` line that
    /// is not a number fails the transaction too late. The package's file is already in the
    /// root by then, and the journal already on disk. The two assertions below pin exactly that.
    #[test]
    fn an_unrecordable_pkginfo_fails_before_the_root_is_touched() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let broken = pkginfo("1.0.0-1", &[]).replace("size = 123", "size = big");
        let cache = cache_with_raw_pkginfo(name, &broken, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap_err();

        assert!(
            matches!(&error, Error::UnusableSource { reason, .. }
                     if reason.contains(".PKGINFO is unreadable")),
            "got {error:?}"
        );
        assert!(!root.path().join("usr/bin/foo").exists(), "the payload was extracted anyway");
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "a journal was written");
    }

    /// Verifies one install of `name` from `cache`, expecting a refusal that names an entry
    /// which cannot be recorded, and nothing written anywhere.
    fn assert_refused_as_unrecordable(cache: &tempfile::TempDir, name: &str, payload: &str) {
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap_err();

        assert!(
            matches!(&error, Error::UnusableSource { reason, .. }
                     if reason.contains("its entry cannot be recorded")),
            "got {error:?}"
        );
        assert!(!root.path().join(payload).exists(), "the payload was extracted anyway");
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "a journal was written");
        assert!(!db.path().join("local/foo-1.0.0-1").exists(), "an entry was written");
    }

    /// The entry format has no escaping. A group named `%REASON%`, then `1`, would read back as
    /// an install reason the package chose for itself: a dependency, so an orphan. It is
    /// refused at `verify`, before the payload reaches the root.
    #[test]
    fn a_group_that_forges_a_section_is_refused_before_the_root_is_touched() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let forged = format!("{}group = %REASON%\ngroup = 1\n", pkginfo("1.0.0-1", &[]));
        let cache = cache_with_raw_pkginfo(name, &forged, &[("usr/bin/foo", b"binary")]);
        assert_refused_as_unrecordable(&cache, name, "usr/bin/foo");
    }

    /// A member path holding a newline would add lines to `%FILES%`: the package would own
    /// `etc/passwd` in the database, and removing it would delete that file. It is refused at
    /// `verify`, before anything is extracted.
    #[test]
    fn a_member_path_holding_a_newline_is_refused_before_the_root_is_touched() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo\netc/passwd", b"binary")]);
        assert_refused_as_unrecordable(&cache, name, "usr/bin");
    }

    /// A device node in a package is refused at `verify`, with the regular file beside it, so
    /// nothing reaches the root, the journal or the database.
    #[test]
    fn a_device_node_in_a_package_is_refused_before_the_root_is_touched() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        for (path, contents, entry_type, mode) in [
            (".PKGINFO", pkginfo("1.0.0-1", &[]).into_bytes(), tar::EntryType::Regular, 0o644),
            ("usr/", Vec::new(), tar::EntryType::Directory, 0o755),
            ("usr/bin/", Vec::new(), tar::EntryType::Directory, 0o755),
            ("usr/bin/foo", b"binary".to_vec(), tar::EntryType::Regular, 0o755),
            ("usr/bin/tty", Vec::new(), tar::EntryType::Char, 0o666),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(entry_type);
            header.set_mode(mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, path, contents.as_slice()).unwrap();
        }
        std::fs::write(cache.path().join(name), builder.into_inner().unwrap()).unwrap();

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap_err();

        assert!(
            matches!(&error, Error::UnsupportedMemberType { kind: "character device", .. }),
            "got {error:?}"
        );
        assert!(!root.path().join("usr/bin").exists(), "the payload was extracted anyway");
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "a journal was written");
    }

    /// `Staged` is the last point at which walking away costs nothing.
    #[test]
    fn abandoning_a_staged_transaction_leaves_no_trace() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        let staged = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap();

        assert!(crate::journal::read(db.path()).unwrap().is_some(), "staging writes a journal");
        staged.abandon().unwrap();

        assert!(crate::journal::read(db.path()).unwrap().is_none());
        assert!(!root.path().join("usr/bin/foo").exists());
    }

    /// A root that cannot be opened is refused before the journal is written. Nothing changed,
    /// so nothing may read as an interrupted transaction.
    #[test]
    fn a_root_that_cannot_be_opened_is_refused_before_the_journal() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        let verified = Transaction::new(
            &root,
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .verify(&lock, &source)
        .unwrap();
        std::fs::remove_dir(&root).unwrap();

        let error = verified.stage().unwrap_err();
        assert!(matches!(error, Error::Io { .. }), "got {error:?}");
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "a journal was left");
    }

    /// A `PreTransaction` hook that cannot be run at all stops the transaction as a failing
    /// `AbortOnFail` hook does: before the first step, and without a journal.
    #[test]
    fn a_pre_transaction_hook_that_cannot_run_leaves_no_journal() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let hooks = tempfile::tempdir().unwrap();
        std::fs::write(
            hooks.path().join("foo.hook"),
            "[Trigger]\nOperation = Install\nType = Path\nTarget = usr/bin/foo\n\n\
             [Action]\nWhen = PreTransaction\nExec = /bin/true\n",
        )
        .unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        let staged = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .hook_dirs(vec![hooks.path().to_path_buf()])
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap();
        // The hook's `Depends` is read from the local database, which is now unreadable.
        std::fs::remove_dir_all(db.path().join("local")).unwrap();
        std::fs::write(db.path().join("local"), b"").unwrap();

        let error = staged.commit().unwrap_err();
        assert!(matches!(error, Error::LocalDatabaseUnreadable { .. }), "got {error:?}");
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "a journal was left");
        assert!(!root.path().join("usr/bin/foo").exists(), "the step ran anyway");
    }

    /// A `PostTransaction` phase that cannot run is a problem on the report. Every step
    /// completed, so the transaction succeeds and its journal is removed.
    #[test]
    fn a_post_transaction_hook_that_cannot_run_is_reported_and_the_transaction_completes() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let hooks = tempfile::tempdir().unwrap();
        std::fs::write(
            hooks.path().join("foo.hook"),
            "[Trigger]\nOperation = Install\nType = Path\nTarget = usr/bin/foo\n\n\
             [Action]\nWhen = PostTransaction\nExec = /bin/true\n",
        )
        .unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        let staged = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .hook_dirs(vec![hooks.path().to_path_buf()])
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap();

        // Once the step is done, the local database the hook's `Depends` is read from becomes
        // unreadable.
        let local = db.path().join("local");
        let report = staged
            .commit_with_progress(&mut |event| {
                if matches!(event, Event::StepFinished { .. }) {
                    std::fs::rename(&local, db.path().join("local.gone")).unwrap();
                    std::fs::write(&local, b"").unwrap();
                }
            })
            .unwrap();

        assert!(root.path().join("usr/bin/foo").exists());
        assert!(report.hooks.is_empty(), "{:?}", report.hooks);
        assert!(
            matches!(
                report.hook_problems.as_slice(),
                [hook::Problem::PostTransactionNotRun { .. }]
            ),
            "{:?}",
            report.hook_problems
        );
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "a journal was left");
    }

    /// A scriptlet that cannot be staged does not stop the transaction half-way. Here the root's
    /// `tmp` is a file. Both functions are reported as not started, and the package installs.
    #[test]
    fn a_scriptlet_that_cannot_be_staged_is_reported_and_the_transaction_completes() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let script: &[u8] = b"pre_install() { :; }\npost_install() { :; }\n";
        let cache = cache_with_package(name, &[(".INSTALL", script), ("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("tmp"), b"").unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        let report = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .scriptlets(true)
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap();

        let kinds: Vec<_> = report.scriptlets.iter().map(|run| run.kind).collect();
        assert_eq!(kinds, [scriptlet::Kind::PreInstall, scriptlet::Kind::PostInstall]);
        for run in &report.scriptlets {
            assert!(matches!(run.outcome.status, crate::exec::Status::NotStarted(_)), "{run:?}");
        }
        assert!(root.path().join("usr/bin/foo").exists());
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "a journal was left");
    }

    /// The check is wired in, and it stops the transaction at `verify`. That is before the
    /// journal, and before a single byte is written.
    #[test]
    fn a_file_another_package_owns_stops_the_transaction() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/tool", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        // Another package already owns `usr/bin/tool`, and the file is really there.
        std::fs::create_dir_all(db.path().join("local/other-1.0.0-1")).unwrap();
        std::fs::write(
            db.path().join("local/other-1.0.0-1/files"),
            "%FILES%\nusr/\nusr/bin/\nusr/bin/tool\n",
        )
        .unwrap();
        std::fs::write(
            db.path().join("local/other-1.0.0-1/desc"),
            "%NAME%\nother\n\n%VERSION%\n1.0.0-1\n\n%ARCH%\nx86_64\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        std::fs::write(root.path().join("usr/bin/tool"), b"theirs").unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap_err();

        let Error::FileConflicts { conflicts } = &error else {
            panic!("expected a file conflict, got {error:?}");
        };
        assert_eq!(conflicts.len(), 1, "{conflicts:?}");
        assert!(error.to_string().contains("usr/bin/tool"), "{error}");
        assert!(error.to_string().contains("other"), "{error}");

        // And the other package's file is untouched, which is the whole point.
        assert_eq!(std::fs::read(root.path().join("usr/bin/tool")).unwrap(), b"theirs");
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "nothing was staged");
    }

    /// `--overwrite` lets the same transaction through, and the file does change hands.
    #[test]
    fn overwrite_releases_the_same_transaction() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/tool", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        std::fs::create_dir_all(db.path().join("local/other-1.0.0-1")).unwrap();
        std::fs::write(
            db.path().join("local/other-1.0.0-1/files"),
            "%FILES%\nusr/\nusr/bin/\nusr/bin/tool\n",
        )
        .unwrap();
        std::fs::write(
            db.path().join("local/other-1.0.0-1/desc"),
            "%NAME%\nother\n\n%VERSION%\n1.0.0-1\n\n%ARCH%\nx86_64\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        std::fs::write(root.path().join("usr/bin/tool"), b"theirs").unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .overwrite(Overwrite::new(|path| path == std::path::Path::new("usr/bin/tool")))
            .verify(&lock, &source)
            .unwrap()
            .stage()
            .unwrap()
            .commit()
            .unwrap();

        assert_eq!(std::fs::read(root.path().join("usr/bin/tool")).unwrap(), b"binary");
    }

    /// With verification on and no signature present, `Required` stops the transaction at
    /// `verify`: before the journal, before anything is written.
    #[test]
    fn an_unsigned_package_is_refused_when_signatures_are_required() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let keys = tempfile::tempdir().unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(
            root.path(),
            db.path(),
            vec![step],
            Verification::Enabled {
                keyring: Keyring::open(keys.path()).unwrap(),
                policy: Policy::for_package(piko_db::config::SigLevel::PACKAGE),
            },
        )
        .ownership(Ownership::Inherit)
        .verify(&lock, &source)
        .unwrap_err();

        assert!(matches!(error, Error::SignatureRejected { .. }), "got {error:?}");
        assert!(!root.path().join("usr/bin/foo").exists(), "nothing should have been written");
        assert!(crate::journal::read(db.path()).unwrap().is_none(), "nothing was staged");
        // A missing signature says nothing against the file, so it stays, as libalpm keeps a
        // package refused with `ALPM_ERR_PKG_MISSING_SIG`.
        assert!(cache.path().join(name).exists(), "an unsigned package was removed");
    }

    /// A named file is replaced after verification, before the commit. The commit installs the
    /// bytes that were verified. The transaction reads a package three times by path, so a
    /// source that served the user's own file would extract the replacement: unverified
    /// bytes, installed by root.
    #[test]
    fn a_named_file_replaced_after_verification_does_not_reach_the_commit() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let downloads = cache_with_package(name, &[("usr/bin/foo", b"verified")]);
        let named = downloads.path().join(name);
        let cache = tempfile::tempdir().unwrap();
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();

        let source = crate::source::FileSource::new(
            HashMap::from([(name.to_owned(), named.clone())]),
            cache.path(),
            Box::new(CacheDirSource::new([cache.path().to_path_buf()]).unwrap()),
        )
        .unwrap();
        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };

        let lock = DbLock::acquire(db.path()).unwrap();
        let verified = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap();

        // Same name, same version, other contents: what a swap after the check looks like.
        let replacement = tempfile::tempdir().unwrap();
        write_package(replacement.path(), name, "1.0.0-1", &[], &[("usr/bin/foo", b"swapped")]);
        std::fs::rename(replacement.path().join(name), &named).unwrap();

        verified.stage().unwrap().commit().unwrap();
        assert_eq!(std::fs::read(root.path().join("usr/bin/foo")).unwrap(), b"verified");
    }

    /// An archive that holds another package than the plan named is refused before anything
    /// is written. The file name says `2.0.0-1`; the `.PKGINFO` inside says `1.0.0-1`. That is
    /// an older signed build served under a newer name, which a signature check alone accepts.
    #[test]
    fn an_archive_holding_another_version_than_planned_is_refused() {
        let name = "foo-2.0.0-1-x86_64.pkg.tar";
        let cache = tempfile::tempdir().unwrap();
        write_package(cache.path(), name, "1.0.0-1", &[], &[("usr/bin/foo", b"older")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap_err();

        let Error::UnusableSource { reason, .. } = &error else {
            panic!("expected the archive to be refused, got {error:?}");
        };
        assert!(reason.contains("foo 1.0.0-1") && reason.contains("foo 2.0.0-1"), "{reason}");
        assert!(!root.path().join("usr/bin/foo").exists(), "nothing should have been written");

        // The refused file leaves the cache, as `prompt_to_delete` removes it.
        assert!(reason.contains("removed from the cache"), "{reason}");
        assert!(!cache.path().join(name).exists(), "the refused file stayed in the cache");
    }

    /// A named file that is not the planned package is refused, and stays where the user put
    /// it. Only a cache file is removed.
    #[test]
    fn a_refused_named_file_is_left_where_the_user_put_it() {
        let name = "foo-2.0.0-1-x86_64.pkg.tar";
        let downloads = tempfile::tempdir().unwrap();
        write_package(downloads.path(), name, "1.0.0-1", &[], &[("usr/bin/foo", b"older")]);
        let named = downloads.path().join(name);
        let cache = tempfile::tempdir().unwrap();
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = crate::source::FileSource::new(
            HashMap::from([(name.to_owned(), named.clone())]),
            cache.path(),
            Box::new(CacheDirSource::new([cache.path().to_path_buf()]).unwrap()),
        )
        .unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap_err();

        let Error::UnusableSource { reason, .. } = &error else {
            panic!("expected the archive to be refused, got {error:?}");
        };
        assert!(!reason.contains("removed"), "{reason}");
        assert!(named.exists(), "the user's own file was removed");
    }

    /// Name and version agree, but the `.PKGINFO` declares another size and a dependency the
    /// plan never saw. Every differing field is named, and nothing is written. The same
    /// archive under an expectation it matches installs.
    #[test]
    fn an_archive_whose_fields_differ_from_the_plan_is_refused() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_raw_pkginfo(
            name,
            &format!("{}depend = glibc\n", pkginfo("1.0.0-1", &[])),
            &[("usr/bin/foo", b"binary")],
        );
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let (info, _) =
            crate::conflict::load_pkginfo(&cache.path().join(name), &PackageLimits::default())
                .unwrap();
        let archive = std::fs::read(cache.path().join(name)).unwrap();
        let step = || Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };

        // What a repository entry with `%ISIZE% 124` and no `%DEPENDS%` would say.
        let planned = {
            let mut info = info.clone();
            info.size = 124;
            info.depends.clear();
            Expected::of_archive(&info)
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(root.path(), db.path(), vec![step()], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .expectations(HashMap::from([(name.to_owned(), planned)]))
            .verify(&lock, &source)
            .unwrap_err();
        let Error::UnusableSource { reason, .. } = &error else {
            panic!("expected the archive to be refused, got {error:?}");
        };
        assert!(reason.contains("size, depend differ"), "{reason}");
        assert!(!root.path().join("usr/bin/foo").exists(), "nothing should have been written");
        assert!(!cache.path().join(name).exists(), "the refused file stayed in the cache");

        // Put back, as a download would: the same archive under a matching expectation.
        std::fs::write(cache.path().join(name), &archive).unwrap();
        Transaction::new(root.path(), db.path(), vec![step()], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .expectations(HashMap::from([(name.to_owned(), Expected::of_archive(&info))]))
            .verify(&lock, &source)
            .unwrap()
            .stage()
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(std::fs::read(root.path().join("usr/bin/foo")).unwrap(), b"binary");
    }

    /// An archive that inflates far past the size its plan declares is refused while it is read,
    /// before anything is written. It stays in the cache: it passed its checksum and signature
    /// checks, so a new download gives the same file.
    #[test]
    fn an_archive_inflating_past_its_declared_size_is_refused_while_read() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let payload = vec![b'x'; 3 * 1024 * 1024];
        let cache = cache_with_raw_pkginfo(
            name,
            &pkginfo("1.0.0-1", &[]),
            &[("usr/share/foo/big", payload.as_slice())],
        );
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let (info, _) =
            crate::conflict::load_pkginfo(&cache.path().join(name), &PackageLimits::default())
                .unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .expectations(HashMap::from([(name.to_owned(), Expected::of_archive(&info))]))
        .verify(&lock, &source)
        .unwrap_err();

        assert!(
            matches!(
                error,
                Error::PackageLimitExceeded { limit: "installed size the plan declares", .. }
            ),
            "got {error:?}"
        );
        assert!(!root.path().join("usr/share/foo/big").exists(), "nothing should be written");
        assert!(cache.path().join(name).exists(), "a signed archive was removed from the cache");
    }

    /// The same holds for the name: `bar`'s file name over `foo`'s archive is refused.
    #[test]
    fn an_archive_holding_another_package_than_planned_is_refused() {
        let name = "bar-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap_err();

        assert!(matches!(error, Error::UnusableSource { .. }), "got {error:?}");
        assert!(!root.path().join("usr/bin/foo").exists(), "nothing should have been written");
    }

    /// The same package under `Optional` installs, and records `none` rather than claiming a
    /// verification that did not happen.
    #[test]
    fn an_optional_policy_installs_and_records_that_nothing_was_verified() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let keys = tempfile::tempdir().unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Enabled {
                keyring: Keyring::open(keys.path()).unwrap(),
                policy: Policy::for_package(
                    piko_db::config::SigLevel::PACKAGE
                        | piko_db::config::SigLevel::PACKAGE_OPTIONAL,
                ),
            },
        )
        .ownership(Ownership::Inherit)
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap();

        let text = std::fs::read_to_string(db.path().join("local/foo-1.0.0-1/desc")).unwrap();
        assert!(text.contains("%VALIDATION%\nnone\n"), "{text}");
    }

    /// A per-file override in `policy_overrides` is checked instead of `verification`'s own
    /// fallback `policy`. This proves a package can be held to a stricter policy than the
    /// transaction's default. One repository's `SigLevel` can differ from another's that way.
    #[test]
    fn a_policy_override_takes_precedence_over_the_fallback() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let keys = tempfile::tempdir().unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(
            root.path(),
            db.path(),
            vec![step],
            Verification::Enabled {
                keyring: Keyring::open(keys.path()).unwrap(),
                policy: Policy::for_package(
                    piko_db::config::SigLevel::PACKAGE
                        | piko_db::config::SigLevel::PACKAGE_OPTIONAL,
                ),
            },
        )
        .ownership(Ownership::Inherit)
        // The fallback above would accept an unsigned package, but this file's own override
        // requires one.
        .policy_overrides(HashMap::from([(
            name.to_owned(),
            Policy::for_package(piko_db::config::SigLevel::PACKAGE),
        )]))
        .verify(&lock, &source)
        .unwrap_err();

        assert!(matches!(error, Error::SignatureRejected { .. }), "got {error:?}");
    }

    /// Installs `foo-<version>` from `cache` into `root`/`db`, and returns what it did.
    fn install_foo(cache: &Path, db: &Path, root: &Path, lock: &DbLock, version: &str) -> Report {
        let source = CacheDirSource::new([cache.to_path_buf()]).unwrap();
        Transaction::new(
            root,
            db,
            vec![Step::Install {
                package: format!("foo-{version}-x86_64.pkg.tar").parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .verify(lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap()
    }

    /// The fake remove transaction (`add.c:508`). A file the old version owned and the new one
    /// does not must go. Everything both ship survives, with the new content.
    ///
    /// Without this, the old file stayed on disk owned by nobody: the entry naming it had just
    /// been replaced.
    #[test]
    fn an_upgrade_deletes_the_files_the_new_version_drops() {
        let cache = tempfile::tempdir().unwrap();
        write_package(
            cache.path(),
            "foo-1.0.0-1-x86_64.pkg.tar",
            "1.0.0-1",
            &[],
            &[("usr/bin/foo", b"old"), ("usr/share/foo/dropped", b"gone soon")],
        );
        write_package(
            cache.path(),
            "foo-2.0.0-1-x86_64.pkg.tar",
            "2.0.0-1",
            &[],
            &[("usr/bin/foo", b"new")],
        );

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();

        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");
        assert!(root.path().join("usr/share/foo/dropped").exists());

        install_foo(cache.path(), db.path(), root.path(), &lock, "2.0.0-1");

        assert!(
            !root.path().join("usr/share/foo/dropped").exists(),
            "the dropped file was orphaned on disk"
        );
        // Its directory, which the new version does not ship either, went with it.
        assert!(!root.path().join("usr/share/foo").exists(), "the emptied directory stayed");
        // Everything both versions ship survives, holding the new content.
        assert_eq!(std::fs::read(root.path().join("usr/bin/foo")).unwrap(), b"new");
        assert!(root.path().join("usr/bin").is_dir(), "a shared directory was destroyed");

        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        let package = local.get_str("foo").expect("the new entry was not recorded");
        assert_eq!(package.version().to_string(), "2.0.0-1");
        assert_eq!(
            package.file_list().unwrap().collect::<Vec<_>>(),
            ["usr/", "usr/bin/", "usr/bin/foo"]
        );
    }

    /// A backup file the new version still ships is left exactly where it is — no `.pacsave`,
    /// no deletion. `should_skip_file`'s third clause (`remove.c:594`). Removing it would
    /// throw away the user's edits a moment before the new copy lands beside them.
    #[test]
    fn an_upgrade_leaves_a_backup_file_the_new_version_still_ships() {
        let cache = tempfile::tempdir().unwrap();
        for version in ["1.0.0-1", "2.0.0-1"] {
            write_package(
                cache.path(),
                &format!("foo-{version}-x86_64.pkg.tar"),
                version,
                &["etc/foo.conf"],
                &[("etc/foo.conf", b"shipped")],
            );
        }

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();

        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");
        // The install recorded the hash of what it shipped, so this edit is detectable —
        // which is the whole point of `%BACKUP%`.
        std::fs::write(root.path().join("etc/foo.conf"), b"edited by the user").unwrap();

        let report = install_foo(cache.path(), db.path(), root.path(), &lock, "2.0.0-1");

        assert!(report.pacsaves.is_empty(), "{:?}", report.pacsaves);
        assert!(
            !root.path().join("etc/foo.conf.pacsave").exists(),
            "a .pacsave was created for a file the new version still manages"
        );
        // The user's edit survives untouched. The two versions ship the same bytes, so
        // `resolve_backup`'s second rule keeps what is there and drops the `.pacnew`.
        assert_eq!(std::fs::read(root.path().join("etc/foo.conf")).unwrap(), b"edited by the user");
        assert!(
            !root.path().join("etc/foo.conf.pacnew").exists(),
            "a redundant .pacnew was left behind"
        );
    }

    /// But a modified backup file the new version **drops** is saved rather than deleted.
    /// This is the one outcome with no recovery if it goes wrong.
    #[test]
    fn an_upgrade_saves_a_modified_backup_file_the_new_version_drops() {
        let cache = tempfile::tempdir().unwrap();
        write_package(
            cache.path(),
            "foo-1.0.0-1-x86_64.pkg.tar",
            "1.0.0-1",
            &["etc/foo.conf"],
            &[("etc/foo.conf", b"shipped"), ("usr/bin/foo", b"old")],
        );
        write_package(
            cache.path(),
            "foo-2.0.0-1-x86_64.pkg.tar",
            "2.0.0-1",
            &[],
            &[("usr/bin/foo", b"new")],
        );

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();

        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");
        std::fs::write(root.path().join("etc/foo.conf"), b"edited by the user").unwrap();

        let report = install_foo(cache.path(), db.path(), root.path(), &lock, "2.0.0-1");

        assert_eq!(report.pacsaves, [PathBuf::from("etc/foo.conf.pacsave")]);
        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf.pacsave")).unwrap(),
            b"edited by the user"
        );
        assert!(!root.path().join("etc/foo.conf").exists(), "the original was left behind");
    }

    /// A second save rotates the first out of the way rather than writing over it.
    ///
    /// Both copies are the user's own edits, from two different times. Overwriting one is a
    /// loss nothing recovers from, which is why `shift_pacsave` (`remove.c:347`) exists.
    #[test]
    fn a_second_pacsave_rotates_the_first_one_out_of_the_way() {
        let cache = tempfile::tempdir().unwrap();
        for version in ["1.0.0-1", "2.0.0-1", "3.0.0-1"] {
            write_package(
                cache.path(),
                &format!("foo-{version}-x86_64.pkg.tar"),
                version,
                &["etc/foo.conf"],
                &[("etc/foo.conf", b"shipped"), ("usr/bin/foo", b"binary")],
            );
        }
        // The version that drops the backup file, so each install of it saves what is there.
        write_package(
            cache.path(),
            "foo-9.0.0-1-x86_64.pkg.tar",
            "9.0.0-1",
            &[],
            &[("usr/bin/foo", b"binary")],
        );

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();

        // Three rounds, each editing the file and then upgrading to the version that drops it.
        for (round, edit) in
            [b"first edit".as_slice(), b"second edit", b"third edit"].iter().enumerate()
        {
            let version = ["1.0.0-1", "2.0.0-1", "3.0.0-1"].get(round).unwrap();
            install_foo(cache.path(), db.path(), root.path(), &lock, version);
            std::fs::write(root.path().join("etc/foo.conf"), edit).unwrap();
            let report = install_foo(cache.path(), db.path(), root.path(), &lock, "9.0.0-1");
            assert_eq!(report.pacsaves, [PathBuf::from("etc/foo.conf.pacsave")]);
            assert!(report.backup_problems.is_empty(), "{:?}", report.backup_problems);
        }

        // The newest save is the plain one; the older two moved up, oldest furthest.
        assert_eq!(std::fs::read(root.path().join("etc/foo.conf.pacsave")).unwrap(), b"third edit");
        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf.pacsave.1")).unwrap(),
            b"second edit"
        );
        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf.pacsave.2")).unwrap(),
            b"first edit"
        );
    }

    /// A package whose archive lists a member twice still produces a usable entry.
    ///
    /// The whole chain is covered, because the damage is spread across it. `install` can claim
    /// the path twice, `record::files` then writes both lines, and `alpm-db` refuses the `files`
    /// record. The install still reports **success**. The entry can never be read again, so the
    /// package can be neither removed nor upgraded. Both of those refuse an unreadable entry
    /// rather than silently doing nothing.
    ///
    /// libalpm writes the duplicate and reads it back without complaint. This is piko staying
    /// inside what its own reader accepts, not a rule pacman also enforces.
    #[test]
    fn a_package_that_lists_a_member_twice_stays_manageable() {
        let cache = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let mut add = |path: &str, contents: &[u8], directory: bool| {
            let mut header = tar::Header::new_gnu();
            header.set_mode(if directory { 0o755 } else { 0o644 });
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(contents.len() as u64);
            if directory {
                header.set_entry_type(tar::EntryType::Directory);
            }
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        };
        add(".PKGINFO", pkginfo("1.0.0-1", &[]).as_bytes(), false);
        add("usr/", &[][..], true);
        add("usr/bin/", &[][..], true);
        add("usr/bin/foo", b"binary", false);
        add("usr/", &[][..], true);
        std::fs::write(
            cache.path().join("foo-1.0.0-1-x86_64.pkg.tar"),
            builder.into_inner().unwrap(),
        )
        .unwrap();

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();
        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");

        // This checks the record itself, because the assertion below would also pass on a
        // list that merely happens to parse.
        let text = std::fs::read_to_string(db.path().join("local/foo-1.0.0-1/files")).unwrap();
        assert_eq!(text.matches("usr/\n").count(), 1, "{text}");

        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        let package = local.get_str("foo").expect("the entry was not recorded");
        assert_eq!(
            package.file_list().expect("the entry piko wrote will not re-open").collect::<Vec<_>>(),
            ["usr/", "usr/bin/", "usr/bin/foo"]
        );

        // It can actually be removed now, which is what an unreadable entry prevented.
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let entry = EntryName::parse("foo-1.0.0-1").unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Remove { entry, no_save: false }],
            Verification::Disabled,
        )
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap();
        assert!(!root.path().join("usr/bin/foo").exists());
    }

    /// The headline case: a **fresh** install records `%BACKUP%`.
    ///
    /// `add.c:333`'s `if(backup)` sits outside the `notouch || needbackup` branch. So libalpm
    /// records a hash for every backup file it extracted, including one that was simply not on
    /// the system before. This is what `install_step`'s `Filters` are for. A default `Filters`
    /// leaves `is_backup` always false, and then no fresh install records a hash.
    #[test]
    fn a_fresh_install_records_the_backup_hash() {
        let cache = tempfile::tempdir().unwrap();
        write_package(
            cache.path(),
            "foo-1.0.0-1-x86_64.pkg.tar",
            "1.0.0-1",
            &["etc/foo.conf"],
            &[("etc/foo.conf", b"shipped"), ("usr/bin/foo", b"binary")],
        );

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();
        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");

        let expected = alpm_types::Md5Checksum::calculate_from(b"shipped").to_string();
        let text = std::fs::read_to_string(db.path().join("local/foo-1.0.0-1/files")).unwrap();
        assert!(text.contains(&format!("%BACKUP%\netc/foo.conf\t{expected}")), "{text}");

        // piko's own reader gives it back, which is what the next upgrade depends on.
        let local = LocalDatabase::open(db.path().join("local")).unwrap();
        let backups = local.get_str("foo").unwrap().backups().unwrap().to_vec();
        assert_eq!(backups.len(), 1, "{backups:?}");
    }

    /// The case the whole `.pacnew` mechanism exists for: the user edited the file *and* the
    /// package changed it. Neither copy may be discarded, so both stay.
    #[test]
    fn an_upgrade_leaves_a_pacnew_when_the_user_and_the_package_both_changed_it() {
        let cache = tempfile::tempdir().unwrap();
        for (version, shipped) in [("1.0.0-1", &b"first"[..]), ("2.0.0-1", &b"second"[..])] {
            write_package(
                cache.path(),
                &format!("foo-{version}-x86_64.pkg.tar"),
                version,
                &["etc/foo.conf"],
                &[("etc/foo.conf", shipped)],
            );
        }

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();

        install_foo(cache.path(), db.path(), root.path(), &lock, "1.0.0-1");
        std::fs::write(root.path().join("etc/foo.conf"), b"edited by the user").unwrap();

        install_foo(cache.path(), db.path(), root.path(), &lock, "2.0.0-1");

        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf")).unwrap(),
            b"edited by the user",
            "the user's configuration was overwritten"
        );
        assert_eq!(std::fs::read(root.path().join("etc/foo.conf.pacnew")).unwrap(), b"second");
        // `%BACKUP%` records what the *package* shipped, not what is on disk. It is the
        // baseline the next upgrade compares against, not a description of the file.
        let expected = alpm_types::Md5Checksum::calculate_from(b"second").to_string();
        let text = std::fs::read_to_string(db.path().join("local/foo-2.0.0-1/files")).unwrap();
        assert!(text.contains(&expected), "{text}");
    }

    /// A `NoExtract` path is never written, never owned, and never reported to a hook.
    ///
    /// The last of the three is why this is one change. A hook told a path changed that
    /// nothing was allowed to write would be a lie.
    #[test]
    fn a_no_extract_path_is_absent_from_the_root_the_entry_and_the_hooks() {
        let cache = tempfile::tempdir().unwrap();
        write_package(
            cache.path(),
            "foo-1.0.0-1-x86_64.pkg.tar",
            "1.0.0-1",
            &[],
            &[("usr/bin/foo", b"binary"), ("usr/share/locale/de.mo", b"translation")],
        );

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let patterns = Patterns {
            no_extract: PatternList::new(vec!["usr/share/locale/*".to_owned()]),
            no_upgrade: PatternList::default(),
        };
        let verified = Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: "foo-1.0.0-1-x86_64.pkg.tar".parse().unwrap(),
                reason: PackageInstallReason::Explicit,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .patterns(patterns.clone())
        .verify(&lock, &source)
        .unwrap();

        // The hooks are told the same list extraction obeys, from the same setting.
        assert_eq!(verified.state.summary.no_extract, patterns.no_extract);

        verified.stage().unwrap().commit().unwrap();

        assert!(!root.path().join("usr/share/locale/de.mo").exists(), "it was written anyway");
        assert!(root.path().join("usr/bin/foo").exists());
        let text = std::fs::read_to_string(db.path().join("local/foo-1.0.0-1/files")).unwrap();
        assert!(!text.contains("de.mo"), "the entry claims a file that is not there:\n{text}");
    }

    /// A `NoUpgrade` path is never overwritten and never removed.
    ///
    /// This checks both halves, because libalpm consults the same list in two places —
    /// `add.c:303` and `should_skip_file` (`remove.c:592`). Wiring only the first would let
    /// `remove` delete the very file the directive protects.
    #[test]
    fn a_no_upgrade_path_is_neither_overwritten_nor_removed() {
        let cache = tempfile::tempdir().unwrap();
        for version in ["1.0.0-1", "2.0.0-1"] {
            write_package(
                cache.path(),
                &format!("foo-{version}-x86_64.pkg.tar"),
                version,
                // Declared `%BACKUP%` *as well*, which is the sharp case. Without it, the
                // three-way rule has no original to compare against, and keeps both anyway.
                // The test would then pass even with `NoUpgrade` ignored.
                &["etc/foo.conf"],
                &[("etc/foo.conf", version.as_bytes())],
            );
        }

        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let lock = DbLock::acquire(db.path()).unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let patterns = Patterns {
            no_extract: PatternList::default(),
            no_upgrade: PatternList::new(vec!["etc/foo.conf".to_owned()]),
        };

        let install = |version: &str| {
            Transaction::new(
                root.path(),
                db.path(),
                vec![Step::Install {
                    package: format!("foo-{version}-x86_64.pkg.tar").parse().unwrap(),
                    reason: PackageInstallReason::Explicit,
                }],
                Verification::Disabled,
            )
            .ownership(Ownership::Inherit)
            .patterns(patterns.clone())
            .verify(&lock, &source)
            .unwrap()
            .stage()
            .unwrap()
            .commit()
            .unwrap()
        };

        install("1.0.0-1");
        // Deliberately *not* edited. `%BACKUP%` records what 1.0.0-1 shipped. So the three-way
        // rule would find `original == local`, conclude the user never touched it, and install
        // the new version. That is exactly what `NoUpgrade` forbids. libalpm never gets there:
        // `notouch` is decided first, and no hash is compared (`add.c:303`).
        install("2.0.0-1");

        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf")).unwrap(),
            b"1.0.0-1",
            "NoUpgrade did not protect the installed file"
        );
        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf.pacnew")).unwrap(),
            b"2.0.0-1",
            "the packaged version should be waiting beside it"
        );

        // The removal leaves it too.
        let entry = EntryName::parse("foo-2.0.0-1").unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Remove { entry, no_save: false }],
            Verification::Disabled,
        )
        .patterns(patterns)
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap();
        assert_eq!(
            std::fs::read(root.path().join("etc/foo.conf")).unwrap(),
            b"1.0.0-1",
            "the removal deleted a file NoUpgrade protects"
        );
    }

    /// An install as a dependency records `%REASON%`, matching pacman.
    #[test]
    fn a_dependency_install_records_its_reason() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();

        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(
            root.path(),
            db.path(),
            vec![Step::Install {
                package: name.parse().unwrap(),
                reason: PackageInstallReason::Depend,
            }],
            Verification::Disabled,
        )
        .ownership(Ownership::Inherit)
        .verify(&lock, &source)
        .unwrap()
        .stage()
        .unwrap()
        .commit()
        .unwrap();

        let text = std::fs::read_to_string(db.path().join("local/foo-1.0.0-1/desc")).unwrap();
        assert!(text.contains("%REASON%\n1\n"), "{text}");
    }

    /// Installs the package `name` from `cache` under `verification` and `published`, and
    /// returns its `%VALIDATION%` lines.
    fn install_validated(
        cache: &Path,
        name: &str,
        verification: Verification,
        published: Option<Published>,
    ) -> Result<Vec<String>> {
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.to_path_buf()]).unwrap();
        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let published: HashMap<String, Published> =
            published.into_iter().map(|published| (name.to_owned(), published)).collect();
        let lock = DbLock::acquire(db.path()).unwrap();
        Transaction::new(root.path(), db.path(), vec![step], verification)
            .ownership(Ownership::Inherit)
            .published(published)
            .verify(&lock, &source)?
            .stage()?
            .commit()?;

        let desc = std::fs::read_to_string(db.path().join("local/foo-1.0.0-1/desc")).unwrap();
        Ok(desc
            .split("%VALIDATION%\n")
            .nth(1)
            .unwrap()
            .lines()
            .take_while(|line| !line.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// What a database publishes for the bytes of `file`, with `signature` if it has one.
    fn published_for(file: &Path, signature: Option<&[u8]>) -> Published {
        use base64::Engine as _;
        let sha256 = alpm_types::Sha256Checksum::calculate_from(std::fs::read(file).unwrap());
        let signature = signature.map(|bytes| {
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
            alpm_types::Base64OpenPGPSignature::new(encoded).unwrap()
        });
        Published::new(sha256, signature)
    }

    /// A GnuPG home with one generated signing key, or `None` if `gpg` is unavailable.
    ///
    /// A key generated locally is ultimately trusted, so `TrustedOnly` accepts its signatures.
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

    /// A detached signature of `file`, made with the key in `home`.
    fn detached_signature(home: &Path, file: &Path) -> Vec<u8> {
        let output = std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(home)
            .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--output", "-", "--detach-sign"])
            .arg(file)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        output.stdout
    }

    /// Package signatures checked under `SigLevel = Required`, against the keyring in `home`.
    fn required(home: &Path) -> Verification {
        Verification::Enabled {
            keyring: Keyring::open(home).unwrap(),
            policy: Policy::for_package(piko_db::config::SigLevel::PACKAGE),
        }
    }

    /// A repository package whose SHA-256 is not the one its database publishes is refused and
    /// removed from the cache. Signature checking is off: libalpm compares `%SHA256SUM%` under
    /// `SigLevel = Never` too.
    #[test]
    fn a_package_whose_checksum_differs_from_its_database_is_refused_and_removed() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let other = cache_with_package(name, &[("usr/bin/foo", b"another binary")]);
        let published = published_for(&other.path().join(name), None);

        let error = install_validated(cache.path(), name, Verification::Disabled, Some(published))
            .unwrap_err();

        let Error::ChecksumMismatch { reason, .. } = &error else {
            panic!("expected a checksum mismatch, got {error:?}");
        };
        assert!(reason.contains("removed from the cache"), "{reason}");
        assert!(!cache.path().join(name).exists(), "the refused file stayed in the cache");
    }

    /// A package that matches its database's checksum installs, and `%VALIDATION%` says what
    /// was checked. A package with nothing published records `none`, as before.
    #[test]
    fn a_package_matching_its_database_checksum_records_sha256() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let published = published_for(&cache.path().join(name), None);

        let validation =
            install_validated(cache.path(), name, Verification::Disabled, Some(published)).unwrap();
        assert_eq!(validation, ["sha256"]);

        let validation = install_validated(cache.path(), name, Verification::Disabled, None);
        assert_eq!(validation.unwrap(), ["none"]);
    }

    /// With signatures checked, the database's signature is checked in place of the `.sig`
    /// beside the file, as `_alpm_pkg_validate_internal` does. A `.sig` that is not a signature
    /// at all changes nothing. The checksum is not compared: the signature covers the file.
    #[test]
    fn a_database_signature_is_checked_in_place_of_the_sig_beside_the_file() {
        let Some(keys) = signing_keyring() else { return };
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let file = cache.path().join(name);
        let signature = detached_signature(keys.path(), &file);
        std::fs::write(piko_sig::signature_path(&file), b"not a signature").unwrap();
        let published = published_for(&file, Some(&signature));

        let validation =
            install_validated(cache.path(), name, required(keys.path()), Some(published));
        assert_eq!(validation.unwrap(), ["pgp"]);
    }

    /// A database signature over other bytes refuses the package, although a good `.sig` sits
    /// beside it. The file and its `.sig` are removed from the cache.
    #[test]
    fn a_database_signature_that_does_not_match_refuses_the_package() {
        let Some(keys) = signing_keyring() else { return };
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let file = cache.path().join(name);
        std::fs::write(piko_sig::signature_path(&file), detached_signature(keys.path(), &file))
            .unwrap();
        let other = cache_with_package(name, &[("usr/bin/foo", b"another binary")]);
        let signature_of_other = detached_signature(keys.path(), &other.path().join(name));
        let published = published_for(&file, Some(&signature_of_other));

        let error = install_validated(cache.path(), name, required(keys.path()), Some(published))
            .unwrap_err();
        let Error::SignatureRejected { reason, .. } = &error else {
            panic!("expected a signature refusal, got {error:?}");
        };
        assert!(reason.contains("removed from the cache"), "{reason}");
        assert!(!file.exists(), "the refused file stayed in the cache");
        assert!(!piko_sig::signature_path(&file).exists(), "its .sig stayed in the cache");
    }

    /// A `.sig` made by a key the keyring does not hold refuses the package, and the file and
    /// its `.sig` are removed from the cache, as `prompt_to_delete` removes them.
    #[test]
    fn a_package_whose_sig_is_refused_is_removed_from_the_cache() {
        let Some(keys) = signing_keyring() else { return };
        let Some(stranger) = signing_keyring() else { return };
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let file = cache.path().join(name);
        std::fs::write(piko_sig::signature_path(&file), detached_signature(stranger.path(), &file))
            .unwrap();

        let error = install_validated(cache.path(), name, required(keys.path()), None).unwrap_err();
        let Error::SignatureRejected { reason, .. } = &error else {
            panic!("expected a signature refusal, got {error:?}");
        };
        assert!(reason.contains("not in the keyring"), "{reason}");
        assert!(reason.contains("removed from the cache"), "{reason}");
        assert!(!file.exists(), "the refused file stayed in the cache");
        assert!(!piko_sig::signature_path(&file).exists(), "its .sig stayed in the cache");
    }

    /// With no database signature, the `.sig` beside the file is checked, and the checksum is
    /// compared too.
    #[test]
    fn without_a_database_signature_the_sig_and_the_checksum_are_both_checked() {
        let Some(keys) = signing_keyring() else { return };
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let file = cache.path().join(name);
        std::fs::write(piko_sig::signature_path(&file), detached_signature(keys.path(), &file))
            .unwrap();
        let published = published_for(&file, None);

        let validation =
            install_validated(cache.path(), name, required(keys.path()), Some(published));
        assert_eq!(validation.unwrap(), ["sha256", "pgp"]);
    }

    /// A journal left by an unfinished transaction refuses the next one in `verify`, before any
    /// package is read, and the journal is left as it was.
    #[test]
    fn a_leftover_journal_refuses_the_transaction_in_verify() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let leftover = [crate::journal::Intent::Remove { entry: "bar-1.0-1".to_owned() }];
        std::mem::forget(
            crate::journal::Journal::begin(db.path(), root.path(), &leftover).unwrap(),
        );
        let journal = std::fs::read(db.path().join(crate::journal::JOURNAL_FILE)).unwrap();

        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let error = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap_err();

        assert!(matches!(error, Error::UnfinishedTransaction { .. }), "got {error:?}");
        assert_eq!(std::fs::read(db.path().join(crate::journal::JOURNAL_FILE)).unwrap(), journal);
    }

    /// A journal that appears between `verify` and `stage` refuses `stage`, and is not written
    /// over. `stage` runs under `db.lck`, so this is the refusal no race can pass.
    #[test]
    fn a_journal_written_after_verify_refuses_stage() {
        let name = "foo-1.0.0-1-x86_64.pkg.tar";
        let cache = cache_with_package(name, &[("usr/bin/foo", b"binary")]);
        let db = dbpath();
        let root = tempfile::tempdir().unwrap();
        let source = CacheDirSource::new([cache.path().to_path_buf()]).unwrap();
        let step = Step::Install {
            package: name.parse().unwrap(),
            reason: PackageInstallReason::Explicit,
        };
        let lock = DbLock::acquire(db.path()).unwrap();
        let verified = Transaction::new(root.path(), db.path(), vec![step], Verification::Disabled)
            .ownership(Ownership::Inherit)
            .verify(&lock, &source)
            .unwrap();

        let other = [crate::journal::Intent::Remove { entry: "bar-1.0-1".to_owned() }];
        std::mem::forget(crate::journal::Journal::begin(db.path(), root.path(), &other).unwrap());
        let journal = std::fs::read(db.path().join(crate::journal::JOURNAL_FILE)).unwrap();

        let error = verified.stage().unwrap_err();
        assert!(matches!(error, Error::UnfinishedTransaction { .. }), "got {error:?}");
        assert_eq!(std::fs::read(db.path().join(crate::journal::JOURNAL_FILE)).unwrap(), journal);
        assert!(!root.path().join("usr/bin/foo").exists(), "files were written anyway");
    }
}
