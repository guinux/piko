//! Turning command line arguments into opened databases.
//!
//! Everything a subcommand needs before it can print anything. Which `pacman.conf` applies, which
//! database path it names, and how to open a local or repository database. Databases open with the
//! options the global flags requested. Each scan diagnostic is printed exactly once.

use std::path::{Path, PathBuf};

use piko_db::{
    LocalDatabase, OpenOptions,
    config::{DbUsage, PacmanConfig},
    repo::{RepoDatabase, RepoName, RepoOpenOptions},
};

use crate::cli::Cli;
use crate::error::Error;
use crate::output::report_dropped_diagnostics;

/// The local database lives in this subdirectory of the database path.
const LOCAL_DB_DIR: &str = "local";

/// Repository (sync) databases live in this subdirectory of the database path.
const SYNC_DB_DIR: &str = "sync";

/// The parsed `pacman.conf`, read at most once per run.
///
/// Several subcommands need two things from the same file: the database path and the repository
/// list. The database path comes from `DBPath` unless `--dbpath` overrides it. Parsing on first
/// use and caching here keeps that to one read. Parsing per call site would re-read the file and
/// every file it `Include`s, and would print each parse diagnostic once per call.
///
/// `Err` is cached too, for the same reason [`piko_db::Lazy`] caches one. A config that could
/// not be read will not read differently a moment later, and the fallback warning belongs on
/// screen once.
#[derive(Debug, Default)]
pub struct ConfigCache {
    parsed: std::cell::OnceCell<Result<PacmanConfig, String>>,
}

impl ConfigCache {
    /// The parsed config, parsing it on first access.
    ///
    /// The error is a rendered `String` rather than a `piko_db::Error` because it is only
    /// ever displayed, and `Error` is not `Clone`.
    fn get(&self, cli: &Cli) -> Result<&PacmanConfig, &str> {
        self.parsed
            .get_or_init(|| {
                PacmanConfig::open(&cli.config)
                    .inspect(|config| {
                        for diagnostic in config.diagnostics() {
                            eprintln!("Warning: {diagnostic}");
                        }
                    })
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(String::as_str)
    }
}

/// The `CacheDir` list: every `--cachedir` first, then the parsed config's, else pacman's
/// default if the config cannot be read.
///
/// `--cachedir` prepends; it does not replace. This is measured, not assumed. `pacman -Sc`
/// with `--cachedir /tmp/CLI1 --cachedir /tmp/CLI2` over a config naming `/tmp/FROMCONF`
/// reports all three, in that order. `--hookdir` is the flag that replaces its list
/// ([`hook_dirs`]), so the two flags differ here on purpose.
///
/// The order carries the behavior. A package downloads into the first *usable* directory
/// (`piko_txn::select_download_dir`), while every directory is searched for an existing file.
/// So `piko install --root /mnt --cachedir /mnt/var/cache/pacman/pkg` writes into the new
/// root and still reads the host cache, which is what pacman does.
///
/// A package source needs at least one directory. An empty list would report every package
/// missing, with an error naming nowhere it looked. So a failure falls back rather than produce
/// one.
pub fn cache_dirs(config: &ConfigCache, cli: &Cli) -> Vec<PathBuf> {
    let mut dirs = cli.cache_dir.clone();

    if let Ok(config) = config.get(cli) {
        dirs.extend(config.options.cache_dirs.iter().cloned());
    }

    if dirs.is_empty() {
        dirs.push(PathBuf::from(piko_db::config::DEFAULT_CACHE_DIR));
    }
    dirs
}

/// The keyring directory, and the three `SigLevel` directives a transaction can hold a
/// package to.
///
/// Which one applies is decided per package, not per transaction, because pacman decides it
/// per package. See [`signing_policy`].
#[derive(Clone, Debug)]
pub struct SigningPolicy {
    /// `GPGDir`: where the keyring lives.
    pub gpg_dir: PathBuf,
    /// `SigLevel`: the fallback for a package whose repository could not be resolved.
    pub sig_level: piko_db::config::SigLevel,
    /// `LocalFileSigLevel`: for a package file named by path on the command line.
    pub local_file_sig_level: piko_db::config::SigLevel,
    /// `RemoteFileSigLevel`: for a package file named by URL on the command line.
    pub remote_file_sig_level: piko_db::config::SigLevel,
}

/// Resolves the keyring directory and every `SigLevel` a transaction may need.
///
/// Three directives, three kinds of target, and pacman picks between them by how the target
/// was written:
///
/// - A package resolved through a repository is held to *that repository's* own `SigLevel`
///   (`piko_db::config::RepositoryConfig::effective_sig_level`). `cmd::txn::install` resolves
///   it per candidate and feeds it to `Transaction::policy_overrides`.
///   [`SigningPolicy::sig_level`] is only the fallback, for a candidate whose repository could
///   not be resolved.
/// - A package file named by path is held to `LocalFileSigLevel`.
/// - A package file named by URL is held to `RemoteFileSigLevel`.
///
/// The split between the last two is `pacman -U`'s: `upgrade.c` partitions its targets on
/// `strstr(i->data, "://")` and loads each half under its own directive. `piko_txn::classify`
/// makes the same split.
///
/// A config that cannot be read falls back to verifying nothing, which is the same fallback
/// every other setting here takes. That is the weak direction, and it is stated plainly in
/// `piko install`'s output rather than left implicit.
pub fn signing_policy(cli: &Cli, config: &ConfigCache) -> SigningPolicy {
    match config.get(cli) {
        Ok(parsed) => SigningPolicy {
            gpg_dir: parsed.options.gpg_dir.clone(),
            sig_level: parsed.options.sig_level,
            local_file_sig_level: parsed.options.local_file_sig_level,
            remote_file_sig_level: parsed.options.remote_file_sig_level,
        },
        Err(_) => SigningPolicy {
            gpg_dir: PathBuf::from(piko_db::config::DEFAULT_GPG_DIR),
            sig_level: piko_db::config::SigLevel::default(),
            local_file_sig_level: piko_db::config::SigLevel::default(),
            remote_file_sig_level: piko_db::config::SigLevel::default(),
        },
    }
}

/// The directories hooks are read from, in increasing priority.
///
/// `--hookdir` replaces the whole list, matching pacman. Otherwise the list is the system
/// directory followed by every configured `HookDir`. So a file in `/etc/pacman.d/hooks` overrides
/// the system copy of the same name.
///
/// The system directory is resolved inside `root`; a configured `HookDir` is a host path.
/// libalpm draws that same line. `alpm_initialize` builds its own default by joining the root
/// to `SYSHOOKDIR`, so `pacman -r /mnt` reads `/mnt/usr/share/libalpm/hooks/`.
/// `alpm_option_add_hookdir` joins nothing, so a `HookDir` from the config stays as written.
///
/// `pacman-conf --root=/mnt HookDir` answers `/etc/pacman.d/hooks/`, which is not evidence
/// against this. It reports the configured directive, never libalpm's root-joined default.
pub fn hook_dirs(
    cli: &Cli,
    config: &ConfigCache,
    override_dirs: &[PathBuf],
    root: &Path,
) -> Vec<PathBuf> {
    if !override_dirs.is_empty() {
        return override_dirs.to_vec();
    }

    let mut dirs = vec![join_root(root, Path::new(piko_txn::hook::SYSTEM_HOOK_DIR))];
    if let Ok(parsed) = config.get(cli) {
        dirs.extend(parsed.options.hook_dirs.iter().cloned());
    }
    dirs
}

/// Joins an absolute system path onto `root`, the way libalpm concatenates its root with
/// `SYSHOOKDIR`.
///
/// `Path::join` replaces the whole path when the argument is absolute, which would hand back
/// the host directory. Stripping the leading separator first is what makes the join happen.
fn join_root(root: &Path, path: &Path) -> PathBuf {
    match path.strip_prefix("/") {
        Ok(relative) => root.join(relative),
        Err(_) => root.join(path),
    }
}

/// The `NoExtract` and `NoUpgrade` patterns from the parsed `pacman.conf`.
///
/// Empty when the config cannot be read, which treats no path specially. That is the unsafe
/// direction for `NoUpgrade`, because a config file the user protected would be overwritten. It is
/// the same fallback every other directive here uses. And a config piko cannot read has already
/// produced a warning from [`resolve_dbpath`].
pub fn path_patterns(cli: &Cli, config: &ConfigCache) -> piko_txn::Patterns {
    let Ok(parsed) = config.get(cli) else {
        return piko_txn::Patterns::default();
    };
    piko_txn::Patterns {
        no_extract: parsed.options.no_extract.clone(),
        no_upgrade: parsed.options.no_upgrade.clone(),
    }
}

/// `pacman.conf`'s `HoldPkg` list — the packages a removal must ask about before taking away.
///
/// Empty when the config cannot be read, which holds nothing. That is the permissive direction. It
/// is the same fallback [`path_patterns`] takes for `NoUpgrade`, and for the same reason. A config
/// piko cannot read has already produced a warning from [`resolve_dbpath`]. And every directive
/// going quiet together is easier to reason about than one of them going strict. `HoldPkg` is also
/// a guard over a prompt rather than over data. So the cost of it being absent is one question not
/// asked, not a file destroyed.
pub fn hold_pkg(cli: &Cli, config: &ConfigCache) -> Vec<String> {
    config.get(cli).map(|parsed| parsed.options.hold_pkg.clone()).unwrap_or_default()
}

/// Resolves `IgnorePkg` and `IgnoreGroup`, as the two lists
/// [`piko_db::resolve::IgnoreList::new`] pairs.
///
/// The same lenient fallback [`hold_pkg`] takes, and for the same reason. A config piko cannot
/// read has already warned through [`resolve_dbpath`]. And two empty lists ignore nothing, which
/// is what an absent `IgnorePkg` directive means anyway.
pub fn ignore_lists(cli: &Cli, config: &ConfigCache) -> (Vec<String>, Vec<String>) {
    config
        .get(cli)
        .map(|parsed| (parsed.options.ignore_pkg.clone(), parsed.options.ignore_group.clone()))
        .unwrap_or_default()
}

/// Resolves the effective installation root: `RootDir` from the parsed pacman.conf, else the
/// hardcoded default with a warning if that cannot be read.
///
/// Used by `check`, which has no `--root` flag at all. Also used by `install`/`update`/`remove`
/// when `--root` is omitted, the same way [`resolve_dbpath`] resolves `DBPath`.
pub fn resolve_root_dir(cli: &Cli, config: &ConfigCache) -> PathBuf {
    match config.get(cli) {
        Ok(config) => config.options.root_dir.clone(),
        Err(error) => {
            eprintln!(
                "Warning: failed to read {} ({error}); falling back to {}",
                cli.config.display(),
                piko_db::config::DEFAULT_ROOT_DIR
            );
            PathBuf::from(piko_db::config::DEFAULT_ROOT_DIR)
        }
    }
}

/// Resolves the effective database root, in three steps. `--dbpath` if given, else `DBPath` from
/// the parsed pacman.conf, else the hardcoded default with a warning if that cannot be read
/// either. `--config` names the file, and defaults to `/etc/pacman.conf`.
pub fn resolve_dbpath(cli: &Cli, config: &ConfigCache) -> PathBuf {
    if let Some(dbpath) = &cli.dbpath {
        return dbpath.clone();
    }

    match config.get(cli) {
        Ok(config) => config.options.db_path.clone(),
        Err(error) => {
            eprintln!(
                "Warning: failed to read {} ({error}); falling back to {}",
                cli.config.display(),
                piko_db::config::DEFAULT_DB_PATH
            );
            PathBuf::from(piko_db::config::DEFAULT_DB_PATH)
        }
    }
}

/// Resolves the keyring `piko key` administers, in three steps. `--gpgdir` if given, else
/// `GPGDir` from the parsed pacman.conf, else the hardcoded default with a warning.
///
/// The same three-step resolution [`resolve_dbpath`] uses. [`signing_policy`] falls back
/// without a warning, because a transaction states its weakened verification on its own. An
/// administration command has no such line, so it says here which keyring it changes.
pub fn resolve_gpg_dir(gpgdir: Option<&Path>, cli: &Cli, config: &ConfigCache) -> PathBuf {
    if let Some(gpgdir) = gpgdir {
        return gpgdir.to_path_buf();
    }

    match config.get(cli) {
        Ok(config) => config.options.gpg_dir.clone(),
        Err(error) => {
            eprintln!(
                "Warning: failed to read {} ({error}); falling back to {}",
                cli.config.display(),
                piko_db::config::DEFAULT_GPG_DIR
            );
            PathBuf::from(piko_db::config::DEFAULT_GPG_DIR)
        }
    }
}

/// Resolves the effective transaction log, in three steps. `--logfile` if given, else `LogFile`
/// from the parsed pacman.conf, else the hardcoded default with a warning.
///
/// The same three-step resolution [`resolve_dbpath`] uses, and for the same reason. A transaction
/// should still be recorded when the config is unreadable, rather than silently recorded nowhere.
pub fn resolve_log_file(cli: &Cli, config: &ConfigCache) -> PathBuf {
    if let Some(log_file) = &cli.log_file {
        return log_file.clone();
    }

    match config.get(cli) {
        Ok(config) => config.options.log_file.clone(),
        Err(error) => {
            eprintln!(
                "Warning: failed to read {} ({error}); falling back to {}",
                cli.config.display(),
                piko_db::config::DEFAULT_LOG_FILE
            );
            PathBuf::from(piko_db::config::DEFAULT_LOG_FILE)
        }
    }
}

/// Builds the transaction record for this invocation. That is the shared `LogFile` and the history
/// store beside `dbpath`, stamped with the command line that asked for it.
///
/// `offset` must be the value captured at the top of `main`. See [`piko_txn::LocalOffset`] for
/// why it cannot be read later.
pub fn recording(
    cli: &Cli,
    config: &ConfigCache,
    dbpath: &Path,
    offset: piko_txn::LocalOffset,
) -> piko_txn::Recording {
    piko_txn::Recording::new(dbpath, Some(resolve_log_file(cli, config)), offset)
        .command(self::command_line())
}

/// This invocation's command line, as one line.
///
/// pacman's frontend records the same thing, reassembled the same way. An argument holding
/// whitespace is quoted, so the line can be read back as the command it was. That matters for a
/// package file path, the one argument that routinely contains a space.
fn command_line() -> String {
    std::env::args_os()
        .map(|argument| {
            let text = argument.to_string_lossy().into_owned();
            if text.contains(char::is_whitespace) { format!("'{text}'") } else { text }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Opens the local database with the options `cli` requested, printing scan diagnostics.
///
/// Diagnostics are warnings. The database opened, and the packages it did find are usable. The
/// caller decides what to do about the rest.
///
/// # Errors
///
/// Whatever [`LocalDatabase::open_with`] refuses on. That is an unreadable or missing
/// `<dbpath>/local`, a schema version this build does not understand, or a limit tripped while
/// scanning.
pub fn open_local_db(cli: &Cli, config: &ConfigCache) -> Result<LocalDatabase, piko_db::Error> {
    let root = resolve_dbpath(cli, config).join(LOCAL_DB_DIR);

    let db = LocalDatabase::open_with(&root, OpenOptions::new())?;
    for diagnostic in db.diagnostics() {
        eprintln!("Warning: {diagnostic}");
    }
    report_dropped_diagnostics(db.diagnostics_dropped());
    Ok(db)
}

fn print_repo_diagnostics(db: &RepoDatabase) {
    for diagnostic in db.diagnostics() {
        eprintln!("Warning: {diagnostic}");
    }
    report_dropped_diagnostics(db.diagnostics_dropped());
}

/// Opens a repository database archive, printing scan diagnostics.
///
/// # Errors
///
/// Whatever [`RepoDatabase::open_with`] refuses on. An unreadable archive, or one that is not a
/// regular file. A member that does not parse. A limit tripped while walking it.
pub fn open_repo_db(path: &Path) -> Result<RepoDatabase, piko_db::Error> {
    let db = RepoDatabase::open_with(path, RepoOpenOptions::new())?;
    print_repo_diagnostics(&db);
    Ok(db)
}

/// Parses a `--repo` repository-name argument (`list`, `repo-files`, `search`).
///
/// Returns the failure rather than printing it. The caller then propagates it with `?`, like every
/// other failure in the dispatch. [`crate::output::report`] renders it at the top.
///
/// # Errors
///
/// [`Error::InvalidRepoName`] if `repo` is not a name `RepoName` accepts.
pub fn parse_repo_arg(repo: &str) -> Result<RepoName, Error> {
    RepoName::parse(repo).map_err(|_| Error::InvalidRepoName { name: repo.to_owned() })
}

/// Opens `<dbpath>/sync/<repo>.db` (preferring `.db` over `.files`), printing scan diagnostics.
///
/// This is the config-driven counterpart to [`open_repo_db`], used to resolve a repository
/// configured in pacman.conf rather than an explicit archive path.
///
/// The archive's signature is checked against the repository's effective `SigLevel` before the
/// database is handed back. So no caller can use an unverified one. See [`verify_repo_archive`].
///
/// # Errors
///
/// Whatever opening the archive refuses on, as [`open_repo_db`], or a signature the
/// repository's effective `SigLevel` does not accept.
pub fn open_repo_by_name(
    dbpath: &Path,
    repo: &RepoName,
    cli: &Cli,
    config: &ConfigCache,
) -> Result<RepoDatabase, Error> {
    let db = RepoDatabase::open_repo_with(dbpath.join(SYNC_DB_DIR), repo, RepoOpenOptions::new())?;
    verify_repo_archive(db.path(), repo, config, cli)?;
    print_repo_diagnostics(&db);
    Ok(db)
}

/// Checks a repository archive against the `SigLevel` configured for that repository.
///
/// # This is what libalpm does, measured rather than assumed
///
/// piko had this check, then removed it on the grounds that libalpm verifies a database only
/// at download. That ground was wrong, so the check is back. `sync_db_validate`
/// (`be_sync.c:71`) runs at both ends: `_alpm_db_register_sync` calls it when a repository is
/// registered (`be_sync.c:758`), and `alpm_db_update` calls it again after the download
/// (`be_sync.c:248`). The open-time half needs no network to observe. Against a temporary
/// `DBPath` holding a copy of `core.db`, `pacman -Sl core` lists packages normally with no
/// `.sig` beside it, and fails with "invalid or corrupted database (PGP signature)" with a
/// bogus one.
///
/// So a database tampered with after `piko refresh`, the window a download-time check cannot
/// close, is caught here, and piko is no longer weaker than pacman about it.
///
/// # Why after opening rather than before
///
/// The check runs on `db.path()`, the archive that was actually opened, rather than on a path
/// recomputed from the repository name. Recomputing would reintroduce a gap: `open_repo`
/// prefers `<repo>.db` and falls back to `<repo>.files`, so a check that guessed `.db` could
/// verify one file while the reader opened another.
///
/// The cost is that the archive has been parsed by the time it is rejected. That is the
/// lesser trade. The repository reader is the bounded, hardened path (`repo_hardening.rs`
/// covers compression bombs, entry floods, and oversized members), and a rejected database is
/// still never used: the error propagates before any caller sees a package from it.
///
/// # What it costs, and where that cost is not
///
/// About 20 ms per `piko` run, measured on `piko plan --names plasma-meta` (412 ms without
/// the check, 433 ms with it, interleaved medians of nine runs each). Almost all of it is
/// one-time GPGME initialization. See [`piko_sig::verify_database`], which does the actual
/// open-and-check and owns that measurement.
///
/// # What stays CLI-side
///
/// Everything here that is a frontend decision rather than an ALPM security rule: resolving
/// `parsed` from `cli`/`config` at all (a GUI might refuse outright rather than fall back),
/// and the "no readable config means no check" fallback (every other setting in this module
/// takes the same fallback; see [`signing_policy`]).
///
/// # The verdict is not an I/O error, and must not be spelled as one
///
/// [`Error::SignatureRejected`] and [`Error::SignatureUncheckable`] exist so that both
/// spellings are accurate. Do not route either back through [`piko_db::Error::Io`] to save a
/// type, however convenient it is that [`open_repo_by_name`] already returns one. A rejected
/// database would then announce itself as:
///
/// ```text
/// Error: failed to open /var/lib/pacman/sync/core.db
///   Caused by: signature rejected: the signature is invalid
/// ```
///
/// The archive opened fine. That first line names the wrong failure, for the one message in
/// the program that says a mirror may be tampered with. [`open_all_repos`] then makes it
/// worse: it prints only the top line of a skipped repository's error, so the signature is
/// never mentioned at all.
///
/// Caching the `Keyring` in [`ConfigCache`] to avoid opening it once per repository would
/// save about 3 µs per extra repository, not enough to justify the complexity.
fn verify_repo_archive(
    archive: &Path,
    repo: &RepoName,
    config: &ConfigCache,
    cli: &Cli,
) -> Result<(), Error> {
    let Ok(parsed) = config.get(cli) else {
        // No readable config means no configured SigLevel to enforce. Every other setting
        // falls back the same way; see `signing_policy`.
        return Ok(());
    };
    let level = database_sig_level(parsed, repo);

    match piko_sig::verify_database(archive, &parsed.options.gpg_dir, level) {
        // An unverifiable archive is not a bad archive. Both stop the read. The two errors keep
        // them apart, so the user knows whether to fix a keyring or a mirror.
        // `piko_sig::Error`'s own message says which. A keyring that could not be opened names
        // the keyring directory; a check that could not run names the archive. It is kept as a
        // `source` rather than stringified, so `output::report` prints it in the chain.
        Err(source) => Err(Error::SignatureUncheckable { archive: archive.to_path_buf(), source }),
        Ok(piko_sig::Verdict::Rejected(rejection)) => {
            Err(Error::SignatureRejected { archive: archive.to_path_buf(), rejection })
        }
        Ok(piko_sig::Verdict::Accepted { .. }) => Ok(()),
    }
}

/// The `SigLevel` a configured repository's database is held to.
///
/// Through `RepositoryConfig::effective_sig_level`, never by reading `sig_level` directly. A
/// repository that declares no `SigLevel` of its own keeps the parser's `USE_DEFAULT` sentinel
/// (bit 31) rather than the global value. Using the raw field would read a sentinel as though
/// it were a policy. Every caller must share the rule rather than restate it.
fn database_sig_level(parsed: &PacmanConfig, repo: &RepoName) -> piko_db::config::SigLevel {
    parsed
        .repositories
        .iter()
        .find(|configured| configured.name == *repo)
        .map_or(parsed.options.sig_level, |configured| {
            configured.effective_sig_level(parsed.options.sig_level)
        })
}

/// When an opened repository database was published, for a command that warns about an old
/// one without refreshing it.
///
/// A signature that verifies under the repository's `SigLevel` dates it; otherwise the
/// archive's newest member does, recorded when the database was opened. This checks the
/// signature a second time, after [`open_repo_by_name`] already did. That costs nothing on a
/// repository with no `.sig`, which is every Arch repository, and one hash of the archive on a
/// signed one. A check that fails, or no readable config, leaves only the archive date.
pub fn repo_publication(
    db: &RepoDatabase,
    cli: &Cli,
    config: &ConfigCache,
) -> Option<piko_db::repo::freshness::Publication> {
    let signed_at = config.get(cli).ok().and_then(|parsed| {
        let level = database_sig_level(parsed, db.name());
        piko_sig::verify_database_dated(db.path(), &parsed.options.gpg_dir, level).ok()?.signed_at
    });
    piko_db::repo::freshness::Publication::new(signed_at, db.newest_member_time())
}

/// Opens every repository configured in `pacman.conf`, in file (priority) order, skipping any that
/// fails to open with a warning.
///
/// Used where every configured repository's own results are wanted regardless of what any other
/// repository holds. A lookup that stops at the first match wants [`open_repos_for_packages`]
/// instead. That one does not pay to open a repository once the search it exists for is satisfied.
///
/// Carries each repository's `Usage` alongside it. Three callers gate on it:
/// [`resolve`](piko_db::resolve), [`Universe::build`](piko_db::solve::Universe::build), and
/// `piko plan`/`piko install`/`piko update`. Two callers do not gate on it: `repo-search`'s
/// `--repo`-less form and `check-updates`. Both simply discard their half of the pair. Bundling
/// `Usage` here beats returning the bare `RepoDatabase`s. One function then serves every subcommand
/// that needs "every configured repository, opened and verified". Each would otherwise maintain its
/// own loop.
///
/// A repository that fails to open is warned about and skipped. So this fails only when there is
/// no configuration to read at all.
///
/// # Errors
///
/// [`ConfigUnavailable`] if `pacman.conf` could not be read.
pub fn open_all_repos(
    cli: &Cli,
    config: &ConfigCache,
) -> Result<Vec<(DbUsage, RepoDatabase)>, ConfigUnavailable> {
    let parsed = require_pacman_config(cli, config)?;
    let dbpath = cli.dbpath.clone().unwrap_or_else(|| parsed.options.db_path.clone());

    let mut opened = Vec::with_capacity(parsed.repositories.len());
    for repo in &parsed.repositories {
        match open_repo_by_name(&dbpath, &repo.name, cli, config) {
            Ok(db) => opened.push((repo.usage, db)),
            Err(error) => {
                eprintln!("Warning: skipping repository {}: {error}", repo.name);
            }
        }
    }
    Ok(opened)
}

/// Opens repositories configured in `pacman.conf` one at a time, in file (priority) order. It stops
/// as soon as every name in `packages` has been found in one of the repositories opened so far. So a
/// request that `core` alone already satisfies never forces `extra` open at all.
///
/// [`open_all_repos`] is the wrong tool for a literal name lookup, and `info`'s default form
/// (no `--installed`, no `--repo`) is one. It opens every configured repository up front, and
/// fully parses each `desc`, wherever the package turns up. Measured at eleven seconds against
/// this machine's real `extra` alone, for a single name. A literal name lookup can instead stop
/// the moment it is satisfied. piko-db's own `.files` archive walk does the same thing one
/// layer down. It stops decompressing once every wanted name has been seen.
///
/// Returns every repository actually opened, not just the ones that matched. The caller still looks
/// each name up itself, because `repo-files`' batching needs to know which repository each match
/// came from. This only limits how many repositories get opened in the first place.
///
/// A repository that fails to open is warned about and skipped, as in [`open_all_repos`].
///
/// # Errors
///
/// [`ConfigUnavailable`] if `pacman.conf` could not be read.
pub fn open_repos_for_packages(
    cli: &Cli,
    config: &ConfigCache,
    packages: &[String],
) -> Result<Vec<RepoDatabase>, ConfigUnavailable> {
    let parsed = require_pacman_config(cli, config)?;
    let dbpath = cli.dbpath.clone().unwrap_or_else(|| parsed.options.db_path.clone());

    let mut remaining: std::collections::HashSet<&str> =
        packages.iter().map(String::as_str).collect();
    let mut opened = Vec::new();
    for repo in &parsed.repositories {
        if remaining.is_empty() {
            break;
        }
        match open_repo_by_name(&dbpath, &repo.name, cli, config) {
            Ok(db) => {
                remaining.retain(|name| db.get_str(name).is_none());
                opened.push(db);
            }
            Err(error) => {
                eprintln!("Warning: skipping repository {}: {error}", repo.name);
            }
        }
    }
    Ok(opened)
}

/// The parsed pacman.conf, or a failure the caller reports as its own error.
///
/// Unlike [`resolve_dbpath`], a subcommand that is *about* the configuration cannot fall back to a
/// default. There is nothing to fall back to. So this turns the cached failure into an error. Those
/// subcommands are `conf`, `resolve`, and a `check-updates` with no explicit archives.
///
/// # Errors
///
/// [`ConfigUnavailable`] naming the path tried and why it failed.
pub fn require_pacman_config<'a>(
    cli: &Cli,
    config: &'a ConfigCache,
) -> Result<&'a PacmanConfig, ConfigUnavailable> {
    config.get(cli).map_err(|error| ConfigUnavailable {
        path: cli.config.display().to_string(),
        reason: error.to_owned(),
    })
}

/// A `pacman.conf` that could not be read, for a subcommand that cannot proceed without one.
#[derive(Debug)]
pub struct ConfigUnavailable {
    path: String,
    reason: String,
}

impl std::fmt::Display for ConfigUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to read {}: {}", self.path, self.reason)
    }
}

impl std::error::Error for ConfigUnavailable {}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use clap::Parser as _;

    use super::*;

    /// Parses `args` as a `piko` command line, with `conf` as a subcommand that needs no
    /// database.
    fn cli(args: &[&str]) -> Cli {
        let mut argv = vec!["piko"];
        argv.extend_from_slice(args);
        argv.push("conf");
        Cli::parse_from(argv)
    }

    /// Writes `text` as a `pacman.conf` under `dir`, and returns its path as a string.
    fn write_conf(dir: &Path, text: &str) -> String {
        let path = dir.join("pacman.conf");
        std::fs::write(&path, text).unwrap();
        path.display().to_string()
    }

    /// Measured against `pacman -Sc`: two `--cachedir` flags over a config naming one
    /// directory report all three, command line first.
    #[test]
    fn cachedir_comes_before_the_configured_list_rather_than_replacing_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_conf(dir.path(), "[options]\nCacheDir = /from/config/\n");
        let cli = cli(&["--config", &path, "--cachedir", "/a/", "--cachedir", "/b/"]);

        let dirs = cache_dirs(&ConfigCache::default(), &cli);

        assert_eq!(
            dirs,
            vec![PathBuf::from("/a/"), PathBuf::from("/b/"), PathBuf::from("/from/config/")]
        );
    }

    #[test]
    fn without_cachedir_the_configured_list_applies() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_conf(dir.path(), "[options]\nCacheDir = /from/config/\n");
        let cli = cli(&["--config", &path]);

        let dirs = cache_dirs(&ConfigCache::default(), &cli);

        assert_eq!(dirs, vec![PathBuf::from("/from/config/")]);
    }

    /// libalpm joins its root to `SYSHOOKDIR`, so a new root reads its own copy. This is what
    /// keeps a hook from running before the target owns the program it calls.
    #[test]
    fn the_system_hook_directory_is_resolved_inside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_conf(dir.path(), "[options]\n");
        let cli = cli(&["--config", &path]);

        let dirs = hook_dirs(&cli, &ConfigCache::default(), &[], Path::new("/mnt"));

        assert_eq!(dirs.first().unwrap(), &PathBuf::from("/mnt/usr/share/libalpm/hooks"));
    }

    /// A root of `/` must leave the system directory exactly where it already was.
    #[test]
    fn the_running_system_reads_the_unprefixed_system_hook_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_conf(dir.path(), "[options]\n");
        let cli = cli(&["--config", &path]);

        let dirs = hook_dirs(&cli, &ConfigCache::default(), &[], Path::new("/"));

        assert_eq!(dirs.first().unwrap(), &PathBuf::from(piko_txn::hook::SYSTEM_HOOK_DIR));
    }

    /// `alpm_option_add_hookdir` joins nothing, so a configured `HookDir` stays a host path
    /// even under `--root`.
    #[test]
    fn a_configured_hookdir_is_not_resolved_inside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_conf(dir.path(), "[options]\nHookDir = /etc/pacman.d/hooks/\n");
        let cli = cli(&["--config", &path]);

        let dirs = hook_dirs(&cli, &ConfigCache::default(), &[], Path::new("/mnt"));

        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/mnt/usr/share/libalpm/hooks"),
                PathBuf::from("/etc/pacman.d/hooks/"),
            ]
        );
    }

    /// `--hookdir` replaces the whole list, so the root never reaches it.
    #[test]
    fn hookdir_replaces_the_list_and_is_taken_as_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_conf(dir.path(), "[options]\nHookDir = /etc/pacman.d/hooks/\n");
        let cli = cli(&["--config", &path]);
        let override_dirs = [PathBuf::from("/only/this/")];

        let dirs = hook_dirs(&cli, &ConfigCache::default(), &override_dirs, Path::new("/mnt"));

        assert_eq!(dirs, vec![PathBuf::from("/only/this/")]);
    }

    /// The flag must not need a readable config. A caller installing into a new root names both
    /// `--config` and `--cachedir`. An unreadable config must not turn that into the host cache
    /// directory alone.
    #[test]
    fn cachedir_applies_even_when_the_config_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.conf");
        let cli = cli(&["--config", &missing.display().to_string(), "--cachedir", "/a/"]);

        let dirs = cache_dirs(&ConfigCache::default(), &cli);

        assert_eq!(dirs, vec![PathBuf::from("/a/")]);
    }
}
