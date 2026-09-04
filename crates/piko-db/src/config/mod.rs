//! `pacman.conf` parsing.
//!
//! Mirrors pacman's own config parser (`conf.c` + `ini.c`) and its dump tool
//! (`pacman-conf.c`). These directives are deliberately unsupported: `DownloadUser`,
//! `XferCommand`, `UseSyslog`, `VerbosePkgLists`, `ILoveCandy`, `DisableSandbox`,
//! `DisableSandboxFilesystem`, `DisableSandboxSyscalls`. All are downloading, logging, or
//! sandboxing concerns — stated non-goals of piko. Each is recognized, so parsing a real
//! `pacman.conf` does not spuriously warn about it, and silently dropped.
//!
//! A missing or unreadable `Include` target is a **fatal** error, not a soft diagnostic.
//! This matches `globdir`'s `GLOB_NOCHECK` flag in `conf.c`: a pattern that matches nothing
//! is not silently skipped. It is retried as a literal path, which then fails to open and
//! aborts the whole parse. A syntactically valid but unrecognized directive name is
//! non-fatal instead, mirroring `pm_printf(ALPM_LOG_WARNING, ...)`. It is reported via
//! [`PacmanConfig::diagnostics`].
//!
//! ```no_run
//! use piko_db::config::PacmanConfig;
//!
//! let config = PacmanConfig::open("/etc/pacman.conf")?;
//! for repo in &config.repositories {
//!     println!("{}", repo.name);
//! }
//! # Ok::<(), piko_db::Error>(())
//! ```

pub mod ini;
mod sig_level;
mod usage;

use std::{
    env, fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use alpm_types::Architecture;

use self::ini::Line;
pub use self::{sig_level::SigLevel, usage::DbUsage};
use crate::{Error, Limits, Result, fs_util::read_capped_utf8, limits::Limit, repo::RepoName};

/// pacman's default `RootDir`. `pub` for the same reason as [`DEFAULT_DB_PATH`].
pub const DEFAULT_ROOT_DIR: &str = "/";

/// pacman's default `DBPath`.
///
/// Used when neither `--dbpath` nor `pacman.conf`'s `DBPath` applies — a config that failed
/// to read at all, not just a section that omitted the directive. Falling back to some
/// database path is a frontend decision, not an ALPM one (see `crates/piko/src/context.rs`).
/// `pub` so that caller does not have to hardcode this string a second time.
pub const DEFAULT_DB_PATH: &str = "/var/lib/pacman/";

/// pacman's default `LogFile`. `pub` for the same reason as [`DEFAULT_DB_PATH`].
pub const DEFAULT_LOG_FILE: &str = "/var/log/pacman.log";

/// pacman's default `GPGDir`. `pub` for the same reason as [`DEFAULT_DB_PATH`].
pub const DEFAULT_GPG_DIR: &str = "/etc/pacman.d/gnupg/";

/// pacman's default `CacheDir`. `pub` for the same reason as [`DEFAULT_DB_PATH`].
pub const DEFAULT_CACHE_DIR: &str = "/var/cache/pacman/pkg/";
const DEFAULT_HOOK_DIR: &str = "/etc/pacman.d/hooks/";

/// `Include` nesting deeper than this is refused, matching `conf.c`'s
/// `config_max_recursion`. This is a cycle guard, not a policy limit.
const MAX_INCLUDE_DEPTH: u8 = 10;

/// `pacman.conf`'s `CleanMethod` directive: how `pacman -Sc` decides what to remove from the
/// cache. Named after `PM_CLEAN_*` in `conf.h`. piko does not implement cache cleaning itself
/// (a stated non-goal). This type exists purely so the directive parses and round-trips
/// faithfully.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanMethod(u32);

impl CleanMethod {
    /// Keep installed packages' cached copies.
    pub const KEEP_INSTALLED: Self = Self(1 << 0);
    /// Keep only the current version of every cached package.
    pub const KEEP_CURRENT: Self = Self(1 << 1);

    fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Returns `true` if every bit in `flag` is set.
    #[must_use]
    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }
}

/// A non-fatal problem found while parsing a `pacman.conf`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigDiagnostic {
    /// A directive name that is not recognized. Matches `conf.c`'s
    /// `"directive '%s' in section '%s' not recognized"` warning. Parsing continues past it,
    /// and the directive is simply dropped.
    UnknownDirective {
        /// The config file the directive was found in.
        path: PathBuf,
        /// The 1-based line number.
        line: usize,
        /// The section the directive appeared in (`"options"` or a repository name).
        section: String,
        /// The unrecognized directive name.
        key: String,
    },
}

impl fmt::Display for ConfigDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDirective { path, line, section, key } => write!(
                f,
                "{} line {line}: directive '{key}' in section '{section}' not recognized",
                path.display()
            ),
        }
    }
}

/// The `[options]` section of a parsed `pacman.conf`, after defaults are applied.
#[derive(Clone, Debug)]
pub struct Options {
    /// `RootDir`. Default `/`.
    pub root_dir: PathBuf,
    /// `DBPath`. Defaults to `/var/lib/pacman/`, or `<root_dir>/var/lib/pacman/` when
    /// `RootDir` was explicitly set.
    pub db_path: PathBuf,
    /// `LogFile`. Same rootdir-conditional default as `db_path`: `/var/log/pacman.log`.
    pub log_file: PathBuf,
    /// `GPGDir`. Default `/etc/pacman.d/gnupg/`. Never rootdir-prefixed, matching `conf.c`.
    pub gpg_dir: PathBuf,
    /// `CacheDir`, repeatable. Default `[/var/cache/pacman/pkg/]`.
    pub cache_dirs: Vec<PathBuf>,
    /// `HookDir`, repeatable. Default `[/etc/pacman.d/hooks/]`.
    pub hook_dirs: Vec<PathBuf>,
    /// `HoldPkg`, repeatable.
    pub hold_pkg: Vec<String>,
    /// `IgnorePkg`, repeatable.
    pub ignore_pkg: Vec<String>,
    /// `IgnoreGroup`, repeatable.
    pub ignore_group: Vec<String>,
    /// `NoUpgrade`, repeatable.
    pub no_upgrade: Vec<String>,
    /// `NoExtract`, repeatable.
    pub no_extract: Vec<String>,
    /// `Architecture`, repeatable. `auto` resolves via `std::env::consts::ARCH`, not
    /// `uname(2)`.
    pub architecture: Vec<Architecture>,
    /// `CleanMethod`. Default `KEEP_INSTALLED`.
    pub clean_method: CleanMethod,
    /// `CheckSpace`.
    pub check_space: bool,
    /// Whether the bare `Color` directive was present. piko does not resolve this to an
    /// on/off state itself. That is an `isatty` decision `conf.c` makes at parse time; piko
    /// does not colorize output.
    pub color: bool,
    /// `NoProgressBar`.
    pub no_progress_bar: bool,
    /// `DisableDownloadTimeout`.
    pub disable_download_timeout: bool,
    /// `ParallelDownloads`. Default `1`.
    pub parallel_downloads: u32,
    /// `SigLevel`. Default `PACKAGE | DATABASE` (required, trusted-only).
    pub sig_level: SigLevel,
    /// `LocalFileSigLevel`, merged against `sig_level`.
    pub local_file_sig_level: SigLevel,
    /// `RemoteFileSigLevel`, merged against `sig_level`.
    pub remote_file_sig_level: SigLevel,
}

/// A `[reponame]` section of a parsed `pacman.conf`, after defaults are applied.
#[derive(Clone, Debug)]
pub struct RepositoryConfig {
    /// The repository name.
    pub name: RepoName,
    /// `Server`, repeatable, with `$repo`/`$arch` substituted.
    pub servers: Vec<String>,
    /// `CacheServer`, repeatable, with `$repo`/`$arch` substituted.
    pub cache_servers: Vec<String>,
    /// `Usage`. Default `ALL`.
    pub usage: DbUsage,
    /// `SigLevel`, merged against the global `SigLevel`.
    pub sig_level: SigLevel,
}

impl RepositoryConfig {
    /// This repository's effective `SigLevel`, falling back to `global` (`[options]`'s own
    /// `SigLevel`) when this repository never set one at all.
    ///
    /// pacman merges the two through a mask, so a repository can relax or tighten individual
    /// bits. The parser already resolves that for a repository that set something. A repository
    /// section with no `SigLevel` directive at all keeps the parser's own
    /// [`SigLevel::USE_DEFAULT`] sentinel bit instead (`conf.c`'s `ALPM_SIG_USE_DEFAULT`, which
    /// this module's repo scratch state starts every repository at), not
    /// [`SigLevel::default()`].
    ///
    /// Test for the sentinel **bit**. `sig_level == SigLevel::default()` never matches:
    /// `SigLevel::default()` is the zero value, while `USE_DEFAULT` is bit 31. Under that test
    /// a repository that set nothing reads as `SigLevel = Never`, whatever `[options]` says.
    /// `sig_level::apply_values` clears the sentinel the moment a repository's own `SigLevel`
    /// directive is parsed at all, which is what separates "unset" from "explicitly set".
    #[must_use]
    pub fn effective_sig_level(&self, global: SigLevel) -> SigLevel {
        if self.sig_level.contains(SigLevel::USE_DEFAULT) { global } else { self.sig_level }
    }
}

/// A parsed and defaulted `pacman.conf`.
#[derive(Clone, Debug)]
pub struct PacmanConfig {
    /// The `[options]` section.
    pub options: Options,
    /// Every `[reponame]` section, in file order. File order **is** repository priority
    /// order — the same convention [`crate::LocalDatabase::check_updates`] uses for its
    /// caller-supplied repository list.
    pub repositories: Vec<RepositoryConfig>,
    diagnostics: Vec<ConfigDiagnostic>,
}

impl PacmanConfig {
    /// Opens and parses `path`, using [`Limits::default`].
    ///
    /// # Errors
    ///
    /// See [`PacmanConfig::open_with`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(path, &Limits::default())
    }

    /// Opens and parses `path` with custom `limits`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] (and friends from [`crate::fs_util`]) if `path` or a file it
    /// `Include`s cannot be read; [`Error::ConfigDirectiveOutsideSection`],
    /// [`Error::ConfigInvalidDirective`], [`Error::ConfigIncludeDepthExceeded`] or
    /// [`Error::ConfigInvalidRepoName`] for a malformed file.
    pub fn open_with(path: impl AsRef<Path>, limits: &Limits) -> Result<Self> {
        let mut parser = Parser::new(limits);
        parser.parse_file(path.as_ref(), 0)?;
        parser.finish()
    }

    /// Non-fatal problems found while parsing: directive names `conf.c` would warn about
    /// and continue past. Never `Include` failures. Those are fatal; see the module docs.
    #[must_use]
    pub fn diagnostics(&self) -> &[ConfigDiagnostic] {
        &self.diagnostics
    }
}

/// The in-progress `[options]` section while parsing, before defaults are resolved.
///
/// `None` on a path field mirrors `conf.c`'s "do not overwrite a path specified elsewhere"
/// pattern. There, `elsewhere` means the command line. piko has no equivalent pre-seed, so
/// this only ever means "first directive occurrence wins". A zero-valued bitmask field
/// mirrors `config_repo_t`/`config_t`'s zero-initialization before `setdefaults` runs.
#[derive(Debug)]
struct OptionsScratch {
    root_dir: Option<PathBuf>,
    db_path: Option<PathBuf>,
    log_file: Option<PathBuf>,
    gpg_dir: Option<PathBuf>,
    cache_dirs: Vec<PathBuf>,
    hook_dirs: Vec<PathBuf>,
    hold_pkg: Vec<String>,
    ignore_pkg: Vec<String>,
    ignore_group: Vec<String>,
    no_upgrade: Vec<String>,
    no_extract: Vec<String>,
    architecture: Vec<Architecture>,
    clean_method: CleanMethod,
    check_space: bool,
    color: bool,
    no_progress_bar: bool,
    disable_download_timeout: bool,
    parallel_downloads: u32,
    sig_level: SigLevel,
    sig_level_mask: SigLevel,
    local_file_sig_level: SigLevel,
    local_file_sig_level_mask: SigLevel,
    remote_file_sig_level: SigLevel,
    remote_file_sig_level_mask: SigLevel,
}

impl Default for OptionsScratch {
    /// Matches `config_new`'s defaults: `parallel_downloads = 1`, `siglevel = PACKAGE |
    /// DATABASE` (assuming signature support, the common case), and both file-specific
    /// `SigLevel`s starting at `USE_DEFAULT`. Everything else is zero/empty.
    fn default() -> Self {
        Self {
            root_dir: None,
            db_path: None,
            log_file: None,
            gpg_dir: None,
            cache_dirs: Vec::new(),
            hook_dirs: Vec::new(),
            hold_pkg: Vec::new(),
            ignore_pkg: Vec::new(),
            ignore_group: Vec::new(),
            no_upgrade: Vec::new(),
            no_extract: Vec::new(),
            architecture: Vec::new(),
            clean_method: CleanMethod::default(),
            check_space: false,
            color: false,
            no_progress_bar: false,
            disable_download_timeout: false,
            parallel_downloads: 1,
            sig_level: SigLevel::default_global(),
            sig_level_mask: SigLevel::default(),
            local_file_sig_level: SigLevel::USE_DEFAULT,
            local_file_sig_level_mask: SigLevel::default(),
            remote_file_sig_level: SigLevel::USE_DEFAULT,
            remote_file_sig_level_mask: SigLevel::default(),
        }
    }
}

/// The in-progress `[reponame]` section while parsing.
#[derive(Debug)]
struct RepoScratch {
    name: String,
    servers: Vec<String>,
    cache_servers: Vec<String>,
    usage: DbUsage,
    sig_level: SigLevel,
    sig_level_mask: SigLevel,
    /// Where the `[reponame]` header itself was seen. Error messages raised later at
    /// `finish()` time — an invalid repo name, or a `$arch` substitution with no configured
    /// architecture — have no single directive line of their own to point at, so they use
    /// this instead.
    declared_path: PathBuf,
    declared_line: usize,
}

impl RepoScratch {
    /// A freshly seen `[reponame]` section. `usage` starts unset (defaults to `ALL` at
    /// `finish()` if still unset), and `sig_level` starts at `USE_DEFAULT`, matching
    /// `section->repo->siglevel = ALPM_SIG_USE_DEFAULT` in `conf.c`.
    fn new(name: &str, path: &Path, line: usize) -> Self {
        Self {
            name: name.to_owned(),
            servers: Vec::new(),
            cache_servers: Vec::new(),
            usage: DbUsage::default(),
            sig_level: SigLevel::USE_DEFAULT,
            sig_level_mask: SigLevel::default(),
            declared_path: path.to_path_buf(),
            declared_line: line,
        }
    }
}

/// Which section a directive currently belongs to. `Repo` owns its in-progress scratch
/// directly, not through an index into a side table, so applying a directive never needs to
/// index a `Vec`. [`Parser::set_section`] moves it into `Parser::repos` the moment a new
/// section header (or the end of the file) supersedes it.
#[derive(Debug)]
enum Section {
    None,
    Options,
    Repo(RepoScratch),
}

/// Parser state threaded through however many files an `Include` chain visits.
#[derive(Debug)]
struct Parser<'a> {
    limits: &'a Limits,
    options: OptionsScratch,
    repos: Vec<RepoScratch>,
    section: Section,
    diagnostics: Vec<ConfigDiagnostic>,
}

impl<'a> Parser<'a> {
    fn new(limits: &'a Limits) -> Self {
        Self {
            limits,
            options: OptionsScratch::default(),
            repos: Vec::new(),
            section: Section::None,
            diagnostics: Vec::new(),
        }
    }

    /// Installs `new_section`, flushing whatever `[reponame]` section was in progress into
    /// `repos` first. This is the whole reason [`Section::Repo`] owns its scratch inline
    /// rather than through an index. Translates the moment `_parse_directive` sees a new
    /// `[name]` header in `conf.c`.
    fn set_section(&mut self, new_section: Section) {
        if let Section::Repo(scratch) = std::mem::replace(&mut self.section, new_section) {
            self.repos.push(scratch);
        }
    }

    fn parse_file(&mut self, path: &Path, depth: u8) -> Result<()> {
        let text = read_capped_utf8(path, Limit::PacmanConf, self.limits.pacman_conf_bytes)?;

        for token in ini::tokenize(&text) {
            match token.content {
                Line::Section { name } => {
                    let section = if name == "options" {
                        Section::Options
                    } else {
                        Section::Repo(RepoScratch::new(name, path, token.line))
                    };
                    self.set_section(section);
                }
                Line::Directive { key: "Include", value } => {
                    self.handle_include(value, path, token.line, depth)?;
                }
                Line::Directive { key, value } => {
                    self.apply_directive(key, value, path, token.line)?;
                }
            }
        }

        Ok(())
    }

    fn handle_include(
        &mut self,
        value: Option<&str>,
        path: &Path,
        line: usize,
        depth: u8,
    ) -> Result<()> {
        let pattern = require_value("Include", value, path, line)?;
        if depth >= MAX_INCLUDE_DEPTH {
            return Err(Error::ConfigIncludeDepthExceeded { path: path.to_path_buf(), line });
        }
        for included in expand_include(pattern) {
            self.parse_file(&included, depth.saturating_add(1))?;
        }
        Ok(())
    }

    fn apply_directive(
        &mut self,
        key: &str,
        value: Option<&str>,
        path: &Path,
        line: usize,
    ) -> Result<()> {
        let diagnostic = match &mut self.section {
            Section::None => {
                return Err(Error::ConfigDirectiveOutsideSection {
                    path: path.to_path_buf(),
                    line,
                });
            }
            Section::Options => apply_option_directive(&mut self.options, key, value, path, line)?,
            Section::Repo(repo) => apply_repo_directive(repo, key, value, path, line)?,
        };
        if let Some(diagnostic) = diagnostic {
            self.diagnostics.push(diagnostic);
        }
        Ok(())
    }

    /// Applies rootdir-conditional and unconditional defaults (`setdefaults` in `conf.c`),
    /// merges every `SigLevel` mask, substitutes `$repo`/`$arch`, and validates every
    /// section name. This is the step that turns scratch state into a [`PacmanConfig`].
    fn finish(mut self) -> Result<PacmanConfig> {
        self.set_section(Section::None); // flush a trailing in-progress repo section

        let root_was_set = self.options.root_dir.is_some();
        let root_dir = self.options.root_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT_DIR));

        let (db_path, log_file) = if root_was_set {
            let trimmed = trim_trailing_slash(&root_dir);
            (
                self.options
                    .db_path
                    .unwrap_or_else(|| trimmed.join(DEFAULT_DB_PATH.trim_start_matches('/'))),
                self.options
                    .log_file
                    .unwrap_or_else(|| trimmed.join(DEFAULT_LOG_FILE.trim_start_matches('/'))),
            )
        } else {
            (
                self.options.db_path.unwrap_or_else(|| PathBuf::from(DEFAULT_DB_PATH)),
                self.options.log_file.unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_FILE)),
            )
        };

        let gpg_dir = self.options.gpg_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_GPG_DIR));
        let cache_dirs = if self.options.cache_dirs.is_empty() {
            vec![PathBuf::from(DEFAULT_CACHE_DIR)]
        } else {
            self.options.cache_dirs
        };
        let hook_dirs = if self.options.hook_dirs.is_empty() {
            vec![PathBuf::from(DEFAULT_HOOK_DIR)]
        } else {
            self.options.hook_dirs
        };
        let clean_method = if self.options.clean_method == CleanMethod::default() {
            CleanMethod::KEEP_INSTALLED
        } else {
            self.options.clean_method
        };

        let local_file_sig_level = SigLevel::merge(
            self.options.sig_level,
            self.options.local_file_sig_level,
            self.options.local_file_sig_level_mask,
        );
        let remote_file_sig_level = SigLevel::merge(
            self.options.sig_level,
            self.options.remote_file_sig_level,
            self.options.remote_file_sig_level_mask,
        );

        let options = Options {
            root_dir,
            db_path,
            log_file,
            gpg_dir,
            cache_dirs,
            hook_dirs,
            hold_pkg: self.options.hold_pkg,
            ignore_pkg: self.options.ignore_pkg,
            ignore_group: self.options.ignore_group,
            no_upgrade: self.options.no_upgrade,
            no_extract: self.options.no_extract,
            architecture: self.options.architecture,
            clean_method,
            check_space: self.options.check_space,
            color: self.options.color,
            no_progress_bar: self.options.no_progress_bar,
            disable_download_timeout: self.options.disable_download_timeout,
            parallel_downloads: self.options.parallel_downloads,
            sig_level: self.options.sig_level,
            local_file_sig_level,
            remote_file_sig_level,
        };

        let mut repositories = Vec::with_capacity(self.repos.len());
        for repo in self.repos {
            let name =
                RepoName::parse(&repo.name).map_err(|source| Error::ConfigInvalidRepoName {
                    path: repo.declared_path.clone(),
                    line: repo.declared_line,
                    name: repo.name.clone(),
                    source,
                })?;
            let usage = if repo.usage == DbUsage::default() { DbUsage::ALL } else { repo.usage };
            let sig_level = SigLevel::merge(options.sig_level, repo.sig_level, repo.sig_level_mask);

            let mut servers = Vec::with_capacity(repo.servers.len());
            for server in &repo.servers {
                servers.push(substitute_repo_vars(
                    server,
                    &repo.name,
                    &options.architecture,
                    &repo.declared_path,
                    repo.declared_line,
                )?);
            }
            let mut cache_servers = Vec::with_capacity(repo.cache_servers.len());
            for server in &repo.cache_servers {
                cache_servers.push(substitute_repo_vars(
                    server,
                    &repo.name,
                    &options.architecture,
                    &repo.declared_path,
                    repo.declared_line,
                )?);
            }

            repositories.push(RepositoryConfig { name, servers, cache_servers, usage, sig_level });
        }

        Ok(PacmanConfig { options, repositories, diagnostics: self.diagnostics })
    }
}

fn require_value<'v>(
    directive: &str,
    value: Option<&'v str>,
    path: &Path,
    line: usize,
) -> Result<&'v str> {
    value.ok_or_else(|| Error::ConfigInvalidDirective {
        path: path.to_path_buf(),
        line,
        directive: directive.to_owned(),
        value: String::new(),
        reason: "directive needs a value".to_owned(),
    })
}

/// Resolves an `Include` pattern to the file(s) it names, replicating `globdir`'s
/// `GLOB_NOCHECK` behavior. A pattern that matches nothing is not dropped — it is retried
/// as a single literal path. That path then simply fails to open, like any other missing
/// file. See the module docs for why that is deliberately fatal here.
fn expand_include(pattern: &str) -> Vec<PathBuf> {
    match glob::glob(pattern) {
        Ok(paths) => {
            let matches: Vec<PathBuf> = paths.filter_map(|entry| entry.ok()).collect();
            if matches.is_empty() { vec![PathBuf::from(pattern)] } else { matches }
        }
        Err(_) => vec![PathBuf::from(pattern)],
    }
}

fn set_first_path(field: &mut Option<PathBuf>, value: &str) {
    if field.is_none() {
        *field = Some(PathBuf::from(value));
    }
}

fn apply_option_directive(
    options: &mut OptionsScratch,
    key: &str,
    value: Option<&str>,
    path: &Path,
    line: usize,
) -> Result<Option<ConfigDiagnostic>> {
    match value {
        None => Ok(apply_bare_option(options, key, path, line)),
        Some(value) => apply_valued_option(options, key, value, path, line),
    }
}

/// `_parse_options`'s `value == NULL` branch.
fn apply_bare_option(
    options: &mut OptionsScratch,
    key: &str,
    path: &Path,
    line: usize,
) -> Option<ConfigDiagnostic> {
    match key {
        "CheckSpace" => options.check_space = true,
        "Color" => options.color = true,
        "NoProgressBar" => options.no_progress_bar = true,
        "DisableDownloadTimeout" => options.disable_download_timeout = true,
        // Explicitly unsupported: downloading, logging, and sandboxing concerns, all stated
        // non-goals. Recognized and silently dropped, not reported as unknown.
        "UseSyslog"
        | "ILoveCandy"
        | "VerbosePkgLists"
        | "DisableSandbox"
        | "DisableSandboxFilesystem"
        | "DisableSandboxSyscalls" => {}
        _ => {
            return Some(ConfigDiagnostic::UnknownDirective {
                path: path.to_path_buf(),
                line,
                section: "options".to_owned(),
                key: key.to_owned(),
            });
        }
    }
    None
}

/// `_parse_options`'s has-a-value branch.
fn apply_valued_option(
    options: &mut OptionsScratch,
    key: &str,
    value: &str,
    path: &Path,
    line: usize,
) -> Result<Option<ConfigDiagnostic>> {
    match key {
        "NoUpgrade" => options.no_upgrade.extend(value.split_whitespace().map(str::to_owned)),
        "NoExtract" => options.no_extract.extend(value.split_whitespace().map(str::to_owned)),
        "IgnorePkg" => options.ignore_pkg.extend(value.split_whitespace().map(str::to_owned)),
        "IgnoreGroup" => options.ignore_group.extend(value.split_whitespace().map(str::to_owned)),
        "HoldPkg" => options.hold_pkg.extend(value.split_whitespace().map(str::to_owned)),
        "CacheDir" => options.cache_dirs.extend(value.split_whitespace().map(PathBuf::from)),
        "HookDir" => options.hook_dirs.extend(value.split_whitespace().map(PathBuf::from)),
        "Architecture" => {
            for word in value.split_whitespace() {
                options.architecture.push(parse_architecture(word, path, line)?);
            }
        }
        "DBPath" => set_first_path(&mut options.db_path, value),
        "RootDir" => set_first_path(&mut options.root_dir, value),
        "GPGDir" => set_first_path(&mut options.gpg_dir, value),
        "LogFile" => set_first_path(&mut options.log_file, value),
        "CleanMethod" => {
            for word in value.split_whitespace() {
                apply_clean_method(&mut options.clean_method, word, path, line)?;
            }
        }
        "SigLevel" => sig_level::apply_values(
            &mut options.sig_level,
            &mut options.sig_level_mask,
            value,
            path,
            line,
            "SigLevel",
        )?,
        "LocalFileSigLevel" => sig_level::apply_values(
            &mut options.local_file_sig_level,
            &mut options.local_file_sig_level_mask,
            value,
            path,
            line,
            "LocalFileSigLevel",
        )?,
        "RemoteFileSigLevel" => sig_level::apply_values(
            &mut options.remote_file_sig_level,
            &mut options.remote_file_sig_level_mask,
            value,
            path,
            line,
            "RemoteFileSigLevel",
        )?,
        "ParallelDownloads" => {
            options.parallel_downloads = parse_parallel_downloads(value, path, line)?;
        }
        // Explicitly unsupported.
        "DownloadUser" | "XferCommand" => {}
        _ => {
            return Ok(Some(ConfigDiagnostic::UnknownDirective {
                path: path.to_path_buf(),
                line,
                section: "options".to_owned(),
                key: key.to_owned(),
            }));
        }
    }
    Ok(None)
}

/// `_parse_repo`. `Server`/`CacheServer`/`SigLevel`/`Usage` all require a value
/// (`CHECK_VALUE` in `conf.c`). A bare occurrence is a fatal
/// [`Error::ConfigInvalidDirective`], not a diagnostic.
fn apply_repo_directive(
    repo: &mut RepoScratch,
    key: &str,
    value: Option<&str>,
    path: &Path,
    line: usize,
) -> Result<Option<ConfigDiagnostic>> {
    match key {
        "Server" => repo.servers.push(require_value(key, value, path, line)?.to_owned()),
        "CacheServer" => repo.cache_servers.push(require_value(key, value, path, line)?.to_owned()),
        "SigLevel" => {
            let value = require_value(key, value, path, line)?;
            sig_level::apply_values(
                &mut repo.sig_level,
                &mut repo.sig_level_mask,
                value,
                path,
                line,
                "SigLevel",
            )?;
        }
        "Usage" => {
            let value = require_value(key, value, path, line)?;
            usage::apply_values(&mut repo.usage, value, path, line)?;
        }
        _ => {
            return Ok(Some(ConfigDiagnostic::UnknownDirective {
                path: path.to_path_buf(),
                line,
                section: repo.name.clone(),
                key: key.to_owned(),
            }));
        }
    }
    Ok(None)
}

/// `process_cleanmethods`. Unlike [`sig_level::apply_values`], a bad keyword aborts
/// immediately rather than being validated as a whole batch. Valid keywords already seen
/// in the same directive occurrence stay applied.
fn apply_clean_method(
    current: &mut CleanMethod,
    word: &str,
    path: &Path,
    line: usize,
) -> Result<()> {
    match word {
        "KeepInstalled" => current.set(CleanMethod::KEEP_INSTALLED),
        "KeepCurrent" => current.set(CleanMethod::KEEP_CURRENT),
        _ => {
            return Err(Error::ConfigInvalidDirective {
                path: path.to_path_buf(),
                line,
                directive: "CleanMethod".to_owned(),
                value: word.to_owned(),
                reason: "expected KeepInstalled or KeepCurrent".to_owned(),
            });
        }
    }
    Ok(())
}

/// `config_add_architecture`. `auto` resolves to the running system's architecture. See the
/// module docs for why that is `std::env::consts::ARCH` rather than an actual `uname(2)`
/// call.
fn parse_architecture(word: &str, path: &Path, line: usize) -> Result<Architecture> {
    let raw = if word.eq_ignore_ascii_case("auto") { env::consts::ARCH } else { word };
    Architecture::from_str(raw).map_err(|source| Error::ConfigInvalidDirective {
        path: path.to_path_buf(),
        line,
        directive: "Architecture".to_owned(),
        value: word.to_owned(),
        reason: source.to_string(),
    })
}

/// `parse_number` plus `ParallelDownloads`'s own positivity/range checks in `_parse_options`.
fn parse_parallel_downloads(value: &str, path: &Path, line: usize) -> Result<u32> {
    let invalid = |reason: &str| Error::ConfigInvalidDirective {
        path: path.to_path_buf(),
        line,
        directive: "ParallelDownloads".to_owned(),
        value: value.to_owned(),
        reason: reason.to_owned(),
    };
    let number: i64 = value.trim().parse().map_err(|_| invalid("expected an integer"))?;
    if number < 1 {
        return Err(invalid("value must be positive"));
    }
    u32::try_from(number).map_err(|_| invalid("value is too large"))
}

/// `replace_server_vars`. Substitutes `$arch` (using the first configured architecture) and
/// `$repo` into a `Server`/`CacheServer` URL. A `$arch` with no `Architecture` configured is
/// a fatal error, matching `conf.c` exactly.
fn substitute_repo_vars(
    value: &str,
    repo_name: &str,
    architecture: &[Architecture],
    path: &Path,
    line: usize,
) -> Result<String> {
    match architecture.first() {
        Some(arch) => {
            let replaced = value.replace("$arch", &arch.to_string());
            Ok(replaced.replace("$repo", repo_name))
        }
        None => {
            if value.contains("$arch") {
                return Err(Error::ConfigInvalidDirective {
                    path: path.to_path_buf(),
                    line,
                    directive: "Server".to_owned(),
                    value: value.to_owned(),
                    reason: "contains $arch but no Architecture is configured".to_owned(),
                });
            }
            Ok(value.replace("$repo", repo_name))
        }
    }
}

/// `RootDir`'s trailing-slash trim in `setdefaults`.
fn trim_trailing_slash(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.strip_suffix('/').unwrap_or(&text))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::io::Write as _;

    use tempfile::TempDir;

    use super::*;

    fn write_conf(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn defaults_with_an_empty_options_section() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(&dir, "pacman.conf", "[options]\n");

        let config = PacmanConfig::open(&path).unwrap();

        assert_eq!(config.options.root_dir, Path::new("/"));
        assert_eq!(config.options.db_path, Path::new("/var/lib/pacman/"));
        assert_eq!(config.options.log_file, Path::new("/var/log/pacman.log"));
        assert_eq!(config.options.gpg_dir, Path::new("/etc/pacman.d/gnupg/"));
        assert_eq!(config.options.cache_dirs, [PathBuf::from("/var/cache/pacman/pkg/")]);
        assert_eq!(config.options.hook_dirs, [PathBuf::from("/etc/pacman.d/hooks/")]);
        assert_eq!(config.options.clean_method, CleanMethod::KEEP_INSTALLED);
        assert_eq!(config.options.parallel_downloads, 1);
        assert_eq!(config.options.sig_level, SigLevel::default_global());
        assert!(config.repositories.is_empty());
        assert!(config.diagnostics().is_empty());
    }

    #[test]
    fn root_dir_changes_the_default_db_path_and_log_file() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(&dir, "pacman.conf", "[options]\nRootDir = /mnt/target/\n");

        let config = PacmanConfig::open(&path).unwrap();

        assert_eq!(config.options.db_path, Path::new("/mnt/target/var/lib/pacman/"));
        assert_eq!(config.options.log_file, Path::new("/mnt/target/var/log/pacman.log"));
        // GPGDir is never rootdir-prefixed.
        assert_eq!(config.options.gpg_dir, Path::new("/etc/pacman.d/gnupg/"));
    }

    #[test]
    fn repeated_directives_accumulate() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(
            &dir,
            "pacman.conf",
            "[options]\nCacheDir = /a\nCacheDir = /b\nIgnorePkg = foo bar\nIgnorePkg = baz\n",
        );

        let config = PacmanConfig::open(&path).unwrap();

        assert_eq!(config.options.cache_dirs, [PathBuf::from("/a"), PathBuf::from("/b")]);
        assert_eq!(config.options.ignore_pkg, ["foo", "bar", "baz"]);
    }

    #[test]
    fn include_resolves_a_literal_path_into_the_current_section() {
        let dir = TempDir::new().unwrap();
        write_conf(&dir, "extra.conf", "CacheDir = /included\n");
        let path = write_conf(
            &dir,
            "pacman.conf",
            &format!("[options]\nInclude = {}\n", dir.path().join("extra.conf").display()),
        );

        let config = PacmanConfig::open(&path).unwrap();

        assert_eq!(config.options.cache_dirs, [PathBuf::from("/included")]);
    }

    #[test]
    fn include_continues_into_a_repo_section_started_before_it() {
        let dir = TempDir::new().unwrap();
        write_conf(&dir, "servers.conf", "Server = https://example.test/core\n");
        let path = write_conf(
            &dir,
            "pacman.conf",
            &format!("[core]\nInclude = {}\n", dir.path().join("servers.conf").display()),
        );

        let config = PacmanConfig::open(&path).unwrap();

        assert_eq!(config.repositories.len(), 1);
        assert_eq!(config.repositories.first().unwrap().servers, ["https://example.test/core"]);
    }

    #[test]
    fn a_missing_include_target_is_a_fatal_error() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(&dir, "pacman.conf", "[options]\nInclude = /does/not/exist\n");

        let err = PacmanConfig::open(&path).unwrap_err();
        assert!(matches!(err, Error::Io { .. }), "got {err:?}");
    }

    #[test]
    fn include_cycles_are_rejected_at_the_depth_limit() {
        let dir = TempDir::new().unwrap();
        let cycle_path = dir.path().join("cycle.conf");
        write_conf(&dir, "cycle.conf", &format!("Include = {}\n", cycle_path.display()));
        let path = write_conf(
            &dir,
            "pacman.conf",
            &format!("[options]\nInclude = {}\n", cycle_path.display()),
        );

        let err = PacmanConfig::open(&path).unwrap_err();
        assert!(matches!(err, Error::ConfigIncludeDepthExceeded { .. }), "got {err:?}");
    }

    #[test]
    fn a_directive_before_any_section_is_a_hard_error() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(&dir, "pacman.conf", "CheckSpace\n[options]\n");

        let err = PacmanConfig::open(&path).unwrap_err();
        assert!(matches!(err, Error::ConfigDirectiveOutsideSection { line: 1, .. }), "got {err:?}");
    }

    #[test]
    fn an_unrecognised_directive_is_a_diagnostic_not_a_failure() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(&dir, "pacman.conf", "[options]\nTotallyMadeUp = yes\n");

        let config = PacmanConfig::open(&path).unwrap();

        assert_eq!(config.diagnostics().len(), 1);
        assert!(matches!(
            config.diagnostics().first().unwrap(),
            ConfigDiagnostic::UnknownDirective { line: 2, .. }
        ));
    }

    #[test]
    fn explicitly_unsupported_directives_do_not_produce_a_diagnostic() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(&dir, "pacman.conf", "[options]\nUseSyslog\nILoveCandy\n");

        let config = PacmanConfig::open(&path).unwrap();

        assert!(config.diagnostics().is_empty());
    }

    /// The mask-merge case worth getting right. Overriding only the package half of
    /// `SigLevel` in a repo section must not force the database half to `Never`.
    #[test]
    fn a_repo_siglevel_override_only_touches_the_bits_it_names() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(
            &dir,
            "pacman.conf",
            "[options]\nSigLevel = Required\n[core]\nSigLevel = PackageTrustAll\n",
        );

        let config = PacmanConfig::open(&path).unwrap();

        let repo = config.repositories.first().unwrap();
        assert!(repo.sig_level.contains(SigLevel::PACKAGE_MARGINAL_OK), "override applied");
        assert!(repo.sig_level.contains(SigLevel::DATABASE), "database half inherited from global");
    }

    #[test]
    fn a_repo_section_name_becomes_a_repo_name() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(&dir, "pacman.conf", "[core]\nServer = https://example.test\n");

        let config = PacmanConfig::open(&path).unwrap();

        assert_eq!(config.repositories.first().unwrap().name.as_str(), "core");
    }

    #[test]
    fn an_invalid_repo_section_name_is_rejected() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(&dir, "pacman.conf", "[co/re]\nServer = https://example.test\n");

        let err = PacmanConfig::open(&path).unwrap_err();
        assert!(matches!(err, Error::ConfigInvalidRepoName { .. }), "got {err:?}");
    }

    #[test]
    fn repo_usage_defaults_to_all_when_unset() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(&dir, "pacman.conf", "[core]\nServer = https://example.test\n");

        let config = PacmanConfig::open(&path).unwrap();

        assert_eq!(config.repositories.first().unwrap().usage, DbUsage::ALL);
    }

    #[test]
    fn server_urls_substitute_repo_and_arch() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(
            &dir,
            "pacman.conf",
            "[options]\nArchitecture = x86_64\n[core]\nServer = https://example.test/$repo/os/$arch\n",
        );

        let config = PacmanConfig::open(&path).unwrap();

        assert_eq!(
            config.repositories.first().unwrap().servers,
            ["https://example.test/core/os/x86_64"]
        );
    }

    #[test]
    fn architecture_auto_resolves_to_the_running_target() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(&dir, "pacman.conf", "[options]\nArchitecture = auto\n");

        let config = PacmanConfig::open(&path).unwrap();

        assert_eq!(
            config.options.architecture,
            [Architecture::from_str(env::consts::ARCH).unwrap()]
        );
    }

    /// The regression `RepositoryConfig::effective_sig_level` exists to fix: a repository
    /// with no `SigLevel` directive at all must inherit the global one. Comparing the
    /// parser's raw `RepositoryConfig::sig_level` against `SigLevel::default()` always
    /// failed to match. `SigLevel::default()` is the zero value, not the `USE_DEFAULT`
    /// sentinel a repository that said nothing actually carries. Every such repository
    /// silently read as `SigLevel = Never`, regardless of what `[options]` said.
    #[test]
    fn a_repository_with_no_sig_level_inherits_the_global_one() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(
            &dir,
            "pacman.conf",
            "[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional\n\n\
             [core]\nServer = https://example.org/$repo/os/$arch\n",
        );
        let config = PacmanConfig::open(&path).unwrap();
        let repo = config.repositories.first().unwrap();

        let effective = repo.effective_sig_level(config.options.sig_level);
        assert_eq!(effective, config.options.sig_level);
        assert!(
            effective.contains(SigLevel::PACKAGE),
            "the global PackageRequired should still apply to a repository that said nothing"
        );
    }

    /// A repository that sets its own `SigLevel` keeps it rather than the global one.
    #[test]
    fn a_repository_with_its_own_sig_level_keeps_it() {
        let dir = TempDir::new().unwrap();
        let path = write_conf(
            &dir,
            "pacman.conf",
            "[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional\n\n\
             [core]\nSigLevel = Never\nServer = https://example.org/$repo/os/$arch\n",
        );
        let config = PacmanConfig::open(&path).unwrap();
        let repo = config.repositories.first().unwrap();

        let effective = repo.effective_sig_level(config.options.sig_level);
        assert!(
            !effective.contains(SigLevel::PACKAGE),
            "the repository's own Never should override the global Required"
        );
    }
}
