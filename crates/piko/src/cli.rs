//! Command line argument definitions.
//!
//! Every doc comment on a [`Command`] variant is its `--help` text. It is written for a
//! reader running `piko help <subcommand>`, not for a reader of this file.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// The default `pacman.conf` path, matching pacman's.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/pacman.conf";

/// A simple, secure ALPM package manager.
#[derive(Debug, Parser)]
#[command(name = "piko", version, about, long_about = None)]
pub struct Cli {
    /// Path to the ALPM database directory. Defaults to `DBPath` from the parsed
    /// pacman.conf (see `--config`); falls back to `/var/lib/pacman` with a warning if that
    /// cannot be read.
    #[arg(long, global = true, value_name = "PATH")]
    pub dbpath: Option<PathBuf>,

    /// Path to the pacman.conf-style configuration file, used by the `conf` subcommand.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH, value_name = "PATH")]
    pub config: PathBuf,

    /// Directory to read and download package files from. Repeatable, in decreasing
    /// priority.
    ///
    /// Each directory given here comes before the `CacheDir` list from the parsed
    /// pacman.conf, rather than replacing it, the same way pacman's flag of the same name
    /// does. A package downloads into the first directory, and every directory is searched
    /// for a package already there. With no `--cachedir` and no readable config, this is
    /// `/var/cache/pacman/pkg`.
    #[arg(long = "cachedir", global = true, value_name = "PATH")]
    pub cache_dir: Vec<PathBuf>,

    /// Path to the transaction log. Defaults to `LogFile` from the parsed pacman.conf (see
    /// `--config`); falls back to `/var/log/pacman.log` with a warning if that cannot be
    /// read.
    ///
    /// This is the log pacman writes too. piko appends to the same file, in the same format,
    /// under its own `[PIKO]` caller name. `history` reads it back.
    #[arg(long = "logfile", global = true, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List installed packages, packages in a repository, or the repositories themselves.
    ///
    /// With neither `--repos` nor `--repo`, lists every installed package, same as
    /// `--installed`. This shows directory names only; no package metadata is opened.
    /// `--repo <NAME>` lists that repository's packages instead. `--repos` lists the
    /// repositories configured in pacman.conf instead, one per line, in file order — no
    /// database is opened for that case. Ends with a one-line summary, unless `--quiet` is
    /// given.
    ///
    /// `-e/--explicit`, `-o/--orphans`, `-m/--foreign` and `-g/--groups` each replace the plain
    /// installed listing with a different filter: `pacman -Qe`/`-Qdtt`/`-Qm`/`-Qg`
    /// respectively. Each is rejected together with `--repos`, `--repo`, and with the other
    /// three.
    #[command(visible_alias = "ls")]
    List {
        /// List installed packages. This is the default when neither `--repos` nor `--repo`
        /// is given.
        #[arg(short, long, conflicts_with_all = ["repos", "repo"])]
        installed: bool,
        /// List the repositories configured in pacman.conf instead of installed packages, one
        /// per line — no database is opened.
        #[arg(short = 'r', long)]
        repos: bool,
        /// List packages in this repository, e.g. `core`.
        #[arg(long, value_name = "NAME", conflicts_with = "installed")]
        repo: Option<String>,
        /// List only explicitly-installed packages — never pulled in as another package's
        /// dependency, `pacman -Qe`.
        #[arg(
            short,
            long,
            conflicts_with_all = ["repos", "repo", "orphans", "foreign", "groups"]
        )]
        explicit: bool,
        /// List installed packages that were pulled in only as a dependency and that no
        /// installed package still requires via `%DEPENDS%` — `%OPTDEPENDS%` never counts,
        /// matching `piko why`/`piko plan -R -s`. Equivalent to `pacman -Qdtt`.
        #[arg(
            short,
            long,
            conflicts_with_all = ["repos", "repo", "explicit", "foreign", "groups"]
        )]
        orphans: bool,
        /// List installed packages whose name is not found in any configured repository,
        /// `pacman -Qm`.
        #[arg(
            short = 'm',
            long,
            conflicts_with_all = ["repos", "repo", "explicit", "orphans", "groups"]
        )]
        foreign: bool,
        /// List installed packages belonging to one of the given groups. With no name given,
        /// lists every group name at least one installed package belongs to instead,
        /// `pacman -Qg`.
        #[arg(
            short,
            long,
            value_name = "NAME",
            num_args = 0..,
            conflicts_with_all = ["repos", "repo", "explicit", "orphans", "foreign"]
        )]
        groups: Option<Vec<String>>,
        /// Print only names, one per line — no color, no checkmark, no summary.
        #[arg(short, long)]
        quiet: bool,
    },

    /// List the files one or more packages own.
    ///
    /// Prints `"{package} /{path}"` for every file each named package owns, one per line.
    /// `--quiet` drops the package-name prefix and prints just `"/{path}"`. That differs from
    /// `list`'s quiet convention (bare names): a files listing has no name to reduce to, since
    /// quiet mode removes the package prefix itself. A name that cannot be found, or whose
    /// file list cannot be read, is reported to stderr. The rest are still processed. The exit
    /// code is a failure only once something was missing or unreadable.
    ///
    /// With neither `--installed` nor `--repo`, each name is looked up among installed
    /// packages first, then in the configured repositories in file (priority) order.
    /// `--installed` restricts the lookup to installed packages only. `--repo <NAME>` looks
    /// the named packages up in that one repository's `.files` archive instead, walked once
    /// for all of them rather than once per package.
    Files {
        /// The package(s) whose files to list.
        #[arg(required = true)]
        packages: Vec<String>,
        /// Look these packages up among installed packages only.
        #[arg(short, long, conflicts_with = "repo")]
        installed: bool,
        /// Look these packages up in this repository only, e.g. `core`.
        #[arg(long, value_name = "NAME", conflicts_with = "installed")]
        repo: Option<String>,
        /// Print only the file paths, one per line, dropping the owning package's name.
        #[arg(short, long)]
        quiet: bool,
    },

    /// Show one or more packages' metadata, from their `desc` file (installed) or a repository
    /// database archive (same as `list --repo`).
    ///
    /// With neither `--installed` nor `--repo`, each package is looked up among installed
    /// packages first, then in the configured repositories in file (priority) order, stopping
    /// as soon as one has it. This is the same "first configured match wins" rule `resolve`
    /// applies to a literal name. `--installed` restricts the lookup to installed packages
    /// only. `--repo <NAME>` looks every package up in that one repository only.
    ///
    /// A repository package's metadata carries fields an installed package's `desc` does not
    /// (File Name, Make/Check Deps, Compressed Size, checksums, PGP-signature presence). It
    /// lacks fields an installed package's `desc` does have (Install Date, Install Reason,
    /// Validated By). The two forms print different field sets, the same as `pacman -Qi` vs
    /// `-Si`.
    ///
    /// More than one package prints each entry in turn, separated by a blank line. A name that
    /// cannot be found, or whose `desc` cannot be read, is reported to stderr. The rest are
    /// still processed. The exit code is a failure only once something was missing or
    /// unreadable.
    #[command(visible_alias = "if")]
    Info {
        /// The package name(s).
        #[arg(required = true)]
        packages: Vec<String>,
        /// Look these packages up among installed packages only.
        #[arg(short, long, conflicts_with = "repo")]
        installed: bool,
        /// Look these packages up in this repository only, e.g. `core`.
        #[arg(long, value_name = "NAME", conflicts_with = "installed")]
        repo: Option<String>,
    },

    /// Check that entries agree with their `desc` files, and that installed files match their
    /// `ALPM-MTREE` data.
    ///
    /// For every file a package owns, this compares existence, type, ownership, mode,
    /// modification time, size, and SHA-256 digest (symlink target, for a symlink) against the
    /// package's recorded `mtree` data. A package with no `mtree` file is reported and
    /// skipped, not treated as a failure. A `%BACKUP%` file's own modification time, size, or
    /// digest may differ; an edited config file is expected to differ. Every other mismatch
    /// still fails, backup file or not. A missing file matching `NoExtract` is not reported at
    /// all.
    Check {
        /// The package name(s) to check. Checks every installed package when omitted.
        packages: Vec<String>,
    },

    /// Search installed and available packages.
    ///
    /// Every term must match for a package to be included (e.g. `firefox browser` only finds
    /// packages matching both). Quote a multi-word phrase (`"web browser"`) to search for it
    /// as a single term instead. Results are ranked most-relevant-first: an exact name match,
    /// then an exact `provides` match, then a name prefix, a name substring, a description
    /// substring, and finally an exact group match. A package matching several terms is
    /// ranked by the best of those matches. A package whose `desc` cannot be read is skipped
    /// unless it matches by name alone.
    ///
    /// With neither `--installed` nor `--repos`, both are searched. Every matching installed
    /// package is printed first, tagged `[Installed]`, followed by every matching repository
    /// package that is not installed. A package that is both installed and in a repository is
    /// shown once, from the installed side, never twice.
    ///
    /// `--installed` searches only installed packages; no repository is opened at all.
    /// `--repos` searches only the configured repositories, printing every match regardless of
    /// install status, one repository after another in file (priority) order, mirroring
    /// `pacman -Ss`.
    ///
    /// `--repo` restricts the search to a single named repository, e.g. `core`, and implies
    /// `--repos`. A specific repository is itself a repos-only request. Otherwise a package's
    /// `[Installed]` line would show up identically no matter which repository was named,
    /// since being installed has nothing to do with any one repository. Every configured
    /// repository is searched, in file (priority) order, when `--repo` is omitted. It
    /// conflicts with `--installed`.
    #[command(visible_alias = "se")]
    Search {
        /// The search term(s); a package must match all of them.
        #[arg(required = true)]
        terms: Vec<String>,
        /// Search only installed packages.
        #[arg(short, long, conflicts_with = "repos")]
        installed: bool,
        /// Search only the configured repositories, not installed packages.
        #[arg(short, long)]
        repos: bool,
        /// Search only this repository, e.g. `core`. Implies `--repos`.
        #[arg(long, value_name = "NAME", conflicts_with = "installed")]
        repo: Option<String>,
        /// Print only names, one per line — no color, no checkmark, no repository prefix, no
        /// summary. For scripting.
        #[arg(short, long)]
        quiet: bool,
    },

    /// Check installed packages for updates.
    ///
    /// Mirrors `pacman -Qu`: prints `name old -> new` for every installed package with a
    /// strictly newer version available. For a package present in more than one repository,
    /// the earliest-listed one wins. A package installed but absent from every repository
    /// (e.g. built locally or installed from a foreign source) is skipped.
    ///
    /// With no repository archive paths given, this resolves repositories from the parsed
    /// pacman.conf instead: `<dbpath>/sync/<name>.db` for every configured repository, in the
    /// order they appear in the file (the same order that is repository priority). A
    /// configured repository with no synced database on disk is skipped with a warning,
    /// rather than failing the whole check. Not every configured repository needs to have
    /// been synced.
    ///
    /// Ends with a one-line summary ("N update(s) available"), unless `--quiet` is given.
    /// `--quiet` prints just each package's name, one per line, matching `list`/`search`'s
    /// `--quiet` convention.
    #[command(visible_alias = "cu")]
    CheckUpdates {
        /// Repository archive paths, in priority order. When omitted, resolved from the
        /// parsed pacman.conf instead.
        repo_paths: Vec<PathBuf>,
        /// Print only the installed package's name, one per line — no color, no version, no
        /// arrow, no summary.
        #[arg(short, long)]
        quiet: bool,
    },

    /// Resolves a dependency string to the name(s) of the sync-repository package(s) that
    /// satisfy it, one per line.
    ///
    /// Opens every repository configured in the parsed pacman.conf and tries a literal match
    /// first. This checks each repository in the file's `[repo]` order for one whose `Usage`
    /// includes `Install` or `Upgrade`, that is literally named `target` (satisfying its
    /// version constraint, if any), and that is not covered by the parsed config's
    /// `IgnorePkg`/`IgnoreGroup`. Resolution falls through to the next repository otherwise,
    /// same as libalpm. A package present in more than one configured repository resolves to
    /// the earliest-listed one, even if a later repository carries a newer version.
    ///
    /// If no package is literally named `target`, this searches every `%PROVIDES%` across
    /// every configured repository instead, and prints every matching package's name, not
    /// just one. A name can be provided by more than one package (e.g. several
    /// implementations of the same virtual package, or the same soname built for more than
    /// one architecture). A plain name (`foo`, `foo>=1.0`, `foo=1.2.3-1`; a bare name matches
    /// any version) matches a `%PROVIDES%` entry the same way `_alpm_depcmp_provides` does: an
    /// unversioned provide satisfies only an unconstrained request, and an exact-version
    /// provide (`foo=1.2.3`) satisfies a compatible constraint. A soname
    /// (`lib:libexample.so.1`, `libexample.so=1.0.0-64`) matches a `%PROVIDES%` entry only by
    /// exact equality, per the `alpm-soname` "exact match" rule.
    ///
    /// This is not full dependency resolution. It does no conflict or replacement handling,
    /// and unlike a real transaction, it has no preference for a provider that is already
    /// installed.
    Resolve {
        /// The dependency string: a package name with an optional version constraint (`foo`,
        /// `foo>=1.0`, `foo=1.2.3-1`), or a soname (`lib:libexample.so.1`,
        /// `libexample.so=1.0.0-64`). Quote it in the shell: `>`, `>=`, `<`, `<=` are
        /// redirection operators otherwise.
        target: String,
    },

    /// Show what installing one or more packages would do, without doing it.
    ///
    /// Resolves every dependency transitively across the configured repositories, applies
    /// `%CONFLICTS%` and `%REPLACES%`, and prints the resulting package set. Nothing is
    /// downloaded, extracted, or written. This command only plans.
    ///
    /// The plan reproduces pacman's own resolution whenever pacman succeeds. Where pacman
    /// would fail — a first-choice provider that turns out to conflict — the solver backs out
    /// and reports that it did, rather than giving up.
    Plan {
        /// The package(s) to plan for: a dependency string (`foo`, `foo>=1.0`), or a path to
        /// a package file. May be empty with `--sysupgrade`.
        ///
        /// A package URL is refused here, since previewing one would have to download it. Use
        /// `piko install` for that.
        targets: Vec<String>,

        /// Skip a target whose installed version is already the one that would be installed.
        #[arg(long)]
        needed: bool,

        /// Print only package names, one per line, for comparison with
        /// `pacman -Sp --print-format '%n'`.
        #[arg(long)]
        names: bool,

        /// Plan removing the targets instead of installing them.
        #[arg(long, short = 'R')]
        remove: bool,

        /// With --remove, also remove dependencies that nothing needs any more.
        #[arg(long, short = 's', requires = "remove")]
        recursive: bool,

        /// With --remove, also remove packages that depend on the targets, instead of
        /// refusing.
        #[arg(long, short = 'c', requires = "remove")]
        cascade: bool,

        /// Plan a full system upgrade. Targets may be given as well, as `pacman -Su foo`
        /// allows; with none, this upgrades everything.
        #[arg(long, short = 'u', conflicts_with = "remove")]
        sysupgrade: bool,

        /// With --sysupgrade, also accept a repository version older than the installed one
        /// (`pacman -Suu`).
        #[arg(long, requires = "sysupgrade")]
        downgrade: bool,
    },

    /// Explain why an installed package is present.
    ///
    /// Walks the reverse-dependency graph breadth-first and prints the shortest chain from an
    /// explicitly-installed package down to the target. `pacman -Qi` reports a "Required By"
    /// list, which answers "what would break" rather than "why is this here". Following that
    /// list by hand across several levels is the question this command answers directly.
    Why {
        /// The installed package name.
        package: String,
    },

    /// Install one or more packages.
    ///
    /// Resolves a target naming a package exactly as `piko plan` does: through the configured
    /// repositories, a literal name or dependency string (`foo`, `foo>=1.0`) first, then a
    /// `%GROUPS%` member expansion. A target naming a package file is read from that file. It
    /// then plans the full transitive closure of dependencies, conflicts, and replacements
    /// before installing any of it. `piko install foo` is `piko plan foo` turned into a
    /// transaction.
    ///
    /// A package already in a cache directory is used as-is. A missing one is downloaded from
    /// its own repository's configured servers, verified, and cached before installing. This
    /// is the same sequential, unresumed download `piko refresh` already does for a database.
    ///
    /// With no `--root`, this resolves `RootDir` from the parsed pacman.conf instead (see
    /// `--config`), falling back to `/` with a warning if that cannot be read.
    ///
    /// Package signatures are checked according to the `SigLevel` of the repository each
    /// package was resolved from. A package file named by path is held to `LocalFileSigLevel`
    /// instead, and one named by URL to `RemoteFileSigLevel`. By default, an unsigned package
    /// is allowed and a signed one must be trusted.
    ///
    /// A named package file is `pacman -U`. Its own dependencies are still resolved from the
    /// configured repositories, and it takes precedence over any repository build of the same
    /// package. A URL is downloaded before the plan is shown, so `piko install <url>` reaches
    /// the network before it asks for confirmation.
    #[command(visible_alias = "in")]
    Install {
        /// Where to install. Use `/` for the running system.
        #[arg(long)]
        root: Option<PathBuf>,
        /// The package(s) to install: a dependency string (`foo`, `foo>=1.0`), a `%GROUPS%`
        /// group name, a path to a package file, or its URL.
        ///
        /// A target is read as a package file when it contains `://` (a URL), when it
        /// contains `/` (a path), or when it ends in `.pkg.tar[.gz|.bz2|.xz|.zst]` and names a
        /// file that exists here. Anything else is a name. Write `./foo.pkg.tar.zst` to say
        /// "the file" where both readings are possible.
        #[arg(required = true)]
        packages: Vec<String>,
        /// Record the named packages as dependencies rather than explicitly installed.
        ///
        /// A package pulled in only to satisfy another's dependency is always recorded as a
        /// dependency, regardless of this flag. This flag governs only the packages named on
        /// the command line.
        #[arg(long)]
        asdeps: bool,
        /// Overwrite files another package owns, for paths matching these glob patterns.
        ///
        /// piko refuses by default. Writing a file another package owns leaves the database
        /// claiming two owners for one path, and removing either package then deletes a file
        /// the other still needs. Repeatable, matched against the path without a leading `/`.
        #[arg(long, value_name = "GLOB")]
        overwrite: Vec<String>,
        /// Do not run a package's `.INSTALL` scriptlet.
        ///
        /// pacman's flag of the same name. A scriptlet is shell code the packager wrote, run
        /// with piko's privileges inside `--root`. Skipping it leaves the package installed,
        /// but whatever the scriptlet was meant to set up stays undone.
        #[arg(long)]
        noscriptlet: bool,
        /// Read hooks from these directories instead of the configured ones.
        ///
        /// pacman's flag of the same name. Repeatable, and in increasing priority — a hook
        /// file name found in a later directory overrides the same name in an earlier one.
        /// Point it at an empty directory to run no hooks at all.
        #[arg(long, value_name = "DIR")]
        hookdir: Vec<PathBuf>,
        /// Assume "yes" to the confirmation prompt instead of asking.
        ///
        /// pacman's flag of the same name. The plan is printed either way. This flag only
        /// skips waiting for an answer, for scripted or automated use.
        #[arg(long)]
        noconfirm: bool,
        /// Download every missing package into the cache without installing anything.
        ///
        /// pacman's `-Sw`. The plan is printed and confirmed exactly as an ordinary install.
        /// Nothing is extracted, no database entry is written, and no journal or lock is
        /// touched. A later `install` of the same targets then finds everything cached.
        #[arg(short = 'w', long = "downloadonly")]
        download_only: bool,
    },

    /// Upgrade installed packages.
    ///
    /// Resolves the full-system upgrade exactly as `piko plan -u` does. For each installed
    /// package, the first configured repository that carries its name at all decides the
    /// outcome, checking a `%REPLACES%` pair before the literal name, gated on `Usage =
    /// Upgrade`. The resulting transaction is planned through the same solver `install` uses.
    /// So a repository build that conflicts with something installed removes it, and a newly
    /// required dependency is pulled in, the same way `install` handles either case.
    /// `piko plan -u [targets]` is this command's preview: it prints the same plan this
    /// command commits.
    ///
    /// Refreshes every configured repository first, `pacman -Syu`. `--norefresh` skips that
    /// and plans against whatever is already on disk, `pacman -Su`. A refresh that fails
    /// stops here: the upgrade is not planned against a database the refresh could not
    /// confirm is current.
    ///
    /// As with `install`, with no `--root`, this resolves `RootDir` from the parsed
    /// pacman.conf instead.
    #[command(visible_alias = "up")]
    Update {
        /// Where to upgrade. Use `/` for the running system.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Extra targets to install alongside the upgrade, as `pacman -Su foo` allows. With
        /// none, every installed package is checked.
        targets: Vec<String>,
        /// Accept a repository version older than the installed one (`pacman -Suu`).
        #[arg(long)]
        downgrade: bool,
        /// Do not refresh repository databases first (`pacman -Su`).
        #[arg(long)]
        norefresh: bool,
        /// Refresh even a database the server reports as unchanged (`pacman -Syyu`).
        ///
        /// Skips the conditional request entirely, so a `304` can never come back. Ignored
        /// with `--norefresh`, since nothing is fetched either way.
        #[arg(short, long)]
        force: bool,
        /// Overwrite files another package owns, for paths matching these glob patterns.
        #[arg(long, value_name = "GLOB")]
        overwrite: Vec<String>,
        /// Do not run a package's `.INSTALL` scriptlet.
        #[arg(long)]
        noscriptlet: bool,
        /// Read hooks from these directories instead of the configured ones.
        #[arg(long, value_name = "DIR")]
        hookdir: Vec<PathBuf>,
        /// Assume "yes" to the confirmation prompt instead of asking.
        #[arg(long)]
        noconfirm: bool,
        /// Download every missing package into the cache without installing anything
        /// (`pacman -Suw`).
        #[arg(short = 'w', long = "downloadonly")]
        download_only: bool,
    },

    /// Remove installed packages.
    ///
    /// As with `install`, with no `--root`, this resolves `RootDir` from the parsed
    /// pacman.conf instead.
    ///
    /// The set of packages removed is decided by the same planner `piko plan -R` prints, so
    /// that command is an exact preview of this one. Removing a package something else still
    /// depends on is refused. `-c` cascades instead. `-s` also takes away dependencies
    /// nothing needs any more.
    #[command(visible_alias = "rm")]
    Remove {
        /// Where to remove from. Use `/` for the running system.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Installed package names.
        #[arg(required = true)]
        packages: Vec<String>,
        /// Do not create `.pacsave` files for modified configuration files.
        #[arg(long)]
        nosave: bool,
        /// Also remove dependencies that nothing needs any more.
        #[arg(short = 's', long)]
        recursive: bool,
        /// Remove packages that depend on the targets, instead of refusing.
        #[arg(short = 'c', long)]
        cascade: bool,
        /// Remove exactly the packages named, checking nothing.
        ///
        /// The escape hatch, equivalent to pacman's `-Rdd`. It can leave the system with
        /// unsatisfied dependencies. That is the point of asking for it.
        #[arg(long)]
        nodeps: bool,
        /// Do not run a package's `.INSTALL` scriptlet.
        #[arg(long)]
        noscriptlet: bool,
        /// Read hooks from these directories instead of the configured ones.
        #[arg(long, value_name = "DIR")]
        hookdir: Vec<PathBuf>,
        /// Assume "yes" to the confirmation prompt instead of asking.
        ///
        /// pacman's flag of the same name. The plan is printed either way. This flag only
        /// skips waiting for an answer, for scripted or automated use.
        #[arg(long)]
        noconfirm: bool,
    },

    /// Download repository databases.
    ///
    /// pacman's `-Sy`. Each configured repository's `Server` list is tried in order; the
    /// first that answers wins. A conditional request means an unchanged database costs one
    /// round trip rather than a download.
    ///
    /// **The signature is checked before the download replaces anything.** A database that
    /// fails its repository's `SigLevel` is discarded, and the existing one is left in place.
    /// So a hostile or broken mirror cannot degrade a working system.
    #[command(visible_alias = "rf")]
    Refresh {
        /// Repositories to refresh. Refreshes every configured one when omitted.
        repos: Vec<String>,
        /// Refresh even a database the server reports as unchanged.
        ///
        /// Skips the conditional request entirely, so a `304` can never come back. Use this
        /// for a locally corrupted database, or a mirror whose clock disagrees with its own
        /// `Last-Modified`.
        #[arg(short, long)]
        force: bool,
    },

    /// Report an unfinished transaction, if the database records one.
    ///
    /// Read-only: it describes what was interrupted and how far it got. It cannot undo what
    /// was applied. piko keeps no copy of overwritten files, so there is nothing to roll back
    /// to. See `docs/locking.md` and the `journal` module.
    Report,

    /// Show the transactions this system has run, newest last.
    ///
    /// Reads the transaction log (`--logfile`, or `LogFile` from pacman.conf), which pacman
    /// writes too, so this covers transactions run by either tool. Each is shown with the
    /// tool that ran it, the command line when the log recorded one, and what it did.
    ///
    /// piko's own transactions carry more than the log format can hold — the exact command
    /// line, the `.pacnew` files left behind, why a transaction failed. That detail comes from
    /// `<dbpath>/piko-history` and is merged in where it exists.
    ///
    /// Read-only. It reports; it changes nothing, and it cannot undo a transaction.
    History {
        /// Show at most this many transactions. The newest are kept.
        #[arg(short = 'n', long, value_name = "COUNT", default_value_t = 20)]
        last: usize,

        /// Show only transactions that touched this package. Repeatable.
        #[arg(short, long, value_name = "NAME")]
        package: Vec<String>,

        /// Show only transactions that started at or after this time, as `YYYY-MM-DD` or a
        /// full `YYYY-MM-DDTHH:MM:SS+ZZZZ`.
        ///
        /// A bare date names the whole day, read in UTC, and both bounds include it. So
        /// `--since D --until D` shows every transaction of day D.
        #[arg(long, value_name = "WHEN")]
        since: Option<String>,

        /// Show only transactions that started at or before this time, in the same formats
        /// `--since` takes. A bare date runs to that day's last second, not to its midnight.
        #[arg(long, value_name = "WHEN")]
        until: Option<String>,

        /// Show every transaction, ignoring `--last`.
        #[arg(short, long)]
        all: bool,

        /// Print one line per transaction, with no per-package detail.
        #[arg(short, long)]
        quiet: bool,
    },

    /// Parse and dump a pacman.conf-style configuration file.
    ///
    /// Prints `[options]` followed by every in-scope directive, after defaults are resolved —
    /// a directive absent from the file still shows its default value, the same way
    /// `pacman-conf` does. Then it prints one `[reponame]` block per configured repository,
    /// in the order they appear in the file (this is repository priority order).
    ///
    /// One directive name prints that directive's value alone instead, with no `[options]`
    /// header and no name. A directive holding several values prints one per line. A flag
    /// directive prints its own name when set, and nothing when unset. The name is matched
    /// without regard to case, the same way `pacman-conf` matches it. An unknown name is an
    /// error. A repository directive (`Server`, `Usage`) is not a name this accepts, since
    /// only the `[options]` section is queried.
    Conf {
        /// The directive to print, for example `DBPath`. Prints every directive when
        /// omitted.
        directive: Option<String>,
    },
}
