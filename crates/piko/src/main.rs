//! The `piko` command line interface.
//!
//! This file only dispatches commands. Argument definitions live in [`cli`]. Database
//! opening lives in [`context`]. Failures live in [`error`]. Value rendering lives in
//! [`output`]. Each subcommand family has its own module under [`cmd`].
//!
//! Each arm uses `?` instead of a hand-written `match`. [`error::Error`] covers all three
//! of the CLI's failure sources — see that module.

mod cli;
mod cmd;
mod context;
mod error;
mod output;
mod progress;
mod signal;
mod style;

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser as _;
use piko_db::resolve::IgnoreList;
use piko_db::solve::{NoCache, PackageCache};
use piko_txn::CacheDirSource;

use crate::cli::{Cli, Command};
use crate::context::{
    ConfigCache, cache_dirs, hold_pkg, hook_dirs, open_all_repos, open_local_db, open_repo_by_name,
    open_repo_db, open_repos_for_packages, parse_repo_arg, path_patterns, recording,
    require_pacman_config, resolve_dbpath, resolve_log_file, resolve_root_dir, signing_policy,
};
use crate::error::Error;
use crate::output::report;

fn main() -> ExitCode {
    // This runs before clap parses anything. The helper's arguments are a program and that
    // program's own arguments; no argument parser should interpret them. See `piko_txn::exec`
    // for why piko re-executes itself at all.
    if let Some(code) = exec_helper() {
        return code;
    }

    // Read here, before anything spawns a thread. `time` refuses to read the local UTC offset
    // from a multi-threaded process, and piko is multi-threaded by the time a transaction runs
    // — see `piko_txn::LocalOffset`. Every timestamp piko writes is rendered in this value.
    let offset = piko_txn::LocalOffset::capture();
    let cli = Cli::parse();

    match run(&cli, offset) {
        Ok(code) => code,
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}

/// Becomes the exec helper if this process started as one.
///
/// Returns `None` for an ordinary `piko` invocation. On success it never returns: the helper
/// `exec`s the requested program over this process.
///
/// [`piko_txn::exec::Runner`] wires the failure message's stderr to the same pipe as the
/// command's own output. So "could not enter the root /mnt" arrives alongside whatever else
/// the command said, instead of vanishing.
fn exec_helper() -> Option<ExitCode> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if !piko_txn::exec::is_helper_argument(&arguments.next()?) {
        return None;
    }

    let Err(message) = piko_txn::exec::helper_main(&arguments.collect::<Vec<_>>());
    eprintln!("piko: error: {message}");
    Some(ExitCode::FAILURE)
}

fn run(cli: &Cli, offset: piko_txn::LocalOffset) -> Result<ExitCode, Error> {
    // stdout is locked once and buffered here, because `piko list` writes over a thousand
    // lines.
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    // This parses the config at most once per run, no matter how many steps below ask for
    // it. Resolving the database path and listing configured repositories both read the same
    // file.
    let config = ConfigCache::default();

    let code = match &cli.command {
        Command::List {
            installed: _,
            repos,
            repo,
            explicit,
            orphans,
            foreign,
            groups,
            with_members,
            quiet,
        } => {
            if let Some(names) = groups {
                // `--repo`/`--repos` select the side a group listing reads, the way they
                // select the side a package listing reads. Neither means the installed set.
                match (repo, repos) {
                    (Some(name), _) => {
                        let repo = parse_repo_arg(name)?;
                        let dbpath = resolve_dbpath(cli, &config);
                        let db = open_repo_by_name(&dbpath, &repo, cli, &config)?;
                        cmd::list::repo_groups([&db], names, *with_members, *quiet, &mut out)
                    }
                    (None, true) => {
                        let opened = open_all_repos(cli, &config)?;
                        cmd::list::repo_groups(
                            opened.iter().map(|(_, db)| db),
                            names,
                            *with_members,
                            *quiet,
                            &mut out,
                        )
                    }
                    (None, false) => cmd::list::groups(
                        &open_local_db(cli, &config)?,
                        names,
                        *with_members,
                        *quiet,
                        &mut out,
                    ),
                }
            } else if *explicit {
                cmd::list::explicit(&open_local_db(cli, &config)?, *quiet, &mut out)
            } else if *orphans {
                cmd::list::orphans(&open_local_db(cli, &config)?, *quiet, &mut out)
            } else if *foreign {
                let local = open_local_db(cli, &config)?;
                let repos = open_all_repos(cli, &config)?;
                cmd::list::foreign(&local, repos.iter().map(|(_, db)| db), *quiet, &mut out)
            } else {
                match repo {
                    Some(name) => {
                        let repo = parse_repo_arg(name)?;
                        let dbpath = resolve_dbpath(cli, &config);
                        cmd::list::repo(
                            &open_repo_by_name(&dbpath, &repo, cli, &config)?,
                            *quiet,
                            &mut out,
                        )
                    }
                    None if *repos => cmd::list::repo_names(
                        require_pacman_config(cli, &config)?,
                        *quiet,
                        &mut out,
                    ),
                    None => cmd::list::installed(&open_local_db(cli, &config)?, *quiet, &mut out),
                }
            }
        }
        Command::Files { packages, installed, repo, quiet } => match repo {
            Some(name) => {
                let repo = parse_repo_arg(name)?;
                let dbpath = resolve_dbpath(cli, &config);
                cmd::files::files_repo(
                    &open_repo_by_name(&dbpath, &repo, cli, &config)?,
                    packages,
                    *quiet,
                    &mut out,
                )
            }
            None if *installed => cmd::files::files_installed(
                &open_local_db(cli, &config)?,
                packages,
                *quiet,
                &mut out,
            ),
            None => {
                let local = open_local_db(cli, &config)?;
                let missing: Vec<String> =
                    packages.iter().filter(|name| local.get_str(name).is_none()).cloned().collect();
                let dbs = open_repos_for_packages(cli, &config, &missing)?;
                cmd::files::files_installed_then_repos(&local, &dbs, packages, *quiet, &mut out)
            }
        },
        Command::Info { packages, installed, repo } => match repo {
            Some(name) => {
                let repo = parse_repo_arg(name)?;
                let dbpath = resolve_dbpath(cli, &config);
                cmd::info::repo(
                    &open_repo_by_name(&dbpath, &repo, cli, &config)?,
                    packages,
                    offset,
                    &mut out,
                )
            }
            None if *installed => {
                cmd::info::installed(&open_local_db(cli, &config)?, packages, offset, &mut out)
            }
            None => {
                let local = open_local_db(cli, &config)?;
                let missing: Vec<String> =
                    packages.iter().filter(|name| local.get_str(name).is_none()).cloned().collect();
                let dbs = open_repos_for_packages(cli, &config, &missing)?;
                cmd::info::installed_then_repos(&local, &dbs, packages, offset, &mut out)
            }
        },
        Command::Check { packages } => {
            let root = resolve_root_dir(cli, &config);
            let no_extract = path_patterns(cli, &config).no_extract;
            let db = open_local_db(cli, &config)?;
            if packages.is_empty() {
                cmd::check::check_all(&db, &root, &no_extract, &mut out)
            } else {
                cmd::check::check_selected(&db, packages, &root, &no_extract, &mut out)
            }
        }
        Command::Search { terms, installed, repos, repo, quiet } => {
            if *installed {
                cmd::search::installed(&open_local_db(cli, &config)?, terms, *quiet, &mut out)
            } else {
                let dbs: Vec<piko_db::repo::RepoDatabase> = match repo {
                    Some(repo) => {
                        let repo = parse_repo_arg(repo)?;
                        let dbpath = resolve_dbpath(cli, &config);
                        vec![open_repo_by_name(&dbpath, &repo, cli, &config)?]
                    }
                    None => open_all_repos(cli, &config)?.into_iter().map(|(_, db)| db).collect(),
                };
                // `--repo` names one specific repository to search. That alone makes the
                // search repos-only, even without `--repos`. Being installed has nothing to
                // do with any one repository, so a merged search would otherwise show an
                // `[Installed]` package the same way regardless of which repository `--repo`
                // named.
                if *repos || repo.is_some() {
                    cmd::search::repos_only(&dbs, terms, *quiet, &mut out)
                } else {
                    cmd::search::merged(
                        &open_local_db(cli, &config)?,
                        &dbs,
                        terms,
                        *quiet,
                        &mut out,
                    )
                }
            }
        }
        Command::CheckUpdates { repo_paths, quiet } => {
            let local = open_local_db(cli, &config)?;
            let repos: Vec<piko_db::repo::RepoDatabase> = if repo_paths.is_empty() {
                open_all_repos(cli, &config)?.into_iter().map(|(_, db)| db).collect()
            } else {
                let mut repos = Vec::with_capacity(repo_paths.len());
                for path in repo_paths {
                    repos.push(open_repo_db(path)?);
                }
                repos
            };
            cmd::sync::check_updates(&local, &repos, *quiet, &mut out)
        }
        Command::Resolve { target } => {
            let parsed = require_pacman_config(cli, &config)?;
            let opened = open_all_repos(cli, &config)?;
            let ignores = IgnoreList::new(&parsed.options.ignore_pkg, &parsed.options.ignore_group);
            cmd::sync::resolve_and_print(&opened, ignores, target, &mut out)
        }
        Command::Plan {
            targets,
            needed,
            names,
            remove,
            recursive,
            cascade,
            sysupgrade,
            downgrade,
        } => {
            let parsed = require_pacman_config(cli, &config)?;
            let local = open_local_db(cli, &config)?;
            let opened = open_all_repos(cli, &config)?;
            let ignores = IgnoreList::new(&parsed.options.ignore_pkg, &parsed.options.ignore_group);
            let format = if *names { cmd::plan::Format::Names } else { cmd::plan::Format::Full };
            if targets.is_empty() && !*sysupgrade {
                eprintln!("piko: error: no targets given (use --sysupgrade to upgrade everything)");
                return Ok(ExitCode::FAILURE);
            }
            let mode = if *remove {
                cmd::plan::Mode::Remove {
                    recursive: *recursive,
                    cascade: *cascade,
                    hold_pkg: &parsed.options.hold_pkg,
                }
            } else {
                cmd::plan::Mode::Install {
                    needed: *needed,
                    sysupgrade: *sysupgrade,
                    downgrade: *downgrade,
                }
            };
            // A plan's download size reports what `piko install` would really fetch. So this
            // command needs the same `CacheDir` list that `install` uses. `cache_dirs` never
            // returns an empty list, so `CacheDirSource::new` cannot fail here. `NoCache` is
            // the honest fallback; it is not a reason to refuse to plan.
            let cache = CacheDirSource::new(cache_dirs(&config, cli)).ok();
            let cache: &dyn PackageCache = match &cache {
                Some(cache) => cache,
                None => &NoCache,
            };
            cmd::plan::plan(
                &local,
                &opened,
                ignores,
                targets,
                mode,
                format,
                cache,
                &parsed.options.architecture,
                &mut out,
            )
        }
        Command::Why { package } => cmd::why::why(&open_local_db(cli, &config)?, package, &mut out),
        Command::Install {
            root,
            packages,
            asdeps,
            overwrite,
            noscriptlet,
            hookdir,
            noconfirm,
            download_only,
        } => {
            let root = root.clone().unwrap_or_else(|| resolve_root_dir(cli, &config));
            sync(
                cli,
                &config,
                SyncArgs {
                    root: &root,
                    targets: packages,
                    as_deps: *asdeps,
                    sysupgrade: None,
                    refresh: false,
                    force: false,
                    overwrite,
                    noscriptlet: *noscriptlet,
                    hookdir,
                    noconfirm: *noconfirm,
                    download_only: *download_only,
                    offset,
                },
                &mut out,
            )?
        }
        Command::Update {
            root,
            targets,
            downgrade,
            norefresh,
            force,
            overwrite,
            noscriptlet,
            hookdir,
            noconfirm,
            download_only,
        } => {
            let root = root.clone().unwrap_or_else(|| resolve_root_dir(cli, &config));
            sync(
                cli,
                &config,
                SyncArgs {
                    root: &root,
                    targets,
                    as_deps: false,
                    sysupgrade: Some(*downgrade),
                    refresh: !*norefresh,
                    force: *force,
                    overwrite,
                    noscriptlet: *noscriptlet,
                    hookdir,
                    noconfirm: *noconfirm,
                    download_only: *download_only,
                    offset,
                },
                &mut out,
            )?
        }
        Command::Remove {
            root,
            packages,
            nosave,
            recursive,
            cascade,
            nodeps,
            noscriptlet,
            hookdir,
            noconfirm,
        } => {
            let root = root.clone().unwrap_or_else(|| resolve_root_dir(cli, &config));
            let record = recording(cli, &config, &resolve_dbpath(cli, &config), offset);
            cmd::txn::note(
                &record,
                &format!("Running '{}'", record.command.as_deref().unwrap_or("piko")),
            );
            cmd::txn::remove(
                &root,
                &resolve_dbpath(cli, &config),
                cache_dirs(&config, cli),
                packages,
                cmd::txn::RemoveOptions {
                    no_save: *nosave,
                    recursive: *recursive,
                    cascade: *cascade,
                    nodeps: *nodeps,
                    patterns: path_patterns(cli, &config),
                    hold_pkg: hold_pkg(cli, &config),
                    noconfirm: *noconfirm,
                },
                cmd::txn::SideEffects {
                    scriptlets: !*noscriptlet,
                    hook_dirs: hook_dirs(cli, &config, hookdir, &root),
                    recording: record.clone(),
                },
                &mut out,
            )
        }
        Command::Refresh { repos, force } => {
            let record = recording(cli, &config, &resolve_dbpath(cli, &config), offset);
            cmd::txn::note(
                &record,
                &format!("Running '{}'", record.command.as_deref().unwrap_or("piko")),
            );
            cmd::txn::note(&record, "synchronizing package lists");
            let (cancel, _mode) = crate::signal::install_cancel_handler();
            cmd::refresh::refresh(
                require_pacman_config(cli, &config)?,
                &resolve_dbpath(cli, &config),
                repos,
                *force,
                &cancel,
            )
        }
        Command::Report => cmd::txn::report(&resolve_dbpath(cli, &config), &mut out),
        Command::History { last, package, since, until, all, quiet } => cmd::history::history(
            &resolve_log_file(cli, &config),
            &resolve_dbpath(cli, &config),
            cmd::history::Options {
                last: (!*all).then_some(*last),
                packages: package.clone(),
                since: since.clone(),
                until: until.clone(),
                quiet: *quiet,
                offset,
            },
            &mut out,
        ),
        Command::Conf { directive } => {
            cmd::conf::conf(require_pacman_config(cli, &config)?, directive.as_deref(), &mut out)
        }
    };

    // A broken pipe is what `piko list | head` looks like. It is not a failure.
    if let Err(error) = out.flush()
        && error.kind() != io::ErrorKind::BrokenPipe
    {
        eprintln!("piko: error: failed to write output: {error}");
        return Ok(ExitCode::FAILURE);
    }

    Ok(code)
}

/// The arguments `piko install` and `piko update` pass to [`sync`].
///
/// The two subcommands differ in exactly four fields. `install` honors `--asdeps` and never
/// refreshes; `update` never records a dependency, always runs a sysupgrade pass, refreshes
/// by default, and can force that refresh. Every other flag matches in name, meaning, and
/// default. This struct
/// gathers them so [`sync`] keeps a readable signature, the same idiom
/// `cmd::txn::InstallOptions` and `cmd::txn::Catalog` use one layer down.
///
/// `cli.rs` keeps two separate sets of clap fields on purpose. The flags match, but the help
/// text does not: `install` documents each flag in full, and `update` restates it in one
/// line. That difference keeps `piko update --help` readable. That duplication is
/// documentation; this struct's duplication was not.
#[derive(Debug)]
struct SyncArgs<'a> {
    /// `--root`, already resolved to a `RootDir` fallback if omitted.
    root: &'a Path,
    /// The packages to install, or the extra targets to upgrade alongside everything else.
    targets: &'a [String],
    /// `--asdeps`. Always `false` for `update`, which has no such flag.
    as_deps: bool,
    /// `Some(downgrade)` runs `update`'s full-system upgrade pass. `None` is a plain install.
    sysupgrade: Option<bool>,
    /// Refresh repository databases before planning. Always `false` for `install`, which has
    /// no such flag. For `update`, `!--norefresh`.
    refresh: bool,
    /// `--force`. Always `false` for `install`, which has no such flag.
    force: bool,
    /// `--overwrite` glob patterns.
    overwrite: &'a [String],
    /// `--noscriptlet`. Inverted into `SideEffects::scriptlets` by [`sync`].
    noscriptlet: bool,
    /// `--hookdir`, replacing the configured list when non-empty.
    hookdir: &'a [PathBuf],
    /// `--noconfirm`.
    noconfirm: bool,
    /// `-w`/`--downloadonly`.
    download_only: bool,
    /// The UTC offset every timestamp is rendered in, captured in `main` — see
    /// [`piko_txn::LocalOffset`].
    offset: piko_txn::LocalOffset,
}

/// Runs `piko install` or `piko update`. It gathers everything either needs from the
/// configuration, then makes the one call that plans and commits.
///
/// `piko update` is `piko install` with a sysupgrade pass and no `--asdeps`. One function
/// serves both for that reason. The two dispatch arms were byte-identical over 55 lines apart
/// from those two fields. That match is the same tell that moved `Request::with_sysupgrade`
/// into a library crate: `piko plan -u` and `piko update` built that request byte-identically
/// at two call sites. Two call sites quietly agreeing on the same block belongs in a library
/// crate, not duplicated in the CLI.
///
/// Nothing here decides anything a second frontend would have to reimplement. The plan, the
/// verification policy, and the download set all belong to `piko_txn::plan` and
/// `cmd::txn::install`. This function only assembles CLI-shaped inputs, which is why it stays
/// in the binary.
///
/// `update`'s pre-refresh step lives here too, since it decides what `open_all_repos` below
/// reads rather than what `cmd::txn::install` does with it. Only this path installs the
/// `SIGINT` handler ahead of the confirmation prompt, threading the same `Cancel` into
/// `InstallOptions::pre_cancel` so the refresh and the transaction that follows share one
/// registration — `ctrlc::set_handler` refuses a second caller. See `crate::signal` for the
/// Ctrl+C trade-off this makes at the confirmation prompt.
fn sync(
    cli: &Cli,
    config: &ConfigCache,
    args: SyncArgs<'_>,
    out: &mut impl io::Write,
) -> Result<ExitCode, Error> {
    let parsed = require_pacman_config(cli, config)?;
    let local = open_local_db(cli, config)?;
    let dbpath = resolve_dbpath(cli, config);
    let record = recording(cli, config, &dbpath, args.offset);
    // pacman's frontend logs the same two lines, in the same order and at the same points
    // (`Running '…'` at startup, `starting full system upgrade` for `-u`).
    cmd::txn::note(&record, &format!("Running '{}'", record.command.as_deref().unwrap_or("piko")));
    if args.sysupgrade.is_some() {
        cmd::txn::note(&record, "starting full system upgrade");
    }
    let pre_cancel = if args.refresh {
        cmd::txn::note(&record, "synchronizing package lists");
        let (cancel, mode) = crate::signal::install_cancel_handler();
        let code = cmd::refresh::refresh(parsed, &dbpath, &[], args.force, &cancel);
        if code != ExitCode::SUCCESS {
            return Ok(code);
        }
        Some(crate::signal::Handoff { cancel, mode })
    } else {
        None
    };
    let opened = open_all_repos(cli, config)?;
    let ignores = IgnoreList::new(&parsed.options.ignore_pkg, &parsed.options.ignore_group);
    let signing = signing_policy(cli, config);
    Ok(cmd::txn::install(
        args.root,
        &dbpath,
        cache_dirs(config, cli),
        cmd::txn::Catalog { local: &local, repos: &opened, ignores, configs: &parsed.repositories },
        args.targets,
        cmd::txn::InstallOptions {
            as_deps: args.as_deps,
            overwrite: args.overwrite.to_vec(),
            gpg_dir: signing.gpg_dir,
            sig_level: signing.sig_level,
            local_file_sig_level: signing.local_file_sig_level,
            remote_file_sig_level: signing.remote_file_sig_level,
            architecture: parsed.options.architecture.clone(),
            side_effects: cmd::txn::SideEffects {
                scriptlets: !args.noscriptlet,
                hook_dirs: hook_dirs(cli, config, args.hookdir, args.root),
                recording: record.clone(),
            },
            patterns: path_patterns(cli, config),
            noconfirm: args.noconfirm,
            sysupgrade: args.sysupgrade,
            download_only: args.download_only,
            parallel_downloads: parsed.options.parallel_downloads,
            pre_cancel,
        },
        out,
    ))
}
