//! The `conf` subcommand: dumping a parsed `pacman.conf`, mirroring `pacman-conf`.

use std::process::ExitCode;

use piko_db::config::PacmanConfig;

use crate::output::{clean_method_lines, emit, sig_level_lines, usage_lines};

pub fn conf_dump(config: &PacmanConfig, out: &mut impl std::io::Write) -> ExitCode {
    let options = &config.options;

    emit!(out, "[options]");
    emit!(out, "RootDir = {}", options.root_dir.display());
    emit!(out, "DBPath = {}", options.db_path.display());
    for dir in &options.cache_dirs {
        emit!(out, "CacheDir = {}", dir.display());
    }
    for dir in &options.hook_dirs {
        emit!(out, "HookDir = {}", dir.display());
    }
    emit!(out, "GPGDir = {}", options.gpg_dir.display());
    emit!(out, "LogFile = {}", options.log_file.display());
    for pkg in &options.hold_pkg {
        emit!(out, "HoldPkg = {pkg}");
    }
    for pkg in &options.ignore_pkg {
        emit!(out, "IgnorePkg = {pkg}");
    }
    for group in &options.ignore_group {
        emit!(out, "IgnoreGroup = {group}");
    }
    for pattern in &options.no_upgrade {
        emit!(out, "NoUpgrade = {pattern}");
    }
    for pattern in &options.no_extract {
        emit!(out, "NoExtract = {pattern}");
    }
    for arch in &options.architecture {
        emit!(out, "Architecture = {arch}");
    }
    if options.color {
        emit!(out, "Color");
    }
    if options.check_space {
        emit!(out, "CheckSpace");
    }
    if options.disable_download_timeout {
        emit!(out, "DisableDownloadTimeout");
    }
    if options.no_progress_bar {
        emit!(out, "NoProgressBar");
    }
    emit!(out, "ParallelDownloads = {}", options.parallel_downloads);
    for line in clean_method_lines(options.clean_method) {
        emit!(out, "CleanMethod = {line}");
    }
    for line in sig_level_lines(options.sig_level, false) {
        emit!(out, "SigLevel = {line}");
    }
    for line in sig_level_lines(options.local_file_sig_level, true) {
        emit!(out, "LocalFileSigLevel = {line}");
    }
    for line in sig_level_lines(options.remote_file_sig_level, true) {
        emit!(out, "RemoteFileSigLevel = {line}");
    }

    for repo in &config.repositories {
        emit!(out, "[{}]", repo.name);
        for line in usage_lines(repo.usage) {
            emit!(out, "Usage = {line}");
        }
        for line in sig_level_lines(repo.sig_level, false) {
            emit!(out, "SigLevel = {line}");
        }
        for server in &repo.cache_servers {
            emit!(out, "CacheServer = {server}");
        }
        for server in &repo.servers {
            emit!(out, "Server = {server}");
        }
    }

    ExitCode::SUCCESS
}
