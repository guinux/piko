//! The `conf` subcommand: dumping a parsed `pacman.conf`, mirroring `pacman-conf`.

use std::process::ExitCode;

use piko_db::config::{Options, PacmanConfig};

use crate::output::{clean_method_lines, emit, sig_level_lines, usage_lines};

/// One `[options]` line: a directive name, and the value that line carries.
///
/// A flag directive carries no value. A dump prints it as its own name. A single-directive
/// query prints it as its own name too, which is what `pacman-conf CheckSpace` prints.
type OptionLine = (&'static str, Option<String>);

/// Every `[options]` directive name a query accepts.
///
/// This is deliberately wider than what [`option_lines`] can produce. A directive absent
/// from the file, or set to nothing, still has to be a name the query knows. Otherwise
/// `piko conf IgnorePkg` reports an unknown directive on a system that simply ignores no
/// package.
///
/// The last four names are the downloading and logging directives piko parses but never acts
/// on. It holds no field for them, and never prints them. A query for one of them succeeds and
/// prints nothing, matching the dump and `pacman-conf`.
///
/// `DisableSandbox` is a name a query accepts but no line carries: see [`answers`].
const KNOWN_DIRECTIVES: &[&str] = &[
    "RootDir",
    "DBPath",
    "CacheDir",
    "HookDir",
    "GPGDir",
    "LogFile",
    "HoldPkg",
    "IgnorePkg",
    "IgnoreGroup",
    "NoUpgrade",
    "NoExtract",
    "Architecture",
    "Color",
    "CheckSpace",
    "DisableDownloadTimeout",
    "NoProgressBar",
    "ParallelDownloads",
    "CleanMethod",
    "SigLevel",
    "LocalFileSigLevel",
    "RemoteFileSigLevel",
    "DownloadUser",
    "DisableSandbox",
    "DisableSandboxFilesystem",
    "DisableSandboxSyscalls",
    "XferCommand",
    "UseSyslog",
    "VerbosePkgLists",
    "ILoveCandy",
];

/// Whether a line printed under `name` answers a query for `known`.
///
/// `DisableSandbox` sets two directives, and `pacman-conf DisableSandbox` prints whichever of
/// the two is set. Every other name answers only for itself.
fn answers(known: &str, name: &str) -> bool {
    name == known
        || (known == "DisableSandbox"
            && matches!(name, "DisableSandboxFilesystem" | "DisableSandboxSyscalls"))
}

/// Every `[options]` line, in the order `pacman-conf` prints them.
///
/// The dump and the single-directive query both read this list. So a directive cannot print
/// one value under `piko conf` and another under `piko conf <directive>`.
fn option_lines(options: &Options) -> Vec<OptionLine> {
    let mut lines: Vec<OptionLine> = Vec::new();
    let mut valued = |name: &'static str, value: String| lines.push((name, Some(value)));

    valued("RootDir", options.root_dir.display().to_string());
    valued("DBPath", options.db_path.display().to_string());
    for dir in &options.cache_dirs {
        valued("CacheDir", dir.display().to_string());
    }
    for dir in &options.hook_dirs {
        valued("HookDir", dir.display().to_string());
    }
    valued("GPGDir", options.gpg_dir.display().to_string());
    valued("LogFile", options.log_file.display().to_string());
    if let Some(user) = &options.download_user {
        valued("DownloadUser", user.clone());
    }
    for pkg in &options.hold_pkg {
        valued("HoldPkg", pkg.clone());
    }
    for pkg in &options.ignore_pkg {
        valued("IgnorePkg", pkg.clone());
    }
    for group in &options.ignore_group {
        valued("IgnoreGroup", group.clone());
    }
    for pattern in &options.no_upgrade {
        valued("NoUpgrade", pattern.clone());
    }
    for pattern in &options.no_extract {
        valued("NoExtract", pattern.clone());
    }
    for arch in &options.architecture {
        valued("Architecture", arch.to_string());
    }
    if options.color {
        lines.push(("Color", None));
    }
    if options.check_space {
        lines.push(("CheckSpace", None));
    }
    if options.disable_download_timeout {
        lines.push(("DisableDownloadTimeout", None));
    }
    if options.no_progress_bar {
        lines.push(("NoProgressBar", None));
    }
    if options.disable_sandbox_filesystem {
        lines.push(("DisableSandboxFilesystem", None));
    }
    if options.disable_sandbox_syscalls {
        lines.push(("DisableSandboxSyscalls", None));
    }
    lines.push(("ParallelDownloads", Some(options.parallel_downloads.to_string())));
    for line in clean_method_lines(options.clean_method) {
        lines.push(("CleanMethod", Some(line.to_owned())));
    }
    for line in sig_level_lines(options.sig_level, false) {
        lines.push(("SigLevel", Some(line.to_owned())));
    }
    for line in sig_level_lines(options.local_file_sig_level, true) {
        lines.push(("LocalFileSigLevel", Some(line.to_owned())));
    }
    for line in sig_level_lines(options.remote_file_sig_level, true) {
        lines.push(("RemoteFileSigLevel", Some(line.to_owned())));
    }

    lines
}

/// Prints the whole parsed config, or one directive of it.
pub fn conf(
    config: &PacmanConfig,
    directive: Option<&str>,
    out: &mut impl std::io::Write,
) -> ExitCode {
    match directive {
        Some(directive) => conf_directive(config, directive, out),
        None => conf_dump(config, out),
    }
}

/// Prints one `[options]` directive's value, one value per line.
fn conf_directive(
    config: &PacmanConfig,
    directive: &str,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let Some(known) = KNOWN_DIRECTIVES.iter().find(|name| name.eq_ignore_ascii_case(directive))
    else {
        crate::i18n::print_error!("conf-unknown-directive", directive = directive);
        return ExitCode::FAILURE;
    };

    for (name, value) in option_lines(&config.options) {
        if !answers(known, name) {
            continue;
        }
        match value {
            Some(value) => emit!(out, "{value}"),
            None => emit!(out, "{name}"),
        }
    }

    ExitCode::SUCCESS
}

/// Prints `[options]`, then one `[reponame]` block per configured repository.
fn conf_dump(config: &PacmanConfig, out: &mut impl std::io::Write) -> ExitCode {
    emit!(out, "[options]");
    for (name, value) in option_lines(&config.options) {
        match value {
            Some(value) => emit!(out, "{name} = {value}"),
            None => emit!(out, "{name}"),
        }
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use std::path::Path;

    use super::*;

    /// Writes `text` as a `pacman.conf` under `dir`, and parses it.
    fn parse(dir: &Path, text: &str) -> PacmanConfig {
        let path = dir.join("pacman.conf");
        std::fs::write(&path, text).unwrap();
        PacmanConfig::open(&path).unwrap()
    }

    /// Runs `piko conf [directive]` and returns its exit code and its output.
    fn run(config: &PacmanConfig, directive: Option<&str>) -> (ExitCode, String) {
        let mut out = Vec::new();
        let code = conf(config, directive, &mut out);
        (code, String::from_utf8(out).unwrap())
    }

    /// A name [`option_lines`] can print but a query rejects would make
    /// `piko conf <directive>` unable to read part of its own dump.
    #[test]
    fn every_printed_directive_is_a_name_a_query_accepts() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(dir.path(), "[options]\nColor\nCheckSpace\nNoProgressBar\n");

        for (name, _) in option_lines(&config.options) {
            assert!(KNOWN_DIRECTIVES.contains(&name), "{name} is printed but not queryable");
        }
    }

    #[test]
    fn a_directive_prints_its_value_without_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(dir.path(), "[options]\nCacheDir = /custom/cache/\n");

        let (code, out) = run(&config, Some("CacheDir"));

        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(out, "/custom/cache/\n");
    }

    #[test]
    fn a_repeatable_directive_prints_one_value_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(dir.path(), "[options]\nCacheDir = /a/ /b/\nCacheDir = /c/\n");

        let (_, out) = run(&config, Some("CacheDir"));

        assert_eq!(out, "/a/\n/b/\n/c/\n");
    }

    /// `pacman-conf CheckSpace` prints `CheckSpace`, not an empty line.
    #[test]
    fn a_set_flag_directive_prints_its_own_name() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(dir.path(), "[options]\nCheckSpace\n");

        let (code, out) = run(&config, Some("CheckSpace"));

        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(out, "CheckSpace\n");
    }

    #[test]
    fn an_unset_directive_prints_nothing_and_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(dir.path(), "[options]\n");

        for directive in ["Color", "IgnorePkg"] {
            let (code, out) = run(&config, Some(directive));
            assert_eq!(code, ExitCode::SUCCESS, "{directive}");
            assert_eq!(out, "", "{directive}");
        }
    }

    /// The four dropped directives are names a query accepts. So a script asking for one
    /// gets the same answer the dump gives, which is nothing.
    #[test]
    fn a_dropped_directive_prints_nothing_and_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(dir.path(), "[options]\nXferCommand = /bin/false %u\nUseSyslog\n");

        for directive in ["XferCommand", "UseSyslog"] {
            let (code, out) = run(&config, Some(directive));
            assert_eq!(code, ExitCode::SUCCESS, "{directive}");
            assert_eq!(out, "", "{directive}");
        }
    }

    /// Measured against `pacman-conf` 7.1.0, including the line order.
    #[test]
    fn the_sandbox_directives_are_printed_where_pacman_conf_prints_them() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(
            dir.path(),
            "[options]\nHoldPkg = a\nDownloadUser = alpm\nNoProgressBar\nDisableSandbox\n",
        );

        let (_, out) = run(&config, None);

        assert!(
            out.contains("\nLogFile = /var/log/pacman.log\nDownloadUser = alpm\nHoldPkg = a\n")
        );
        assert!(out.contains(
            "\nNoProgressBar\nDisableSandboxFilesystem\nDisableSandboxSyscalls\nParallelDownloads"
        ));
        assert_eq!(run(&config, Some("DownloadUser")).1, "alpm\n");
    }

    /// `pacman-conf DisableSandbox` prints whichever half is set.
    #[test]
    fn a_disable_sandbox_query_prints_each_half_that_is_set() {
        let dir = tempfile::tempdir().unwrap();
        let both = parse(dir.path(), "[options]\nDisableSandbox\n");
        let one = parse(dir.path(), "[options]\nDisableSandboxSyscalls\n");
        let none = parse(dir.path(), "[options]\n");

        assert_eq!(
            run(&both, Some("DisableSandbox")).1,
            "DisableSandboxFilesystem\nDisableSandboxSyscalls\n"
        );
        assert_eq!(run(&one, Some("disablesandbox")).1, "DisableSandboxSyscalls\n");
        assert_eq!(run(&none, Some("DisableSandbox")), (ExitCode::SUCCESS, String::new()));
    }

    /// `pacman-conf DisableSandboxFilesystem` reports an unknown directive, which is a defect
    /// in its lookup table: the dump prints that name. piko answers the query.
    #[test]
    fn a_disable_sandbox_filesystem_query_is_answered() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(dir.path(), "[options]\nDisableSandboxFilesystem\n");

        let (code, out) = run(&config, Some("DisableSandboxFilesystem"));

        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(out, "DisableSandboxFilesystem\n");
    }

    /// `pacman-conf dbpath` answers the same as `pacman-conf DBPath`, measured.
    #[test]
    fn a_directive_name_is_matched_without_regard_to_case() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(dir.path(), "[options]\nCacheDir = /custom/cache/\n");

        assert_eq!(run(&config, Some("cachedir")).1, "/custom/cache/\n");
        assert_eq!(run(&config, Some("CACHEDIR")).1, "/custom/cache/\n");
    }

    #[test]
    fn an_unknown_directive_fails() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(dir.path(), "[options]\n");

        assert_eq!(run(&config, Some("Nonsense")).0, ExitCode::FAILURE);
    }

    /// Only the `[options]` section is queried, so a repository directive is not a name a
    /// query accepts. `pacman-conf Server` rejects it the same way, measured.
    #[test]
    fn a_repository_directive_is_not_a_queryable_name() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(dir.path(), "[options]\n");

        for directive in ["Server", "Usage", "CacheServer"] {
            assert_eq!(run(&config, Some(directive)).0, ExitCode::FAILURE, "{directive}");
        }
    }

    #[test]
    fn no_directive_dumps_the_options_and_every_repository() {
        let dir = tempfile::tempdir().unwrap();
        let config =
            parse(dir.path(), "[options]\n[core]\nServer = https://example.invalid/core\n");

        let (code, out) = run(&config, None);

        assert_eq!(code, ExitCode::SUCCESS);
        assert!(out.starts_with("[options]\n"), "{out}");
        assert!(out.contains("\nDBPath = "), "{out}");
        assert!(out.contains("\n[core]\n"), "{out}");
        assert!(out.contains("\nServer = https://example.invalid/core\n"), "{out}");
    }
}
