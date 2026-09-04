//! Scriptlets and hooks, run for real through the `piko` binary.
//!
//! ```text
//! cargo test -p piko --test side_effects
//! ```
//!
//! # Why these live here and not in `piko-txn`
//!
//! [`piko_txn::exec::Runner`] starts commands by re-executing piko itself. That is how it
//! enters a chroot without `unsafe`. A unit test inside `piko-txn` has no piko binary:
//! `current_exe()` is the test harness, and handing libtest `__exec-in-root /root /bin/sh …`
//! makes it treat those as name filters, run nothing, and exit zero. A scriptlet would then be
//! reported as having succeeded without ever running, which is worse than no test at all.
//!
//! So the execution tests run the real binary, from the one crate that has one.
//!
//! Everything writes into a `tempfile::TempDir`. Nothing here touches the real system.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    path::Path,
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

const PIKO: &str = env!("CARGO_BIN_EXE_piko");

/// A `.PKGINFO` for `name` at `version`.
fn pkginfo(name: &str, version: &str) -> String {
    format!(
        "pkgname = {name}\npkgbase = {name}\npkgver = {version}\npkgdesc = x\n\
         url = https://example.org/\nbuilddate = 1733737242\n\
         packager = A <a@b.c>\nsize = 4\narch = x86_64\nlicense = MIT\n"
    )
}

/// Writes a `foo` package carrying `script` as its `.INSTALL`.
fn write_package(cache: &Path, version: &str, script: Option<&str>) {
    write_package_with(cache, "foo", version, script, &[]);
}

/// As [`write_package`], shipping `extra` payload paths on top of the usual `usr/bin/<name>`,
/// for a package named `name` rather than always `foo`.
///
/// Each `extra` entry is a `(path, contents)` pair. Contents matter only for a file the
/// transaction reads back, such as a `.hook` the package installs. Otherwise they are ignored.
fn write_package_with(
    cache: &Path,
    name: &str,
    version: &str,
    script: Option<&str>,
    extra: &[(&str, &str)],
) {
    std::fs::write(
        cache.join(format!("{name}-{version}-x86_64.pkg.tar")),
        package_tar(name, version, script, extra),
    )
    .unwrap();
}

/// Builds the bytes of a `foo`-shaped package archive, without writing it anywhere. Shared by
/// [`write_package_with`] (which puts it straight in the cache) and a download test (which
/// serves the same bytes over HTTP instead).
fn package_tar(name: &str, version: &str, script: Option<&str>, extra: &[(&str, &str)]) -> Vec<u8> {
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

    add(".PKGINFO", pkginfo(name, version).as_bytes(), false);
    if let Some(script) = script {
        add(".INSTALL", script.as_bytes(), false);
    }
    add("usr/", &[][..], true);
    add("usr/bin/", &[][..], true);
    add(&format!("usr/bin/{name}"), version.as_bytes(), false);

    // A real package lists every parent directory it owns exactly once, and `alpm-db` will
    // not re-read a `%FILES%` section that repeats one.
    let mut listed: std::collections::BTreeSet<String> =
        ["usr/".to_owned(), "usr/bin/".to_owned()].into_iter().collect();
    for (path, contents) in extra {
        let mut prefix = String::new();
        let parts: Vec<&str> = path.split('/').collect();
        for part in parts.iter().take(parts.len().saturating_sub(1)) {
            prefix.push_str(part);
            prefix.push('/');
            if listed.insert(prefix.clone()) {
                add(&prefix, &[][..], true);
            }
        }
        add(path, contents.as_bytes(), false);
    }

    builder.into_inner().unwrap()
}

/// A minimal, valid repository `desc` for `name` at `version`, naming exactly the file
/// [`write_package_with`] writes (no compression suffix) so `CacheDirSource` finds it.
fn repo_desc(name: &str, version: &str, depends: &[&str]) -> String {
    let mut desc = format!(
        "%FILENAME%\n{name}-{version}-x86_64.pkg.tar\n\n\
         %NAME%\n{name}\n\n\
         %BASE%\n{name}\n\n\
         %VERSION%\n{version}\n\n\
         %DESC%\nAn example package\n\n\
         %CSIZE%\n4\n\n\
         %ISIZE%\n4\n\n\
         %SHA256SUM%\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n\
         %URL%\nhttps://example.org/\n\n\
         %ARCH%\nx86_64\n\n\
         %BUILDDATE%\n1733737242\n\n\
         %PACKAGER%\nFoobar McFooface <foobar@mcfooface.org>\n\n"
    );
    if !depends.is_empty() {
        desc.push_str("%DEPENDS%\n");
        for dep in depends {
            desc.push_str(dep);
            desc.push('\n');
        }
        desc.push('\n');
    }
    desc
}

/// One repository entry with relations beyond `%DEPENDS%`: name, version, depends, replaces,
/// conflicts.
type RepoEntryWithRelations<'a> = (&'a str, &'a str, &'a [&'a str], &'a [&'a str], &'a [&'a str]);

/// As [`repo_desc`], also declaring `%REPLACES%`/`%CONFLICTS%`. The `update` tests need this to
/// prove those fields drive a real removal. Kept separate so every other call site's plain
/// 3-tuple through [`Sandbox::write_repo`] stays as it is.
fn repo_desc_with_relations(
    name: &str,
    version: &str,
    depends: &[&str],
    replaces: &[&str],
    conflicts: &[&str],
) -> String {
    let mut desc = repo_desc(name, version, depends);
    for (key, values) in [("REPLACES", replaces), ("CONFLICTS", conflicts)] {
        if values.is_empty() {
            continue;
        }
        desc.push_str(&format!("%{key}%\n"));
        for value in values {
            desc.push_str(value);
            desc.push('\n');
        }
        desc.push('\n');
    }
    desc
}

/// A throwaway root, database and cache, with a `pacman.conf` pointing at the cache.
struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self::build(None)
    }

    /// As [`Sandbox::new`], but the `[test]` repository also carries a `Server` directive, so a
    /// download test has somewhere to download from.
    fn with_server(url: &str) -> Self {
        Self::build(Some(url))
    }

    fn build(server: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["cache", "root", "db/local", "db/sync", "hooks"] {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
        }
        std::fs::write(dir.path().join("db/local/ALPM_DB_VERSION"), "9\n").unwrap();
        let server_line = server.map(|url| format!("Server = {url}\n")).unwrap_or_default();
        std::fs::write(
            dir.path().join("pacman.conf"),
            format!(
                "[options]\nCacheDir = {}/\nLogFile = {}\nSigLevel = Never\n\n[test]\n\
                 SigLevel = Never\n{server_line}",
                dir.path().join("cache").display(),
                dir.path().join("pacman.log").display()
            ),
        )
        .unwrap();
        Self { dir }
    }

    fn path(&self, sub: &str) -> std::path::PathBuf {
        self.dir.path().join(sub)
    }

    /// Adds a `ParallelDownloads` line to `[options]`.
    fn set_parallel_downloads(&self, count: u32) {
        let path = self.path("pacman.conf");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            text.replace("[options]\n", &format!("[options]\nParallelDownloads = {count}\n")),
        )
        .unwrap();
    }

    /// The transaction log this sandbox's `pacman.conf` names, or an empty string if nothing
    /// wrote one.
    fn log(&self) -> String {
        std::fs::read_to_string(self.path("pacman.log")).unwrap_or_default()
    }

    /// The history store beside this sandbox's database, or an empty string.
    fn history(&self) -> String {
        std::fs::read_to_string(self.path("db/piko-history")).unwrap_or_default()
    }

    fn write_hook(&self, name: &str, body: &str) {
        std::fs::write(self.path("hooks").join(name), body).unwrap();
    }

    /// Rewrites both `SigLevel` directives to `Required DatabaseOptional`, with a `GPGDir` of
    /// its own.
    ///
    /// The keyring is a throwaway empty directory. That is all an unsigned package needs to be
    /// refused: `Policy::for_package` asks for a check, no `.sig` is beside the file, and
    /// `piko_sig::decide` resolves zero signatures under `Required` as a rejection without ever
    /// consulting a key. A test that needs a valid signature has to generate a key instead, as
    /// `piko-db`'s `signed_database.rs` does.
    fn require_signatures(&self) {
        std::fs::create_dir_all(self.path("gnupg")).unwrap();
        let conf = std::fs::read_to_string(self.path("pacman.conf")).unwrap();
        // `DatabaseOptional`, not a bare `Required`. The fixture repository database is
        // unsigned too, and a `Required` database is refused at open. The run would then fail
        // for want of a repository, never reaching the package this test is about.
        let patched =
            conf.replace("SigLevel = Never", "SigLevel = Required DatabaseOptional").replace(
                "[options]\n",
                &format!("[options]\nGPGDir = {}/\n", self.path("gnupg").display()),
            );
        assert_ne!(patched, conf, "the pacman.conf layout moved; fix this helper");
        std::fs::write(self.path("pacman.conf"), patched).unwrap();
    }

    /// Adds a `HoldPkg` directive to `[options]`, as `/etc/pacman.conf` ships with.
    ///
    /// Rewritten rather than appended: `[options]` is the first section in the file
    /// [`Sandbox::build`] writes, and a line appended to the end would land inside `[test]`,
    /// where `HoldPkg` is not a valid directive.
    fn set_hold_pkg(&self, names: &str) {
        let conf = std::fs::read_to_string(self.path("pacman.conf")).unwrap();
        let patched = conf.replace("[options]\n", &format!("[options]\nHoldPkg = {names}\n"));
        assert_ne!(patched, conf, "the [options] section moved; fix this helper");
        std::fs::write(self.path("pacman.conf"), patched).unwrap();
    }

    /// Runs `piko remove` for `targets`, answering the prompts with `answer`. `None` sends no
    /// answer at all: a closed stdin, which is what an unattended run has.
    ///
    /// `--hookdir` points at the sandbox's own empty directory so a removal that goes through
    /// does not run this machine's real `/usr/share/libalpm/hooks`.
    fn run_remove(&self, targets: &[&str], extra: &[&str], answer: Option<&str>) -> Output {
        let mut command = Command::new(PIKO);
        command
            .arg("remove")
            .arg("--config")
            .arg(self.path("pacman.conf"))
            .arg("--root")
            .arg(self.path("root"))
            .arg("--dbpath")
            .arg(self.path("db"))
            .arg("--hookdir")
            .arg(self.path("hooks"))
            .args(extra)
            .args(targets)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let Some(answer) = answer else {
            return command.stdin(Stdio::null()).output().unwrap();
        };
        let mut child = command.stdin(Stdio::piped()).spawn().unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), answer.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    }

    /// Writes `<dbpath>/sync/test.db` with one `desc` per `(name, version, depends)` triple.
    /// `piko install <name>` resolves against this, through the `[test]` repository configured
    /// in `pacman.conf`.
    fn write_repo(&self, packages: &[(&str, &str, &[&str])]) {
        let bodies: Vec<(String, Vec<u8>)> = packages
            .iter()
            .map(|(name, version, depends)| {
                (format!("{name}-{version}/desc"), repo_desc(name, version, depends).into_bytes())
            })
            .collect();
        let entries: Vec<(&str, &[u8])> =
            bodies.iter().map(|(path, body)| (path.as_str(), body.as_slice())).collect();
        std::fs::write(self.path("db/sync/test.db"), piko_db::fixture::gzip_tar(&entries)).unwrap();
    }

    /// As [`Sandbox::write_repo`], for entries that also declare `%REPLACES%`/`%CONFLICTS%`.
    fn write_repo_with_relations(&self, packages: &[RepoEntryWithRelations<'_>]) {
        let bodies: Vec<(String, Vec<u8>)> = packages
            .iter()
            .map(|(name, version, depends, replaces, conflicts)| {
                (
                    format!("{name}-{version}/desc"),
                    repo_desc_with_relations(name, version, depends, replaces, conflicts)
                        .into_bytes(),
                )
            })
            .collect();
        let entries: Vec<(&str, &[u8])> =
            bodies.iter().map(|(path, body)| (path.as_str(), body.as_slice())).collect();
        std::fs::write(self.path("db/sync/test.db"), piko_db::fixture::gzip_tar(&entries)).unwrap();
    }

    /// Runs `piko install` for `targets`, with the given extra arguments.
    fn run_install(&self, targets: &[&str], extra: &[&str]) -> Output {
        let mut command = Command::new(PIKO);
        command
            .arg("install")
            .arg("--config")
            .arg(self.path("pacman.conf"))
            .arg("--root")
            .arg(self.path("root"))
            .arg("--dbpath")
            .arg(self.path("db"))
            .arg("--hookdir")
            .arg(self.path("hooks"))
            // `install` asks for confirmation before committing. Every test here checks the
            // transaction's outcome, not the prompt, so it opts out. A child inheriting the
            // test harness's own stdin would otherwise hang waiting for an answer nobody is
            // there to give.
            .arg("--noconfirm")
            .stdin(Stdio::null())
            .args(extra)
            .args(targets);
        command.output().unwrap()
    }

    /// Runs `piko update` for `targets`, with the given extra arguments. As [`Self::run_install`],
    /// non-interactive by default.
    ///
    /// `update` now refreshes every configured repository before planning, unless
    /// `--norefresh` is in `extra`. A sandbox built with [`Self::new`] (no `Server`) has
    /// nowhere to refresh from, so any test exercising solve/apply logic against a
    /// hand-written [`Self::write_repo`] fixture must pass `--norefresh`.
    fn run_update(&self, targets: &[&str], extra: &[&str]) -> Output {
        let mut command = Command::new(PIKO);
        command
            .arg("update")
            .arg("--config")
            .arg(self.path("pacman.conf"))
            .arg("--root")
            .arg(self.path("root"))
            .arg("--dbpath")
            .arg(self.path("db"))
            .arg("--hookdir")
            .arg(self.path("hooks"))
            .arg("--noconfirm")
            .stdin(Stdio::null())
            .args(extra)
            .args(targets);
        command.output().unwrap()
    }

    /// Runs `piko install foo`, registering `foo` at `version` in the `test` repository first.
    /// The convenience every existing test in this file uses.
    fn install(&self, version: &str, extra: &[&str]) -> Output {
        self.write_repo(&[("foo", version, &[])]);
        self.run_install(&["foo"], extra)
    }
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

const SCRIPT: &str = "\
post_install() {
  echo \"POST_INSTALL $1\"
}
post_upgrade() {
  echo \"POST_UPGRADE $1 $2\"
}
pre_remove() {
  echo \"PRE_REMOVE $1\"
}
";

/// The root is a temporary directory and the tests are unprivileged, so `chroot` is refused.
///
/// That is not a gap in coverage. It is the security property, asserted directly: the command
/// must fail closed, never fall back to running on the host. Everything below therefore checks
/// that piko reached the point of trying, and reported honestly when it could not, rather than
/// checking a scriptlet's side effects.
///
/// The chroot path itself is exercised by `chrooted_scriptlets_and_hooks_really_run`, which
/// needs an unprivileged user namespace and is `#[ignore]`d.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn a_scriptlet_that_cannot_enter_the_root_fails_closed() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", Some(SCRIPT));

    let output = sandbox.install("1.0.0-1", &[]);
    let seen = text(&output);

    assert!(output.status.success(), "the install itself should still succeed:\n{seen}");
    assert!(
        seen.contains("could not enter the root"),
        "the scriptlet did not report why it could not run:\n{seen}"
    );
    assert!(
        !seen.contains("POST_INSTALL"),
        "the scriptlet ran outside the chroot, on the host:\n{seen}"
    );
    // libalpm discards a scriptlet's exit status at every call site, and so does piko: the
    // package is installed either way.
    assert!(sandbox.path("root/usr/bin/foo").exists());
}

/// `--noscriptlet` must mean nothing is attempted at all: no staging, no shell, no message.
#[test]
fn noscriptlet_does_not_even_try() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", Some(SCRIPT));

    let seen = text(&sandbox.install("1.0.0-1", &["--noscriptlet"]));

    assert!(!seen.contains("could not enter the root"), "a scriptlet was still attempted:\n{seen}");
    assert!(!seen.contains("POST_INSTALL"), "{seen}");
    assert!(!sandbox.path("root/tmp").exists(), "a staging directory was created anyway");
}

/// A package with no `.INSTALL` must not attempt anything either.
#[test]
fn a_package_without_a_scriptlet_runs_nothing() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);

    let seen = text(&sandbox.install("1.0.0-1", &[]));
    assert!(!seen.contains("could not enter the root"), "{seen}");
    assert!(!sandbox.path("root/tmp").exists(), "a staging directory was created anyway");
}

/// A `PreTransaction` hook with `AbortOnFail` must stop the transaction with nothing written.
///
/// It fails here because the chroot is refused, which is a perfectly good failure for the
/// purpose: what is under test is that the *transaction* stops and leaves no trace.
#[test]
fn abort_on_fail_stops_the_transaction_before_anything_changes() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    sandbox.write_hook(
        "10-abort.hook",
        "[Trigger]\nOperation = Install\nType = Package\nTarget = foo\n\n\
         [Action]\nWhen = PreTransaction\nExec = /bin/false\nAbortOnFail\n",
    );

    let output = sandbox.install("1.0.0-1", &[]);
    let seen = text(&output);

    assert!(!output.status.success(), "the transaction should have been refused:\n{seen}");
    assert!(seen.contains("AbortOnFail"), "{seen}");
    assert!(!sandbox.path("root/usr/bin/foo").exists(), "files were written anyway");
    assert!(
        sandbox.path("db/local/foo-1.0.0-1").symlink_metadata().is_err(),
        "an entry was written"
    );
    // Nothing was applied, so nothing should look interrupted.
    assert!(!sandbox.path("db/piko-journal").exists(), "a journal was left behind");
}

/// Without `AbortOnFail`, the same failing hook must not stop anything.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn a_failing_hook_without_abort_on_fail_is_only_a_warning() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    sandbox.write_hook(
        "10-noisy.hook",
        "[Trigger]\nOperation = Install\nType = Package\nTarget = foo\n\n\
         [Action]\nWhen = PreTransaction\nExec = /bin/false\n",
    );

    let output = sandbox.install("1.0.0-1", &[]);
    let seen = text(&output);

    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("10-noisy.hook"), "the failure was not reported at all:\n{seen}");
    assert!(sandbox.path("root/usr/bin/foo").exists());
}

/// A hook whose `Depends` nothing satisfies is skipped, and says so.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn an_unsatisfied_hook_dependency_skips_the_hook() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    sandbox.write_hook(
        "10-needs.hook",
        "[Trigger]\nOperation = Install\nType = Package\nTarget = foo\n\n\
         [Action]\nWhen = PostTransaction\nDepends = definitely-not-installed\n\
         Exec = /bin/false\nAbortOnFail\n",
    );

    let output = sandbox.install("1.0.0-1", &[]);
    let seen = text(&output);

    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("nothing installed satisfies definitely-not-installed"), "{seen}");
}

/// A hook whose trigger does not match must not run at all.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn a_hook_for_another_package_does_not_run() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    sandbox.write_hook(
        "10-other.hook",
        "[Trigger]\nOperation = Install\nType = Package\nTarget = something-else\n\n\
         [Action]\nDescription = Should not appear\nWhen = PostTransaction\n\
         Exec = /bin/false\nAbortOnFail\n",
    );

    let output = sandbox.install("1.0.0-1", &[]);
    let seen = text(&output);

    assert!(output.status.success(), "{seen}");
    assert!(!seen.contains("Should not appear"), "an unmatched hook ran:\n{seen}");
}

/// An unparseable hook file is reported and does not stop the transaction.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn a_broken_hook_file_is_reported_and_skipped() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    sandbox.write_hook("10-broken.hook", "[Nonsense]\nWhat = ever\n");

    let output = sandbox.install("1.0.0-1", &[]);
    let seen = text(&output);

    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("10-broken.hook"), "{seen}");
    assert!(sandbox.path("root/usr/bin/foo").exists());
}

/// A hook file the transaction itself deletes must not run afterwards.
///
/// This is the whole reason a removal on Arch does not call binaries it just deleted. Arch ships
/// each hook in the same package as the program it runs. 31 of this machine's 46 hooks name an
/// `Exec` their own package owns, and only 8 declare a `Depends`, so `Depends` is not what
/// protects them. libalpm reads the hook directories inside `_alpm_hook_run` (`hook.c:536`),
/// called once before the transaction and once after (`trans.c:202`, `trans.c:238`). So the
/// `PostTransaction` pass simply never finds the file.
///
/// The two halves are asserted together on purpose. Without the `PreTransaction` hook running,
/// the absence of the `PostTransaction` one would prove nothing: a trigger that never matched
/// looks exactly the same.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn a_hook_the_removal_deletes_does_not_run_afterwards() {
    let sandbox = Sandbox::new();
    let hook = |when: &str| {
        format!(
            "[Trigger]\nOperation = Remove\nType = Package\nTarget = foo\n\n\
             [Action]\nWhen = {when}\nExec = /bin/true\n"
        )
    };
    let pre = hook("PreTransaction");
    let post = hook("PostTransaction");
    write_package_with(
        &sandbox.path("cache"),
        "foo",
        "1.0.0-1",
        None,
        &[("hooks/10-pre.hook", pre.as_str()), ("hooks/20-post.hook", post.as_str())],
    );
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);

    // The hook directory is inside the root here, matching the real layout: with pacman's own
    // root of `/`, `/usr/share/libalpm/hooks` is both a host path and a path packages write to.
    let hookdir = sandbox.path("root/hooks");
    let piko = |subcommand: &str| {
        let mut command = Command::new(PIKO);
        command
            .arg(subcommand)
            .arg("--config")
            .arg(sandbox.path("pacman.conf"))
            .arg("--root")
            .arg(sandbox.path("root"))
            .arg("--dbpath")
            .arg(sandbox.path("db"))
            .arg("--hookdir")
            .arg(&hookdir)
            .arg("--noconfirm")
            .stdin(Stdio::null());
        command.arg("foo");
        command.output().unwrap()
    };

    let installed = piko("install");
    assert!(installed.status.success(), "{}", text(&installed));
    assert!(hookdir.join("20-post.hook").exists(), "the fixture shipped no hook");

    let output = piko("remove");
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");

    // Both hooks fail, because the chroot is refused unprivileged, so each one that runs names
    // itself in a warning. That is the signal both assertions read.
    assert!(
        seen.contains("10-pre.hook"),
        "the PreTransaction hook did not run, so the trigger proves nothing:\n{seen}"
    );
    assert!(
        !seen.contains("20-post.hook"),
        "a hook whose file the removal deleted ran anyway:\n{seen}"
    );
    assert!(
        !hookdir.join("20-post.hook").exists(),
        "the removal left the hook file behind, so nothing was under test"
    );
}

/// An install of a newer version must leave exactly one entry.
///
/// `install_step` must remove the entry installed under this name, whatever its version.
/// Matching on name *and* version leaves `foo-1.0.0-1` and `foo-2.0.0-1` side by side after an
/// upgrade. The reader, finding two entries for one name, then keeps the older one, and the
/// database reports a version that is not on disk.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn upgrading_replaces_the_entry_rather_than_adding_one() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    write_package(&sandbox.path("cache"), "2.0.0-1", None);

    assert!(sandbox.install("1.0.0-1", &[]).status.success());
    // No `--overwrite`. A package upgrading itself owns the files it is replacing, and conflict
    // detection recognizes that. Passing it here would hide a regression in exactly that rule.
    let output = sandbox.install("2.0.0-1", &[]);
    assert!(output.status.success(), "{}", text(&output));

    let entries: Vec<String> = std::fs::read_dir(sandbox.path("db/local"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("foo-"))
        .collect();
    assert_eq!(entries, ["foo-2.0.0-1"], "the old entry survived the upgrade");
}

/// An upgrade must take the old version's files with it: the fake remove transaction.
///
/// libalpm runs `_alpm_remove_single_package(handle, oldpkg, newpkg, 0, 0)` (`add.c:508`)
/// before extracting. piko did not, so a package that dropped a file between versions left it
/// on disk owned by nobody: the entry that named it had just been replaced.
///
/// The two halves are asserted together on purpose. Deleting the dropped file is only correct
/// if everything both versions ship survives, holding the new content. A removal that ran after
/// extraction instead of before would pass the first assertion and fail the second.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn upgrading_deletes_a_file_the_new_version_drops() {
    let sandbox = Sandbox::new();
    write_package_with(
        &sandbox.path("cache"),
        "foo",
        "1.0.0-1",
        None,
        &[("usr/share/foo/dropped", "1.0.0-1")],
    );
    write_package(&sandbox.path("cache"), "2.0.0-1", None);

    assert!(sandbox.install("1.0.0-1", &[]).status.success());
    assert!(sandbox.path("root/usr/share/foo/dropped").exists(), "the fixture shipped nothing");

    let output = sandbox.install("2.0.0-1", &[]);
    assert!(output.status.success(), "{}", text(&output));

    assert!(
        !sandbox.path("root/usr/share/foo/dropped").exists(),
        "the dropped file was orphaned on disk:\n{}",
        text(&output)
    );
    // The directory the new version does not ship goes with it too, once it is empty.
    assert!(!sandbox.path("root/usr/share/foo").exists(), "the emptied directory stayed");
    // The shared file is still there, with the new content rather than a hole.
    assert_eq!(std::fs::read(sandbox.path("root/usr/bin/foo")).unwrap(), b"2.0.0-1");
    assert!(sandbox.path("root/usr/bin").is_dir(), "a shared directory was destroyed");

    // The entry agrees with the disk: nothing it claims is missing.
    let files = std::fs::read_to_string(sandbox.path("db/local/foo-2.0.0-1/files")).unwrap();
    assert!(!files.contains("dropped"), "{files}");
    for line in files.lines().filter(|line| line.starts_with("usr/")) {
        let path = sandbox.path("root").join(line.trim_end_matches('/'));
        assert!(path.symlink_metadata().is_ok(), "the entry claims a missing {line}");
    }
}

/// `piko install <name>` must resolve through the repository and pull in a dependency,
/// recording the named target as `Explicit` and the pulled-in package as `Depend`. This is what
/// turns `install` from "extract this file" into "`piko plan` as a transaction".
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn installing_by_name_pulls_in_its_dependency() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    write_package_with(&sandbox.path("cache"), "bar", "1.0.0-1", None, &[]);
    sandbox.write_repo(&[("foo", "1.0.0-1", &["bar"]), ("bar", "1.0.0-1", &[])]);

    let output = sandbox.run_install(&["foo"], &[]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");

    // The plan is shown before anything is committed: both packages, and the step count.
    assert!(seen.contains("install   foo"), "the plan did not list foo:\n{seen}");
    assert!(seen.contains("install   bar"), "the plan did not list bar:\n{seen}");
    assert!(seen.contains("2 to install"), "the plan was not shown before committing:\n{seen}");

    assert!(sandbox.path("root/usr/bin/foo").exists(), "the named target was not installed");
    assert!(sandbox.path("root/usr/bin/bar").exists(), "the dependency was not pulled in");

    let foo_desc = std::fs::read_to_string(sandbox.path("db/local/foo-1.0.0-1/desc")).unwrap();
    assert!(!foo_desc.contains("%REASON%"), "the named target was not explicit:\n{foo_desc}");
    let bar_desc = std::fs::read_to_string(sandbox.path("db/local/bar-1.0.0-1/desc")).unwrap();
    assert!(
        bar_desc.contains("%REASON%\n1"),
        "the dependency was not recorded as one:\n{bar_desc}"
    );
}

/// `--asdeps` must apply to the named target too, not only to what it pulls in.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn asdeps_downgrades_the_named_target_as_well() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);

    let output = sandbox.run_install(&["foo"], &["--asdeps"]);
    assert!(output.status.success(), "{}", text(&output));

    let desc = std::fs::read_to_string(sandbox.path("db/local/foo-1.0.0-1/desc")).unwrap();
    assert!(desc.contains("%REASON%\n1"), "--asdeps did not apply to the named target:\n{desc}");
}

/// Without `--noconfirm`, `install` must show the plan and wait for an answer. Declining it
/// must leave the system exactly as it was, with a clean exit rather than an error.
#[test]
fn declining_the_install_prompt_changes_nothing() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);

    let mut child = Command::new(PIKO)
        .arg("install")
        .arg("--config")
        .arg(sandbox.path("pacman.conf"))
        .arg("--root")
        .arg(sandbox.path("root"))
        .arg("--dbpath")
        .arg(sandbox.path("db"))
        .arg("foo")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), b"n\n").unwrap();
    let output = child.wait_with_output().unwrap();
    let seen = text(&output);

    assert!(output.status.success(), "declining should not be an error:\n{seen}");
    assert!(seen.contains("install   foo"), "the plan was not shown before asking:\n{seen}");
    assert!(seen.contains("Proceed with installation?"), "no prompt was shown:\n{seen}");
    assert!(!sandbox.path("root/usr/bin/foo").exists(), "the package was installed anyway");
    assert!(
        std::fs::read_dir(sandbox.path("db/local")).unwrap().count() == 1,
        "an entry was written despite declining"
    );
}

/// `remove` shows the same kind of plan `install` does, and a declined answer removes nothing.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn declining_the_remove_prompt_changes_nothing() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    assert!(sandbox.install("1.0.0-1", &[]).status.success());

    let mut child = Command::new(PIKO)
        .arg("remove")
        .arg("--config")
        .arg(sandbox.path("pacman.conf"))
        .arg("--root")
        .arg(sandbox.path("root"))
        .arg("--dbpath")
        .arg(sandbox.path("db"))
        .arg("foo")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), b"n\n").unwrap();
    let output = child.wait_with_output().unwrap();
    let seen = text(&output);

    assert!(output.status.success(), "declining should not be an error:\n{seen}");
    assert!(seen.contains("remove    foo"), "the plan was not shown before asking:\n{seen}");
    assert!(seen.contains("Do you want to remove these packages?"), "no prompt was shown:\n{seen}");
    assert!(sandbox.path("root/usr/bin/foo").exists(), "the package was removed anyway");
}

/// `HoldPkg` stops an unattended removal, because its prompt defaults to no.
///
/// This is the one place `--noconfirm` does not mean "assume yes". pacman's `question` returns
/// its preset under `noconfirm` (`util.c:1737`), and the `HoldPkg` guard uses `noyes`, whose
/// preset is 0 (`remove.c:143`). A script that removes a held package by accident is exactly
/// what the directive exists to prevent, so the flag must not be an escape hatch from it.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn holdpkg_refuses_an_unattended_removal() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    assert!(sandbox.install("1.0.0-1", &[]).status.success());
    sandbox.set_hold_pkg("foo");

    let output = sandbox.run_remove(&["foo"], &["--noconfirm"], None);
    let seen = text(&output);

    assert!(!output.status.success(), "a held package was removed unattended:\n{seen}");
    assert!(
        seen.contains("foo is designated as a HoldPkg"),
        "the refusal did not name the held package:\n{seen}"
    );
    assert!(
        sandbox.path("root/usr/bin/foo").exists(),
        "the package was removed despite the refusal"
    );
}

/// `HoldPkg` is a prompt, not a veto: an explicit `y` goes through.
///
/// The answer is `y\ny\n` because there are two questions in a row: the guard's, then the
/// ordinary "Do you want to remove these packages?". Their order is asserted rather than
/// assumed. pacman warns and asks about `HoldPkg` before displaying the target list
/// (`remove.c:133-145`, above `display_targets`), so the warning is not buried under a plan.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn holdpkg_asks_and_an_explicit_yes_removes_the_package() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    assert!(sandbox.install("1.0.0-1", &[]).status.success());
    sandbox.set_hold_pkg("foo");

    let output = sandbox.run_remove(&["foo"], &[], Some("y\ny\n"));
    let seen = text(&output);

    assert!(output.status.success(), "{seen}");
    assert!(
        seen.contains("HoldPkg was found in target list"),
        "no HoldPkg question was asked:\n{seen}"
    );
    let guard = seen.find("HoldPkg was found in target list").unwrap();
    let plan = seen.find("remove    foo").unwrap();
    assert!(guard < plan, "the guard was asked after the plan was shown:\n{seen}");
    assert!(
        !sandbox.path("root/usr/bin/foo").exists(),
        "an accepted removal did not happen:\n{seen}"
    );
}

/// A bare Enter at the guard answers no, unlike every other prompt piko shows.
///
/// The two presets are the whole difference between pacman's `yesno` and `noyes`, so a shared
/// prompt helper that ignored the default would pass the accept case above and still be wrong
/// here.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn holdpkg_defaults_to_no_on_a_bare_enter() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    assert!(sandbox.install("1.0.0-1", &[]).status.success());
    sandbox.set_hold_pkg("foo");

    let output = sandbox.run_remove(&["foo"], &[], Some("\n"));
    let seen = text(&output);

    assert!(!output.status.success(), "an empty answer accepted:\n{seen}");
    assert!(sandbox.path("root/usr/bin/foo").exists(), "the package was removed on a bare Enter");
}

/// A `HoldPkg` list that does not cover the target changes nothing.
///
/// The guard must stay silent, not merely harmless. An extra question on every unrelated
/// removal would train users to answer it without reading.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn holdpkg_is_silent_for_a_package_it_does_not_name() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    assert!(sandbox.install("1.0.0-1", &[]).status.success());
    sandbox.set_hold_pkg("glibc pacman");

    let output = sandbox.run_remove(&["foo"], &["--noconfirm"], None);
    let seen = text(&output);

    assert!(output.status.success(), "{seen}");
    assert!(
        !seen.contains("HoldPkg"),
        "the guard spoke up for a package it does not hold:\n{seen}"
    );
    assert!(!sandbox.path("root/usr/bin/foo").exists(), "the removal did not happen:\n{seen}");
}

/// `--nodeps` is not an exemption. pacman's guard sits in `pacman_remove` above everything the
/// flags select, so `-Rdd` is checked exactly like `-Rcs`.
///
/// Worth its own test because the `--nodeps` path in `cmd::txn` skips the planner entirely and
/// builds its name list separately. That is the one place the guard could have been left out
/// without any other test noticing.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn holdpkg_applies_to_the_nodeps_path_too() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    assert!(sandbox.install("1.0.0-1", &[]).status.success());
    sandbox.set_hold_pkg("foo");

    let output = sandbox.run_remove(&["foo"], &["--nodeps", "--noconfirm"], None);
    let seen = text(&output);

    assert!(!output.status.success(), "--nodeps walked past the HoldPkg guard:\n{seen}");
    assert!(
        sandbox.path("root/usr/bin/foo").exists(),
        "the package was removed despite being held"
    );
}

/// `--downgrade` is the only thing that lets `update` move a package backwards.
///
/// Without it, a repository offering an older build than the one installed is not an upgrade,
/// and `update` has nothing to do. That is also what makes this the honest test of the flag:
/// the same sandbox answers differently with and without it. A `--downgrade` that stopped
/// reaching `InstallOptions::sysupgrade` would leave the second half reporting "nothing to do"
/// instead of silently doing the right thing anyway.
///
/// Pinned because `install` and `update` share one dispatch helper (`main::sync`), and
/// `sysupgrade` is one of exactly two fields that tell the two subcommands apart. The other,
/// `as_deps`, is covered by `asdeps_downgrades_the_named_target_as_well`.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn update_downgrade_moves_a_package_backwards_and_nothing_else_does() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "2.0.0-1", None);
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    assert!(sandbox.install("2.0.0-1", &[]).status.success());

    // The repository now carries only the older build, as a mirror rolled back would.
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);

    let output = sandbox.run_update(&[], &["--norefresh"]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert!(
        seen.contains("nothing to do"),
        "a plain update downgraded, or failed instead of reporting nothing to do:\n{seen}"
    );

    let output = sandbox.run_update(&[], &["--norefresh", "--downgrade"]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");

    let entries: Vec<String> = std::fs::read_dir(sandbox.path("db/local"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("foo-"))
        .collect();
    assert_eq!(entries, ["foo-1.0.0-1"], "--downgrade did not downgrade:\n{seen}");
}

/// A system already at the newest available version has nothing to do, and `update` must say
/// so rather than showing an empty plan and asking about it.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn update_with_nothing_pending_reports_it() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);
    assert!(sandbox.run_install(&["foo"], &[]).status.success());

    let output = sandbox.run_update(&[], &["--norefresh"]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("nothing to do"), "{seen}");
}

/// `update` must apply a `%REPLACES%` pair: install the replacement and remove what it
/// replaces, both shown in the plan before anything happens.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn update_applies_a_replaces_pair() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "old", "1.0.0-1", None, &[]);
    sandbox.write_repo(&[("old", "1.0.0-1", &[])]);
    assert!(sandbox.run_install(&["old"], &[]).status.success());

    // The repository no longer offers `old` at all, only `new`, which replaces it.
    write_package_with(&sandbox.path("cache"), "new", "1.0.0-1", None, &[]);
    sandbox.write_repo_with_relations(&[("new", "1.0.0-1", &[], &["old"], &[])]);

    let output = sandbox.run_update(&[], &["--norefresh"]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");

    assert!(seen.contains("install   new"), "the replacement was not planned:\n{seen}");
    assert!(seen.contains("remove    old"), "the replaced package was not planned:\n{seen}");

    assert!(sandbox.path("root/usr/bin/new").exists(), "the replacement was not installed");
    assert!(!sandbox.path("root/usr/bin/old").exists(), "the replaced package survived");
    assert!(
        sandbox.path("db/local/old-1.0.0-1").symlink_metadata().is_err(),
        "the old entry survived"
    );
}

/// `update` must take away a package the new version of something else conflicts with. This is
/// the same relax-and-retry the solver already applies to `install`, now exercised through a
/// real upgrade rather than a fresh install.
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn update_removes_a_conflicting_package() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "bar", "1.0.0-1", None, &[]);
    sandbox.write_repo(&[("bar", "1.0.0-1", &[])]);
    assert!(sandbox.run_install(&["bar"], &[]).status.success());

    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);
    assert!(sandbox.run_install(&["foo"], &[]).status.success());

    // The next `foo` version conflicts with the already-installed `bar`.
    write_package_with(&sandbox.path("cache"), "foo", "2.0.0-1", None, &[]);
    sandbox.write_repo_with_relations(&[("foo", "2.0.0-1", &[], &[], &["bar"])]);

    let output = sandbox.run_update(&[], &["--norefresh"]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");

    assert!(seen.contains("upgrade   foo"), "the upgrade was not planned:\n{seen}");
    assert!(seen.contains("remove    bar"), "the conflicting package was not planned:\n{seen}");

    assert_eq!(std::fs::read(sandbox.path("root/usr/bin/foo")).unwrap(), b"2.0.0-1");
    assert!(!sandbox.path("root/usr/bin/bar").exists(), "the conflicting package survived");
    assert!(
        sandbox.path("db/local/bar-1.0.0-1").symlink_metadata().is_err(),
        "the old entry survived"
    );
}

/// `update` refreshes every configured repository before planning, `pacman -Syu`. The
/// sandbox's `[test]` repository is never written to disk directly (no
/// [`Sandbox::write_repo`] call); the only way `db/sync/test.db` can exist afterwards is if
/// `update` downloaded it itself.
#[test]
fn update_refreshes_repositories_by_default() {
    let body = piko_db::fixture::gzip_tar(&[(
        "foo-1.0.0-1/desc",
        repo_desc("foo", "1.0.0-1", &[]).as_bytes(),
    )]);
    let sandbox = Sandbox::with_server(&serve_once(body));

    let output = sandbox.run_update(&[], &[]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("nothing to do"), "{seen}");
    assert!(
        sandbox.path("db/sync/test.db").exists(),
        "update did not refresh the database:\n{seen}"
    );
}

/// `--norefresh` skips the pre-plan refresh entirely, `pacman -Su`. `Server` points at a port
/// with nothing listening, so any connection attempt fails immediately; success here is direct
/// proof that no attempt was made.
#[test]
fn update_norefresh_skips_the_database_refresh() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let sandbox = Sandbox::with_server(&format!("http://127.0.0.1:{port}"));

    let output = sandbox.run_update(&[], &["--norefresh"]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("nothing to do"), "{seen}");
    assert!(
        !sandbox.path("db/sync/test.db").exists(),
        "--norefresh refreshed the database anyway:\n{seen}"
    );
}

/// Serves `body` for exactly one HTTP GET request, then stops.
///
/// As `piko-net`'s own `conditional.rs`/`package.rs` test harnesses: the crudest server that
/// works. That is all a package download from a repository's `Server` needs here.
fn serve_once(body: Vec<u8>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::{Read as _, Write as _};
            let mut discard = [0_u8; 4096];
            let _ = stream.read(&mut discard);
            let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// Serves every `.pkg.tar` request from `bodies` (keyed by file name), each on its own thread,
/// and answers a `.sig` with `404`.
///
/// `serve_once` cannot be used for a parallel test: it answers one connection and stops, so
/// several workers dialling at once would hang. Returns the base URL and a count of the
/// requests actually served.
fn serve_many(bodies: std::collections::HashMap<String, Vec<u8>>) -> (String, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);
    let bodies = Arc::new(bodies);

    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let bodies = Arc::clone(&bodies);
            let counter = Arc::clone(&counter);
            std::thread::spawn(move || {
                use std::io::{BufRead as _, BufReader, Write as _};
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                let _ = reader.read_line(&mut first);
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let path = first
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .trim_start_matches('/')
                    .to_owned();
                match bodies.get(&path) {
                    Some(body) => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let header =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(body);
                    }
                    None => {
                        let _ = stream
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                    }
                }
                let _ = stream.flush();
            });
        }
    });
    (format!("http://127.0.0.1:{port}"), served)
}

/// `-w` with `ParallelDownloads > 1` still reports every package as downloaded, not as a
/// cache hit.
///
/// The guard for a real trap. Package downloads happen in a `prefetch` phase ahead of the
/// per-package loop, so a `was_cached` check asked inside that loop would answer "yes" for
/// everything, reporting a run that fetched the whole transaction as one that fetched nothing.
/// That is `-w`'s verification regression in reverse. `download_only` collects the answer
/// before `prefetch` runs; this test says so out loud. Three packages, so more than one worker
/// has something to do.
#[test]
fn download_only_reports_parallel_downloads_as_downloads_not_cache_hits() {
    let names = ["foo", "bar", "baz"];
    let bodies: std::collections::HashMap<String, Vec<u8>> = names
        .iter()
        .map(|name| {
            (format!("{name}-1.0.0-1-x86_64.pkg.tar"), package_tar(name, "1.0.0-1", None, &[]))
        })
        .collect();
    let (url, served) = serve_many(bodies);

    let sandbox = Sandbox::with_server(&url);
    sandbox.set_parallel_downloads(5);
    let repo: Vec<(&str, &str, &[&str])> =
        names.iter().map(|name| (*name, "1.0.0-1", &[] as &[&str])).collect();
    sandbox.write_repo(&repo);

    let output = sandbox.run_install(&names, &["--downloadonly"]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");

    for name in names {
        assert!(
            seen.contains(&format!("downloaded {name}-1.0.0-1-x86_64.pkg.tar")),
            "{name} was not reported as downloaded:\n{seen}"
        );
        assert!(
            sandbox.path(&format!("cache/{name}-1.0.0-1-x86_64.pkg.tar")).exists(),
            "{name} did not land in the cache:\n{seen}"
        );
    }
    assert!(
        !seen.contains("already in cache:"),
        "a freshly downloaded package was reported as a cache hit:\n{seen}"
    );
    assert_eq!(served.load(Ordering::SeqCst), names.len(), "not every package was fetched");
}

/// A package that is not in the cache is downloaded from the repository's `Server` before it
/// is installed. This is the whole point of [`piko_txn::source::DownloadingSource`].
#[test]
#[ignore = "requires root: install now always applies the archive's ownership (0:0 in these fixtures), which needs CAP_CHOWN"]
fn installing_a_package_not_in_the_cache_downloads_it() {
    let bytes = package_tar("foo", "1.0.0-1", None, &[]);
    let sandbox = Sandbox::with_server(&serve_once(bytes.clone()));
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);
    // Deliberately not written into the cache. That is exactly what this test proves.

    let output = sandbox.run_install(&["foo"], &[]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");

    assert!(
        sandbox.path("root/usr/bin/foo").exists(),
        "the downloaded package was not installed:\n{seen}"
    );
    assert_eq!(
        std::fs::read(sandbox.path("cache/foo-1.0.0-1-x86_64.pkg.tar")).unwrap(),
        bytes,
        "the download did not land in the cache byte-for-byte"
    );
}

/// `--downloadonly` fetches the package into the cache and installs nothing at all: no files
/// under `--root`, no database entry, no journal or lock touched.
#[test]
fn download_only_downloads_without_installing() {
    let bytes = package_tar("foo", "1.0.0-1", None, &[]);
    let sandbox = Sandbox::with_server(&serve_once(bytes.clone()));
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);

    let output = sandbox.run_install(&["foo"], &["--downloadonly"]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("downloaded"), "no download was reported:\n{seen}");
    // The prefetch phase must not turn a fresh download into a cache hit. See
    // `download_only_reports_parallel_downloads_as_downloads_not_cache_hits`.
    assert!(
        !seen.contains("already in cache:"),
        "reported as cached rather than downloaded:\n{seen}"
    );

    assert_eq!(
        std::fs::read(sandbox.path("cache/foo-1.0.0-1-x86_64.pkg.tar")).unwrap(),
        bytes,
        "the package was not downloaded into the cache"
    );
    assert!(!sandbox.path("root/usr/bin/foo").exists(), "--downloadonly installed the package");
    assert!(
        sandbox.path("db/local/foo-1.0.0-1").symlink_metadata().is_err(),
        "--downloadonly wrote a database entry"
    );
    assert!(
        sandbox.path("db/piko-journal").symlink_metadata().is_err(),
        "--downloadonly left a journal behind"
    );
}

/// `--downloadonly` verifies what it has: an unsigned package under `SigLevel = Required` is
/// refused there, not left in the cache for a later install to complain about.
///
/// libalpm does the same. `check_validity` (`sync.c:1275`) runs before `_alpm_sync_load`
/// returns on `ALPM_TRANS_FLAG_DOWNLOADONLY` (`sync.c:1279`), and piko did not. This test pins
/// that.
///
/// The package is pre-cached rather than served, which checks the same thing for the same
/// reason: `check_validity` runs over `_alpm_filecache_find`'s answer, so a file already in the
/// cache is validated exactly like one just fetched. It also keeps a single-shot HTTP fixture
/// out of a test about signatures.
#[test]
fn download_only_refuses_an_unsigned_package() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);
    sandbox.require_signatures();

    let output = sandbox.run_install(&["foo"], &["--downloadonly"]);
    let seen = text(&output);
    assert!(
        !output.status.success(),
        "--downloadonly accepted an unsigned package under SigLevel = Required:\n{seen}"
    );
    assert!(
        seen.contains("it is not signed"),
        "the refusal did not name the missing signature as the reason:\n{seen}"
    );
    assert!(
        !seen.contains("already in cache:"),
        "the package was reported as supplied before being refused:\n{seen}"
    );
}

/// `--root /` skips the `chroot(2)` call (libalpm does the same, to run with fewer
/// capabilities), but the working directory still has to end up at `/`. A scriptlet is free to
/// use a path relative to the root, and gstreamer's real `post_upgrade` does exactly that,
/// running `setcap` on `usr/lib/gstreamer-1.0/gst-ptp-helper` with no leading slash.
///
/// No privilege is needed to exercise this. With `root == "/"` the helper never calls `chroot`
/// at all, so this runs as an ordinary process, launched from a directory that is deliberately
/// not `/`. It only checks what directory the command sees: it writes nothing and touches no
/// path other than `/bin/sh`.
#[test]
fn root_slash_skips_the_chroot_but_not_the_chdir() {
    let elsewhere = tempfile::tempdir().unwrap();
    let output = Command::new(PIKO)
        .args(["__exec-in-root", "/", "/bin/sh", "-c", "pwd"])
        .current_dir(elsewhere.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert_eq!(seen.trim(), "/", "the command did not see / as its working directory:\n{seen}");
}

/// The whole sequence, with a working chroot.
///
/// `#[ignore]`d because it needs `unshare --user --map-root-user` (an unprivileged user
/// namespace, which gives `CAP_SYS_CHROOT` inside it), plus a `/bin/sh` and its loader copied
/// into the throwaway root. Run it with:
///
/// ```text
/// cargo test -p piko --test side_effects -- --ignored --nocapture
/// ```
#[test]
#[ignore = "requires unprivileged user namespaces and a copyable /bin/sh"]
fn chrooted_scriptlets_and_hooks_really_run() {
    let sandbox = Sandbox::new();
    if !populate_shell(&sandbox.path("root")) {
        eprintln!("skipping: could not assemble a minimal /bin/sh in the test root");
        return;
    }
    write_package(&sandbox.path("cache"), "1.0.0-1", Some(SCRIPT));
    write_package(&sandbox.path("cache"), "2.0.0-1", Some(SCRIPT));
    sandbox.write_hook(
        "50-hello.hook",
        "[Trigger]\nOperation = Install\nOperation = Upgrade\nType = Package\nTarget = foo\n\n\
         [Action]\nDescription = Saying hello...\nWhen = PostTransaction\n\
         Exec = /bin/sh -c 'echo HOOK_RAN'\n",
    );

    let unshared = |args: &[&std::ffi::OsStr]| {
        Command::new("unshare")
            .args(["--user", "--map-root-user", PIKO])
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let common: Vec<std::ffi::OsString> = vec![
        "--config".into(),
        sandbox.path("pacman.conf").into(),
        "--root".into(),
        sandbox.path("root").into(),
        "--dbpath".into(),
        sandbox.path("db").into(),
        "--hookdir".into(),
        sandbox.path("hooks").into(),
    ];
    let with = |first: &str, rest: &[&str]| -> Vec<std::ffi::OsString> {
        let mut all: Vec<std::ffi::OsString> = vec![first.into()];
        all.extend(common.iter().cloned());
        all.extend(rest.iter().map(Into::into));
        all
    };
    let run = |args: Vec<std::ffi::OsString>| {
        let borrowed: Vec<&std::ffi::OsStr> = args.iter().map(AsRef::as_ref).collect();
        unshared(&borrowed)
    };

    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);
    let output = run(with("install", &["--noconfirm", "foo"]));
    let seen = text(&output);
    if seen.contains("could not enter the root") {
        eprintln!("skipping: unprivileged user namespaces are unavailable here");
        return;
    }
    assert!(output.status.success(), "{seen}");
    assert!(
        seen.contains("Running post install script"),
        "the announcement line is missing:\n{seen}"
    );
    assert!(seen.contains("POST_INSTALL 1.0.0-1"), "post_install did not run:\n{seen}");
    assert!(seen.contains("HOOK_RAN"), "the hook did not run:\n{seen}");
    assert!(seen.contains("Saying hello..."), "the description was not shown:\n{seen}");
    assert!(
        !seen.contains("50-hello.hook"),
        "the hook's file name leaked into the display:\n{seen}"
    );

    // The staging directory is cleaned up: `<root>/tmp` survives, nothing inside it does.
    let leftovers: Vec<String> = std::fs::read_dir(sandbox.path("root/tmp"))
        .map(|reader| {
            reader
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    assert!(leftovers.is_empty(), "the scriptlet left {leftovers:?} behind");

    // The upgrade pair: the repository now offers 2.0.0-1 instead.
    sandbox.write_repo(&[("foo", "2.0.0-1", &[])]);
    let output = run(with("install", &["--noconfirm", "foo"]));
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert!(
        seen.contains("Running post upgrade script"),
        "the announcement line is missing:\n{seen}"
    );
    assert!(
        seen.contains("POST_UPGRADE 2.0.0-1 1.0.0-1"),
        "post_upgrade did not get both versions:\n{seen}"
    );
    assert!(!seen.contains("POST_INSTALL"), "post_install ran for an upgrade:\n{seen}");

    // And the removal side.
    let output = run(with("remove", &["--noconfirm", "foo"]));
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert!(
        seen.contains("Running pre remove script"),
        "the announcement line is missing:\n{seen}"
    );
    assert!(seen.contains("PRE_REMOVE 2.0.0-1"), "pre_remove did not run:\n{seen}");
}

/// Copies `/bin/sh` and the libraries it needs into `root`, so a chroot can exec it.
fn populate_shell(root: &Path) -> bool {
    let Ok(output) = Command::new("ldd").arg("/bin/sh").output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    if std::fs::create_dir_all(root.join("bin")).is_err()
        || std::fs::create_dir_all(root.join("usr/lib")).is_err()
        || std::fs::copy("/bin/sh", root.join("bin/sh")).is_err()
    {
        return false;
    }
    // `/lib` and `/lib64` are where the loader is looked for; on Arch both are symlinks.
    for link in ["lib", "lib64"] {
        let _ = std::os::unix::fs::symlink("usr/lib", root.join(link));
    }

    for token in String::from_utf8_lossy(&output.stdout).split_whitespace() {
        if !token.starts_with('/') || !token.contains(".so") {
            continue;
        }
        let source = Path::new(token);
        let Some(name) = source.file_name() else {
            continue;
        };
        let _ = std::fs::copy(source, root.join("usr/lib").join(name));
    }
    root.join("bin/sh").exists()
}

// ---------------------------------------------------------------------------
// The transaction records: `pacman.log` and `<dbpath>/piko-history`.
//
// Every sandbox writes a `LogFile` into its own temporary directory, so these read the same
// two files a real run writes and never touch `/var/log/pacman.log`.
// ---------------------------------------------------------------------------

/// Runs `piko history` against a sandbox, with the given extra arguments.
fn run_history(sandbox: &Sandbox, extra: &[&str]) -> Output {
    Command::new(PIKO)
        .arg("history")
        .arg("--config")
        .arg(sandbox.path("pacman.conf"))
        .arg("--dbpath")
        .arg(sandbox.path("db"))
        .args(extra)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// The line a `piko install` writes before it does anything, matching pacman's own
/// `Running '…'`. It is the only evidence in the log of *what was asked for*, as opposed to
/// what happened.
#[test]
fn the_command_line_reaches_the_log_before_anything_is_planned() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    drop(sandbox.install("1.0.0-1", &[]));

    let log = sandbox.log();
    assert!(log.contains("[PIKO] Running '"), "{log}");
    assert!(log.contains(" install "), "{log}");
}

/// A transaction a `PreTransaction` hook refuses has still started. It must be recorded as a
/// failure rather than left looking like a run that never happened — that is the state the
/// journal is deleted for, and the log is what remains to say so.
#[test]
fn a_refused_transaction_is_recorded_as_failed() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    sandbox.write_hook(
        "10-abort.hook",
        "[Trigger]\nOperation = Install\nType = Package\nTarget = foo\n\n\
         [Action]\nWhen = PreTransaction\nExec = /bin/false\nAbortOnFail\n",
    );

    let output = sandbox.install("1.0.0-1", &[]);
    assert!(!output.status.success(), "{}", text(&output));

    let log = sandbox.log();
    assert!(log.contains("[PIKO] transaction started (id "), "{log}");
    assert!(log.contains("[PIKO] transaction failed"), "{log}");
    assert!(!log.contains("installed foo"), "a refused transaction reported an install:\n{log}");

    let history = sandbox.history();
    assert!(history.contains("end failed "), "{history}");
    assert!(!history.contains("installed foo"), "{history}");
}

/// The log the user configured is the only file written. A run must not fall back to
/// `/var/log/pacman.log`, and must not invent a location of its own.
#[test]
fn nothing_is_written_outside_the_configured_log() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    drop(sandbox.install("1.0.0-1", &[]));

    assert!(sandbox.path("pacman.log").is_file(), "the configured log was not written");
    assert!(!sandbox.path("root/var/log/pacman.log").exists(), "a second log appeared");
}

/// A `LogFile` whose directory does not exist is a warning, not a failure. libalpm raises
/// `ALPM_ERR_BADPERMS` here; piko does not, because the history store beside the database is
/// the record that must not be lost, and refusing would break bootstrapping a fresh root.
#[test]
fn an_unwritable_log_warns_and_the_transaction_still_runs() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);

    let output = sandbox.run_install(
        &["foo"],
        &["--logfile", &sandbox.path("no/such/directory/pacman.log").display().to_string()],
    );
    let seen = text(&output);

    assert!(seen.contains("cannot write the transaction log"), "no warning was printed:\n{seen}");
    // The transaction itself is unaffected: it fails only for the reason it would have failed
    // anyway (extraction needs `CAP_CHOWN` in this fixture), never for the log.
    assert!(!seen.contains("no transactions"), "{seen}");
}

/// `piko history` reads the shared log, so pacman's own transactions show up beside piko's.
/// Nothing here writes through piko: the point is that the log is the interface.
#[test]
fn history_reports_a_transaction_pacman_wrote() {
    let sandbox = Sandbox::new();
    std::fs::write(
        sandbox.path("pacman.log"),
        "[2026-09-03T16:19:47+0200] [PACMAN] Running 'pacman -Syu'\n\
         [2026-09-03T16:19:48+0200] [ALPM] transaction started\n\
         [2026-09-03T16:19:49+0200] [ALPM] upgraded linux (6.1-1 -> 6.2-1)\n\
         [2026-09-03T16:19:50+0200] [ALPM] transaction completed\n",
    )
    .unwrap();

    let output = run_history(&sandbox, &[]);
    let seen = text(&output);

    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("[ALPM]"), "the tool that acted was not named:\n{seen}");
    assert!(seen.contains("pacman -Syu"), "{seen}");
    assert!(seen.contains("upgraded"), "{seen}");
    assert!(seen.contains("linux"), "{seen}");
}

/// `--package` keeps only the transactions that touched a package, and `--quiet` drops the
/// per-package detail while keeping one line per transaction.
#[test]
fn history_filters_by_package_and_shortens_with_quiet() {
    let sandbox = Sandbox::new();
    std::fs::write(
        sandbox.path("pacman.log"),
        "[2026-09-03T16:19:48+0200] [ALPM] transaction started\n\
         [2026-09-03T16:19:49+0200] [ALPM] installed linux (6.2-1)\n\
         [2026-09-03T16:19:50+0200] [ALPM] transaction completed\n\
         [2026-09-04T16:19:48+0200] [ALPM] transaction started\n\
         [2026-09-04T16:19:49+0200] [ALPM] installed vim (9.1-1)\n\
         [2026-09-04T16:19:50+0200] [ALPM] transaction completed\n",
    )
    .unwrap();

    let all = text(&run_history(&sandbox, &[]));
    assert!(all.contains("2 transaction(s)"), "{all}");

    let filtered = text(&run_history(&sandbox, &["--package", "vim"]));
    assert!(filtered.contains("1 transaction(s)"), "{filtered}");
    assert!(!filtered.contains("linux"), "{filtered}");

    // A detail line is indented and carries its kind's icon. `--quiet` is one line per
    // transaction, so no such line may appear.
    let quiet = text(&run_history(&sandbox, &["--package", "vim", "--quiet"]));
    assert!(!quiet.contains("  + installed"), "detail survived --quiet:\n{quiet}");
    assert_eq!(quiet.lines().filter(|line| line.contains("vim")).count(), 1, "{quiet}");
}

/// The detail lines carry the icon and the past-tense verb `piko plan` and `piko history`
/// share, so an install, a removal and an upgrade are told apart by shape, not only by a word.
#[test]
fn history_marks_each_kind_with_its_own_icon() {
    let sandbox = Sandbox::new();
    std::fs::write(
        sandbox.path("pacman.log"),
        "[2026-09-03T16:19:48+0200] [ALPM] transaction started\n\
         [2026-09-03T16:19:49+0200] [ALPM] installed vim (9.1-1)\n\
         [2026-09-03T16:19:49+0200] [ALPM] removed nano (8.0-1)\n\
         [2026-09-03T16:19:49+0200] [ALPM] upgraded linux (6.1-1 -> 6.2-1)\n\
         [2026-09-03T16:19:49+0200] [ALPM] downgraded mesa (25.0-1 -> 24.9-1)\n\
         [2026-09-03T16:19:49+0200] [ALPM] reinstalled glibc (2.44-1)\n\
         [2026-09-03T16:19:50+0200] [ALPM] transaction completed\n",
    )
    .unwrap();

    let seen = text(&run_history(&sandbox, &[]));
    for expected in ["+ installed", "- removed", "↑ upgraded", "↓ downgraded", "↻ reinstalled"]
    {
        assert!(seen.contains(expected), "missing {expected}:\n{seen}");
    }
}

/// The duplication this rendering exists to remove. A transaction with one action and no
/// recorded command line used to print that action in the header and again below it.
#[test]
fn a_single_action_is_reported_exactly_once() {
    let sandbox = Sandbox::new();
    std::fs::write(
        sandbox.path("pacman.log"),
        "[2026-09-03T16:19:48+0200] [ALPM] transaction started\n\
         [2026-09-03T16:19:49+0200] [ALPM] installed vim (9.1-1)\n\
         [2026-09-03T16:19:50+0200] [ALPM] transaction completed\n",
    )
    .unwrap();

    let seen = text(&run_history(&sandbox, &[]));
    assert_eq!(seen.lines().filter(|line| line.contains("vim")).count(), 1, "{seen}");
}

/// The package count says how big a transaction was, which the detail below already shows. So
/// it appears only where that detail is hidden or narrowed.
#[test]
fn the_package_count_appears_only_where_the_detail_does_not() {
    let sandbox = Sandbox::new();
    std::fs::write(
        sandbox.path("pacman.log"),
        "[2026-09-03T16:19:47+0200] [PACMAN] Running 'pacman -Syu'\n\
         [2026-09-03T16:19:48+0200] [ALPM] transaction started\n\
         [2026-09-03T16:19:49+0200] [ALPM] installed vim (9.1-1)\n\
         [2026-09-03T16:19:49+0200] [ALPM] installed nano (8.0-1)\n\
         [2026-09-03T16:19:50+0200] [ALPM] transaction completed\n",
    )
    .unwrap();

    let full = text(&run_history(&sandbox, &[]));
    assert!(!full.contains("(2 packages)"), "the count doubled the detail:\n{full}");

    let quiet = text(&run_history(&sandbox, &["--quiet"]));
    assert!(quiet.contains("(2 packages)"), "{quiet}");

    let filtered = text(&run_history(&sandbox, &["--package", "vim"]));
    assert!(filtered.contains("(2 packages)"), "{filtered}");
}

/// The command line goes on its own line and is never shortened. It is the record of what was
/// actually typed, and a history that abbreviates it has to be double-checked elsewhere.
#[test]
fn the_command_line_is_printed_whole_on_its_own_line() {
    let sandbox = Sandbox::new();
    let long = "pacman --upgrade --noconfirm -- \
                /home/guillaume/.cache/paru/clone/claude-code/claude-code-2.1.259-1-x86_64.pkg.tar.zst";
    std::fs::write(
        sandbox.path("pacman.log"),
        format!(
            "[2026-09-03T16:19:47+0200] [PACMAN] Running '{long}'\n\
             [2026-09-03T16:19:48+0200] [ALPM] transaction started\n\
             [2026-09-03T16:19:49+0200] [ALPM] upgraded claude-code (2.1.250-1 -> 2.1.259-1)\n\
             [2026-09-03T16:19:50+0200] [ALPM] transaction completed\n"
        ),
    )
    .unwrap();

    let seen = text(&run_history(&sandbox, &[]));
    let command_line =
        seen.lines().find(|line| line.contains("claude-code-2.1.259")).expect("the command line");
    assert_eq!(command_line.trim(), long, "the command line was altered:\n{seen}");
    // Its own line: the header above it carries the timestamp, and does not carry this.
    assert!(!command_line.contains("2026-09-03T16:19:47"), "{seen}");
}

/// `--since` and `--until` cut the list by start time.
#[test]
fn history_filters_by_date() {
    let sandbox = Sandbox::new();
    std::fs::write(
        sandbox.path("pacman.log"),
        "[2026-09-03T16:19:48+0000] [ALPM] transaction started\n\
         [2026-09-03T16:19:49+0000] [ALPM] installed linux (6.2-1)\n\
         [2026-09-03T16:19:50+0000] [ALPM] transaction completed\n\
         [2026-09-05T16:19:48+0000] [ALPM] transaction started\n\
         [2026-09-05T16:19:49+0000] [ALPM] installed vim (9.1-1)\n\
         [2026-09-05T16:19:50+0000] [ALPM] transaction completed\n",
    )
    .unwrap();

    let since = text(&run_history(&sandbox, &["--since", "2026-09-04"]));
    assert!(since.contains("vim") && !since.contains("linux"), "{since}");

    let until = text(&run_history(&sandbox, &["--until", "2026-09-04"]));
    assert!(until.contains("linux") && !until.contains("vim"), "{until}");

    // A bare date names the whole day at both ends, so the day a transaction ran is a range
    // that contains it. Read as two midnights, this returns nothing at all.
    let one_day = text(&run_history(&sandbox, &["--since", "2026-09-05", "--until", "2026-09-05"]));
    assert!(one_day.contains("vim"), "a single-day range excluded its own day:\n{one_day}");
    assert!(!one_day.contains("linux"), "{one_day}");
}

/// `-n` keeps the newest transactions, and `--all` overrides it.
#[test]
fn history_keeps_the_newest_and_all_overrides_it() {
    let sandbox = Sandbox::new();
    let mut log = String::new();
    for day in 1..=5 {
        log.push_str(&format!(
            "[2026-09-0{day}T10:00:00+0000] [ALPM] transaction started\n\
             [2026-09-0{day}T10:00:01+0000] [ALPM] installed p{day} (1-1)\n\
             [2026-09-0{day}T10:00:02+0000] [ALPM] transaction completed\n"
        ));
    }
    std::fs::write(sandbox.path("pacman.log"), log).unwrap();

    let last_two = text(&run_history(&sandbox, &["-n", "2"]));
    assert!(last_two.contains("2 transaction(s)"), "{last_two}");
    assert!(last_two.contains("p5") && last_two.contains("p4"), "{last_two}");
    assert!(!last_two.contains("p1"), "{last_two}");

    let all = text(&run_history(&sandbox, &["-n", "2", "--all"]));
    assert!(all.contains("5 transaction(s)"), "{all}");
}

/// An empty history says so, and names what it read. "Nothing happened" and "piko looked in
/// the wrong place" are different answers, and a user cannot tell them apart otherwise.
#[test]
fn an_empty_history_names_the_files_it_read() {
    let sandbox = Sandbox::new();
    let seen = text(&run_history(&sandbox, &[]));
    assert!(seen.contains("no transactions recorded"), "{seen}");
    assert!(seen.contains("pacman.log"), "{seen}");
    assert!(seen.contains("piko-history"), "{seen}");
}

/// A time `--since` cannot read is refused by name, rather than silently ignored.
#[test]
fn an_unreadable_since_is_refused() {
    let sandbox = Sandbox::new();
    let output = run_history(&sandbox, &["--since", "last tuesday"]);
    assert!(!output.status.success());
    assert!(text(&output).contains("last tuesday"), "{}", text(&output));
}

/// A history run must never write. It is a report, and the two files it reads are the record
/// of what actually happened.
#[test]
fn history_writes_nothing() {
    let sandbox = Sandbox::new();
    std::fs::write(
        sandbox.path("pacman.log"),
        "[2026-09-03T16:19:48+0200] [ALPM] transaction started\n\
         [2026-09-03T16:19:50+0200] [ALPM] transaction completed\n",
    )
    .unwrap();
    let before = std::fs::read_to_string(sandbox.path("pacman.log")).unwrap();

    drop(run_history(&sandbox, &[]));

    assert_eq!(std::fs::read_to_string(sandbox.path("pacman.log")).unwrap(), before);
    assert!(!sandbox.path("db/piko-history").exists(), "history wrote a store");
    assert!(!sandbox.path("db/db.lck").exists(), "history took the lock");
}

/// The whole record of a completed install, in both files.
///
/// Ignored for the same reason every other applying test here is: extraction applies the
/// archive's ownership (`0:0` in these fixtures), which needs `CAP_CHOWN`.
#[test]
#[ignore = "requires root: install applies the archive's ownership, which needs CAP_CHOWN"]
fn a_completed_install_is_recorded_in_both_records() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    let output = sandbox.install("1.0.0-1", &[]);
    assert!(output.status.success(), "{}", text(&output));

    let log = sandbox.log();
    let started = log.find("[PIKO] transaction started").expect("a start line");
    let installed = log.find("[PIKO] installed foo (1.0.0-1)").expect("an install line");
    let completed = log.find("[PIKO] transaction completed").expect("an end line");
    assert!(started < installed && installed < completed, "out of order:\n{log}");

    let history = sandbox.history();
    assert!(history.contains("installed foo 1.0.0-1"), "{history}");
    assert!(history.contains("end completed "), "{history}");
    assert!(history.contains("command "), "{history}");

    // The journal is gone; the history is what remains.
    assert!(!sandbox.path("db/piko-journal").exists(), "a journal was left behind");

    let seen = text(&run_history(&sandbox, &[]));
    assert!(seen.contains("installed") && seen.contains("foo"), "{seen}");
    assert!(seen.contains("1 transaction(s)"), "{seen}");
}

/// The verb must come from a version comparison. An upgrade and a downgrade of the same
/// package are told apart by direction, not by which ran second.
#[test]
#[ignore = "requires root: install applies the archive's ownership, which needs CAP_CHOWN"]
fn an_upgrade_and_a_downgrade_are_named_by_direction() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    write_package(&sandbox.path("cache"), "1.1.0-1", None);
    assert!(sandbox.install("1.0.0-1", &[]).status.success());

    sandbox.write_repo(&[("foo", "1.1.0-1", &[])]);
    assert!(sandbox.run_update(&["foo"], &["--norefresh"]).status.success());
    assert!(sandbox.log().contains("upgraded foo (1.0.0-1 -> 1.1.0-1)"), "{}", sandbox.log());

    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);
    assert!(sandbox.run_update(&["foo"], &["--norefresh", "--downgrade"]).status.success());
    assert!(sandbox.log().contains("downgraded foo (1.1.0-1 -> 1.0.0-1)"), "{}", sandbox.log());
}

/// A removal is recorded with the version that went away, which nothing else on the system
/// records once the entry is gone.
#[test]
#[ignore = "requires root: install applies the archive's ownership, which needs CAP_CHOWN"]
fn a_removal_is_recorded_with_the_version_that_went() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    assert!(sandbox.install("1.0.0-1", &[]).status.success());
    assert!(sandbox.run_remove(&["foo"], &["--noconfirm"], None).status.success());

    assert!(sandbox.log().contains("removed foo (1.0.0-1)"), "{}", sandbox.log());
    assert!(sandbox.history().contains("removed foo 1.0.0-1"), "{}", sandbox.history());
}
