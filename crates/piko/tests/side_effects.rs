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
fn pkginfo(name: &str, version: &str, depends: &[&str], backups: &[&str]) -> String {
    let depends: String = depends.iter().map(|entry| format!("depend = {entry}\n")).collect();
    let backups: String = backups.iter().map(|entry| format!("backup = {entry}\n")).collect();
    format!(
        "pkgname = {name}\npkgbase = {name}\npkgver = {version}\npkgdesc = x\n\
         url = https://example.org/\nbuilddate = 1733737242\n\
         packager = A <a@b.c>\nsize = 4\narch = x86_64\nlicense = MIT\n{depends}{backups}"
    )
}

/// Writes a `foo` package carrying `script` as its `.INSTALL`.
fn write_package(cache: &Path, version: &str, script: Option<&str>) {
    write_package_with(cache, "foo", version, script, &[]);
}

/// As [`write_package`], but with the `0:0` a real package names.
///
/// Only [`chrooted_scriptlets_and_hooks_really_run`] wants this. It runs piko under
/// `unshare --user --map-root-user`, where the running user *is* uid 0 and the outer uid has
/// no mapping at all. So an archive naming the caller's own ids would fail the `chown` with
/// `EINVAL`. Everywhere else the reverse holds. See [`package_tar`].
fn write_package_as_root(cache: &Path, version: &str, script: Option<&str>) {
    std::fs::write(
        cache.join(format!("foo-{version}-x86_64.pkg.tar")),
        package_tar_owned("foo", version, script, &[], &[], &[], 0, 0),
    )
    .unwrap();
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

/// As [`write_package_with`], for a package whose `.PKGINFO` declares `depends`.
///
/// The repository `desc` a test writes is not what the installed entry carries. An install
/// copies `.PKGINFO`. So a package whose dependency must survive into `<dbpath>/local` has to
/// declare it here too.
fn write_package_depending_on(cache: &Path, name: &str, version: &str, depends: &[&str]) {
    std::fs::write(
        cache.join(format!("{name}-{version}-x86_64.pkg.tar")),
        package_tar_owned(
            name,
            version,
            None,
            &[],
            depends,
            &[],
            u64::from(rustix::process::getuid().as_raw()),
            u64::from(rustix::process::getgid().as_raw()),
        ),
    )
    .unwrap();
}

/// Builds the bytes of a `foo`-shaped package archive, without writing it anywhere. Shared by
/// [`write_package_with`] (which puts it straight in the cache) and a download test (which
/// serves the same bytes over HTTP instead).
///
/// # Why the archive is owned by the caller
///
/// An install always extracts under `Ownership::FromArchive`, so every member is `chown`ed to
/// the ids the archive names. A real package names `0:0`, which needs `CAP_CHOWN`. Naming the
/// running user's own ids instead keeps the whole path reachable from an ordinary test. A
/// `chown` to one's own uid and gid needs no privilege, and Linux still runs the same
/// `chown_common` that clears `S_ISUID`/`S_ISGID`. So the ordering these tests sit downstream
/// of stays exercised, rather than skipped.
///
/// The one test that needs `0:0` instead uses [`write_package_as_root`], which says why.
fn package_tar(name: &str, version: &str, script: Option<&str>, extra: &[(&str, &str)]) -> Vec<u8> {
    package_tar_owned(
        name,
        version,
        script,
        extra,
        &[],
        &[],
        u64::from(rustix::process::getuid().as_raw()),
        u64::from(rustix::process::getgid().as_raw()),
    )
}

/// [`package_tar`], for a package that declares `backups` as `%BACKUP%` paths.
///
/// A path declared here must also be shipped in `extra`, the way a real package ships the
/// configuration file it backs up.
fn package_tar_with_backups(
    name: &str,
    version: &str,
    extra: &[(&str, &str)],
    backups: &[&str],
) -> Vec<u8> {
    package_tar_owned(
        name,
        version,
        None,
        extra,
        &[],
        backups,
        u64::from(rustix::process::getuid().as_raw()),
        u64::from(rustix::process::getgid().as_raw()),
    )
}

/// [`package_tar`], with the ownership every member names spelled out.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct part of the archive this builds"
)]
fn package_tar_owned(
    name: &str,
    version: &str,
    script: Option<&str>,
    extra: &[(&str, &str)],
    depends: &[&str],
    backups: &[&str],
    uid: u64,
    gid: u64,
) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let mut add = |path: &str, contents: &[u8], directory: bool| {
        let mut header = tar::Header::new_gnu();
        header.set_mode(if directory { 0o755 } else { 0o644 });
        header.set_uid(uid);
        header.set_gid(gid);
        header.set_mtime(0);
        header.set_size(contents.len() as u64);
        if directory {
            header.set_entry_type(tar::EntryType::Directory);
        }
        header.set_cksum();
        builder.append_data(&mut header, path, contents).unwrap();
    };

    add(".PKGINFO", pkginfo(name, version, depends, backups).as_bytes(), false);
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
    /// refused. `Policy::for_package` asks for a check, and no `.sig` is beside the file.
    /// `piko_sig::decide` resolves zero signatures under `Required` as a rejection, without ever
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

    /// Adds a `RootDir` directive to `[options]`, pointing at this sandbox's own root.
    ///
    /// Rewritten rather than appended, for the reason [`Sandbox::set_hold_pkg`] states. A
    /// subcommand with no `--root` flag of its own reads this, the way `piko check` and
    /// `piko owns` both do.
    fn set_root_dir(&self) {
        let conf = std::fs::read_to_string(self.path("pacman.conf")).unwrap();
        let patched = conf.replace(
            "[options]\n",
            &format!("[options]\nRootDir = {}/\n", self.path("root").display()),
        );
        assert_ne!(patched, conf, "the [options] section moved; fix this helper");
        std::fs::write(self.path("pacman.conf"), patched).unwrap();
    }

    /// Runs `piko owns` for `targets`. Reads `RootDir` from the sandbox's `pacman.conf`, so
    /// [`Sandbox::set_root_dir`] must have run first.
    fn run_owns(&self, targets: &[&str], extra: &[&str]) -> Output {
        let mut command = Command::new(PIKO);
        command
            .arg("owns")
            .arg("--config")
            .arg(self.path("pacman.conf"))
            .arg("--dbpath")
            .arg(self.path("db"))
            .stdin(Stdio::null())
            .args(extra)
            .args(targets);
        command.output().unwrap()
    }

    /// Adds a `HoldPkg` directive to `[options]`, as `/etc/pacman.conf` ships with.
    ///
    /// Rewritten rather than appended. `[options]` is the first section in the file
    /// [`Sandbox::build`] writes. A line appended to the end would land inside `[test]`, where
    /// `HoldPkg` is not a valid directive.
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

    /// Runs `piko merge`, answering the prompts with `answer` when one is given.
    ///
    /// `--diffprog` and `--mergeprog` are pointed at `true`, a program that starts, prints
    /// nothing and succeeds. A test here checks what piko does with a pair, not what an
    /// external program shows.
    fn run_merge(&self, extra: &[&str], answer: Option<&str>) -> Output {
        let mut command = Command::new(PIKO);
        command
            .arg("merge")
            .arg("--config")
            .arg(self.path("pacman.conf"))
            .arg("--root")
            .arg(self.path("root"))
            .arg("--dbpath")
            .arg(self.path("db"))
            .arg("--diffprog")
            .arg("true")
            .arg("--mergeprog")
            .arg("true")
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let Some(answer) = answer else {
            return command.stdin(Stdio::null()).output().unwrap();
        };
        let mut child = command.stdin(Stdio::piped()).spawn().unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), answer.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    }

    /// Installs a package that ships `etc/foo.conf` and declares it as a `%BACKUP%` path.
    fn install_with_backup(&self, version: &str, shipped: &str) -> Output {
        std::fs::write(
            self.path(&format!("cache/conf-{version}-x86_64.pkg.tar")),
            package_tar_with_backups(
                "conf",
                version,
                &[("etc/foo.conf", shipped)],
                &["etc/foo.conf"],
            ),
        )
        .unwrap();
        self.write_repo(&[("conf", version, &[])]);
        self.run_install(&["conf"], &[])
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
    /// `update` refreshes every configured repository before planning, unless `--norefresh` is
    /// in `extra`. A sandbox built with [`Self::new`] carries no `Server`, so it has nowhere to
    /// refresh from. Any test exercising solve or apply logic against a hand-written
    /// [`Self::write_repo`] fixture must therefore pass `--norefresh`.
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

/// What piko says when a scriptlet was attempted and did not succeed.
///
/// The exec helper reports its own reason and exits `ExitCode::FAILURE`. So this line reads the
/// same whether the failure was the `chroot` or the `exec` that follows it. It is the evidence
/// that the scriptlet was tried and its failure surfaced, rather than swallowed.
const SCRIPTLET_FAILED: &str = "post_install scriptlet exited with status 1";

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

/// The root is a temporary directory holding only the package's own files, so the scriptlet
/// cannot run. It fails at one of two points, and the privileges of whoever runs the suite
/// decide which. `chroot` is refused without `CAP_SYS_CHROOT`. Where `chroot` is granted, the
/// `exec` that follows finds no `/bin/sh` inside the root. Both are the same answer, and
/// `SCRIPTLET_FAILED` is what both spell.
///
/// That is not a gap in coverage. It is the security property, asserted directly. The command
/// must fail closed, and never fall back to running on the host. So everything below checks
/// that piko reached the point of trying, and reported honestly when it could not. It does not
/// check a scriptlet's side effects.
///
/// The chroot path itself is exercised by `chrooted_scriptlets_and_hooks_really_run`, which
/// needs an unprivileged user namespace and is `#[ignore]`d.
#[test]
fn a_scriptlet_that_cannot_enter_the_root_fails_closed() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", Some(SCRIPT));

    let output = sandbox.install("1.0.0-1", &[]);
    let seen = text(&output);

    assert!(output.status.success(), "the install itself should still succeed:\n{seen}");
    assert!(seen.contains(SCRIPTLET_FAILED), "the scriptlet's failure was not reported:\n{seen}");
    assert!(
        seen.contains("could not enter the root") || seen.contains("could not run /bin/sh"),
        "the scriptlet failed for neither of the two reasons the root allows:\n{seen}"
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
/// The hook fails because `/bin/false` cannot be reached inside a root that holds neither it
/// nor a `chroot` this process may enter. That is a perfectly good failure for the purpose:
/// what is under test is that the *transaction* stops and leaves no trace.
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

/// An `AbortOnFail` refusal must name its cause, even when the hook printed nothing.
///
/// A hook that never ran has no output to show. The refusal is then the only place the cause
/// can appear. The report that carries the ordinary warning is not returned when the commit
/// fails.
#[test]
fn an_abort_on_fail_refusal_names_a_cause_the_hook_never_printed() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    sandbox.write_hook(
        "00-abort.hook",
        "[Trigger]\nOperation = Install\nType = Package\nTarget = *\n\n\
         [Action]\nDescription = Creating a snapshot...\nWhen = PreTransaction\n\
         Depends = definitely-not-installed\nExec = /bin/true\nAbortOnFail\n",
    );

    let output = sandbox.install("1.0.0-1", &[]);
    let seen = text(&output);

    assert!(!output.status.success(), "the transaction should have been refused:\n{seen}");
    assert!(seen.contains("AbortOnFail"), "{seen}");
    assert!(
        seen.contains("nothing installed satisfies definitely-not-installed"),
        "the refusal did not say why the hook failed:\n{seen}"
    );
    assert!(!sandbox.path("root/usr/bin/foo").exists(), "files were written anyway");
}

/// A hook whose trigger does not match must not run at all.
#[test]
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
/// `Exec` their own package owns, and only 8 declare a `Depends`. So `Depends` is not what
/// protects them. libalpm reads the hook directories inside `_alpm_hook_run` (`hook.c:536`),
/// called once before the transaction and once after (`trans.c:202`, `trans.c:238`). So the
/// `PostTransaction` pass simply never finds the file.
///
/// The two halves are asserted together on purpose. Without the `PreTransaction` hook running,
/// the absence of the `PostTransaction` one would prove nothing. A trigger that never matched
/// looks exactly the same.
#[test]
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

    // The hook directory is inside the root here, matching the real layout. With pacman's own
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

    // Both hooks fail, because `/bin/true` cannot be reached inside this root, so each one
    // that runs names itself in a warning. That is the signal both assertions read.
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
/// upgrade. The reader then finds two entries for one name and keeps the older one. The database
/// reports a version that is not on disk.
#[test]
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
/// before extracting. Without that run, a package that drops a file between versions leaves it
/// on disk owned by nobody. The entry that named it has just been replaced.
///
/// The two halves are asserted together on purpose. Deleting the dropped file is only correct
/// if everything both versions ship survives, holding the new content. A removal that ran after
/// extraction instead of before would pass the first assertion and fail the second.
#[test]
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

/// `piko install <name>` must resolve through the repository and pull in a dependency. It
/// records the named target as `Explicit` and the pulled-in package as `Depend`. This is what
/// turns `install` from "extract this file" into "`piko plan` as a transaction".
#[test]
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

/// A force-removed dependency must not make every later transaction plan its dependents away.
///
/// This runs the real binary. `foo` depends on `bar`, `bar` is taken out with `--nodeps`
/// (pacman's `-Rdd`), and something unrelated is installed afterwards. `alpm_checkdeps` raises
/// a dependency of an installed package only when the transaction itself breaks it
/// (`deps.c:369`). So the plan must not touch `foo`, and must not reinstall `bar` to repair
/// the dependency either.
#[test]
fn a_force_removed_dependency_does_not_take_its_dependents_with_it() {
    let sandbox = Sandbox::new();
    write_package_depending_on(&sandbox.path("cache"), "foo", "1.0.0-1", &["bar"]);
    write_package_with(&sandbox.path("cache"), "bar", "1.0.0-1", None, &[]);
    write_package_with(&sandbox.path("cache"), "baz", "1.0.0-1", None, &[]);
    write_package_with(&sandbox.path("cache"), "qux", "1.0.0-1", None, &[]);
    sandbox.write_repo(&[
        ("foo", "1.0.0-1", &["bar"]),
        ("bar", "1.0.0-1", &[]),
        ("baz", "1.0.0-1", &[]),
    ]);
    assert!(sandbox.run_install(&["foo"], &[]).status.success());

    let removed = sandbox.run_remove(&["bar"], &["--nodeps", "--noconfirm"], None);
    assert!(removed.status.success(), "--nodeps did not remove bar:\n{}", text(&removed));
    assert!(!sandbox.path("root/usr/bin/bar").exists(), "bar survived the forced removal");

    // First, with `bar` still in the repository. An available satisfier is not a reason to
    // repair the dependency. pacman leaves it unmet, and so does piko.
    let output = sandbox.run_install(&["baz"], &[]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("1 to install"), "the plan was more than the named target:\n{seen}");
    assert!(!sandbox.path("root/usr/bin/bar").exists(), "the broken dependency was repaired");
    assert!(!seen.contains(BROKEN_WARNING), "install was asked about baz, not foo:\n{seen}");

    // Then with `bar` gone from the repository too. This is the reported system's shape: a
    // dependency no repository can supply, so the clause would have no satisfier at all.
    sandbox.write_repo(&[("foo", "1.0.0-1", &["bar"]), ("qux", "1.0.0-1", &[])]);
    let output = sandbox.run_install(&["qux"], &[]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");

    assert!(!seen.contains("remove    foo"), "foo was planned away over a broken dep:\n{seen}");
    assert!(seen.contains("1 to install"), "the plan was more than the named target:\n{seen}");
    assert!(sandbox.path("db/local/foo-1.0.0-1").exists(), "foo's entry was removed");
    assert!(sandbox.path("root/usr/bin/foo").exists(), "foo's files were removed");
}

/// The line `piko update` prints for a dependency nothing installed answers.
const BROKEN_WARNING: &str = "Warning: foo requires bar, which nothing installed provides";

/// Only `piko update` reports a dependency that was broken before it ran.
///
/// `update` decides something about every installed package, so pre-existing state of an
/// untouched one is its business. `install` and `remove` were asked about their targets. pacman
/// reports this at no point at all, so the choice of command is piko's own.
#[test]
fn only_a_sysupgrade_reports_a_dependency_broken_before_it_ran() {
    let sandbox = Sandbox::new();
    write_package_depending_on(&sandbox.path("cache"), "foo", "1.0.0-1", &["bar"]);
    write_package_with(&sandbox.path("cache"), "bar", "1.0.0-1", None, &[]);
    write_package_with(&sandbox.path("cache"), "baz", "1.0.0-1", None, &[]);
    sandbox.write_repo(&[
        ("foo", "1.0.0-1", &["bar"]),
        ("bar", "1.0.0-1", &[]),
        ("baz", "1.0.0-1", &[]),
    ]);
    assert!(sandbox.run_install(&["foo"], &[]).status.success());
    assert!(sandbox.run_remove(&["bar"], &["--nodeps", "--noconfirm"], None).status.success());

    // `bar` leaves the repository too, so no transaction can answer `foo`'s dependency.
    sandbox.write_repo(&[("foo", "1.0.0-1", &["bar"]), ("baz", "1.0.0-1", &[])]);

    let installing = text(&sandbox.run_install(&["baz"], &[]));
    assert!(!installing.contains(BROKEN_WARNING), "install must stay quiet:\n{installing}");

    let removing = text(&sandbox.run_remove(&["baz"], &["--noconfirm"], None));
    assert!(!removing.contains(BROKEN_WARNING), "remove must stay quiet:\n{removing}");

    // No `Server` is configured in this sandbox, so the refresh a real `update` runs first has
    // nowhere to go.
    let updating = text(&sandbox.run_update(&[], &["--norefresh"]));
    assert!(updating.contains(BROKEN_WARNING), "update must report it:\n{updating}");
}

/// `--asdeps` must apply to the named target too, not only to what it pulls in.
#[test]
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
/// what the directive exists to prevent. So the flag must not be an escape hatch from it.
#[test]
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
/// The answer is `y\ny\n` because two questions come in a row. First the guard's, then the
/// ordinary "Do you want to remove these packages?". Their order is asserted rather than
/// assumed. pacman warns and asks about `HoldPkg` before displaying the target list
/// (`remove.c:133-145`, above `display_targets`). So the warning is not buried under a plan.
#[test]
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
/// The two presets are the whole difference between pacman's `yesno` and `noyes`. A shared
/// prompt helper that ignored the default would pass the accept case above and still be wrong
/// here.
#[test]
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
/// and `update` has nothing to do. That is also what makes this the honest test of the flag.
/// The same sandbox answers differently with and without it. A `--downgrade` that stopped
/// reaching `InstallOptions::sysupgrade` would leave the second half reporting "nothing to do".
/// It would not silently do the right thing anyway.
///
/// Pinned because `install` and `update` share one dispatch helper (`main::sync`). `sysupgrade`
/// is one of exactly two fields that tell the two subcommands apart. The other, `as_deps`, is
/// covered by `asdeps_downgrades_the_named_target_as_well`.
#[test]
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
        seen.contains("Nothing to do"),
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

/// A system already at the newest available version has nothing to do. `update` must say so,
/// rather than show an empty plan and ask about it.
#[test]
fn update_with_nothing_pending_reports_it() {
    let sandbox = Sandbox::new();
    write_package_with(&sandbox.path("cache"), "foo", "1.0.0-1", None, &[]);
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);
    assert!(sandbox.run_install(&["foo"], &[]).status.success());

    let output = sandbox.run_update(&[], &["--norefresh"]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("Nothing to do"), "{seen}");
}

/// `update` must apply a `%REPLACES%` pair: install the replacement and remove what it
/// replaces, both shown in the plan before anything happens.
#[test]
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

/// `update` refreshes every configured repository before planning, `pacman -Syu`. The sandbox's
/// `[test]` repository is never written to disk directly, since nothing calls
/// [`Sandbox::write_repo`]. So the only way `db/sync/test.db` can exist afterwards is if
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
    assert!(seen.contains("Nothing to do"), "{seen}");
    assert!(
        sandbox.path("db/sync/test.db").exists(),
        "update did not refresh the database:\n{seen}"
    );
}

/// `--norefresh` skips the pre-plan refresh entirely, `pacman -Su`. `Server` points at a port
/// with nothing listening, so any connection attempt fails immediately. Success here is direct
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
    assert!(seen.contains("Nothing to do"), "{seen}");
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

/// `-w` with `ParallelDownloads > 1` fetches every package exactly once and verifies each one.
///
/// Three packages, so more than one worker has something to do. The run has two halves: one
/// `prefetch` phase, then a per-package loop that locates and checks each file. Both halves
/// must cover all three packages. The request count pins the fetch. The "Verifying signatures"
/// row pins the check.
#[test]
fn download_only_fetches_and_verifies_every_package_in_parallel() {
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
            sandbox.path(&format!("cache/{name}-1.0.0-1-x86_64.pkg.tar")).exists(),
            "{name} did not land in the cache:\n{seen}"
        );
    }
    assert!(seen.contains("Downloading packages"), "no download phase was shown:\n{seen}");
    assert!(seen.contains("Verifying signatures"), "no verification phase was shown:\n{seen}");
    assert_eq!(served.load(Ordering::SeqCst), names.len(), "not every package was fetched");
}

/// A package that is not in the cache is downloaded from the repository's `Server` before it
/// is installed. This is the whole point of [`piko_txn::source::DownloadingSource`].
#[test]
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

/// `--downloadonly` fetches the package into the cache and installs nothing at all. No files
/// under `--root`, no database entry, and no journal or lock touched.
#[test]
fn download_only_downloads_without_installing() {
    let bytes = package_tar("foo", "1.0.0-1", None, &[]);
    let sandbox = Sandbox::with_server(&serve_once(bytes.clone()));
    sandbox.write_repo(&[("foo", "1.0.0-1", &[])]);

    let output = sandbox.run_install(&["foo"], &["--downloadonly"]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    // `-w` reports the phases it ran, not a per-package summary. The cache holds the result,
    // and the assertions below read it there.
    assert!(seen.contains("Downloading packages"), "no download phase was shown:\n{seen}");
    assert!(seen.contains("Verifying signatures"), "no verification phase was shown:\n{seen}");

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

/// `--downloadonly` verifies what it has. An unsigned package under `SigLevel = Required` is
/// refused there, not left in the cache for a later install to complain about.
///
/// libalpm orders it the same way. `check_validity` (`sync.c:1275`) runs before
/// `_alpm_sync_load` returns on `ALPM_TRANS_FLAG_DOWNLOADONLY` (`sync.c:1279`). This test pins
/// that ordering.
///
/// The package is pre-cached rather than served, which checks the same thing for the same
/// reason. `check_validity` runs over `_alpm_filecache_find`'s answer, so a file already in the
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
        !sandbox.path("root/usr/bin/foo").exists(),
        "the refused package was installed anyway:\n{seen}"
    );
}

/// `--root /` skips the `chroot(2)` call, as libalpm does, to run with fewer capabilities. The
/// working directory still has to end up at `/`. A scriptlet is free to use a path relative to
/// the root. gstreamer's real `post_upgrade` does exactly that, running `setcap` on
/// `usr/lib/gstreamer-1.0/gst-ptp-helper` with no leading slash.
///
/// No privilege is needed to exercise this. With `root == "/"` the helper never calls `chroot`
/// at all. So this runs as an ordinary process, launched from a directory that is deliberately
/// not `/`. It only checks what directory the command sees. It writes nothing, and touches no
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
    write_package_as_root(&sandbox.path("cache"), "1.0.0-1", Some(SCRIPT));
    write_package_as_root(&sandbox.path("cache"), "2.0.0-1", Some(SCRIPT));
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
// Every sandbox writes a `LogFile` into its own temporary directory. So these read the same two
// files a real run writes, and never touch `/var/log/pacman.log`.
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
/// failure, not left looking like a run that never happened. That is the state the journal is
/// deleted for, and the log is what remains to say so.
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
/// `ALPM_ERR_BADPERMS` here, and piko does not. The history store beside the database is the
/// record that must not be lost, and refusing would break bootstrapping a fresh root.
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
    assert!(output.status.success(), "the log stopped the transaction:\n{seen}");
    assert!(!seen.contains("no transactions"), "{seen}");
    assert!(sandbox.path("db/local/foo-1.0.0-1/desc").is_file(), "the install did not land");
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
/// share. So an install, a removal and an upgrade are told apart by shape, not only by a word.
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

/// The duplication this rendering exists to remove. Take a transaction with one action and no
/// recorded command line. It prints that action in the header only. Nothing repeats it below.
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
    assert!(seen.contains("No transactions recorded"), "{seen}");
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
#[test]
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
fn a_removal_is_recorded_with_the_version_that_went() {
    let sandbox = Sandbox::new();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    assert!(sandbox.install("1.0.0-1", &[]).status.success());
    assert!(sandbox.run_remove(&["foo"], &["--noconfirm"], None).status.success());

    assert!(sandbox.log().contains("removed foo (1.0.0-1)"), "{}", sandbox.log());
    assert!(sandbox.history().contains("removed foo 1.0.0-1"), "{}", sandbox.history());
}

// --- Glob targets ---------------------------------------------------------------------------
//
// A pattern is a rewrite of the target list. So these check three things: that the rewrite
// happened, that its cause was printed, and that nothing else about the transaction changed.

/// The whole claim, end to end: `app-*` installs exactly the packages whose names it matches,
/// and says which they were.
#[test]
fn a_glob_install_target_expands_to_every_matching_repository_package() {
    let sandbox = Sandbox::new();
    for name in ["app-a", "app-b", "other"] {
        write_package_with(&sandbox.path("cache"), name, "1.0.0-1", None, &[]);
    }
    sandbox.write_repo(&[
        ("app-a", "1.0.0-1", &[][..]),
        ("app-b", "1.0.0-1", &[][..]),
        ("other", "1.0.0-1", &[][..]),
    ]);

    let output = sandbox.run_install(&["app-*"], &[]);
    let seen = text(&output);

    assert!(output.status.success(), "{seen}");
    assert!(
        seen.contains("Note: app-* matched 2 packages"),
        "the expansion was not reported:\n{seen}"
    );
    assert!(sandbox.path("db/local/app-a-1.0.0-1").is_dir(), "{seen}");
    assert!(sandbox.path("db/local/app-b-1.0.0-1").is_dir(), "{seen}");
    assert!(
        !sandbox.path("db/local/other-1.0.0-1").exists(),
        "a package the pattern does not match was installed:\n{seen}"
    );
}

/// A pattern that selects nothing is a refused transaction, not an empty successful one.
#[test]
fn a_glob_install_target_that_matches_nothing_installs_nothing() {
    let sandbox = Sandbox::new();
    sandbox.write_repo(&[("app-a", "1.0.0-1", &[][..])]);

    let output = sandbox.run_install(&["zzz-*"], &[]);
    let seen = text(&output);

    assert!(!output.status.success(), "an unmatched pattern succeeded:\n{seen}");
    assert!(seen.contains("no package or group matching zzz-*"), "{seen}");
    assert!(!sandbox.path("db/local/app-a-1.0.0-1").exists(), "{seen}");
}

/// A pattern carrying a version requirement has two honest readings, so it is refused rather
/// than guessed at.
#[test]
fn a_versioned_glob_target_is_refused() {
    let sandbox = Sandbox::new();
    sandbox.write_repo(&[("app-a", "1.0.0-1", &[][..])]);

    let output = sandbox.run_install(&["app-*>=1.0"], &[]);
    let seen = text(&output);

    assert!(!output.status.success(), "{seen}");
    assert!(seen.contains("glob pattern with a version requirement"), "{seen}");
}

/// `classify`'s path rule fires before the pattern rule, and a `Name` cannot hold a `/`. So a
/// path-shaped target stays a file target even when it carries a metacharacter.
#[test]
fn a_glob_is_never_taken_for_a_file_target() {
    let sandbox = Sandbox::new();
    sandbox.write_repo(&[("app-a", "1.0.0-1", &[][..])]);

    let output = sandbox.run_install(&["./app-*.pkg.tar.zst"], &[]);
    let seen = text(&output);

    assert!(!output.status.success(), "{seen}");
    assert!(
        !seen.contains("matched") && !seen.contains("no package or group matching"),
        "a path was read as a pattern:\n{seen}"
    );
}

#[test]
fn a_glob_remove_target_removes_every_matching_installed_package() {
    let sandbox = Sandbox::new();
    for name in ["app-a", "app-b", "other"] {
        write_package_with(&sandbox.path("cache"), name, "1.0.0-1", None, &[]);
    }
    sandbox.write_repo(&[
        ("app-a", "1.0.0-1", &[][..]),
        ("app-b", "1.0.0-1", &[][..]),
        ("other", "1.0.0-1", &[][..]),
    ]);
    assert!(sandbox.run_install(&["app-a", "app-b", "other"], &[]).status.success());

    let output = sandbox.run_remove(&["app-*"], &["--noconfirm"], None);
    let seen = text(&output);

    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("Note: app-* matched 2 packages"), "{seen}");
    assert!(!sandbox.path("db/local/app-a-1.0.0-1").exists(), "{seen}");
    assert!(!sandbox.path("db/local/app-b-1.0.0-1").exists(), "{seen}");
    assert!(sandbox.path("db/local/other-1.0.0-1").is_dir(), "{seen}");
}

/// `HoldPkg` is the guard a glob removal needs. It runs over the *solved* removal set rather
/// than the names typed, and `--noconfirm` answers no to it. That is why an unattended pattern
/// needs no second guard.
#[test]
fn a_glob_remove_target_is_still_subject_to_hold_pkg() {
    let sandbox = Sandbox::new();
    for name in ["app-a", "app-b"] {
        write_package_with(&sandbox.path("cache"), name, "1.0.0-1", None, &[]);
    }
    sandbox.write_repo(&[("app-a", "1.0.0-1", &[][..]), ("app-b", "1.0.0-1", &[][..])]);
    assert!(sandbox.run_install(&["app-a", "app-b"], &[]).status.success());
    sandbox.set_hold_pkg("app-a");

    let output = sandbox.run_remove(&["app-*"], &["--noconfirm"], None);
    let seen = text(&output);

    assert!(!output.status.success(), "a held package was removed by a pattern:\n{seen}");
    assert!(seen.contains("app-a is designated as a HoldPkg"), "{seen}");
    assert!(sandbox.path("db/local/app-a-1.0.0-1").is_dir(), "{seen}");
    assert!(sandbox.path("db/local/app-b-1.0.0-1").is_dir(), "{seen}");
}

/// The `--nodeps` path expands too, and against package names only. It resolves a target with
/// `LocalDatabase::get_str` alone, and takes no group name.
#[test]
fn a_glob_remove_target_works_on_the_nodeps_path() {
    let sandbox = Sandbox::new();
    for name in ["app-a", "app-b"] {
        write_package_with(&sandbox.path("cache"), name, "1.0.0-1", None, &[]);
    }
    sandbox.write_repo(&[("app-a", "1.0.0-1", &[][..]), ("app-b", "1.0.0-1", &[][..])]);
    assert!(sandbox.run_install(&["app-a", "app-b"], &[]).status.success());

    let output = sandbox.run_remove(&["app-*"], &["--noconfirm", "--nodeps"], None);
    let seen = text(&output);

    assert!(output.status.success(), "{seen}");
    assert!(!sandbox.path("db/local/app-a-1.0.0-1").exists(), "{seen}");
    assert!(!sandbox.path("db/local/app-b-1.0.0-1").exists(), "{seen}");
}

/// `piko owns` names a package piko itself installed, through the real binary.
///
/// The library tests cover the resolution rules. This covers the wiring: the argument parsing,
/// the `RootDir` resolution a subcommand with no `--root` flag depends on, and the line format.
#[test]
fn owns_names_the_package_that_installed_a_file() {
    let sandbox = Sandbox::new();
    sandbox.set_root_dir();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    let seen = text(&sandbox.install("1.0.0-1", &[]));
    assert!(sandbox.path("root/usr/bin/foo").exists(), "{seen}");

    let installed = sandbox.path("root/usr/bin/foo");
    let target = installed.to_str().unwrap();

    let output = sandbox.run_owns(&[target], &[]);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("{target} is owned by foo 1.0.0-1")
    );

    // `--quiet` drops the path and the version, as `pacman -Qoq` does.
    let quiet = sandbox.run_owns(&[target], &["--quiet"]);
    assert!(quiet.status.success(), "{}", text(&quiet));
    assert_eq!(String::from_utf8_lossy(&quiet.stdout).trim(), "foo");

    // A directory the package owns names it too, and the answer carries the trailing slash.
    let directory = sandbox.path("root/usr/bin").to_str().unwrap().to_owned();
    let dir_output = sandbox.run_owns(&[&directory], &["--quiet"]);
    assert!(dir_output.status.success(), "{}", text(&dir_output));
    assert_eq!(String::from_utf8_lossy(&dir_output.stdout).trim(), "foo");
}

/// An unowned path is reported and fails, and it does not stop the paths beside it.
#[test]
fn owns_continues_past_a_path_nothing_owns() {
    let sandbox = Sandbox::new();
    sandbox.set_root_dir();
    write_package(&sandbox.path("cache"), "1.0.0-1", None);
    let seen = text(&sandbox.install("1.0.0-1", &[]));
    assert!(sandbox.path("root/usr/bin/foo").exists(), "{seen}");

    let owned = sandbox.path("root/usr/bin/foo").to_str().unwrap().to_owned();
    let stray = sandbox.path("root/usr/bin/stray").to_str().unwrap().to_owned();
    std::fs::write(&stray, b"").unwrap();

    let output = sandbox.run_owns(&[&stray, &owned], &["--quiet"]);
    let seen = text(&output);
    assert!(!output.status.success(), "an unowned path must fail the run: {seen}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "foo",
        "the owned path was still answered: {seen}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(&format!("No package owns {stray}")),
        "{seen}"
    );
}

/// An upgrade that leaves a `.pacnew` says so once the transaction is over, and `piko merge`
/// then finds the same file.
///
/// The transaction reports and stops. Resolving a configuration file is an irreversible act
/// with no safe default, so it is never asked for here.
#[test]
fn an_upgrade_that_leaves_a_pacnew_says_so_after_the_transaction() {
    let sandbox = Sandbox::new();
    sandbox.install_with_backup("1.0.0-1", "shipped by version one");
    std::fs::write(sandbox.path("root/etc/foo.conf"), b"edited by the user").unwrap();

    let output = sandbox.install_with_backup("2.0.0-1", "shipped by version two");
    let printed = text(&output);

    assert!(printed.contains("Configuration files need attention"), "{printed}");
    assert!(printed.contains("foo.conf.pacnew"), "{printed}");
    assert!(printed.contains("Run 'piko merge' to resolve them."), "{printed}");
    assert!(!printed.contains("(V)iew"), "{printed}");
    assert!(!printed.contains("Resolve them now"), "{printed}");

    assert_eq!(std::fs::read(sandbox.path("root/etc/foo.conf")).unwrap(), b"edited by the user");
    let listed = text(&sandbox.run_merge(&["--output"], None));
    assert!(listed.contains("etc/foo.conf.pacnew"), "{listed}");
}

/// `--output` is the non-interactive mode. It lists and changes nothing.
#[test]
fn merge_output_lists_a_pacnew_and_changes_nothing() {
    let sandbox = Sandbox::new();
    sandbox.install_with_backup("1.0.0-1", "shipped by version one");
    std::fs::write(sandbox.path("root/etc/foo.conf"), b"edited by the user").unwrap();
    sandbox.install_with_backup("2.0.0-1", "shipped by version two");

    let output = sandbox.run_merge(&["--output"], None);

    assert!(output.status.success(), "{}", text(&output));
    assert!(text(&output).contains("etc/foo.conf.pacnew"), "{}", text(&output));
    assert!(sandbox.path("root/etc/foo.conf.pacnew").exists());
    assert_eq!(std::fs::read(sandbox.path("root/etc/foo.conf")).unwrap(), b"edited by the user");
}

/// A pending file holding the target's bytes carries nothing, so it goes without a question.
/// Stdin is closed, which proves no question was asked.
#[test]
fn merge_removes_a_pacnew_identical_to_the_installed_file_without_asking() {
    let sandbox = Sandbox::new();
    sandbox.install_with_backup("1.0.0-1", "shipped by version one");
    std::fs::write(sandbox.path("root/etc/foo.conf"), b"edited by the user").unwrap();
    sandbox.install_with_backup("2.0.0-1", "shipped by version two");
    // Make the two agree behind piko's back.
    std::fs::write(sandbox.path("root/etc/foo.conf"), b"shipped by version two").unwrap();

    let output = sandbox.run_merge(&[], None);

    assert!(output.status.success(), "{}", text(&output));
    assert!(!sandbox.path("root/etc/foo.conf.pacnew").exists());
    assert_eq!(
        std::fs::read(sandbox.path("root/etc/foo.conf")).unwrap(),
        b"shipped by version two"
    );
}

/// A closed stdin quits rather than skipping every file. "Everything skipped" and "everything
/// resolved" would otherwise exit the same way.
#[test]
fn merge_quits_on_a_closed_stdin_rather_than_skipping_everything() {
    let sandbox = Sandbox::new();
    sandbox.install_with_backup("1.0.0-1", "shipped by version one");
    std::fs::write(sandbox.path("root/etc/foo.conf"), b"edited by the user").unwrap();
    sandbox.install_with_backup("2.0.0-1", "shipped by version two");

    let output = sandbox.run_merge(&[], None);

    assert!(output.status.success(), "{}", text(&output));
    assert!(sandbox.path("root/etc/foo.conf.pacnew").exists());
    assert_eq!(std::fs::read(sandbox.path("root/etc/foo.conf")).unwrap(), b"edited by the user");
}

#[test]
fn merge_overwrite_moves_the_pacnew_into_place() {
    let sandbox = Sandbox::new();
    sandbox.install_with_backup("1.0.0-1", "shipped by version one");
    std::fs::write(sandbox.path("root/etc/foo.conf"), b"edited by the user").unwrap();
    sandbox.install_with_backup("2.0.0-1", "shipped by version two");

    let output = sandbox.run_merge(&[], Some("o\n"));

    assert!(output.status.success(), "{}", text(&output));
    assert!(!sandbox.path("root/etc/foo.conf.pacnew").exists());
    assert_eq!(
        std::fs::read(sandbox.path("root/etc/foo.conf")).unwrap(),
        b"shipped by version two"
    );
}

#[test]
fn merge_remove_deletes_only_the_pacnew() {
    let sandbox = Sandbox::new();
    sandbox.install_with_backup("1.0.0-1", "shipped by version one");
    std::fs::write(sandbox.path("root/etc/foo.conf"), b"edited by the user").unwrap();
    sandbox.install_with_backup("2.0.0-1", "shipped by version two");

    let output = sandbox.run_merge(&[], Some("r\n"));

    assert!(output.status.success(), "{}", text(&output));
    assert!(!sandbox.path("root/etc/foo.conf.pacnew").exists());
    assert_eq!(std::fs::read(sandbox.path("root/etc/foo.conf")).unwrap(), b"edited by the user");
}

/// A numbered `.pacsave` has no current version to merge against, so it is named and left
/// alone. `pacdiff` warns about these once at the end too.
#[test]
fn a_numbered_pacsave_is_reported_and_never_offered() {
    let sandbox = Sandbox::new();
    sandbox.install_with_backup("1.0.0-1", "shipped by version one");
    std::fs::write(sandbox.path("root/etc/foo.conf.pacsave.1"), b"an older save").unwrap();

    let output = sandbox.run_merge(&[], Some("q\n"));

    let printed = text(&output);
    assert!(printed.contains("foo.conf.pacsave.1"), "{printed}");
    assert!(printed.contains("no current version to merge against"), "{printed}");
    assert!(!printed.contains("(V)iew"), "{printed}");
    assert_eq!(
        std::fs::read(sandbox.path("root/etc/foo.conf.pacsave.1")).unwrap(),
        b"an older save"
    );
}

/// A second removal must not write over the first save. Both are the user's own edits.
#[test]
fn a_second_removal_rotates_the_first_pacsave() {
    let sandbox = Sandbox::new();

    for edit in [b"first edit".as_slice(), b"second edit"] {
        sandbox.install_with_backup("1.0.0-1", "shipped by the package");
        std::fs::write(sandbox.path("root/etc/foo.conf"), edit).unwrap();
        let output = sandbox.run_remove(&["conf"], &["--noconfirm"], None);
        assert!(output.status.success(), "{}", text(&output));
    }

    assert_eq!(std::fs::read(sandbox.path("root/etc/foo.conf.pacsave")).unwrap(), b"second edit");
    assert_eq!(std::fs::read(sandbox.path("root/etc/foo.conf.pacsave.1")).unwrap(), b"first edit");
}

/// The recap names what this transaction wrote, and nothing else. A `.pacnew` left by an
/// earlier transaction belongs to `piko merge`.
#[test]
fn the_recap_names_only_what_this_transaction_wrote() {
    let sandbox = Sandbox::new();

    // An older pending file, from a package this transaction never touches.
    std::fs::write(
        sandbox.path("cache/other-1.0.0-1-x86_64.pkg.tar"),
        package_tar_with_backups(
            "other",
            "1.0.0-1",
            &[("etc/other.conf", "shipped")],
            &["etc/other.conf"],
        ),
    )
    .unwrap();
    sandbox.write_repo(&[("other", "1.0.0-1", &[])]);
    assert!(sandbox.run_install(&["other"], &[]).status.success());
    std::fs::write(sandbox.path("root/etc/other.conf"), b"edited long ago").unwrap();
    std::fs::write(sandbox.path("root/etc/other.conf.pacnew"), b"from an old upgrade").unwrap();

    // Now a transaction that leaves one of its own.
    sandbox.install_with_backup("1.0.0-1", "shipped by version one");
    std::fs::write(sandbox.path("root/etc/foo.conf"), b"edited by the user").unwrap();
    let printed = text(&sandbox.install_with_backup("2.0.0-1", "shipped by version two"));

    assert!(printed.contains("foo.conf.pacnew"), "{printed}");
    assert!(!printed.contains("other.conf.pacnew"), "{printed}");

    // `piko merge` on its own still lists both.
    let listed = text(&sandbox.run_merge(&["--output"], None));
    assert!(listed.contains("etc/foo.conf.pacnew"), "{listed}");
    assert!(listed.contains("etc/other.conf.pacnew"), "{listed}");
}

/// A path names a pair however it is spelled, and the rest of the list is left alone.
#[test]
fn merge_resolves_only_the_path_it_was_given() {
    let sandbox = Sandbox::new();
    sandbox.install_with_backup("1.0.0-1", "shipped by version one");
    std::fs::write(sandbox.path("root/etc/foo.conf"), b"edited by the user").unwrap();
    sandbox.install_with_backup("2.0.0-1", "shipped by version two");
    std::fs::write(sandbox.path("root/etc/spare.conf.pacnew"), b"not in the selection").unwrap();

    let listed = text(&sandbox.run_merge(&["--output", "/etc/foo.conf"], None));
    assert!(listed.contains("etc/foo.conf.pacnew"), "{listed}");
    assert!(!listed.contains("spare.conf"), "{listed}");

    let output = sandbox.run_merge(&["etc/foo.conf.pacnew"], Some("r\n"));
    assert!(output.status.success(), "{}", text(&output));
    assert!(!sandbox.path("root/etc/foo.conf.pacnew").exists());
}

/// An interactive transaction reports its configuration files and asks nothing about them.
///
/// The prompt this test drives is the install confirmation. Nothing follows it: the recap is
/// the last thing printed, and the run ends with stdin still holding an unread answer.
#[test]
fn an_interactive_transaction_reports_pending_files_without_asking() {
    let sandbox = Sandbox::new();
    sandbox.install_with_backup("1.0.0-1", "shipped by version one");
    std::fs::write(sandbox.path("root/etc/foo.conf"), b"edited by the user").unwrap();

    std::fs::write(
        sandbox.path("cache/conf-2.0.0-1-x86_64.pkg.tar"),
        package_tar_with_backups(
            "conf",
            "2.0.0-1",
            &[("etc/foo.conf", "shipped by version two")],
            &["etc/foo.conf"],
        ),
    )
    .unwrap();
    sandbox.write_repo(&[("conf", "2.0.0-1", &[])]);

    // `y` answers the install confirmation. The second line would answer a follow-up, and is
    // left unread on purpose.
    let mut child = Command::new(PIKO)
        .arg("install")
        .arg("--config")
        .arg(sandbox.path("pacman.conf"))
        .arg("--root")
        .arg(sandbox.path("root"))
        .arg("--dbpath")
        .arg(sandbox.path("db"))
        .arg("--hookdir")
        .arg(sandbox.path("hooks"))
        .arg("conf")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), b"y\nq\n").unwrap();
    let output = child.wait_with_output().unwrap();
    let printed = text(&output);

    assert!(printed.contains("Proceed with installation?"), "{printed}");
    assert!(printed.contains("Configuration files need attention"), "{printed}");
    assert!(printed.contains("Run 'piko merge' to resolve them."), "{printed}");
    assert!(!printed.contains("Resolve them now"), "{printed}");
    assert!(!printed.contains("(V)iew"), "{printed}");

    // Both files are still there, untouched.
    assert_eq!(std::fs::read(sandbox.path("root/etc/foo.conf")).unwrap(), b"edited by the user");
    assert_eq!(
        std::fs::read(sandbox.path("root/etc/foo.conf.pacnew")).unwrap(),
        b"shipped by version two"
    );
}
