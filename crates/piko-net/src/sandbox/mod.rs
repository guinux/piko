//! The download sandbox: every request to a mirror runs in a confined helper process.
//!
//! A mirror is untrusted until its signature is checked, and the code that reads what it sends
//! — DNS, TLS, HTTP — runs before that check. A defect there would otherwise run the mirror's
//! code as root. libalpm answers this with `DownloadUser` and the `sandbox*.c` files. piko answers
//! it the same way, with one difference in shape.
//!
//! # The helper transfers bytes and writes no file
//!
//! libalpm's sandboxed child writes each download into a temporary directory that the download
//! user owns. The parent then takes the file. A child that a mirror took over can leave a
//! process behind that keeps the file open, and change it after the parent checked it.
//!
//! Here the helper makes one request and writes the answer to its stdout, in the frames that
//! `protocol` defines. The parent keeps everything else: the size bound, the atomic write,
//! the `Last-Modified` checks, and the signature check. So the helper needs no write access
//! anywhere, and no file the parent checks was ever open for writing in the helper.
//!
//! # One helper per request
//!
//! A database, its `.sig`, and each package are separate requests, so separate processes. A
//! mirror that took over one helper cannot touch another file's transfer.
//!
//! # Starting the helper without `unsafe`
//!
//! `fork` is `unsafe`, and the workspace forbids `unsafe_code`. So piko starts itself again, as
//! `piko_txn::exec` does for scriptlets, through `/proc/self/exe` with [`HELPER_ARG`]. A program
//! that uses this crate must call [`run_helper_if_requested`] first thing in `main`. The
//! executable path is `/proc/self/exe` rather than [`std::env::current_exe`] for two reasons.
//! The magic link still works after the binary is replaced on disk. And it needs no search
//! permission on the directories above the binary, which the download user may not have.
//!
//! The user switch is `std`'s own `CommandExt::uid`/`gid`, which drop the supplementary groups
//! first. The helper then confines itself before it reads anything: see `confine`.
//!
//! # Never root
//!
//! Under root, the helper always switches to another user: `DownloadUser` when it is set, and
//! [`FALLBACK_USER`] otherwise. libalpm confines nothing without `DownloadUser`. A helper left
//! as root would keep every capability, and the owner's access to every file, which no
//! Landlock or system call rule takes back: it could read the keyring's secret keys, or change
//! the firewall through the netlink socket its resolver needs.

mod confine;
pub(crate) mod protocol;

use std::{
    ffi::OsStr,
    io::{BufWriter, Read, Write as _},
    os::unix::process::CommandExt as _,
    process::{Child, ChildStdout, Command, ExitCode, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    time::{Duration, Instant},
};

use piko_db::config::Options;

use self::protocol::{Header, Opening, Reader, Request, Tag, Writer};
use crate::cancel::Cancel;

/// The user a helper started by root switches to when `pacman.conf` names no `DownloadUser`.
pub const FALLBACK_USER: &str = "nobody";

/// The user and group ids [`FALLBACK_USER`] stands for when it has no account: the kernel's
/// overflow ids, which `nobody` is on every Linux system that has it.
const OVERFLOW_ID: u32 = 65_534;

/// The hidden argument that turns a `piko` process into the download helper.
///
/// It is not a documented subcommand. Anyone can run it, and gains nothing: it fetches one URL
/// with fewer rights than the caller already has.
pub const HELPER_ARG: &str = "__fetch";

/// The executable the helper is started from.
const SELF_EXE: &str = "/proc/self/exe";

/// How long the helper may outlive its own timeout before the parent kills it.
///
/// The helper enforces the request's timeout itself. This bound is for a helper that does not.
const WATCHDOG_GRACE: Duration = Duration::from_secs(5);

/// How often the watchdog looks at the cancellation flag.
const WATCHDOG_TICK: Duration = Duration::from_millis(100);

/// Ports a request may always reach: DNS over TCP, and HTTPS for a redirect.
///
/// HTTP's port 80 is added only for an `http` URL. An `https` URL is followed only to `https`,
/// so it has no use for it.
const ALWAYS_ALLOWED_PORTS: [u16; 2] = [53, 443];

/// HTTP's default port.
const HTTP_PORT: u16 = 80;

/// The proxy variables passed to the helper. Its environment is otherwise empty.
///
/// `SSL_CERT_FILE` and `SSL_CERT_DIR` are passed too, because they choose the CA store the
/// platform verifier reads.
const PASSED_ENVIRONMENT: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// The proxy variables whose port the helper must be able to reach.
const PROXY_VARIABLES: &[&str] =
    &["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"];

/// How downloads are confined, from `pacman.conf`.
///
/// Build it with [`Sandbox::from_options`] and give it to
/// [`Refresher::with_sandbox`](crate::Refresher::with_sandbox).
#[derive(Clone, Debug)]
pub struct Sandbox {
    enabled: Option<Enabled>,
}

#[derive(Clone, Debug)]
struct Enabled {
    /// `DownloadUser`, resolved when the first request runs. `None` means [`FALLBACK_USER`].
    user: Option<String>,
    /// Apply Landlock.
    filesystem: bool,
    /// Apply the system call filter.
    syscalls: bool,
    /// The user and group ids to switch to, or why they are not known.
    account: OnceLock<Result<Option<Account>, String>>,
}

#[derive(Clone, Copy, Debug)]
struct Account {
    uid: u32,
    gid: u32,
}

impl Sandbox {
    /// The sandbox `pacman.conf` asks for.
    ///
    /// `DisableSandbox`, or both `DisableSandboxFilesystem` and `DisableSandboxSyscalls`, turn it
    /// off. Downloads then run in this process, as libalpm runs them.
    #[must_use]
    pub fn from_options(options: &Options) -> Self {
        Self::new(
            options.download_user.as_deref(),
            !options.disable_sandbox_filesystem,
            !options.disable_sandbox_syscalls,
        )
    }

    /// A sandbox with explicit settings.
    ///
    /// `download_user` is used only when this process runs as root, as in libalpm. Unlike
    /// libalpm, a root process with no download user still switches, to [`FALLBACK_USER`]. And
    /// the other two restrictions apply without root and without a download user. Neither needs
    /// a privilege.
    #[must_use]
    pub fn new(download_user: Option<&str>, filesystem: bool, syscalls: bool) -> Self {
        if !filesystem && !syscalls {
            return Self::disabled();
        }
        Self {
            enabled: Some(Enabled {
                user: download_user.map(str::to_owned),
                filesystem,
                syscalls,
                account: OnceLock::new(),
            }),
        }
    }

    /// No sandbox: downloads run in this process.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: None }
    }

    /// Whether downloads run in a helper process.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled.is_some()
    }

    /// Starts one request in a helper and reads the first frame of its answer.
    ///
    /// Returns `None` when the sandbox is disabled.
    pub(crate) fn fetch(
        &self,
        url: &str,
        if_modified_since: Option<&str>,
        timeouts: Timeouts,
        cancel: &Cancel,
    ) -> Option<Result<(Header, Fetch), Failure>> {
        let enabled = self.enabled.as_ref()?;
        Some(enabled.fetch(url, if_modified_since, timeouts, cancel))
    }
}

impl Default for Sandbox {
    /// Both restrictions, and no download user: the sandbox an empty `pacman.conf` asks for.
    /// Under root, the helper runs as [`FALLBACK_USER`].
    fn default() -> Self {
        Self::new(None, true, true)
    }
}

/// The two timeouts a request runs under.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timeouts {
    pub(crate) whole: Duration,
    pub(crate) connect: Duration,
}

/// Why a request did not produce a response.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The sandbox could not run the request: the helper could not be started or confined. No
    /// other server can do better.
    Sandbox(String),
    /// This request failed. Another server might not.
    Request(String),
}

impl Enabled {
    fn account(&self) -> Result<Option<Account>, String> {
        self.account.get_or_init(|| resolve_account(self.user.as_deref())).clone()
    }

    fn fetch(
        &self,
        url: &str,
        if_modified_since: Option<&str>,
        timeouts: Timeouts,
        cancel: &Cancel,
    ) -> Result<(Header, Fetch), Failure> {
        // The request is one line per field, so a line break would move every field after it.
        if [url, if_modified_since.unwrap_or_default()]
            .iter()
            .any(|text| text.contains(['\n', '\r']))
        {
            return Err(Failure::Request("the URL contains a line break".to_owned()));
        }
        let account = self.account().map_err(Failure::Sandbox)?;
        let request = Request {
            url: url.to_owned(),
            if_modified_since: if_modified_since.map(str::to_owned),
            timeout_secs: timeouts.whole.as_secs(),
            connect_timeout_secs: timeouts.connect.as_secs(),
            filesystem: self.filesystem,
            syscalls: self.syscalls,
            ports: allowed_ports(url),
        };

        let mut command = Command::new(SELF_EXE);
        command
            .arg0("piko")
            .arg(HELPER_ARG)
            .env_clear()
            .envs(
                PASSED_ENVIRONMENT.iter().filter_map(|name| Some((name, std::env::var_os(name)?))),
            )
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(Account { uid, gid }) = account {
            // `std` calls `setgroups(0)` before `setgid` and `setuid`, so the helper keeps no
            // supplementary group of root's.
            command.uid(uid).gid(gid);
        }
        let mut child = command.spawn().map_err(|error| {
            Failure::Sandbox(format!("could not start the download helper: {error}"))
        })?;

        let (stdin, stdout) = (child.stdin.take(), child.stdout.take());
        let guard = Guard::new(child, timeouts.whole.saturating_add(WATCHDOG_GRACE), cancel);
        let (Some(mut stdin), Some(stdout)) = (stdin, stdout) else {
            return Err(Failure::Sandbox("the download helper has no pipes".to_owned()));
        };
        // The request is far smaller than a pipe's buffer, so this write does not wait for the
        // helper to read it.
        stdin.write_all(&request.encode()).map_err(|error| {
            Failure::Sandbox(format!("could not send the request to the download helper: {error}"))
        })?;
        drop(stdin);

        let mut reader = Reader::new(stdout);
        match reader.opening() {
            Ok(Opening::Header(header)) => Ok((header, Fetch { reader, guard })),
            Ok(Opening::Failure(message)) => Err(Failure::Request(message)),
            Ok(Opening::Setup(message)) => Err(Failure::Sandbox(message)),
            Err(error) => Err(Failure::Request(guard.describe(&error))),
        }
    }
}

/// The account a helper switches to: none unless this process runs as root.
///
/// A named `DownloadUser` must exist, as in libalpm. With none named, [`FALLBACK_USER`] is
/// looked up, and the overflow ids stand in when it cannot be. A minimal chroot may have no
/// `nobody`, and root can switch to an id no account names.
fn resolve_account(user: Option<&str>) -> Result<Option<Account>, String> {
    if !rustix::process::geteuid().is_root() {
        return Ok(None);
    }
    let Some(name) = user else {
        let account = match nix::unistd::User::from_name(FALLBACK_USER) {
            Ok(Some(user)) => Account { uid: user.uid.as_raw(), gid: user.gid.as_raw() },
            Ok(None) | Err(_) => Account { uid: OVERFLOW_ID, gid: OVERFLOW_ID },
        };
        return Ok(Some(account));
    };
    match nix::unistd::User::from_name(name) {
        Ok(Some(user)) => Ok(Some(Account { uid: user.uid.as_raw(), gid: user.gid.as_raw() })),
        Ok(None) => Err(format!("download user '{name}' does not exist")),
        Err(error) => Err(format!("failed to get download user '{name}': {error}")),
    }
}

/// The TCP ports a request to `url` may reach.
fn allowed_ports(url: &str) -> Vec<u16> {
    let mut ports = ALWAYS_ALLOWED_PORTS.to_vec();
    if !crate::transport::is_https(url) {
        ports.push(HTTP_PORT);
    }
    let proxies = PROXY_VARIABLES.iter().filter_map(|name| std::env::var(name).ok());
    for target in std::iter::once(url.to_owned()).chain(proxies) {
        if let Some(port) = url_port(&target) {
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The port a URL names, or its scheme's default.
fn url_port(url: &str) -> Option<u16> {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    // An IPv6 host is bracketed, and its colons are not a port separator.
    let after_host = host_port.rsplit_once(']').map_or(host_port, |(_, rest)| rest);
    if let Some((_, port)) = after_host.rsplit_once(':') {
        return port.parse().ok();
    }
    match scheme.to_ascii_lowercase().as_str() {
        "http" => Some(80),
        "https" => Some(443),
        "socks4" | "socks4a" | "socks5" | "socks5h" | "socks" => Some(1080),
        _ => None,
    }
}

/// The body of an answer that a helper is still sending.
///
/// Dropping it kills the helper, so a transfer the parent stops reading — too large, cancelled,
/// or not wanted — does not keep a process running.
#[derive(Debug)]
pub(crate) struct Fetch {
    reader: Reader<ChildStdout>,
    guard: Guard,
}

impl Read for Fetch {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buffer).map_err(|error| std::io::Error::other(self.guard.describe(&error)))
    }
}

/// Owns a helper process, and kills it on a timeout, on a cancellation, or when dropped.
#[derive(Debug)]
struct Guard {
    child: Arc<Mutex<Child>>,
    /// Dropping the sender stops the watchdog.
    stop: Option<mpsc::Sender<()>>,
    /// Set when the watchdog killed the helper for running too long.
    timed_out: Arc<AtomicBool>,
}

impl Guard {
    fn new(child: Child, limit: Duration, cancel: &Cancel) -> Self {
        let child = Arc::new(Mutex::new(child));
        let timed_out = Arc::new(AtomicBool::new(false));
        let (stop, stopped) = mpsc::channel::<()>();
        let watched = Arc::clone(&child);
        let flag = Arc::clone(&timed_out);
        let cancel = cancel.clone();
        let deadline = Instant::now().checked_add(limit);
        std::thread::spawn(move || {
            loop {
                match stopped.recv_timeout(WATCHDOG_TICK) {
                    Err(RecvTimeoutError::Timeout) => {}
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
                }
                let expired = deadline.is_some_and(|deadline| Instant::now() >= deadline);
                if expired || cancel.is_requested() {
                    flag.store(expired, Ordering::Relaxed);
                    // Under the lock, so the process cannot have been reaped and its id reused.
                    if let Ok(mut child) = watched.lock() {
                        let _ = child.kill();
                    }
                    return;
                }
            }
        });
        Self { child, stop: Some(stop), timed_out }
    }

    /// The message for a read that failed, naming a timeout when the watchdog caused it.
    fn describe(&self, error: &std::io::Error) -> String {
        if self.timed_out.load(Ordering::Relaxed) {
            "the download helper timed out".to_owned()
        } else {
            error.to_string()
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Applies the helper's restrictions to the calling process, as the helper does before its
/// request: no core dump, `no_new_privs`, then Landlock if `filesystem`, then the system call
/// filter if `syscalls`. TCP `connect` may reach only `ports`.
///
/// The restrictions cannot be lifted. This exists so that they can be tested from a process
/// that then tries what they forbid.
///
/// # Errors
///
/// A message naming the restriction that could not be applied.
pub fn confine_self(filesystem: bool, syscalls: bool, ports: &[u16]) -> Result<(), String> {
    confine::apply(&confine::Confinement { filesystem, syscalls, ports })
}

/// Becomes the download helper if this process was started as one.
///
/// Call this first in `main`, before any thread starts and before any argument parser runs.
/// It returns `None` for an ordinary invocation. Otherwise it runs one request and returns the
/// helper's exit code, which `main` returns.
#[must_use]
pub fn run_helper_if_requested() -> Option<ExitCode> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new(HELPER_ARG)) {
        return None;
    }
    Some(helper_main())
}

/// The helper: confine this process, run one request, and send the answer on stdout.
fn helper_main() -> ExitCode {
    // Started through `/proc/self/exe`, the process would show as `exe` in `ps` and `top`. A
    // failure changes nothing but that name.
    let _ = rustix::thread::set_name(c"piko-fetch");
    let stdout = std::io::stdout().lock();
    let capacity = (protocol::MAX_DATA as usize).saturating_add(5);
    let mut writer = Writer::new(BufWriter::with_capacity(capacity, stdout));
    // A failure to write the answer means the parent has gone. There is nobody to tell.
    let setup = |writer: &mut Writer<_>, message: &str| {
        let _ = writer.message(Tag::Setup, message);
        ExitCode::from(2)
    };

    // Before anything is read. Landlock checks a file when it is opened, so a descriptor
    // inherited open would carry its rights past every restriction below.
    if let Err(message) = no_inherited_descriptors() {
        return setup(&mut writer, &message);
    }
    let request = match Request::decode(std::io::stdin().lock()) {
        Ok(request) => request,
        Err(message) => return setup(&mut writer, &message),
    };
    let confinement = confine::Confinement {
        filesystem: request.filesystem,
        syscalls: request.syscalls,
        ports: &request.ports,
    };
    if let Err(message) = confine::apply(&confinement) {
        return setup(&mut writer, &message);
    }

    let agent = crate::transport::agent(Timeouts {
        whole: Duration::from_secs(request.timeout_secs),
        connect: Duration::from_secs(request.connect_timeout_secs),
    });
    let call =
        crate::transport::request(&agent, &request.url, request.if_modified_since.as_deref());
    let response = match call.call() {
        Ok(response) => response,
        Err(error) => {
            let _ = writer.message(Tag::Failure, &error.to_string());
            return ExitCode::FAILURE;
        }
    };

    let header = crate::transport::header(&response);
    if writer.header(&header).is_err() {
        return ExitCode::FAILURE;
    }
    match writer.body(response.into_body().into_reader()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

/// Refuses a descriptor above the three standard ones.
///
/// The parent opens every file with `O_CLOEXEC`, so only a descriptor the parent itself
/// inherited, from whatever started it, can reach the helper. Nothing here can close one:
/// that needs `unsafe`. So the helper refuses to run, and names it.
fn no_inherited_descriptors() -> Result<(), String> {
    let fail = |error: std::io::Error| format!("could not list the open descriptors: {error}");
    // The listing's own descriptor appears in it, pointing at this directory.
    let own = format!("/proc/{}/fd", std::process::id());
    let mut inherited = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd").map_err(fail)? {
        let entry = entry.map_err(fail)?;
        let name = entry.file_name();
        let Some(number) = name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        if number <= 2 {
            continue;
        }
        let target = std::fs::read_link(entry.path()).unwrap_or_default();
        if target.as_os_str() == own.as_str() {
            continue;
        }
        inherited.push(format!("{number} ({})", target.display()));
    }
    if inherited.is_empty() {
        return Ok(());
    }
    Err(format!(
        "the download helper inherited open descriptors: {}. Whatever started piko left them \
         open.",
        inherited.join(", ")
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    #[test]
    fn a_url_names_its_port_or_its_default() {
        assert_eq!(url_port("https://mirror.example/core"), Some(443));
        assert_eq!(url_port("http://mirror.example/core"), Some(80));
        assert_eq!(url_port("http://mirror.example:8080/core"), Some(8080));
        assert_eq!(url_port("https://user:pw@mirror.example:8443/a:b"), Some(8443));
        assert_eq!(url_port("http://[::1]:3128"), Some(3128));
        assert_eq!(url_port("http://[::1]/core"), Some(80));
        assert_eq!(url_port("socks5://proxy.example"), Some(1080));
        assert_eq!(url_port("proxy.example:3128"), Some(3128));
        assert_eq!(url_port("ftp://mirror.example/core"), None);
    }

    #[test]
    fn the_allowed_ports_always_include_dns_and_both_web_ports_for_http() {
        let ports = allowed_ports("http://127.0.0.1:43210/core.db");

        for port in [53, 80, 443, 43210] {
            assert!(ports.contains(&port), "{ports:?}");
        }
    }

    /// An `https` URL is followed only to `https`, so it has no use for port 80.
    #[test]
    fn an_https_url_gets_no_http_port() {
        let ports = allowed_ports("https://mirror.example/core.db");

        assert!(ports.contains(&443), "{ports:?}");
        // A proxy variable on port 80 would add it back, and this process has none.
        if PROXY_VARIABLES.iter().all(|name| std::env::var_os(name).is_none()) {
            assert!(!ports.contains(&80), "{ports:?}");
        }
    }

    #[test]
    fn disabling_both_halves_disables_the_sandbox() {
        assert!(!Sandbox::new(Some("alpm"), false, false).is_enabled());
        assert!(Sandbox::new(None, true, false).is_enabled());
        assert!(Sandbox::new(None, false, true).is_enabled());
    }

    /// A helper switches user only under root, so this test is meaningful only when it does not
    /// run as root. Neither a named download user nor the fallback is used.
    #[test]
    fn no_user_switch_happens_without_root() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        assert!(resolve_account(Some("no-such-user-for-piko")).unwrap().is_none());
        assert!(resolve_account(None).unwrap().is_none());
    }
}
