//! The download sandbox: every request to a mirror runs in a confined helper process.

mod confine;
pub use confine::Confined;
// rustfmt resolves a module file whatever its `cfg`, and a published tree has no `fuzzing.rs`.
// `skip` keeps `cargo fmt` from looking for it there.
#[cfg(feature = "fuzzing")]
#[rustfmt::skip]
#[doc(hidden)]
pub mod fuzzing;
pub(crate) mod protocol;

use std::{
    ffi::OsStr,
    io::{BufWriter, Read, Write as _},
    os::unix::process::CommandExt as _,
    process::{Child, ChildStdout, Command, ExitCode, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
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
pub(crate) const HELPER_ARG: &str = "__fetch";

/// The executable the helper is started from.
const SELF_EXE: &str = "/proc/self/exe";

/// How long the helper may outlive one of its own timeouts before the parent kills it.
///
/// The helper enforces the request's timeouts itself. This bound is for a helper that does not.
const WATCHDOG_GRACE: Duration = Duration::from_secs(5);

/// How often the watchdog looks at the cancellation flag.
const WATCHDOG_TICK: Duration = Duration::from_millis(100);

/// The port a request may always reach: DNS over TCP.
const DNS_PORT: u16 = 53;

/// HTTPS's default port, which an `https` URL may be redirected to.
const HTTPS_PORT: u16 = 443;

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
///
/// A mirror is untrusted until its signature is checked, and the code that reads what it sends
/// — DNS, TLS, HTTP — runs before that check. A defect there would otherwise run the mirror's
/// code as root. libalpm answers this with `DownloadUser` and the `sandbox*.c` files. piko answers
/// it the same way, with one difference in shape.
///
/// # The helper transfers bytes and writes no file
///
/// libalpm's sandboxed child writes each download into a temporary directory that the download
/// user owns. The parent then takes the file. A child that a mirror took over can leave a
/// process behind that keeps the file open, and change it after the parent checked it.
///
/// Here the helper makes one request and writes the answer to its stdout, in the frames that
/// `protocol` defines. The parent keeps everything else: the size bound, the atomic write,
/// the `Last-Modified` checks, and the signature check. So the helper needs no write access
/// anywhere, and no file the parent checks was ever open for writing in the helper.
///
/// # One helper per request
///
/// A database, its `.sig`, and each package are separate requests, so separate processes. A
/// mirror that took over one helper cannot touch another file's transfer.
///
/// # Starting the helper without `unsafe`
///
/// `fork` is `unsafe`, and the workspace forbids `unsafe_code`. So piko starts itself again, as
/// `piko_txn::exec` does for scriptlets, through `/proc/self/exe` with `HELPER_ARG`. A program
/// that uses this crate must call [`run_helper_if_requested`] first thing in `main`. The
/// executable path is `/proc/self/exe` rather than [`std::env::current_exe`] for two reasons.
/// The magic link still works after the binary is replaced on disk. And it needs no search
/// permission on the directories above the binary, which the download user may not have.
///
/// The user switch is `std`'s own `CommandExt::uid`/`gid`, which drop the supplementary groups
/// first. The helper then confines itself before it reads anything: see `confine`.
///
/// # Never root
///
/// Under root, the helper always switches to another user: `DownloadUser` when it is set, and
/// `FALLBACK_USER`, `nobody`, otherwise. A `DownloadUser` whose user ID is 0 is refused, since switching
/// to it keeps every capability. libalpm confines nothing without `DownloadUser`. A helper left
/// as root would keep every capability, and the owner's access to every file, which no
/// Landlock or system call rule takes back: it could read the keyring's secret keys, or change
/// the firewall through the netlink socket its resolver needs.
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

/// The timeouts a request runs under.
///
/// None of them bounds the whole transfer. A package of several gigabytes on a slow link takes
/// as long as it takes, and a bound on the total would refuse it on every server. What is
/// bounded is each wait: for a connection, for the response to begin, and for the next bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timeouts {
    /// How long a name lookup may take, and then how long a connection may take to establish.
    pub(crate) connect: Duration,
    /// How long the response may take to begin, once the request is sent.
    pub(crate) response: Duration,
    /// How long the transfer may receive nothing. `None` is no limit.
    pub(crate) stall: Option<Duration>,
}

impl Timeouts {
    /// How long a helper may stay silent before its first frame: one name lookup, one
    /// connection and one response, and the grace.
    fn opening(self) -> Duration {
        self.connect
            .saturating_add(self.connect)
            .saturating_add(self.response)
            .saturating_add(WATCHDOG_GRACE)
    }

    /// How long a helper may stay silent between two frames of a body.
    fn between_frames(self) -> Option<Duration> {
        self.stall.map(|stall| stall.saturating_add(WATCHDOG_GRACE))
    }
}

/// `duration` in whole milliseconds, as a request carries it.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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
            response_timeout_millis: millis(timeouts.response),
            connect_timeout_millis: millis(timeouts.connect),
            stall_timeout_millis: timeouts.stall.map(millis),
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
        let guard = Guard::new(child, timeouts, cancel);
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
            Ok(Opening::Header(header)) => {
                guard.activity.begin_body();
                Ok((header, Fetch { reader, guard }))
            }
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
///
/// A `DownloadUser` whose user ID is 0 is refused. `setuid(0)` from root keeps every
/// capability, so the helper would stay root, which is what the switch exists to prevent.
fn resolve_account(user: Option<&str>) -> Result<Option<Account>, String> {
    if !rustix::process::geteuid().is_root() {
        return Ok(None);
    }
    named_account(user)
}

/// [`resolve_account`] for a process that runs as root.
fn named_account(user: Option<&str>) -> Result<Option<Account>, String> {
    let Some(name) = user else {
        let account = match nix::unistd::User::from_name(FALLBACK_USER) {
            // A `nobody` that is root is no switch, so the overflow ids stand in for it too.
            Ok(Some(user)) if !user.uid.is_root() => {
                Account { uid: user.uid.as_raw(), gid: user.gid.as_raw() }
            }
            Ok(_) | Err(_) => Account { uid: OVERFLOW_ID, gid: OVERFLOW_ID },
        };
        return Ok(Some(account));
    };
    match nix::unistd::User::from_name(name) {
        Ok(Some(user)) if user.uid.is_root() => Err(format!(
            "download user '{name}' has user ID 0, and the download helper must not run as root"
        )),
        Ok(Some(user)) => Ok(Some(Account { uid: user.uid.as_raw(), gid: user.gid.as_raw() })),
        Ok(None) => Err(format!("download user '{name}' does not exist")),
        Err(error) => Err(format!("failed to get download user '{name}': {error}")),
    }
}

/// The TCP ports a request to `url` may reach.
///
/// DNS, the URL's own port, and each proxy's. An `https` URL also gets 443: a mirror often
/// redirects to another host, and the redirect is followed only to `https`. An `http` URL gets
/// nothing more, because it follows no redirect (`transport::request`), so it never reaches a
/// port other than its own.
fn allowed_ports(url: &str) -> Vec<u16> {
    let mut ports = vec![DNS_PORT];
    if crate::transport::is_https(url) {
        ports.push(HTTPS_PORT);
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
        // Marked before the read as well as after it. The silence the watchdog measures is then
        // the time this process waited for the helper, and never the time it spent writing the
        // previous chunk to disk.
        self.guard.activity.mark();
        let read = self.reader.read(buffer);
        self.guard.activity.mark();
        read.map_err(|error| std::io::Error::other(self.guard.describe(&error)))
    }
}

/// When the parent last waited for, or heard from, a helper.
///
/// The watchdog measures the helper's silence against it. A transfer that keeps sending is
/// never killed for its length.
#[derive(Debug)]
struct Activity {
    started: Instant,
    /// The last mark, in milliseconds after `started`.
    last_millis: AtomicU64,
    /// Whether the first frame arrived, so the bound is the one between two frames.
    in_body: AtomicBool,
}

impl Activity {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            last_millis: AtomicU64::new(0),
            in_body: AtomicBool::new(false),
        }
    }

    fn mark(&self) {
        self.last_millis.store(millis(self.started.elapsed()), Ordering::Relaxed);
    }

    fn begin_body(&self) {
        self.mark();
        self.in_body.store(true, Ordering::Relaxed);
    }

    /// Whether the helper has been silent for longer than `timeouts` allow.
    fn expired(&self, timeouts: Timeouts) -> bool {
        let limit = if self.in_body.load(Ordering::Relaxed) {
            timeouts.between_frames()
        } else {
            Some(timeouts.opening())
        };
        let silent =
            millis(self.started.elapsed()).saturating_sub(self.last_millis.load(Ordering::Relaxed));
        limit.is_some_and(|limit| silent >= millis(limit))
    }
}

/// Owns a helper process, and kills it on a timeout, on a cancellation, or when dropped.
#[derive(Debug)]
struct Guard {
    child: Arc<Mutex<Child>>,
    /// Dropping the sender stops the watchdog.
    stop: Option<mpsc::Sender<()>>,
    /// Set when the watchdog killed the helper for staying silent too long.
    timed_out: Arc<AtomicBool>,
    /// What the watchdog measures the helper's silence against.
    activity: Arc<Activity>,
}

impl Guard {
    fn new(child: Child, timeouts: Timeouts, cancel: &Cancel) -> Self {
        let child = Arc::new(Mutex::new(child));
        let timed_out = Arc::new(AtomicBool::new(false));
        let activity = Arc::new(Activity::new());
        let (stop, stopped) = mpsc::channel::<()>();
        let watched = Arc::clone(&child);
        let flag = Arc::clone(&timed_out);
        let heard = Arc::clone(&activity);
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            loop {
                match stopped.recv_timeout(WATCHDOG_TICK) {
                    Err(RecvTimeoutError::Timeout) => {}
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
                }
                let expired = heard.expired(timeouts);
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
        Self { child, stop: Some(stop), timed_out, activity }
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
pub fn confine_self(filesystem: bool, syscalls: bool, ports: &[u16]) -> Result<Confined, String> {
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
        connect: Duration::from_millis(request.connect_timeout_millis),
        response: Duration::from_millis(request.response_timeout_millis),
        stall: request.stall_timeout_millis.map(Duration::from_millis),
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
    // The listing's own descriptor appears in it, pointing at this directory. `/proc/self`
    // names this process as the mounted `/proc` sees it, which is not `getpid`'s answer in a
    // PID namespace that kept the host's `/proc`: `unshare --fork --pid` without `--mount-proc`,
    // as `pacstrap` starts pacman.
    let own = std::path::Path::new("/proc")
        .join(std::fs::read_link("/proc/self").map_err(fail)?)
        .join("fd");
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
        if target == own {
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
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
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

    /// Whether this process has no proxy variable, which would add its own port.
    fn no_proxy() -> bool {
        PROXY_VARIABLES.iter().all(|name| std::env::var_os(name).is_none())
    }

    /// An `http` URL follows no redirect, so it reaches its own port and DNS, nothing else.
    #[test]
    fn an_http_url_gets_its_own_port_and_dns_only() {
        let ports = allowed_ports("http://127.0.0.1:43210/core.db");

        for port in [53, 43210] {
            assert!(ports.contains(&port), "{ports:?}");
        }
        if no_proxy() {
            assert_eq!(ports, [53, 43210]);
        }
        assert!(allowed_ports("http://localhost/core.db").contains(&80));
    }

    /// An `https` URL is followed only to `https`, so it has no use for port 80.
    #[test]
    fn an_https_url_gets_no_http_port() {
        let ports = allowed_ports("https://mirror.example:8443/core.db");

        for port in [53, 443, 8443] {
            assert!(ports.contains(&port), "{ports:?}");
        }
        if no_proxy() {
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

    /// Switching to user ID 0 keeps every capability, so a download user that is root is no
    /// switch at all.
    #[test]
    fn a_download_user_with_user_id_0_is_refused() {
        let error = named_account(Some("root")).unwrap_err();

        assert!(error.contains("user ID 0"), "{error}");
    }

    #[test]
    fn without_a_download_user_the_fallback_is_never_root() {
        let account = named_account(None).unwrap().unwrap();

        assert_ne!(account.uid, 0);
    }
}
