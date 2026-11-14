//! The download sandbox, against the real kernel and a local HTTP server.
//!
//! ```text
//! cargo test -p piko-net --test sandbox
//! ```
//!
//! This test binary has its own `main` (`harness = false`), because the sandbox starts
//! `/proc/self/exe` as its helper. Here that is this binary, so `main` must become the helper
//! when asked, exactly as `piko`'s own `main` does. It also becomes a probe: a process that
//! confines itself and then tries what the confinement forbids.
//!
//! These test the sandbox's security claims: the helper writes no file, changes no file's
//! metadata, reads only what a request needs, starts no program and no process, and reaches only
//! the ports it was given, while it can still read the resolver's configuration and start the
//! thread its resolver uses. They also test that a transfer through the helper arrives byte
//! for byte, and that a cancellation stops a helper that is waiting on a silent server.
//!
//! Only one test needs root: a download user is used only by root. It reports itself skipped
//! otherwise. To run it as root without building as root, build with
//! `cargo test -p piko-net --test sandbox --no-run`. That command prints the test binary's path.
//! Run that path under `sudo`, with the argument `as_root`.
//!
//! It switches to `alpm`, or to the user named by `PIKO_TEST_DOWNLOAD_USER`.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Command, ExitCode},
    str::FromStr as _,
    time::{Duration, Instant},
};

use alpm_types::PackageFileName;
use piko_net::{Cancel, Error, Limits, PackageFetch, Refresher, Sandbox};
use piko_sig::Policy;

mod connection;

/// The hidden argument that turns this binary into a probe.
const PROBE_ARG: &str = "__probe";

const NAME: &str = "foo-1.0.0-1-x86_64.pkg.tar.zst";

fn main() -> ExitCode {
    if let Some(code) = piko_net::run_helper_if_requested() {
        return code;
    }
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.get(1).map(String::as_str) == Some(PROBE_ARG) {
        return probe(arguments.get(2..).unwrap_or_default());
    }

    let tests: &[(&str, fn())] = &[
        ("a_package_arrives_byte_for_byte_through_the_helper", arrives_byte_for_byte),
        ("a_failing_server_falls_through_to_the_next", failing_server_falls_through),
        ("the_helper_refuses_an_inherited_descriptor", refuses_an_inherited_descriptor),
        ("the_helper_runs_in_a_pid_namespace_under_the_hosts_proc", runs_in_a_pid_namespace),
        ("a_missing_signature_is_absent_through_the_helper", missing_signature_is_absent),
        ("a_cancellation_stops_a_helper_waiting_on_a_silent_server", cancellation_stops_helper),
        (
            "a_slow_transfer_that_keeps_arriving_completes_through_the_helper",
            slow_transfer_completes,
        ),
        ("a_transfer_that_stops_is_given_up_through_the_helper", stopped_transfer_is_given_up),
        ("the_helper_cannot_write_a_file", cannot_write),
        ("the_helper_cannot_read_outside_what_a_request_needs", cannot_read_elsewhere),
        ("the_helper_cannot_change_a_files_metadata", cannot_change_metadata),
        ("the_helper_cannot_start_a_program", cannot_start_a_program),
        ("the_system_call_filter_alone_refuses_a_new_process", filter_alone_refuses_a_process),
        ("the_helper_cannot_connect_to_a_port_it_was_not_given", cannot_connect_elsewhere),
        ("the_helper_can_connect_to_a_port_it_was_given", can_connect_to_its_port),
        (
            "the_helper_cannot_connect_to_a_unix_socket_a_path_names",
            cannot_connect_to_a_unix_socket,
        ),
        ("the_helper_can_read_a_file_and_start_a_thread", can_read_and_start_a_thread),
        ("as_root_the_helper_runs_as_the_download_user", runs_as_the_download_user),
        ("as_root_without_a_download_user_the_helper_runs_as_nobody", runs_as_nobody),
    ];
    let filter = arguments.iter().skip(1).find(|argument| !argument.starts_with('-'));
    let mut failed = 0_usize;
    for (name, test) in tests {
        if filter.is_some_and(|filter| !name.contains(filter.as_str())) {
            continue;
        }
        let outcome = std::panic::catch_unwind(test);
        println!("test {name} ... {}", if outcome.is_ok() { "ok" } else { "FAILED" });
        if outcome.is_err() {
            failed = failed.saturating_add(1);
        }
    }
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// Confines this process, then tries one forbidden or allowed action.
///
/// Exits 0 when the action did what the test expects to see, and says what happened otherwise.
fn probe(arguments: &[String]) -> ExitCode {
    let [action, target] = arguments else { return ExitCode::from(3) };
    let port = target.parse::<u16>().ok();
    let ports: Vec<u16> =
        if action == "connect-allowed" { port.into_iter().collect() } else { vec![] };
    // Landlock alone also refuses a program, because it grants no execute right. This action
    // leaves it out, so only the system call filter can refuse.
    let filesystem = action != "spawn-without-landlock";
    let confined = match piko_net::confine_self(filesystem, true, &ports) {
        Ok(confined) => confined,
        Err(message) => {
            eprintln!("confinement failed: {message}");
            return ExitCode::from(4);
        }
    };
    // Landlock refuses a UNIX socket that a path names from ABI 9 only.
    if action == "connect-unix" && confined.landlock_abi.is_none_or(|abi| abi < 9) {
        println!("skipped: needs Landlock ABI 9, this kernel has {:?}", confined.landlock_abi);
        return ExitCode::SUCCESS;
    }

    let refused = |result: std::io::Result<()>| match result {
        Err(_) => ExitCode::SUCCESS,
        Ok(()) => {
            eprintln!("{action} was allowed");
            ExitCode::FAILURE
        }
    };
    match action.as_str() {
        "write" => refused(std::fs::write(Path::new(target).join("escaped"), b"x")),
        "read" => refused(std::fs::read(target).map(drop)),
        "metadata" => {
            let allowed: Vec<&str> = change_metadata(Path::new(target))
                .into_iter()
                .filter_map(|(change, result)| result.is_ok().then_some(change))
                .collect();
            if allowed.is_empty() {
                ExitCode::SUCCESS
            } else {
                eprintln!("allowed: {allowed:?}");
                ExitCode::FAILURE
            }
        }
        "exec" | "spawn-without-landlock" => refused(Command::new(target).status().map(drop)),
        "connect-unix" => refused(std::os::unix::net::UnixStream::connect(target).map(drop)),
        "connect" => refused(TcpStream::connect(("127.0.0.1", port.unwrap_or(1))).map(drop)),
        "connect-allowed" => match TcpStream::connect(("127.0.0.1", port.unwrap_or(1))) {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("connect was refused: {error}");
                ExitCode::FAILURE
            }
        },
        "read-and-thread" => {
            let read = std::fs::read(target).map(drop);
            let thread = std::thread::spawn(|| 7).join();
            match (read, thread) {
                (Ok(()), Ok(7)) => ExitCode::SUCCESS,
                (read, thread) => {
                    eprintln!("read: {read:?}, thread: {:?}", thread.is_ok());
                    ExitCode::FAILURE
                }
            }
        }
        _ => ExitCode::from(3),
    }
}

/// Runs a probe and asserts it saw what the test expects.
fn run_probe(action: &str, target: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([PROBE_ARG, action, target])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "probe {action} {target}: {:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn cannot_write() {
    let dir = tempfile::tempdir().unwrap();
    run_probe("write", dir.path().to_str().unwrap());
    assert!(!dir.path().join("escaped").exists());
}

/// Changes `path`'s mode, owner, extended attributes and times, and says how each went.
///
/// Landlock covers none of these, so only the system call filter can refuse them.
fn change_metadata(path: &Path) -> Vec<(&'static str, std::io::Result<()>)> {
    use std::os::unix::fs::PermissionsExt as _;

    vec![
        ("chmod", std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o4755))),
        ("chown", std::os::unix::fs::chown(path, None, None)),
        (
            "setxattr",
            rustix::fs::setxattr(path, "user.piko", b"x", rustix::fs::XattrFlags::empty())
                .map_err(Into::into),
        ),
        (
            "utimensat",
            std::fs::File::open(path).and_then(|file| file.set_modified(std::time::UNIX_EPOCH)),
        ),
    ]
}

fn cannot_change_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let (target, control) = (dir.path().join("target"), dir.path().join("control"));
    for path in [&target, &control] {
        std::fs::write(path, b"x").unwrap();
    }
    // Every change works outside the sandbox, so a refusal inside it is the filter's.
    for (change, result) in change_metadata(&control) {
        assert!(result.is_ok(), "{change} fails even unconfined: {result:?}");
    }

    let before = std::fs::metadata(&target).unwrap();
    run_probe("metadata", target.to_str().unwrap());
    let after = std::fs::metadata(&target).unwrap();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&before.permissions()),
        std::os::unix::fs::PermissionsExt::mode(&after.permissions())
    );
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
}

/// A file the helper's user can read is still out of reach when no request needs it: one in a
/// temporary directory, and `/etc/passwd`, which every user can read.
fn cannot_read_elsewhere() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret");
    std::fs::write(&secret, b"a secret").unwrap();
    std::fs::read(&secret).unwrap();
    run_probe("read", secret.to_str().unwrap());

    std::fs::read("/etc/passwd").unwrap();
    run_probe("read", "/etc/passwd");
}

fn cannot_start_a_program() {
    run_probe("exec", "/usr/bin/true");
}

fn filter_alone_refuses_a_process() {
    run_probe("spawn-without-landlock", "/usr/bin/true");
}

fn cannot_connect_elsewhere() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    run_probe("connect", &listener.local_addr().unwrap().port().to_string());
}

/// A socket this user owns, as a session bus or a key agent is. Landlock refuses it from ABI 9,
/// and the probe checks nothing on a kernel below it.
fn cannot_connect_to_a_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bus");
    let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    std::os::unix::net::UnixStream::connect(&path).unwrap();
    run_probe("connect-unix", path.to_str().unwrap());
}

fn can_connect_to_its_port() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    run_probe("connect-allowed", &listener.local_addr().unwrap().port().to_string());
}

/// `/etc/hosts` is read by every name lookup, and `ca-certificates.crt` is Arch's certificate
/// store, a link into `/etc/ca-certificates`.
fn can_read_and_start_a_thread() {
    run_probe("read-and-thread", "/etc/hosts");
    let store = "/etc/ssl/certs/ca-certificates.crt";
    if Path::new(store).exists() {
        run_probe("read-and-thread", store);
    }
}

/// As `package.rs`'s `serve`: one canned response per connection.
fn serve(responses: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            connection::write_closing(&mut stream, &response);
            let _ = stream.flush();
        }
    });
    (format!("http://127.0.0.1:{port}"), handle)
}

fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}

fn not_found() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
}

fn sandboxed() -> Refresher {
    Refresher::new(Limits::default()).with_sandbox(Sandbox::new(None, true, true))
}

fn fetch(
    refresher: &Refresher,
    cache: &Path,
    servers: &[String],
    policy: Policy,
    cancel: &Cancel,
) -> piko_net::Result<std::path::PathBuf> {
    let file_name = PackageFileName::from_str(NAME).unwrap();
    let wanted = PackageFetch::new(&file_name, "core", servers, policy);
    refresher.fetch_package(cache, wanted, cancel)
}

fn unsigned() -> Policy {
    Policy::for_package(piko_db::config::SigLevel::default())
}

fn arrives_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    // Several data frames, and a last one that is not full.
    let body: Vec<u8> = (0..300_001_u32).map(|n| n.to_le_bytes()[0] ^ 0x5a).collect();
    let (url, server) = serve(vec![ok_response(&body)]);

    let path = fetch(&sandboxed(), dir.path(), &[url], unsigned(), &Cancel::new()).unwrap();

    assert_eq!(std::fs::read(path).unwrap(), body);
    drop(server.join());
}

/// A descriptor the parent inherited without `O_CLOEXEC` reaches the helper, and Landlock does
/// not look at a file already open. The helper refuses to run, names it, and no server is
/// tried: every one would meet the same helper.
fn refuses_an_inherited_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(dir.path().join("inherited")).unwrap();
    // `dup` clears `FD_CLOEXEC`, the way a descriptor from whatever started piko arrives.
    let inherited = rustix::io::dup(&file).unwrap();
    let (url, _server) = serve(vec![ok_response(b"never sent")]);

    let error = fetch(&sandboxed(), dir.path(), &[url], unsigned(), &Cancel::new()).unwrap_err();
    drop(inherited);

    let Error::Sandbox { reason } = &error else { panic!("{error:?}") };
    assert!(reason.contains("inherited open descriptors"), "{reason}");
    assert!(reason.contains("inherited)"), "the descriptor is not named: {reason}");
    assert!(!dir.path().join(NAME).exists());
}

/// `unshare --fork --pid` without `--mount-proc`, as `pacstrap` and `pikostrap` start pacman and
/// piko, leaves `/proc` the host's. There `/proc/self` names the host's process id, while
/// `getpid` returns the namespace's. The descriptor that lists `/proc/self/fd` is the helper's
/// own, and not one it inherited. The helper must still recognize it as its own.
///
/// This runs the byte-for-byte test again inside such a namespace. A user namespace makes it
/// work without root, and maps no user, so the helper does not see itself as root.
fn runs_in_a_pid_namespace() {
    let unshare = ["--user", "--fork", "--pid"];
    let available = Command::new("unshare").args(unshare).arg("true").output();
    if !available.is_ok_and(|output| output.status.success()) {
        println!("  skipped: unshare cannot create a user and a PID namespace");
        return;
    }
    let output = Command::new("unshare")
        .args(unshare)
        .arg(std::env::current_exe().unwrap())
        .arg("a_package_arrives_byte_for_byte_through_the_helper")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{:?}: {}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn failing_server_falls_through() {
    let dir = tempfile::tempdir().unwrap();
    let (first, first_server) = serve(vec![not_found()]);
    let (second, second_server) = serve(vec![ok_response(b"from the second server")]);

    let path =
        fetch(&sandboxed(), dir.path(), &[first, second], unsigned(), &Cancel::new()).unwrap();

    assert_eq!(std::fs::read(path).unwrap(), b"from the second server");
    drop(first_server.join());
    drop(second_server.join());
}

/// A `404` on a `.sig` travels as a status through the helper, so it still means "unsigned"
/// rather than "the signature could not be fetched".
fn missing_signature_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(vec![ok_response(b"a package"), not_found()]);
    let checked = Policy::for_package(piko_db::config::SigLevel::PACKAGE);

    let path = fetch(&sandboxed(), dir.path(), &[url], checked, &Cancel::new()).unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), b"a package");
    assert!(!dir.path().join(format!("{NAME}.sig")).exists());
    drop(server.join());
}

/// A helper blocked on a server that never answers is killed by the watchdog on a
/// cancellation, well before any timeout.
fn cancellation_stops_helper() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let held = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream));

    let cancel = Cancel::new();
    let requester = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        requester.request();
    });
    let started = Instant::now();
    let error = fetch(&sandboxed(), dir.path(), &[url], unsigned(), &cancel).unwrap_err();

    assert!(matches!(error, Error::Cancelled), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    assert!(!dir.path().join(NAME).exists());
    drop(held.join());
}

/// Serves one `200` whose body is `chunks` chunks of 256 bytes, one every `pause`.
fn serve_slowly(chunks: usize, pause: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) != 0 && line != "\r\n" {
            line.clear();
        }
        let length = chunks.saturating_mul(256);
        let head =
            format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {length}\r\n\r\n");
        let _ = stream.write_all(head.as_bytes());
        for _ in 0..chunks {
            if stream.write_all(&[7_u8; 256]).is_err() || stream.flush().is_err() {
                return;
            }
            std::thread::sleep(pause);
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// The helper's own timeouts and the parent's watchdog both restart with each chunk, so a body
/// that keeps arriving outlives every one of them.
fn slow_transfer_completes() {
    let dir = tempfile::tempdir().unwrap();
    // Three seconds in all, and never more than 250 ms without a byte.
    let url = serve_slowly(12, Duration::from_millis(250));
    let refresher = Refresher::new(Limits {
        timeout: Duration::from_secs(1),
        stall_timeout: Some(Duration::from_secs(1)),
        ..Limits::default()
    })
    .with_sandbox(Sandbox::new(None, true, true));

    let path = fetch(&refresher, dir.path(), &[url], unsigned(), &Cancel::new()).unwrap();

    assert_eq!(std::fs::read(path).unwrap().len(), 12 * 256);
}

/// A body that stops is given up: by the helper's own stall bound, or by the watchdog 5 s after
/// it. Nothing reaches the cache.
fn stopped_transfer_is_given_up() {
    let dir = tempfile::tempdir().unwrap();
    let url = serve_slowly(2, Duration::from_secs(20));
    let refresher =
        Refresher::new(Limits { stall_timeout: Some(Duration::from_secs(1)), ..Limits::default() })
            .with_sandbox(Sandbox::new(None, true, true));
    let started = Instant::now();

    let error = fetch(&refresher, dir.path(), &[url], unsigned(), &Cancel::new()).unwrap_err();

    assert!(error.to_string().contains("time"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    assert!(!dir.path().join(NAME).exists());
}

/// As root, the helper runs as the download user, with no supplementary group. The test binary
/// sits under a home directory the download user usually cannot search, so this also shows that
/// starting the helper through `/proc/self/exe` needs no such permission.
fn runs_as_the_download_user() {
    if !rustix::process::geteuid().is_root() {
        println!("  skipped: needs root");
        return;
    }
    let user = std::env::var("PIKO_TEST_DOWNLOAD_USER").unwrap_or_else(|_| "alpm".to_owned());
    assert_helper_runs_as(Some(&user), &user);
}

/// With no `DownloadUser`, a helper started by root still leaves root, and every capability.
fn runs_as_nobody() {
    if !rustix::process::geteuid().is_root() {
        println!("  skipped: needs root");
        return;
    }
    assert_helper_runs_as(None, piko_net::FALLBACK_USER);
}

/// Starts a helper with `download_user`, and asserts it runs as `expected`, with no
/// supplementary group, no capability, and `no_new_privs`.
fn assert_helper_runs_as(download_user: Option<&str>, expected: &str) {
    let id = |flag: &str| {
        let output = Command::new("id").args([flag, expected]).output().unwrap();
        assert!(output.status.success(), "no user {expected}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    let (uid, gid) = (id("-u"), id("-g"));

    // The server answers late, so the helper is still running while the test looks at it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(1));
        connection::write_closing(&mut stream, &ok_response(b"late"));
    });
    let dir = tempfile::tempdir().unwrap();
    let refresher =
        Refresher::new(Limits::default()).with_sandbox(Sandbox::new(download_user, true, true));
    let cache = dir.path().to_path_buf();
    let fetching = std::thread::spawn(move || {
        fetch(&refresher, &cache, &[url], unsigned(), &Cancel::new()).map(drop)
    });

    let status = helper_status().expect("no helper process appeared");
    fetching.join().unwrap().unwrap();
    drop(server.join());

    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    assert_eq!(field("Uid:").split_whitespace().next(), Some(uid.as_str()), "{status}");
    assert_eq!(field("Gid:").split_whitespace().next(), Some(gid.as_str()), "{status}");
    assert_eq!(field("Groups:"), "", "{status}");
    assert_eq!(field("NoNewPrivs:"), "1", "{status}");
    assert_eq!(field("CapEff:"), "0000000000000000", "{status}");
}

/// `/proc/<pid>/status` of this process's helper child, once one appears.
fn helper_status() -> Option<String> {
    let parent = std::process::id().to_string();
    let deadline = Instant::now().checked_add(Duration::from_secs(5))?;
    while Instant::now() < deadline {
        for entry in std::fs::read_dir("/proc").ok()?.flatten() {
            let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else { continue };
            let named = status.lines().any(|line| line == "Name:\tpiko-fetch");
            let ours = status.lines().any(|line| line.strip_prefix("PPid:\t") == Some(&parent));
            if named && ours {
                return Some(status);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}
