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
//! These test the sandbox's security claims: the helper writes no file, starts no program and
//! no process, and reaches only the ports it was given, while it can still read files and start
//! the thread its resolver uses. They also test that a transfer through the helper arrives byte
//! for byte, and that a cancellation stops a helper that is waiting on a silent server.
//!
//! Only one test needs root: a download user is used only by root. It reports itself skipped
//! otherwise. To run it as root without building as root, build with
//! `cargo test -p piko-net --test sandbox --no-run`. That command prints the test binary's path.
//! Run that path under `sudo`, with the argument `download_user`.
//!
//! It switches to `alpm`, or to the user named by `PIKO_TEST_DOWNLOAD_USER`.

#![allow(
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
use piko_net::{Cancel, Error, Refresher, Sandbox, refresh::Limits};
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
        ("a_missing_signature_is_absent_through_the_helper", missing_signature_is_absent),
        ("a_cancellation_stops_a_helper_waiting_on_a_silent_server", cancellation_stops_helper),
        ("the_helper_cannot_write_a_file", cannot_write),
        ("the_helper_cannot_start_a_program", cannot_start_a_program),
        ("the_system_call_filter_alone_refuses_a_new_process", filter_alone_refuses_a_process),
        ("the_helper_cannot_connect_to_a_port_it_was_not_given", cannot_connect_elsewhere),
        ("the_helper_can_connect_to_a_port_it_was_given", can_connect_to_its_port),
        ("the_helper_can_read_a_file_and_start_a_thread", can_read_and_start_a_thread),
        ("as_root_the_helper_runs_as_the_download_user", runs_as_the_download_user),
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
    if let Err(message) = piko_net::sandbox::confine_self(filesystem, true, &ports) {
        eprintln!("confinement failed: {message}");
        return ExitCode::from(4);
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
        "exec" | "spawn-without-landlock" => refused(Command::new(target).status().map(drop)),
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

fn can_connect_to_its_port() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    run_probe("connect-allowed", &listener.local_addr().unwrap().port().to_string());
}

fn can_read_and_start_a_thread() {
    run_probe("read-and-thread", "/etc/os-release");
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
    refresher.fetch_package(cache, &file_name, "core", servers, policy, cancel)
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

/// As root, the helper runs as the download user, with no supplementary group. The test binary
/// sits under a home directory the download user usually cannot search, so this also shows that
/// starting the helper through `/proc/self/exe` needs no such permission.
fn runs_as_the_download_user() {
    if !rustix::process::geteuid().is_root() {
        println!("  skipped: needs root");
        return;
    }
    let user = std::env::var("PIKO_TEST_DOWNLOAD_USER").unwrap_or_else(|_| "alpm".to_owned());
    let id = |flag: &str| {
        let output = Command::new("id").args([flag, &user]).output().unwrap();
        assert!(output.status.success(), "no user {user}");
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
        Refresher::new(Limits::default()).with_sandbox(Sandbox::new(Some(&user), true, true));
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
