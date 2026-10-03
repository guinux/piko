//! Sends a signal to `piko refresh` while its download waits on a server that never answers.
//!
//! A hangup and a terminate request stop the run cleanly, however many arrive. A second Ctrl+C
//! is not tested here: the stop completes before a second signal can reliably land. Hermetic: the server is a `TcpListener` on `127.0.0.1:0` that accepts
//! each connection and then sends nothing.

#![expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]

use std::{
    io::Read,
    net::{TcpListener, TcpStream},
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    time::Duration,
};

use rustix::process::{Pid, Signal};

/// Starts a server that accepts every connection and never answers. Each accepted connection
/// is reported on the returned channel, and kept open until the test process ends.
fn silent_server() -> (u16, mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (accepted, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut open: Vec<TcpStream> = Vec::new();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            open.push(stream);
            let _ = accepted.send(());
        }
    });
    (port, receiver)
}

/// Starts `piko refresh` against a server on `port`, into a database path inside `dir`.
fn start_refresh(dir: &Path, port: u16) -> Child {
    let config = dir.join("pacman.conf");
    std::fs::write(
        &config,
        format!(
            "[options]\nSigLevel = Never\nLogFile = {}\n\n[core]\nServer = http://127.0.0.1:{port}/core\n",
            dir.join("pacman.log").display()
        ),
    )
    .unwrap();
    let dbpath = dir.join("db");
    std::fs::create_dir(&dbpath).unwrap();
    Command::new(env!("CARGO_BIN_EXE_piko"))
        .arg("refresh")
        .arg("--config")
        .arg(&config)
        .arg("--dbpath")
        .arg(&dbpath)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Sends each of `signals` to `child`, once its request reached the server, and waits for it.
fn signal_during_download(signals: &[Signal]) -> (Output, tempfile::TempDir) {
    let (port, accepted) = silent_server();
    let dir = tempfile::tempdir().unwrap();
    let mut child = start_refresh(dir.path(), port);
    accepted.recv_timeout(Duration::from_secs(30)).unwrap();
    let pid = Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    for &signal in signals {
        rustix::process::kill_process(pid, signal).unwrap();
        // Short enough that the second signal lands before the stop completes, which takes
        // about 100 ms here. A longer wait tests one signal twice over.
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    let status = child.wait().unwrap();
    (Output { status, stdout: Vec::new(), stderr: stderr.into_bytes() }, dir)
}

/// The downloaded database, or any temporary of it, left in the sync directory.
fn leftovers(dir: &Path) -> Vec<std::path::PathBuf> {
    let sync = dir.join("db/sync");
    let Ok(entries) = std::fs::read_dir(sync) else { return Vec::new() };
    entries.map(|entry| entry.unwrap().path()).collect()
}

/// Two hangups stop the download. The process ends by returning, not by the signal, and not by
/// the forced exit a second Ctrl+C takes.
#[test]
fn a_hangup_stops_a_refresh_and_never_forces_the_exit() {
    let (output, dir) = signal_during_download(&[Signal::HUP, Signal::HUP]);
    assert_eq!(output.status.signal(), None, "the hangup killed the process");
    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(leftovers(dir.path()), Vec::<std::path::PathBuf>::new());
}

/// Two terminate requests stop the download the same way, and the first one says so.
#[test]
fn a_terminate_request_stops_a_refresh_and_never_forces_the_exit() {
    let (output, dir) = signal_during_download(&[Signal::TERM, Signal::TERM]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.signal(), None, "the terminate request killed the process");
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Stopping: terminate request received..."), "{stderr}");
    assert_eq!(leftovers(dir.path()), Vec::<std::path::PathBuf>::new());
}
