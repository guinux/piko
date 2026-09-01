//! Regression tests for the conditional-request path, against a local HTTP server.
//!
//! ```text
//! cargo test -p piko-net --test conditional
//! ```
//!
//! Hermetic: a `TcpListener` on `127.0.0.1:0` in a background thread, a `TempDir` for the
//! sync directory, no network and no keyring.
//!
//! # What these exist for
//!
//! A `304 Not Modified` used to destroy the local database. ureq returns 304 as `Ok` with an
//! empty body rather than as `Err(StatusCode(304))`, so a successful conditional request
//! looked like a successful download of nothing, and installing it truncated a working
//! `core.db` to zero bytes. This was observed against a real mirror, not caught by any test.
//! Signature verification cannot catch it either, because with `DatabaseOptional` and no
//! signature there is nothing to contradict an empty file.
//!
//! Both halves are pinned here: that a 304 leaves the database alone, and that a 200 with an
//! empty body is refused rather than installed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::Path,
};

use piko_net::{Outcome, Refresher};
use piko_sig::Policy;

/// Serves `responses` in order, one per connection, then stops.
///
/// Deliberately the crudest HTTP server that works. It reads the request headers, discards
/// them, and writes back a canned response. The point is to control the status, which is
/// what the code under test gets wrong.
fn serve(responses: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                request.push_str(&line);
            }
            seen.push(request);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        }
        seen
    });

    (format!("http://127.0.0.1:{port}"), handle)
}

fn ok_response(body: &[u8], last_modified: &str) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nLast-Modified: {last_modified}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn not_modified() -> Vec<u8> {
    b"HTTP/1.1 304 Not Modified\r\n\r\n".to_vec()
}

/// Databases are unsigned here; the policy under test is the download path, not the keyring.
fn unsigned() -> Policy {
    Policy::for_database(piko_db::config::SigLevel::default())
}

fn refresh(sync: &Path, url: &str) -> piko_net::Result<Outcome> {
    refresh_forced(sync, url, false)
}

fn refresh_forced(sync: &Path, url: &str, force: bool) -> piko_net::Result<Outcome> {
    Refresher::default().refresh(
        sync,
        "core",
        &[url.to_owned()],
        None,
        unsigned(),
        force,
        &piko_net::Cancel::new(),
    )
}

/// The regression: a 304 must leave the installed database exactly as it was.
#[test]
fn a_not_modified_response_does_not_touch_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let sync = dir.path();
    let (url, server) = serve(vec![
        ok_response(b"a real database", "Tue, 18 Aug 2026 18:18:06 GMT"),
        not_modified(),
    ]);

    assert_eq!(refresh(sync, &url).unwrap(), Outcome::Updated);
    assert_eq!(std::fs::read(sync.join("core.db")).unwrap(), b"a real database");

    // Second run: the file is stamped, so the conditional request goes out and is answered 304.
    assert_eq!(refresh(sync, &url).unwrap(), Outcome::UpToDate);
    assert_eq!(
        std::fs::read(sync.join("core.db")).unwrap(),
        b"a real database",
        "a 304 truncated or replaced the live database"
    );

    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests.get(1).unwrap().contains("if-modified-since: Tue, 18 Aug 2026 18:18:06 GMT")
            || requests
                .get(1)
                .unwrap()
                .contains("If-Modified-Since: Tue, 18 Aug 2026 18:18:06 GMT"),
        "the second request did not send the server's own Last-Modified back:\n{}",
        requests.get(1).unwrap()
    );
}

/// The first request has nothing to be conditional about.
#[test]
fn the_first_request_is_unconditional() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(vec![ok_response(b"db", "Tue, 18 Aug 2026 18:18:06 GMT")]);

    assert_eq!(refresh(dir.path(), &url).unwrap(), Outcome::Updated);

    let requests = server.join().unwrap();
    assert!(
        !requests.first().unwrap().to_lowercase().contains("if-modified-since"),
        "a conditional header was sent with no local file:\n{}",
        requests.first().unwrap()
    );
}

/// Defence in depth behind the status check: a 200 carrying nothing is refused, not installed.
#[test]
fn an_empty_body_is_refused_rather_than_installed() {
    let dir = tempfile::tempdir().unwrap();
    let sync = dir.path();
    let (url, server) = serve(vec![
        ok_response(b"a real database", "Tue, 18 Aug 2026 18:18:06 GMT"),
        ok_response(b"", "Wed, 19 Aug 2026 10:00:00 GMT"),
    ]);

    refresh(sync, &url).unwrap();
    let error = refresh(sync, &url).unwrap_err();

    // Reported through `AllServersFailed`, because an empty body from one mirror is a reason
    // to try the next rather than to abort — the same fallthrough any other failure gets.
    assert!(
        error.to_string().contains("was empty"),
        "an empty body was not reported as such: {error}"
    );
    assert_eq!(
        std::fs::read(sync.join("core.db")).unwrap(),
        b"a real database",
        "an empty download replaced the live database"
    );
    drop(server.join());
}

/// The server's timestamp is what lands on the file, not the moment of download — which is
/// what makes the next conditional request send a value the server recognises.
#[test]
fn the_download_carries_the_servers_last_modified() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(vec![ok_response(b"db", "Tue, 18 Aug 2026 18:18:06 GMT")]);

    refresh(dir.path(), &url).unwrap();

    let mtime = std::fs::metadata(dir.path().join("core.db")).unwrap().modified().unwrap();
    let seconds = mtime.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    // Tue, 18 Aug 2026 18:18:06 GMT, per `date -u -d '...' +%s`. The first constant written
    // here was wrong and the implementation was right, which is why it is now sourced from
    // the reference tool rather than from arithmetic done by hand.
    assert_eq!(seconds, 1_787_077_086);
    drop(server.join());
}

/// An unexpected status is an error, not a body to install.
#[test]
fn an_unexpected_status_is_not_installed() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) =
        serve(vec![b"HTTP/1.1 500 Server Error\r\nContent-Length: 0\r\n\r\n".to_vec()]);

    let error = refresh(dir.path(), &url).unwrap_err();
    assert!(matches!(error, piko_net::Error::AllServersFailed { .. }), "{error:?}");
    assert!(!dir.path().join("core.db").exists(), "a 500 left a file behind");
    drop(server.join());
}

/// `force` skips the conditional request entirely, so a stamped local file never turns the
/// second request into one the server could answer 304.
#[test]
fn force_bypasses_the_conditional_request() {
    let dir = tempfile::tempdir().unwrap();
    let sync = dir.path();
    let (url, server) = serve(vec![
        ok_response(b"a real database", "Tue, 18 Aug 2026 18:18:06 GMT"),
        ok_response(b"an updated database", "Wed, 19 Aug 2026 10:00:00 GMT"),
    ]);

    assert_eq!(refresh_forced(sync, &url, false).unwrap(), Outcome::Updated);
    assert_eq!(refresh_forced(sync, &url, true).unwrap(), Outcome::Updated);
    assert_eq!(std::fs::read(sync.join("core.db")).unwrap(), b"an updated database");

    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        !requests.get(1).unwrap().to_lowercase().contains("if-modified-since"),
        "force still sent a conditional header:\n{}",
        requests.get(1).unwrap()
    );
}
