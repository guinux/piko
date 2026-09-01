//! Regression tests for package downloading, against a local HTTP server.
//!
//! ```text
//! cargo test -p piko-net --test package
//! ```
//!
//! Hermetic: a `TcpListener` on `127.0.0.1:0` runs in a background thread, a `TempDir` serves
//! as the cache, and no network is used. This mirrors `tests/conditional.rs`'s harness. The
//! same crude server works for a package fetch as for a database refresh.

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
    str::FromStr as _,
};

use alpm_types::PackageFileName;
use piko_net::{Cancel, Refresher};
use piko_sig::Policy;

const NAME: &str = "foo-1.0.0-1-x86_64.pkg.tar.zst";

fn file_name() -> PackageFileName {
    PackageFileName::from_str(NAME).unwrap()
}

/// As `conditional.rs`'s `serve`: the crudest HTTP server that works, one response per
/// connection.
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

fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}

fn not_found() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
}

fn required() -> Policy {
    Policy::for_package(piko_db::config::SigLevel::PACKAGE)
}

fn unsigned() -> Policy {
    Policy::for_package(piko_db::config::SigLevel::default())
}

fn fetch(cache: &Path, url: &str, policy: Policy) -> piko_net::Result<std::path::PathBuf> {
    Refresher::default().fetch_package(
        cache,
        &file_name(),
        "core",
        &[url.to_owned()],
        policy,
        &Cancel::new(),
    )
}

/// A missing package downloads and lands in the cache under its own name.
#[test]
fn a_missing_package_downloads_and_lands_in_the_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(vec![ok_response(b"a real package")]);

    let path = fetch(dir.path(), &url, unsigned()).unwrap();
    assert_eq!(path, dir.path().join(NAME));
    assert_eq!(std::fs::read(&path).unwrap(), b"a real package");
    drop(server.join());
}

/// When the policy checks signatures, the package's own detached `.sig` is fetched alongside
/// it, at the exact path `piko_sig::Keyring::check` looks for.
#[test]
fn a_signature_is_fetched_alongside_a_checked_package() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(vec![ok_response(b"a real package"), ok_response(b"a signature")]);

    fetch(dir.path(), &url, required()).unwrap();

    assert_eq!(std::fs::read(dir.path().join(format!("{NAME}.sig"))).unwrap(), b"a signature");
    drop(server.join());
}

/// When the policy does not check, no request is made for a signature at all.
#[test]
fn no_signature_is_fetched_when_the_policy_does_not_check() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(vec![ok_response(b"a real package")]);

    fetch(dir.path(), &url, unsigned()).unwrap();

    assert!(!dir.path().join(format!("{NAME}.sig")).exists());
    // Only one request reaches the server: the package, not a signature.
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 1, "{requests:?}");
}

/// A `404` for the signature is not an error. It means the package is simply unsigned.
/// Accepting or rejecting that is the policy's business, not this crate's.
#[test]
fn a_missing_signature_is_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(vec![ok_response(b"a real package"), not_found()]);

    let path = fetch(dir.path(), &url, required()).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"a real package");
    assert!(!dir.path().join(format!("{NAME}.sig")).exists());
    drop(server.join());
}

/// No configured servers is refused before any I/O, naming the repository.
#[test]
fn no_servers_is_refused_before_any_io() {
    let dir = tempfile::tempdir().unwrap();
    let error = Refresher::default()
        .fetch_package(dir.path(), &file_name(), "core", &[], unsigned(), &Cancel::new())
        .unwrap_err();
    assert!(matches!(error, piko_net::Error::NoServers { .. }), "{error:?}");
}

/// An empty body is refused rather than written into the cache.
#[test]
fn an_empty_body_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(vec![ok_response(b"")]);

    let error = fetch(dir.path(), &url, unsigned()).unwrap_err();
    assert!(error.to_string().contains("was empty"), "{error}");
    assert!(!dir.path().join(NAME).exists(), "an empty download left a file behind");
    drop(server.join());
}

/// A download exceeding the bound is refused, and nothing is left behind.
#[test]
fn an_oversized_body_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let big = vec![0_u8; 200];
    let (url, server) = serve(vec![ok_response(&big)]);

    let limits = piko_net::refresh::Limits { max_package_bytes: 100, ..Default::default() };
    let error = Refresher::new(limits)
        .fetch_package(dir.path(), &file_name(), "core", &[url], unsigned(), &Cancel::new())
        .unwrap_err();
    assert!(matches!(error, piko_net::Error::AllServersFailed { .. }), "{error:?}");
    assert!(!dir.path().join(NAME).exists(), "an oversized download left a file behind");
    drop(server.join());
}

/// A cancellation requested before the transfer starts stops it immediately, leaving nothing
/// behind. The temporary file is unlinked on drop, since it was never committed.
///
/// The server here is deliberately not joined. `Cancel` is checked before the request is
/// issued, not only inside the stream. A run cancelled this early never opens a connection, so
/// `accept()` would block forever. The server never being dialled is the property under test;
/// a `join` would turn it into a hang.
#[test]
fn a_cancelled_download_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(vec![ok_response(&vec![0_u8; 1024 * 1024])]);

    let cancel = Cancel::new();
    cancel.request();
    let error = Refresher::default()
        .fetch_package(dir.path(), &file_name(), "core", &[url], unsigned(), &cancel)
        .unwrap_err();
    assert!(matches!(error, piko_net::Error::Cancelled), "{error:?}");
    assert!(error.to_string().contains("cancelled"), "{error}");
    assert!(!dir.path().join(NAME).exists(), "a cancelled download left a file behind");
    assert!(!server.is_finished(), "the server should still be waiting for a call that never came");
}
