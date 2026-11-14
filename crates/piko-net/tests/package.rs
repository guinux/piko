//! Regression tests for package downloading, against a local HTTP server.
//!
//! ```text
//! cargo test -p piko-net --test package
//! ```
//!
//! Hermetic: a `TcpListener` on `127.0.0.1:0` runs in a background thread, a `TempDir` serves
//! as the cache, and no network is used. This mirrors `tests/conditional.rs`'s harness. The
//! same crude server works for a package fetch as for a database refresh.

#![expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]

use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::Path,
    str::FromStr as _,
    time::Duration,
};

use alpm_types::PackageFileName;
use piko_net::{Cancel, Limits, PackageFetch, Refresher};
use piko_sig::Policy;

mod connection;

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
            connection::write_closing(&mut stream, &response);
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

/// A fetch of [`NAME`] from `servers`, declaring `size` bytes.
fn wanted<'a>(
    file_name: &'a PackageFileName,
    servers: &'a [String],
    policy: Policy,
    size: Option<u64>,
) -> PackageFetch<'a> {
    PackageFetch::new(file_name, "core", servers, policy).with_size(size)
}

fn fetch(cache: &Path, url: &str, policy: Policy) -> piko_net::Result<std::path::PathBuf> {
    fetch_declared(cache, url, policy, None)
}

fn fetch_declared(
    cache: &Path,
    url: &str,
    policy: Policy,
    size: Option<u64>,
) -> piko_net::Result<std::path::PathBuf> {
    let (file_name, servers) = (file_name(), [url.to_owned()]);
    Refresher::default().fetch_package(
        cache,
        wanted(&file_name, &servers, policy, size),
        &Cancel::new(),
    )
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

/// Bounds short enough to test: one second for the response to begin, and one second with no
/// bytes.
fn short_waits() -> Refresher {
    Refresher::new(Limits {
        timeout: Duration::from_secs(1),
        stall_timeout: Some(Duration::from_secs(1)),
        ..Limits::default()
    })
}

/// No bound covers the whole transfer. A body that keeps arriving completes, however long it
/// takes against the two waits.
#[test]
fn a_slow_transfer_that_keeps_arriving_completes() {
    let dir = tempfile::tempdir().unwrap();
    // Three seconds in all, and never more than 250 ms without a byte.
    let url = serve_slowly(12, Duration::from_millis(250));
    let (file_name, servers) = (file_name(), [url]);

    let path = short_waits()
        .fetch_package(dir.path(), wanted(&file_name, &servers, unsigned(), None), &Cancel::new())
        .unwrap();

    assert_eq!(std::fs::read(path).unwrap().len(), 12 * 256);
}

/// A body that stops arriving is given up after the stall bound, and nothing reaches the cache.
#[test]
fn a_transfer_that_stops_is_given_up() {
    let dir = tempfile::tempdir().unwrap();
    let url = serve_slowly(2, Duration::from_secs(4));
    let (file_name, servers) = (file_name(), [url]);
    let started = std::time::Instant::now();

    let error = short_waits()
        .fetch_package(dir.path(), wanted(&file_name, &servers, unsigned(), None), &Cancel::new())
        .unwrap_err();

    assert!(error.to_string().contains("timeout"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    assert!(!dir.path().join(NAME).exists());
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

/// A plain `http` mirror off this machine is refused before any connection, and the next
/// mirror serves the package. With no other mirror, the refusal is what the error reports.
#[test]
fn a_plain_http_mirror_is_refused_and_the_next_one_serves() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(vec![ok_response(b"a real package")]);
    let (file_name, servers) =
        (file_name(), ["http://mirror.example.invalid/core".to_owned(), url]);
    let path = Refresher::default()
        .fetch_package(dir.path(), wanted(&file_name, &servers, unsigned(), None), &Cancel::new())
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"a real package");
    drop(server.join());

    let error = fetch(dir.path(), "http://mirror.example.invalid/core", unsigned()).unwrap_err();
    assert!(error.to_string().contains("https only"), "{error}");
}

/// An `http` URL on the loopback follows no redirect: one could lead off the machine.
#[test]
fn a_loopback_http_mirror_follows_no_redirect() {
    let dir = tempfile::tempdir().unwrap();
    let (target, target_server) = serve(vec![ok_response(b"a real package")]);
    let redirect =
        format!("HTTP/1.1 302 Found\r\nLocation: {target}/{NAME}\r\nContent-Length: 0\r\n\r\n");
    let (url, server) = serve(vec![redirect.into_bytes()]);

    let error = fetch(dir.path(), &url, unsigned()).unwrap_err();
    assert!(error.to_string().contains("302"), "{error}");
    assert!(!dir.path().join(NAME).exists());
    drop(server.join());
    // Unblock the target's accept, and check it was never asked.
    drop(std::net::TcpStream::connect(target.trim_start_matches("http://")));
    assert!(target_server.join().unwrap().iter().all(|request| request.is_empty()));
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
    let file_name = file_name();
    let error = Refresher::default()
        .fetch_package(dir.path(), wanted(&file_name, &[], unsigned(), None), &Cancel::new())
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

    let limits = piko_net::Limits { max_package_bytes: 100, ..Default::default() };
    let (file_name, servers) = (file_name(), [url]);
    // A declared size above the ceiling does not lift it.
    let error = Refresher::new(limits)
        .fetch_package(
            dir.path(),
            wanted(&file_name, &servers, unsigned(), Some(1000)),
            &Cancel::new(),
        )
        .unwrap_err();
    assert!(matches!(error, piko_net::Error::AllServersFailed { .. }), "{error:?}");
    assert!(error.to_string().contains("100 byte download limit"), "{error}");
    assert!(!dir.path().join(NAME).exists(), "an oversized download left a file behind");
    drop(server.join());
}

/// A signature is bounded at libalpm's 16 KiB (`dload.c:667`). One byte more is refused, and
/// the package that came with it does not reach the cache either.
#[test]
fn a_signature_past_sixteen_kib_is_refused() {
    let bound = usize::try_from(piko_sig::MAX_SIGNATURE_BYTES).unwrap();
    assert_eq!(bound, 16 * 1024);

    let dir = tempfile::tempdir().unwrap();
    let (url, server) =
        serve(vec![ok_response(b"a real package"), ok_response(&vec![0_u8; bound + 1])]);
    let error = fetch(dir.path(), &url, required()).unwrap_err();
    assert!(error.to_string().contains("16384 byte download limit"), "{error}");
    assert!(!dir.path().join(NAME).exists(), "the package was kept without its signature");
    drop(server.join());

    let (url, server) =
        serve(vec![ok_response(b"a real package"), ok_response(&vec![0_u8; bound])]);
    let path = fetch(dir.path(), &url, required()).unwrap();
    assert_eq!(std::fs::metadata(piko_sig::signature_path(&path)).unwrap().len(), 16 * 1024);
    drop(server.join());
}

/// A package is bounded by the `%CSIZE%` its repository declares, well below the ceiling. A
/// mirror that sends more is refused while it sends, and nothing reaches the cache.
#[test]
fn a_body_past_its_declared_size_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(vec![ok_response(&[0_u8; 200])]);

    let error = fetch_declared(dir.path(), &url, unsigned(), Some(100)).unwrap_err();
    assert!(matches!(error, piko_net::Error::AllServersFailed { .. }), "{error:?}");
    assert!(error.to_string().contains("larger than the 100 bytes"), "{error}");
    assert!(!dir.path().join(NAME).exists(), "a download past its size left a file behind");
    drop(server.join());
}

/// A body of exactly its declared size is the ordinary case, and downloads.
#[test]
fn a_body_of_exactly_its_declared_size_downloads() {
    let dir = tempfile::tempdir().unwrap();
    let body = b"a real package";
    let (url, server) = serve(vec![ok_response(body)]);

    let size = u64::try_from(body.len()).unwrap();
    let path = fetch_declared(dir.path(), &url, unsigned(), Some(size)).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), body);
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
    let (file_name, servers) = (file_name(), [url]);
    let error = Refresher::default()
        .fetch_package(dir.path(), wanted(&file_name, &servers, unsigned(), None), &cancel)
        .unwrap_err();
    assert!(matches!(error, piko_net::Error::Cancelled), "{error:?}");
    assert!(error.to_string().contains("cancelled"), "{error}");
    assert!(!dir.path().join(NAME).exists(), "a cancelled download left a file behind");
    assert!(!server.is_finished(), "the server should still be waiting for a call that never came");
}

/// A password in a server URL is sent, and never reported. libalpm names a server by its host
/// alone (`curl_gethost`, `dload.c:307`).
#[test]
fn a_server_password_is_sent_and_never_reported() {
    let dir = tempfile::tempdir().unwrap();
    let server_error = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec();
    let (url, server) = serve(vec![not_found(), ok_response(b"a real package"), server_error]);
    let with_password = url.replace("http://", "http://user:secret@");

    // The package itself fails.
    let error = fetch(dir.path(), &with_password, unsigned()).unwrap_err();
    let text = format!("{error} {error:?}");
    assert!(!text.contains("secret"), "{text}");
    assert!(text.contains(&format!("{url}/{NAME}")), "{text}");

    // The package downloads and its signature fails.
    let error = fetch(dir.path(), &with_password, required()).unwrap_err();
    let text = format!("{error} {error:?}");
    assert!(!text.contains("secret"), "{text}");
    assert!(text.contains(&format!("{url}/{NAME}.sig answered HTTP 500")), "{text}");

    let seen = server.join().unwrap();
    // `user:secret`, as HTTP basic authentication spells it.
    assert!(seen.iter().all(|request| request.contains("dXNlcjpzZWNyZXQ=")), "{seen:?}");
}

/// Ends a `serve` thread still waiting for a connection, and returns what it saw. A request
/// this makes is empty, so a test can tell it from a real one.
fn finish(url: &str, server: std::thread::JoinHandle<Vec<String>>) -> Vec<String> {
    let address = url.trim_start_matches("http://");
    drop(std::net::TcpStream::connect(address));
    server.join().unwrap()
}

/// A host that failed three requests is not asked again by the same `Refresher`, as libalpm
/// skips it for the rest of a transaction (`server_error_limit`, `dload.c:136`).
#[test]
fn a_host_that_failed_three_times_is_not_asked_again() {
    let dir = tempfile::tempdir().unwrap();
    let (dead, dead_server) = serve(vec![not_found(); 4]);
    let (good, good_server) = serve(vec![ok_response(b"a real package"); 3]);
    let file_name = file_name();
    let refresher = Refresher::default();

    let both = [format!("{dead}/core"), good.clone()];
    let skipped = std::sync::Mutex::new(Vec::new());
    let sink = |event: piko_net::Event| {
        if let piko_net::Event::HostSkipped { host } = event {
            skipped.lock().unwrap().push(host);
        }
    };
    for _ in 0..3 {
        let fetched = refresher.fetch_package_with_progress(
            dir.path(),
            wanted(&file_name, &both, unsigned(), None),
            &Cancel::new(),
            &sink,
        );
        assert!(fetched.is_ok(), "{fetched:?}");
    }
    // Said once, by the request that reached the limit.
    assert_eq!(*skipped.lock().unwrap(), [dead.trim_start_matches("http://")]);
    // Another path on the same host: the count is the host's.
    let only_dead = [format!("{dead}/extra")];
    let error = refresher
        .fetch_package(dir.path(), wanted(&file_name, &only_dead, unsigned(), None), &Cancel::new())
        .unwrap_err();
    assert!(format!("{error:?}").contains("not asked"), "{error:?}");

    let seen = finish(&dead, dead_server);
    assert_eq!(seen.iter().filter(|request| request.starts_with("GET")).count(), 3, "{seen:?}");
    drop(finish(&good, good_server));
}

/// A `CacheServer` that does not hold a file is asked again for the next one. libalpm does not
/// count its errors (`request_errors_ok`, `dload.c:233`).
#[test]
fn a_cache_server_is_asked_again_after_any_number_of_misses() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, cache_server) = serve(vec![not_found(); 5]);
    let (good, good_server) = serve(vec![ok_response(b"a real package"); 5]);
    let file_name = file_name();
    let refresher = Refresher::default();
    let servers = [cache.clone(), good.clone()];

    for _ in 0..5 {
        let fetched = refresher.fetch_package(
            dir.path(),
            wanted(&file_name, &servers, unsigned(), None).with_cache_servers(1),
            &Cancel::new(),
        );
        assert!(fetched.is_ok(), "{fetched:?}");
    }

    let seen = finish(&cache, cache_server);
    assert_eq!(seen.iter().filter(|request| request.starts_with("GET")).count(), 5, "{seen:?}");
    drop(finish(&good, good_server));
}

/// A server that answers every request with `body` after a short wait, and counts them.
fn counting_server(
    body: &'static [u8],
) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            seen.fetch_add(1, Ordering::Relaxed);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) != 0 && line != "\r\n" {
                    line.clear();
                }
                // Long enough for every worker of the batch to hold a transfer at once.
                std::thread::sleep(Duration::from_millis(100));
                connection::write_closing(&mut stream, &ok_response(body));
            });
        }
    });
    (format!("http://127.0.0.1:{port}"), count)
}

/// Mirror spreading starts each group of workers on another mirror. It never starts one past a
/// `CacheServer`: a cache that holds every file serves every file.
#[test]
fn every_worker_of_a_batch_asks_the_cache_server_first() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, cache_requests) = counting_server(b"from the cache");
    let (mirror, mirror_requests) = counting_server(b"from the mirror");
    let servers = [cache, mirror];
    let names: Vec<PackageFileName> = (0..10)
        .map(|n| PackageFileName::from_str(&format!("foo{n}-1.0.0-1-x86_64.pkg.tar.zst")).unwrap())
        .collect();
    let batch: Vec<PackageFetch<'_>> = names
        .iter()
        .map(|name| wanted(name, &servers, unsigned(), None).with_cache_servers(1))
        .collect();

    let results = Refresher::default().fetch_packages(
        dir.path(),
        &batch,
        piko_net::Concurrency::new(5),
        &Cancel::new(),
        &|_| {},
    );

    for result in results {
        assert_eq!(std::fs::read(result.unwrap()).unwrap(), b"from the cache");
    }
    let count = |requests: &std::sync::atomic::AtomicUsize| {
        requests.load(std::sync::atomic::Ordering::Relaxed)
    };
    assert_eq!((count(&cache_requests), count(&mirror_requests)), (10, 0));
}
