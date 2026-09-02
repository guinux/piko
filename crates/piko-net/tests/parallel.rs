//! What `ParallelDownloads` actually does, against local HTTP servers.
//!
//! ```text
//! cargo test -p piko-net --test parallel
//! ```
//!
//! Hermetic: one `TcpListener` on `127.0.0.1:0` serves each simulated mirror, a `TempDir`
//! serves each test, and no network or keyring is used.
//!
//! # What these exist for
//!
//! A serial downloader holds three properties by construction. Concurrency turns each into a
//! property that needs an explicit assertion:
//!
//! - **Results stay in input order.** A caller reads failures in configuration order. With
//!   several transfers in flight, completion order does not match it.
//! - **Work spreads across mirrors.** The per-host cap is a starting offset, not a semaphore.
//!   The only way to confirm it holds is to watch how many connections each mirror sees at once.
//! - **`ParallelDownloads = 1` stays serial.** The whole design rests on one worker running
//!   the same code path a serial downloader runs. A test that pins the peak at one connection
//!   keeps that claim honest.
//!
//! Unlike `conditional.rs` and `package.rs`, the servers here accept many connections and
//! answer each on its own thread. A single-connection-at-a-time server cannot observe
//! concurrency at all, and it would deadlock the moment two workers dialled it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    io::{BufRead, BufReader, Write},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use alpm_types::PackageFileName;
use piko_net::{Cancel, Concurrency, Outcome, PackageFetch, Refresher, RepoRefresh};
use piko_sig::Policy;

/// How long each response is held open, so overlapping transfers actually overlap.
const HOLD: Duration = Duration::from_millis(60);

/// What one simulated mirror saw.
#[derive(Debug, Default)]
struct Seen {
    /// Connections open right now.
    live: AtomicUsize,
    /// The most connections ever open at once. This is the whole point of this harness.
    peak: AtomicUsize,
    /// Every path requested, in the order the server received it.
    paths: Mutex<Vec<String>>,
}

impl Seen {
    fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    fn paths(&self) -> Vec<String> {
        self.paths.lock().unwrap().clone()
    }
}

/// Starts a mirror that answers every request concurrently, and returns its base URL.
///
/// A `.sig` request gets a `404`. This means "the repository is simply not signed", the norm
/// on real Arch mirrors, so these tests exercise the download path without needing a keyring.
/// Anything else gets a `200` with a small body.
///
/// The acceptor is detached rather than joined. It must keep serving for as long as the test
/// needs it, and there is no fixed request count to stop after: workers decide who fetches what.
fn mirror() -> (String, Arc<Seen>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Seen::default());
    let for_thread = Arc::clone(&seen);

    std::thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            let seen = Arc::clone(&for_thread);
            std::thread::spawn(move || serve_one(stream, &seen));
        }
    });

    (format!("http://127.0.0.1:{port}"), seen)
}

fn serve_one(mut stream: std::net::TcpStream, seen: &Seen) {
    let live = seen.live.fetch_add(1, Ordering::SeqCst).saturating_add(1);
    seen.peak.fetch_max(live, Ordering::SeqCst);

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut first = String::new();
    let _ = reader.read_line(&mut first);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
    }
    let path = first.split_whitespace().nth(1).unwrap_or_default().to_owned();
    seen.paths.lock().unwrap().push(path.clone());

    // Held open long enough for two overlapping transfers to register on `peak`. Without this
    // delay, a worker can finish before the next one dials, and the test passes even on a
    // serial implementation.
    std::thread::sleep(HOLD);

    let response = if path.ends_with(".sig") {
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
    } else {
        let body = b"a database or a package, as far as this test is concerned";
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nLast-Modified: Wed, 26 Aug 2026 08:31:27 \
             GMT\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    };
    let _ = stream.write_all(&response);
    let _ = stream.flush();
    seen.live.fetch_sub(1, Ordering::SeqCst);
}

/// Unsigned: the path under test is the download, not the keyring.
fn unsigned_database() -> Policy {
    Policy::for_database(piko_db::config::SigLevel::default())
}

fn unsigned_package() -> Policy {
    Policy::for_package(piko_db::config::SigLevel::default())
}

fn package_name(index: usize) -> PackageFileName {
    PackageFileName::from_str(&format!("pkg{index}-1.0.0-1-x86_64.pkg.tar.zst")).unwrap()
}

/// Five transfers over four mirrors: the fastest two mirrors take two workers each, so no host
/// ever sees more than the per-host cap at once.
#[test]
fn work_is_spread_so_no_mirror_sees_more_than_the_per_host_cap() {
    let mirrors: Vec<(String, Arc<Seen>)> = (0..4).map(|_| mirror()).collect();
    let servers: Vec<String> = mirrors.iter().map(|(url, _)| url.clone()).collect();
    let cache = tempfile::tempdir().unwrap();

    let names: Vec<PackageFileName> = (0..12).map(package_name).collect();
    let wanted: Vec<PackageFetch<'_>> = names
        .iter()
        .map(|file_name| PackageFetch {
            file_name,
            repo_name: "core",
            servers: &servers,
            policy: unsigned_package(),
            size: 0,
        })
        .collect();

    let concurrency = Concurrency::new(5);
    let results = Refresher::default().fetch_packages(
        cache.path(),
        &wanted,
        concurrency,
        &Cancel::new(),
        &|_| {},
    );
    assert!(results.iter().all(Result::is_ok), "every package should have downloaded");

    for (index, (_, seen)) in mirrors.iter().enumerate() {
        assert!(
            seen.peak() <= concurrency.per_host(),
            "mirror {index} saw {} concurrent connections, above the cap of {}",
            seen.peak(),
            concurrency.per_host()
        );
    }
    let busiest = mirrors.iter().map(|(_, seen)| seen.peak()).max().unwrap_or(0);
    assert!(busiest > 1, "nothing ran concurrently at all — the test proved nothing");
}

/// The regression gate for the whole design. One worker must behave exactly like the serial
/// code path it replaced: it must never open a second connection.
#[test]
fn parallel_downloads_of_one_never_opens_a_second_connection() {
    let (url, seen) = mirror();
    let cache = tempfile::tempdir().unwrap();

    let names: Vec<PackageFileName> = (0..6).map(package_name).collect();
    let servers = vec![url];
    let wanted: Vec<PackageFetch<'_>> = names
        .iter()
        .map(|file_name| PackageFetch {
            file_name,
            repo_name: "core",
            servers: &servers,
            policy: unsigned_package(),
            size: 0,
        })
        .collect();

    let results = Refresher::default().fetch_packages(
        cache.path(),
        &wanted,
        Concurrency::new(1),
        &Cancel::new(),
        &|_| {},
    );
    assert!(results.iter().all(Result::is_ok));
    assert_eq!(seen.peak(), 1, "one worker must not overlap two transfers");
}

/// The schedule decides what runs first. It must not decide what the caller reads.
#[test]
fn packages_are_fetched_largest_first_but_reported_in_input_order() {
    let (url, seen) = mirror();
    let cache = tempfile::tempdir().unwrap();
    let servers = vec![url];

    let names: Vec<PackageFileName> = (0..4).map(package_name).collect();
    // Ascending sizes, so largest-first is the exact reverse of input order.
    let wanted: Vec<PackageFetch<'_>> = names
        .iter()
        .enumerate()
        .map(|(index, file_name)| PackageFetch {
            file_name,
            repo_name: "core",
            servers: &servers,
            policy: unsigned_package(),
            size: index as u64,
        })
        .collect();

    let results = Refresher::default().fetch_packages(
        cache.path(),
        &wanted,
        // One worker: the order the server sees is the schedule, undisturbed by racing.
        Concurrency::new(1),
        &Cancel::new(),
        &|_| {},
    );

    for (index, result) in results.iter().enumerate() {
        let path = result.as_ref().expect("every package downloads");
        assert_eq!(
            path.file_name().unwrap().to_string_lossy(),
            names[index].to_string(),
            "result {index} belongs to a different package than input {index}"
        );
    }

    let fetched: Vec<String> =
        seen.paths().into_iter().filter(|path| !path.ends_with(".sig")).collect();
    assert_eq!(
        fetched.first().map(String::as_str),
        Some(format!("/{}", names[3]).as_str()),
        "the largest package should have been claimed first"
    );
}

/// Several repositories at once, and the caller still reads them in configuration order.
#[test]
fn repositories_refresh_concurrently_and_report_in_input_order() {
    let (url, seen) = mirror();
    let sync = tempfile::tempdir().unwrap();
    let servers = vec![url];

    let names = ["core", "extra", "multilib", "community"];
    let repos: Vec<RepoRefresh<'_>> = names
        .iter()
        .map(|name| RepoRefresh { name, servers: &servers, policy: unsigned_database() })
        .collect();

    let seen_order = Mutex::new(Vec::new());
    let results = Refresher::default().refresh_all(
        sync.path(),
        &repos,
        None,
        Concurrency::new(4),
        false,
        &Cancel::new(),
        &|index, event| {
            if let piko_net::Event::Downloaded { kind: piko_net::Kind::Database, .. } = event {
                seen_order.lock().unwrap().push(index);
            }
        },
    );

    assert_eq!(results.len(), names.len());
    for (index, result) in results.iter().enumerate() {
        assert_eq!(
            *result.as_ref().expect("every repository refreshes"),
            Outcome::Updated,
            "repository {index} ({}) did not update",
            names[index]
        );
        assert!(
            sync.path().join(format!("{}.db", names[index])).exists(),
            "{}.db was not installed",
            names[index]
        );
    }
    assert!(seen.peak() > 1, "the refreshes did not actually overlap");

    let mut reported = seen_order.lock().unwrap().clone();
    reported.sort_unstable();
    assert_eq!(reported, vec![0, 1, 2, 3], "every repository reported its own index");
}

/// A cancelled batch stops claiming work. It reports the work it never reached.
#[test]
fn a_cancelled_batch_stops_and_reports_what_it_never_claimed() {
    let (url, _seen) = mirror();
    let cache = tempfile::tempdir().unwrap();
    let servers = vec![url];

    let names: Vec<PackageFileName> = (0..24).map(package_name).collect();
    let wanted: Vec<PackageFetch<'_>> = names
        .iter()
        .map(|file_name| PackageFetch {
            file_name,
            repo_name: "core",
            servers: &servers,
            policy: unsigned_package(),
            size: 0,
        })
        .collect();

    let cancel = Cancel::new();
    let stopper = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(HOLD);
        stopper.request();
    });

    let results = Refresher::default().fetch_packages(
        cache.path(),
        &wanted,
        Concurrency::new(2),
        &cancel,
        &|_| {},
    );

    assert_eq!(results.len(), names.len());
    let cancelled =
        results.iter().filter(|result| matches!(result, Err(piko_net::Error::Cancelled))).count();
    assert!(cancelled > 0, "a cancelled batch must report the work it abandoned");

    // Nothing half-written is left behind. A cancelled transfer's temporary file is unlinked
    // on drop.
    let leftovers: Vec<_> = std::fs::read_dir(cache.path())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".new"))
        .collect();
    assert!(leftovers.is_empty(), "cancellation left temporaries behind: {leftovers:?}");
}

/// Two workers writing to one atomic-write temporary file would corrupt it. A duplicate is
/// refused rather than silently collapsed.
#[test]
fn a_batch_refuses_a_duplicate_rather_than_racing_for_one_temporary() {
    let (url, seen) = mirror();
    let cache = tempfile::tempdir().unwrap();
    let servers = vec![url];

    let name = package_name(1);
    let wanted: Vec<PackageFetch<'_>> = (0..2)
        .map(|_| PackageFetch {
            file_name: &name,
            repo_name: "core",
            servers: &servers,
            policy: unsigned_package(),
            size: 0,
        })
        .collect();

    let results = Refresher::default().fetch_packages(
        cache.path(),
        &wanted,
        Concurrency::new(4),
        &Cancel::new(),
        &|_| {},
    );
    assert_eq!(results.len(), 2);
    assert!(
        results.iter().all(|result| matches!(result, Err(piko_net::Error::DuplicateTarget { .. }))),
        "a duplicate must fail the batch, not half of it"
    );
    assert!(seen.paths().is_empty(), "the refusal must come before any I/O");
}

/// The same rule for databases, since they share the destination-derived temporary.
#[test]
fn a_repository_named_twice_is_refused_before_any_io() {
    let (url, seen) = mirror();
    let sync = tempfile::tempdir().unwrap();
    let servers = vec![url];
    let repos: Vec<RepoRefresh<'_>> = ["core", "core"]
        .iter()
        .map(|name| RepoRefresh { name, servers: &servers, policy: unsigned_database() })
        .collect();

    let results = Refresher::default().refresh_all(
        sync.path(),
        &repos,
        None,
        Concurrency::new(4),
        false,
        &Cancel::new(),
        &|_, _| {},
    );
    assert!(
        results.iter().all(|result| matches!(result, Err(piko_net::Error::DuplicateTarget { .. })))
    );
    assert!(seen.paths().is_empty(), "the refusal must come before any I/O");
}

/// Progress bytes are deltas, so a sink can sum them across concurrent transfers and reach
/// the real total.
#[test]
fn progress_deltas_sum_to_the_bytes_actually_received() {
    let (url, _seen) = mirror();
    let cache = tempfile::tempdir().unwrap();
    let servers = vec![url];

    let names: Vec<PackageFileName> = (0..6).map(package_name).collect();
    let wanted: Vec<PackageFetch<'_>> = names
        .iter()
        .map(|file_name| PackageFetch {
            file_name,
            repo_name: "core",
            servers: &servers,
            policy: unsigned_package(),
            size: 0,
        })
        .collect();

    let counted = AtomicUsize::new(0);
    let results = Refresher::default().fetch_packages(
        cache.path(),
        &wanted,
        Concurrency::new(4),
        &Cancel::new(),
        &|event| {
            if let piko_net::Event::Progress { kind: piko_net::Kind::Package, bytes } = event {
                counted.fetch_add(bytes as usize, Ordering::Relaxed);
            }
        },
    );

    let mut on_disk = 0_u64;
    for result in &results {
        let path = result.as_ref().expect("every package downloads");
        on_disk = on_disk.saturating_add(std::fs::metadata(path).unwrap().len());
    }
    assert_eq!(
        counted.load(Ordering::Relaxed) as u64,
        on_disk,
        "summed deltas must equal the bytes that landed in the cache"
    );
}
