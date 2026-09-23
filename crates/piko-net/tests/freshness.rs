//! A refresh refuses an older database, passes over a mirror that is behind, and looks
//! further when the database in place is old.
//!
//! ```text
//! cargo test -p piko-net --test freshness
//! ```
//!
//! Hermetic: each mirror is a `TcpListener` on `127.0.0.1:0` in a background thread, and a
//! `TempDir` is the sync directory. No keyring: every database here is unsigned, so it is dated
//! by its newest archive member. `rollback_attack.rs` covers the signed case.
//!
//! # What these exist for
//!
//! pacman refuses a mirror that is behind without meaning to. libcurl's time condition turns a
//! `200` whose `Last-Modified` is not newer than the local file into "not modified". Some
//! mirrors answer `304` only to an exact `If-Modified-Since`, so without that check a mirror
//! that is behind replaces a newer database. These tests pin that piko makes the same check,
//! then goes further: it tries the next mirror instead of stopping, it checks the archive's own
//! date as well as the header, and `force` does not turn any of it off.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use piko_db::repo::freshness::{Comparison, Tier};
use piko_net::{
    Cancel, Concurrency, DatabaseKind, FreshnessNote, FreshnessPolicy, Outcome, Refreshed,
    Refresher, RepoRefresh,
};
use piko_sig::Policy;

/// Tue, 18 Aug 2026 18:18:06 GMT.
const T1: u64 = 1_787_077_086;
/// Wed, 19 Aug 2026 10:00:00 GMT.
const T2: u64 = 1_787_133_600;
/// Wed, 26 Aug 2026 08:31:27 GMT.
const T3: u64 = 1_787_733_087;
/// Fri, 01 Jan 2027 00:00:00 GMT.
const T9: u64 = 1_798_761_600;

/// The `Last-Modified` spelling of each constant, checked against `date -u -d @<n>`.
fn http_date(seconds: u64) -> &'static str {
    match seconds {
        T1 => "Tue, 18 Aug 2026 18:18:06 GMT",
        T2 => "Wed, 19 Aug 2026 10:00:00 GMT",
        T3 => "Wed, 26 Aug 2026 08:31:27 GMT",
        T9 => "Fri, 01 Jan 2027 00:00:00 GMT",
        other => panic!("no HTTP date for {other}"),
    }
}

/// A repository archive published at `mtime`, labelled so two of them differ in their bytes.
fn database(label: &str, mtime: u64) -> Vec<u8> {
    piko_db::fixture::gzip_tar_at(&[("foo-1.0.0-1/desc", label.as_bytes())], mtime)
}

/// Serves `responses` in order, one per connection, then stops. Returns the base URL and a
/// handle that yields every request line and header block it read.
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

/// A `200` that ignores any `If-Modified-Since`, the way an exact-match-only mirror answers a
/// date it does not recognise.
fn ok(body: &[u8], last_modified: u64) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nLast-Modified: {}\r\n\r\n",
        body.len(),
        http_date(last_modified)
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn not_modified() -> Vec<u8> {
    b"HTTP/1.1 304 Not Modified\r\n\r\n".to_vec()
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// A policy at `now`, with the default age limit.
fn policy_at(now: u64) -> FreshnessPolicy {
    FreshnessPolicy::new(at(now))
}

/// Writes `bytes` as the installed `core.db`, stamped with `mtime` the way a download stamps
/// it with the server's `Last-Modified`.
fn install(sync: &Path, bytes: &[u8], mtime: u64) {
    let path = sync.join("core.db");
    std::fs::write(&path, bytes).unwrap();
    std::fs::File::options().write(true).open(&path).unwrap().set_modified(at(mtime)).unwrap();
}

fn refresh_kind(
    sync: &Path,
    kind: DatabaseKind,
    servers: &[String],
    freshness: FreshnessPolicy,
    force: bool,
) -> piko_net::Result<Refreshed> {
    let repos = [RepoRefresh {
        name: "core",
        kind,
        servers,
        // Unsigned: nothing is verified, and the archive's own date is what gets compared.
        policy: Policy::for_database(piko_db::config::SigLevel::default()),
        freshness,
    }];
    Refresher::default()
        .refresh_all(sync, &repos, None, Concurrency::new(1), force, &Cancel::new(), &|_, _| {})
        .pop()
        .unwrap()
}

fn refresh(
    sync: &Path,
    servers: &[String],
    freshness: FreshnessPolicy,
    force: bool,
) -> piko_net::Result<Refreshed> {
    refresh_kind(sync, DatabaseKind::Db, servers, freshness, force)
}

fn installed(sync: &Path) -> Vec<u8> {
    std::fs::read(sync.join("core.db")).unwrap()
}

/// libcurl's parity case, with piko's difference: the mirror that is behind is passed over and
/// the next one serves. pacman would stop at the first and call the database up to date.
#[test]
fn a_mirror_whose_last_modified_is_older_is_passed_over_for_the_next() {
    let sync = tempfile::tempdir().unwrap();
    install(sync.path(), &database("installed", T2), T2);
    let newer = database("newer", T3);
    let (behind, _) = serve(vec![ok(&database("behind", T1), T1)]);
    let (ahead, _) = serve(vec![ok(&newer, T3)]);

    let refreshed =
        refresh(sync.path(), &[behind.clone(), ahead], policy_at(T3 + 3_600), false).unwrap();

    assert_eq!(refreshed.outcome, Outcome::Updated);
    assert_eq!(installed(sync.path()), newer, "the second mirror's database must be installed");
    assert_eq!(
        refreshed.notes,
        [FreshnessNote::Behind { server: format!("{behind}/core.db"), last_modified: T1 }]
    );
}

/// The synthetic `304`: a `200` whose `Last-Modified` equals the local stamp is "not modified",
/// and the file is not replaced.
#[test]
fn an_equal_last_modified_counts_as_not_modified() {
    let sync = tempfile::tempdir().unwrap();
    let live = database("installed", T2);
    install(sync.path(), &live, T2);
    let (mirror, requests) = serve(vec![ok(&database("same publication", T2), T2)]);

    let refreshed = refresh(sync.path(), &[mirror], policy_at(T2 + 3_600), false).unwrap();

    assert_eq!(refreshed.outcome, Outcome::UpToDate);
    assert_eq!(installed(sync.path()), live);
    assert_eq!(requests.join().unwrap().len(), 1);
}

/// A mirror that does not keep file times sends a new `Last-Modified` for old content. The
/// header passes it, and the archive's own date catches it.
#[test]
fn an_older_archive_behind_a_newer_last_modified_is_refused() {
    let sync = tempfile::tempdir().unwrap();
    install(sync.path(), &database("installed", T2), T2);
    let newer = database("newer", T3);
    let (lying, _) = serve(vec![ok(&database("old content", T1), T9)]);
    let (honest, _) = serve(vec![ok(&newer, T3)]);

    let refreshed =
        refresh(sync.path(), &[lying.clone(), honest], policy_at(T3 + 3_600), false).unwrap();

    assert_eq!(refreshed.outcome, Outcome::Updated);
    assert_eq!(installed(sync.path()), newer);
    let [FreshnessNote::RefusedOlder { server, candidate, installed, comparison }] =
        refreshed.notes.as_slice()
    else {
        panic!("expected one refusal: {:?}", refreshed.notes);
    };
    assert_eq!(server, &format!("{lying}/core.db"));
    assert_eq!(*comparison, Comparison::Older);
    assert_eq!(candidate.unwrap().at, T1);
    assert_eq!(candidate.unwrap().tier, Tier::Unauthenticated);
    assert_eq!(installed.unwrap().at, T2);
}

/// When no server has anything as new, the installed database stays, and that is not an
/// error.
#[test]
fn every_mirror_older_keeps_the_installed_database() {
    let sync = tempfile::tempdir().unwrap();
    let live = database("installed", T2);
    install(sync.path(), &live, T2);
    let (first, _) = serve(vec![ok(&database("behind", T1), T1)]);
    let (second, _) = serve(vec![ok(&database("old content", T1), T9)]);

    let refreshed = refresh(sync.path(), &[first, second], policy_at(T2 + 3_600), false).unwrap();

    assert_eq!(refreshed.outcome, Outcome::Kept);
    assert_eq!(installed(sync.path()), live, "a refused database replaced the installed one");
    assert_eq!(refreshed.notes.len(), 2, "{:?}", refreshed.notes);
    assert_eq!(refreshed.publication.map(|publication| publication.at), Some(T2));
}

/// `force` re-downloads, and nothing more. pacman's `-yy` also switches off libcurl's time
/// condition. A habitual forced refresh must not switch off the rollback check with it.
#[test]
fn force_does_not_accept_an_older_database() {
    let sync = tempfile::tempdir().unwrap();
    let live = database("installed", T2);
    install(sync.path(), &live, T2);
    let (behind, _) = serve(vec![ok(&database("behind", T1), T1)]);
    let (lying, lying_requests) = serve(vec![ok(&database("old content", T1), T9)]);

    let refreshed = refresh(sync.path(), &[behind, lying], policy_at(T2 + 3_600), true).unwrap();

    assert_eq!(refreshed.outcome, Outcome::Kept);
    assert_eq!(installed(sync.path()), live);
    let requests = lying_requests.join().unwrap();
    assert!(
        !requests.first().unwrap().to_lowercase().contains("if-modified-since"),
        "force still sent a conditional request"
    );
}

/// `force` still re-downloads a database with the same date.
#[test]
fn force_downloads_an_equal_last_modified_again() {
    let sync = tempfile::tempdir().unwrap();
    install(sync.path(), &database("installed", T2), T2);
    let again = database("the same publication, compressed again", T2);
    let (mirror, _) = serve(vec![ok(&again, T2)]);

    let refreshed = refresh(sync.path(), &[mirror], policy_at(T2 + 3_600), true).unwrap();

    assert_eq!(refreshed.outcome, Outcome::Updated);
    assert_eq!(installed(sync.path()), again);
}

/// The explicit override: an older database is installed, and the caller hears about it.
#[test]
fn accept_older_installs_an_older_database_and_says_so() {
    let sync = tempfile::tempdir().unwrap();
    install(sync.path(), &database("installed", T2), T2);
    let snapshot = database("an archive snapshot", T1);
    let (archive, _) = serve(vec![ok(&snapshot, T1)]);

    let freshness = FreshnessPolicy { accept_older: true, ..policy_at(T2 + 3_600) };
    let refreshed = refresh(sync.path(), &[archive], freshness, false).unwrap();

    assert_eq!(refreshed.outcome, Outcome::Updated);
    assert_eq!(installed(sync.path()), snapshot);
    assert!(
        matches!(
            refreshed.notes.as_slice(),
            [FreshnessNote::AcceptedOlder { candidate: Some(candidate), replaced: Some(replaced), .. }]
                if candidate.at == T1 && replaced.at == T2
        ),
        "{:?}",
        refreshed.notes
    );
}

/// A database older than the age limit sends the refresh to the next mirror, and a newer one
/// found there is installed.
#[test]
fn a_stale_database_is_replaced_by_a_newer_one_from_another_mirror() {
    let sync = tempfile::tempdir().unwrap();
    install(sync.path(), &database("installed", T1), T1);
    let newer = database("newer", T3);
    let (frozen, _) = serve(vec![not_modified()]);
    let (current, _) = serve(vec![ok(&newer, T3)]);

    // Twenty days after T1, which is past the 14-day limit. T3 is then 12.4 days old.
    let refreshed =
        refresh(sync.path(), &[frozen, current], policy_at(T1 + 20 * 86_400), false).unwrap();

    assert_eq!(refreshed.outcome, Outcome::Updated);
    assert_eq!(installed(sync.path()), newer);
    assert!(refreshed.notes.is_empty(), "{:?}", refreshed.notes);
}

/// With nothing newer anywhere, the refresh warns, and asks no more than
/// `Limits::freshness_probes` other mirrors.
#[test]
fn a_stale_database_is_reported_after_a_bounded_number_of_probes() {
    let sync = tempfile::tempdir().unwrap();
    let live = database("installed", T1);
    install(sync.path(), &live, T1);
    let mirrors: Vec<_> = (0..5).map(|_| serve(vec![not_modified()])).collect();
    let servers: Vec<String> = mirrors.iter().map(|(url, _)| url.clone()).collect();

    let now = T1 + 20 * 86_400;
    let refreshed = refresh(sync.path(), &servers, policy_at(now), false).unwrap();

    assert_eq!(refreshed.outcome, Outcome::UpToDate);
    assert_eq!(installed(sync.path()), live);
    assert_eq!(
        refreshed.notes,
        [FreshnessNote::Stale {
            publication: refreshed.publication.unwrap(),
            age: Duration::from_secs(20 * 86_400),
            max_age: piko_db::repo::freshness::DEFAULT_MAX_AGE,
            probed: 3,
        }]
    );
    // The first mirror answered the refresh, and three more were probed. The fifth was never
    // asked. Unblock its listener so its thread can finish.
    let mut handles: Vec<_> = mirrors.into_iter().map(|(_, handle)| handle).collect();
    let last = handles.pop().unwrap();
    for handle in handles {
        assert_eq!(handle.join().unwrap().len(), 1);
    }
    drop(std::net::TcpStream::connect(servers.last().unwrap().trim_start_matches("http://")));
    assert_eq!(last.join().unwrap().len(), 1, "only the unblocking connection");
}

/// A `.files` archive is not checked for age: it installs nothing, and dating a large one
/// costs a full decompression on every refresh.
#[test]
fn a_files_archive_is_not_probed_for_age() {
    let sync = tempfile::tempdir().unwrap();
    std::fs::write(sync.path().join("core.files"), database("files", T1)).unwrap();
    std::fs::File::options()
        .write(true)
        .open(sync.path().join("core.files"))
        .unwrap()
        .set_modified(at(T1))
        .unwrap();
    let (first, _) = serve(vec![not_modified()]);
    let (second, second_requests) = serve(vec![not_modified()]);

    let refreshed = refresh_kind(
        sync.path(),
        DatabaseKind::Files,
        &[first, second.clone()],
        policy_at(T1 + 60 * 86_400),
        false,
    )
    .unwrap();

    assert_eq!(refreshed.outcome, Outcome::UpToDate);
    assert!(refreshed.notes.is_empty(), "{:?}", refreshed.notes);
    drop(std::net::TcpStream::connect(second.trim_start_matches("http://")));
    assert_eq!(second_requests.join().unwrap().len(), 1, "only the unblocking connection");
}

/// A date in the future is reported and the database kept: the local clock may be the one
/// that is wrong.
#[test]
fn a_database_from_the_future_is_installed_and_reported() {
    let sync = tempfile::tempdir().unwrap();
    let (mirror, _) = serve(vec![ok(&database("new", T3), T3)]);

    let refreshed = refresh(sync.path(), &[mirror], policy_at(T3 - 2 * 86_400), false).unwrap();

    assert_eq!(refreshed.outcome, Outcome::Updated);
    assert!(
        matches!(
            refreshed.notes.as_slice(),
            [FreshnessNote::FromTheFuture { ahead, .. }] if *ahead == Duration::from_secs(2 * 86_400)
        ),
        "{:?}",
        refreshed.notes
    );
}

/// An unsigned download that is not a readable archive cannot be dated, so it is this mirror's
/// failure and the next one serves.
#[test]
fn an_unreadable_archive_moves_on_to_the_next_mirror() {
    let sync = tempfile::tempdir().unwrap();
    let good = database("good", T3);
    let (broken, _) = serve(vec![ok(b"not an archive at all", T3)]);
    let (working, _) = serve(vec![ok(&good, T3)]);

    let refreshed = refresh(sync.path(), &[broken, working], policy_at(T3 + 60), false).unwrap();

    assert_eq!(refreshed.outcome, Outcome::Updated);
    assert_eq!(installed(sync.path()), good);
}

/// The first refresh has no installed database to compare with, so any database is accepted.
#[test]
fn the_first_refresh_accepts_any_database() {
    let sync = tempfile::tempdir().unwrap();
    let old = database("old", T1);
    let (mirror, _) = serve(vec![ok(&old, T1)]);

    let refreshed = refresh(sync.path(), &[mirror], policy_at(T1 + 60), false).unwrap();

    assert_eq!(refreshed.outcome, Outcome::Updated);
    assert_eq!(installed(sync.path()), old);
}
