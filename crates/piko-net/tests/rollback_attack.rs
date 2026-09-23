//! The attack itself: a mirror replays an old, correctly signed database.
//!
//! ```text
//! cargo test -p piko-net --test rollback_attack
//! ```
//!
//! A valid signature proves who produced a database, not that it is current. So a mirror that
//! kept an old signed `core.db` can serve it again, and every signature check passes. The
//! signature's own creation time is what gives the replay away: only the key holder can make
//! a signature, so only the key holder can make a newer one.
//!
//! Hermetic: a throwaway GnuPG home builds the key and signs with `--faked-system-time`, so an
//! older and a newer signature exist without waiting between them. Each mirror is a
//! `TcpListener` on `127.0.0.1:0`. The tests skip rather than fail when `gpg` is absent, as
//! `signature_download.rs` does.

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
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use piko_db::{
    config::SigLevel,
    repo::freshness::{Comparison, Tier},
};
use piko_net::{
    Cancel, Concurrency, DatabaseKind, FreshnessNote, FreshnessPolicy, Outcome, Refreshed,
    Refresher, RepoRefresh,
};
use piko_sig::{Keyring, Policy};

/// Wed, 19 Aug 2026 10:00:00 GMT: the installed database's stamp.
const STAMP: u64 = 1_787_133_600;
/// Fri, 01 Jan 2027 00:00:00 GMT: a `Last-Modified` newer than the stamp, so the header lets
/// every download through and the signature date alone decides.
const SERVED: &str = "Fri, 01 Jan 2027 00:00:00 GMT";

/// A GnuPG home with one generated, ultimately trusted signing key.
struct Signer {
    home: tempfile::TempDir,
    /// When the key was made. Every faked signing time comes after it, or gpg refuses to sign
    /// with a key from its own future.
    created: u64,
}

impl Signer {
    fn new() -> Option<Self> {
        let home = tempfile::tempdir().ok()?;
        std::fs::set_permissions(home.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .ok()?;
        let created = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let output = Command::new("gpg")
            .arg("--homedir")
            .arg(home.path())
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "piko test signer <test@example.invalid>",
                "ed25519",
                "sign",
                "never",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            eprintln!("skipping: could not create a test key");
            return None;
        }
        Some(Self { home, created })
    }

    fn keyring(&self) -> Keyring {
        Keyring::open(self.home.path()).unwrap()
    }

    /// A detached signature over `bytes`, made `offset` seconds after the key was created.
    fn sign(&self, bytes: &[u8], offset: u64) -> Vec<u8> {
        let work = tempfile::tempdir().unwrap();
        let file = work.path().join("core.db");
        std::fs::write(&file, bytes).unwrap();
        let output = Command::new("gpg")
            .arg("--homedir")
            .arg(self.home.path())
            .args(["--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--faked-system-time", &format!("{}!", self.created + offset)])
            .arg("--output")
            .arg(work.path().join("core.db.sig"))
            .arg("--detach-sign")
            .arg(&file)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        std::fs::read(work.path().join("core.db.sig")).unwrap()
    }
}

/// A repository archive whose members were written at `mtime`.
fn database(label: &str, mtime: u64) -> Vec<u8> {
    piko_db::fixture::gzip_tar_at(&[("foo-1.0.0-1/desc", label.as_bytes())], mtime)
}

/// Serves `responses` in order, one per connection, then stops.
fn serve(responses: Vec<Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            write_closing(&mut stream, &response);
            let _ = stream.flush();
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// Writes `response` with a `Connection: close` header after its status line.
///
/// This server answers one request per connection. Without the header, the client keeps the
/// connection for its next request. If it sends that request before this server closes the
/// connection, nothing reads the request, and the client gets a reset. That happens only on a
/// loaded machine, so the header is what makes a two-request test deterministic.
fn write_closing(stream: &mut impl Write, response: &[u8]) {
    let end = response.windows(2).position(|pair| pair == b"\r\n").unwrap_or(response.len());
    let (status, rest) = response.split_at(end);
    let _ = stream.write_all(status);
    let _ = stream.write_all(b"\r\nConnection: close");
    let _ = stream.write_all(rest);
}

fn ok(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nLast-Modified: {SERVED}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn not_found() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
}

/// Installs `bytes` as `core.db`, with `signature` beside it when there is one.
fn install(sync: &Path, bytes: &[u8], signature: Option<&[u8]>) {
    let path = sync.join("core.db");
    std::fs::write(&path, bytes).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(STAMP))
        .unwrap();
    if let Some(signature) = signature {
        std::fs::write(sync.join("core.db.sig"), signature).unwrap();
    }
}

fn refresh(
    sync: &Path,
    server: String,
    keyring: &Keyring,
    level: SigLevel,
    now: SystemTime,
) -> Refreshed {
    let servers = [server];
    let repos = [RepoRefresh {
        name: "core",
        kind: DatabaseKind::Db,
        servers: &servers,
        policy: Policy::for_database(level),
        freshness: FreshnessPolicy::new(now),
    }];
    Refresher::default()
        .refresh_all(
            sync,
            &repos,
            Some(keyring),
            Concurrency::new(1),
            false,
            &Cancel::new(),
            &|_, _| {},
        )
        .pop()
        .expect("one result per repository")
        .unwrap_or_else(|error| panic!("the refresh of core.db failed: {error:?}"))
}

/// The replay: an older database with its own authentic signature. Every signature check
/// passes, and the signature's date is what refuses it.
#[test]
fn a_replayed_older_signed_database_is_refused() {
    let Some(signer) = Signer::new() else { return };
    let sync = tempfile::tempdir().unwrap();
    // The archive dates agree with the signatures here. The next test separates them.
    let old = database("old", STAMP - 86_400);
    let current = database("current", STAMP);
    install(sync.path(), &current, Some(&signer.sign(&current, 2_000)));
    let mirror = serve(vec![ok(&old), ok(&signer.sign(&old, 1_000))]);

    let refreshed =
        refresh(sync.path(), mirror, &signer.keyring(), SigLevel::DATABASE, SystemTime::now());

    assert_eq!(refreshed.outcome, Outcome::Kept);
    assert_eq!(std::fs::read(sync.path().join("core.db")).unwrap(), current);
    let [FreshnessNote::RefusedOlder { candidate, installed, comparison, .. }] =
        refreshed.notes.as_slice()
    else {
        panic!("expected one refusal: {:?}", refreshed.notes);
    };
    assert_eq!(*comparison, Comparison::Older);
    assert_eq!(candidate.unwrap().tier, Tier::Authenticated);
    assert_eq!(candidate.unwrap().at, signer.created + 1_000);
    assert_eq!(installed.unwrap().at, signer.created + 2_000);
}

/// A signed database is dated by its signature, never by its archive. A replay whose archive
/// claims to be newer is still refused, because the mirror could have written that archive
/// date, and it could not have written the signature date.
#[test]
fn a_signed_database_is_dated_by_its_signature_not_its_archive() {
    let Some(signer) = Signer::new() else { return };
    let sync = tempfile::tempdir().unwrap();
    let current = database("current", STAMP);
    install(sync.path(), &current, Some(&signer.sign(&current, 2_000)));
    let old = database("old, with a new archive date", STAMP + 30 * 86_400);
    let mirror = serve(vec![ok(&old), ok(&signer.sign(&old, 1_000))]);

    let refreshed =
        refresh(sync.path(), mirror, &signer.keyring(), SigLevel::DATABASE, SystemTime::now());

    assert_eq!(refreshed.outcome, Outcome::Kept);
    assert_eq!(std::fs::read(sync.path().join("core.db")).unwrap(), current);
}

/// Under `DatabaseOptional`, a mirror can leave out the signature. If that made the database
/// incomparable, and so acceptable, dropping the `.sig` would bypass the whole check.
#[test]
fn leaving_out_the_signature_does_not_bypass_the_check() {
    let Some(signer) = Signer::new() else { return };
    let sync = tempfile::tempdir().unwrap();
    let current = database("current", STAMP);
    install(sync.path(), &current, Some(&signer.sign(&current, 2_000)));
    let unsigned = database("unsigned, with a new archive date", STAMP + 30 * 86_400);
    let mirror = serve(vec![ok(&unsigned), not_found()]);

    let refreshed = refresh(
        sync.path(),
        mirror,
        &signer.keyring(),
        SigLevel::DATABASE | SigLevel::DATABASE_OPTIONAL,
        SystemTime::now(),
    );

    assert_eq!(refreshed.outcome, Outcome::Kept);
    assert_eq!(std::fs::read(sync.path().join("core.db")).unwrap(), current);
    assert!(
        matches!(
            refreshed.notes.as_slice(),
            [FreshnessNote::RefusedOlder { comparison: Comparison::LostAuthentication, .. }]
        ),
        "{:?}",
        refreshed.notes
    );
}

/// A newer signed database is accepted: the check refuses a step back, not a step forward.
#[test]
fn a_newer_signed_database_is_installed() {
    let Some(signer) = Signer::new() else { return };
    let sync = tempfile::tempdir().unwrap();
    let current = database("current", STAMP);
    install(sync.path(), &current, Some(&signer.sign(&current, 1_000)));
    let newer = database("newer", STAMP);
    let mirror = serve(vec![ok(&newer), ok(&signer.sign(&newer, 2_000))]);

    let refreshed =
        refresh(sync.path(), mirror, &signer.keyring(), SigLevel::DATABASE, SystemTime::now());

    assert_eq!(refreshed.outcome, Outcome::Updated);
    assert_eq!(std::fs::read(sync.path().join("core.db")).unwrap(), newer);
    assert_eq!(
        refreshed.publication.map(|publication| publication.tier),
        Some(Tier::Authenticated)
    );
}

/// The limit of the check, pinned so nobody reads more into it. An unsigned database carries
/// only dates the mirror wrote. A mirror that forges a newer archive date over old content is
/// accepted. Only a signed database defends against a mirror that lies, and Arch does not sign
/// its databases.
#[test]
fn an_unsigned_database_with_a_forged_date_is_accepted() {
    let Some(signer) = Signer::new() else { return };
    let sync = tempfile::tempdir().unwrap();
    install(sync.path(), &database("current", STAMP), None);
    let forged = database("old content, forged date", STAMP + 86_400);
    let mirror = serve(vec![ok(&forged), not_found()]);

    let refreshed = refresh(
        sync.path(),
        mirror,
        &signer.keyring(),
        SigLevel::DATABASE | SigLevel::DATABASE_OPTIONAL,
        UNIX_EPOCH + Duration::from_secs(STAMP + 2 * 86_400),
    );

    assert_eq!(refreshed.outcome, Outcome::Updated);
    assert_eq!(std::fs::read(sync.path().join("core.db")).unwrap(), forged);
    assert_eq!(
        refreshed.publication.map(|publication| publication.tier),
        Some(Tier::Unauthenticated)
    );
}
