//! What happens when a mirror answers a `.sig` request oddly, or has none at all.
//!
//! Hermetic: a `TcpListener` on `127.0.0.1:0` runs in a background thread, and a `TempDir`
//! serves as the sync directory. One test needs `gpg` on `PATH` to build a throwaway keyring.
//! It skips rather than fails when `gpg` is absent, the same way `piko-sig`'s own tests do.
//!
//! # What these exist for
//!
//! ureq turns 4xx and 5xx into `Err`, but returns 3xx as `Ok` with an empty body. So both
//! `fetch` and `fetch_signature` must inspect the HTTP status themselves. On the database side,
//! an unguarded `304` truncates a live database to zero bytes. On the signature side, an empty
//! file reaches GPGME. It comes back as "No data (gpg error 58)", which names the wrong
//! culprit. Nothing is destroyed there, so the refusal is quiet. The refresh simply fails for
//! a reason the user cannot act on.
//!
//! The stale-signature test covers a different question. A repository database changes content
//! under a fixed name. So a `.sig` left from an earlier refresh vouches for bytes that no
//! longer exist. piko itself never reads that file; it checks a signature at download and at
//! open. Pacman verifies at open too, and shares `/var/lib/pacman/sync` with piko. A stale file
//! left there makes the next `pacman -Sy` reject a database piko installed correctly.

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
    process::Command,
};

use piko_net::Refresher;
use piko_sig::{Keyring, Policy};

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

fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}

fn not_found() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
}

/// Signatures are checked, but a missing one is acceptable. This matches pacman's
/// `DatabaseOptional`.
fn optional() -> Policy {
    Policy { check: true, optional: true, marginal_ok: false, unknown_ok: false }
}

/// `SigLevel = Never`: nothing is checked and no `.sig` is ever requested.
fn never() -> Policy {
    Policy { check: false, optional: true, marginal_ok: false, unknown_ok: false }
}

fn refresh(
    sync: &Path,
    url: &str,
    keyring: Option<&Keyring>,
    policy: Policy,
) -> piko_net::Result<piko_net::Outcome> {
    refresh_from(sync, &[url.to_owned()], keyring, policy)
}

/// [`refresh`] across several mirrors, tried in the order given.
fn refresh_from(
    sync: &Path,
    servers: &[String],
    keyring: Option<&Keyring>,
    policy: Policy,
) -> piko_net::Result<piko_net::Outcome> {
    Refresher::default()
        .refresh(sync, "core", servers, keyring, policy, false, &piko_net::Cancel::new())
        .map(|refreshed| refreshed.outcome)
}

/// A repository archive whose one member holds `label`, so two databases differ in their
/// bytes. A refresh dates an unsigned download by reading it as an archive, so the body must
/// be one.
fn database(label: &str) -> Vec<u8> {
    piko_db::fixture::gzip_tar_at(&[("foo-1.0.0-1/desc", label.as_bytes())], 1_787_077_086)
}

/// A throwaway GnuPG home. It lets the test reach "the database is unsigned and that is
/// allowed". `install` insists on a keyring whenever the policy checks at all.
fn keyring() -> Option<(tempfile::TempDir, Keyring)> {
    let home = tempfile::tempdir().ok()?;
    std::fs::set_permissions(home.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .ok()?;
    let output = Command::new("gpg")
        .arg("--homedir")
        .arg(home.path())
        .args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            // ed25519 so key creation does not wait on entropy.
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
    let opened = Keyring::open(home.path()).ok()?;
    Some((home, opened))
}

/// The `304` guard, in the path that never had it. The message must name the status.
#[test]
fn a_not_modified_answer_to_a_signature_request_is_reported_as_such() {
    let dir = tempfile::tempdir().unwrap();
    let url = serve(vec![
        ok_response(&database("a real database")),
        b"HTTP/1.1 304 Not Modified\r\n\r\n".to_vec(),
    ]);

    let error = refresh(dir.path(), &url, None, optional()).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("304"), "{message}");
    // Nothing landed. Any previous database stays untouched.
    assert!(!dir.path().join("core.db").exists(), "a database was installed anyway");
}

/// A `200` with nothing in it is not "unsigned". The server said it had a signature.
#[test]
fn an_empty_signature_body_is_refused_rather_than_handed_to_the_verifier() {
    let dir = tempfile::tempdir().unwrap();
    let url = serve(vec![ok_response(&database("a real database")), ok_response(b"")]);

    let error = refresh(dir.path(), &url, None, optional()).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("empty signature"), "{message}");
    // Specifically not GPGME's "No data", which is what the old code reported.
    assert!(!message.contains("No data"), "{message}");
    assert!(!dir.path().join("core.db").exists(), "a database was installed anyway");
}

/// The stale `.sig` must go when the server says there is none.
#[test]
fn a_signature_from_a_previous_refresh_is_removed_when_the_server_has_none() {
    let Some((_home, keyring)) = keyring() else { return };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("core.db.sig"), b"a signature for the previous database")
        .unwrap();

    let url = serve(vec![ok_response(&database("a real database")), not_found()]);
    assert_eq!(
        refresh(dir.path(), &url, Some(&keyring), optional()).unwrap(),
        piko_net::Outcome::Updated
    );

    assert_eq!(std::fs::read(dir.path().join("core.db")).unwrap(), database("a real database"));
    assert!(
        !dir.path().join("core.db.sig").exists(),
        "a signature for the previous database survived beside the new one"
    );
}

/// A mirror that serves the database but cannot be asked for its signature loses **both** to
/// the next mirror.
///
/// The signature has to come from the same server as the database. Otherwise a well-behaved
/// mirror could vouch for a hostile one. That rule decides the recovery too. The next server
/// supplies the pair. Failing the whole repository instead lets one mirror's transient `500` on
/// a `.sig` end a refresh four other mirrors could have served.
///
/// The second mirror's bytes are what must land. That is the assertion this test rests on. A
/// test that kept the first mirror's database would pass on content alone.
#[test]
fn a_mirror_that_cannot_supply_a_signature_hands_the_whole_file_to_the_next_one() {
    let Some((_home, keyring)) = keyring() else { return };
    let dir = tempfile::tempdir().unwrap();

    // The first mirror answers the database, then fails the `.sig` with a server error.
    let broken = serve(vec![
        ok_response(&database("the first mirror's database")),
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ]);
    // The second answers both: a database, and "no signature here", which `DatabaseOptional`
    // accepts.
    let working = serve(vec![ok_response(&database("the second mirror's database")), not_found()]);

    let outcome = refresh_from(dir.path(), &[broken, working], Some(&keyring), optional()).unwrap();

    assert_eq!(outcome, piko_net::Outcome::Updated);
    assert_eq!(
        std::fs::read(dir.path().join("core.db")).unwrap(),
        database("the second mirror's database"),
        "the database and its signature came from different mirrors"
    );
}

/// Every mirror failing its `.sig` is still a failed refresh, naming each attempt.
///
/// The fallback above must not turn a repository nobody can serve into a silent success. The
/// error also has to say what each mirror did, not only that none worked.
#[test]
fn a_signature_failure_on_every_mirror_fails_the_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let server_error =
        || b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec();
    let first = serve(vec![ok_response(&database("a database")), server_error()]);
    let second = serve(vec![ok_response(&database("a database")), server_error()]);

    let error = refresh_from(dir.path(), &[first, second], None, optional()).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("500"), "{message}");
    assert!(!dir.path().join("core.db").exists(), "a database was installed anyway");
}

/// The other half of the same rule. It also shows why `Signature` has three cases rather than
/// an `Option`. Under `SigLevel = Never`, no signature is ever requested, so the code learns
/// nothing about whether the database is signed. Deleting the file here would destroy data
/// over a question that was never asked.
#[test]
fn a_signature_is_left_alone_when_the_policy_never_asks_for_one() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("core.db.sig"), b"the user's own signature").unwrap();

    // One response only: no `.sig` request is made at all under this policy.
    let url = serve(vec![ok_response(&database("a real database"))]);
    assert_eq!(refresh(dir.path(), &url, None, never()).unwrap(), piko_net::Outcome::Updated);

    assert_eq!(std::fs::read(dir.path().join("core.db.sig")).unwrap(), b"the user's own signature");
}
