//! Security properties of the repository database reader, exercised through the public API.
//!
//! Mirrors `tests/hardening.rs`, extended for two properties specific to a repository archive.
//! One is bounded decompression, which piko does itself because `alpm-compress` has no size
//! cap of its own. The other is the `.db`/`.files` version-skew defence documented on
//! [`piko_db::Error::FilesVersionSkew`].

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{path::Path, time::Duration};

use piko_db::{
    Error, Limit, Limits,
    fixture::{MINIMAL_REPO_DESC_V2, MINIMAL_REPO_FILES, RepoFixture},
    repo::{RepoDatabase, RepoName, RepoOpenOptions},
};

/// Runs `body` on another thread, failing if it does not finish within `timeout`.
fn with_timeout(timeout: Duration, body: impl FnOnce() + Send + 'static) {
    let (sender, receiver) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        body();
        let _ = sender.send(());
    });

    match receiver.recv_timeout(timeout) {
        Ok(()) => handle.join().unwrap(),
        Err(_) => panic!("operation did not finish within {timeout:?} — it is blocking"),
    }
}

/// [`MINIMAL_REPO_DESC_V2`] with its `%NAME%` and `%VERSION%` rewritten.
fn desc_for(name: &str, version: &str) -> String {
    MINIMAL_REPO_DESC_V2
        .replacen("%NAME%\nfoo", &format!("%NAME%\n{name}"), 1)
        .replacen("%VERSION%\n1.0.0-1", &format!("%VERSION%\n{version}"), 1)
        .replacen("%BASE%\nfoo", &format!("%BASE%\n{name}"), 1)
}

fn entry(name: &str, version: &str) -> String {
    format!("{name}-{version}")
}

/// The package-count bound exists to stop an allocation, so it must fire *during* the walk.
/// Checking the assembled list's length after the walk would mean every `desc` in an
/// oversized archive was already decompressed and parsed — the exact cost the bound exists
/// to prevent. This is proven the same way as `walk_matching`'s early stop: a total inflated
/// limit the whole archive genuinely cannot satisfy, which an aborted walk never reaches.
#[test]
fn an_archive_with_too_many_packages_aborts_before_parsing_all_of_them() {
    let fixture = RepoFixture::new();

    // Ten packages, each `desc` padded so that reading all of them must exceed
    // `repo_inflated_bytes` — but reading only the first few need not.
    let descs: Vec<(String, String)> = (0..10)
        .map(|index| {
            let name = format!("pkg{index}");
            let padded = format!("{}{}", desc_for(&name, "1.0.0-1"), "\n".repeat(4096));
            (format!("{}/desc", entry(&name, "1.0.0-1")), padded)
        })
        .collect();
    let members: Vec<(&str, &[u8])> =
        descs.iter().map(|(path, body)| (path.as_str(), body.as_bytes())).collect();
    let path = fixture.write_gzip_archive("core.db", &members);

    let options = RepoOpenOptions::new().limits(Limits {
        repo_max_packages: 2,
        repo_inflated_bytes: 16 * 1024,
        ..Limits::default()
    });
    let err = RepoDatabase::open_with(&path, options).unwrap_err();

    assert!(
        matches!(&err, Error::TooManyEntries { max: 2, .. }),
        "the package bound must fire before the inflated-size bound the full walk would \
         have tripped, proving the walk stopped early; got {err:?}"
    );
}

/// A flood of unusable members must not allocate a diagnostic per member without bound. It
/// must also not stop the archive's readable packages from being read.
#[test]
fn a_flood_of_unusable_members_is_bounded_without_failing_the_open() {
    let fixture = RepoFixture::new();

    let good_desc = desc_for("foo", "1.0.0-1");
    let good_path = format!("{}/desc", entry("foo", "1.0.0-1"));
    let junk: Vec<(String, &[u8])> = (0..200)
        .map(|index| (format!("not-a-valid-entry-{index}/desc"), b"x".as_slice()))
        .collect();

    let mut members: Vec<(&str, &[u8])> = vec![(good_path.as_str(), good_desc.as_bytes())];
    members.extend(junk.iter().map(|(path, body)| (path.as_str(), *body)));
    let path = fixture.write_gzip_archive("core.db", &members);

    let options =
        RepoOpenOptions::new().limits(Limits { max_diagnostics: 10, ..Limits::default() });
    let db = RepoDatabase::open_with(&path, options).unwrap();

    assert_eq!(db.len(), 1, "the one readable package must still be readable");
    assert_eq!(db.diagnostics().len(), 10, "diagnostics must be bounded");
    assert_eq!(db.diagnostics_dropped(), 190, "the overflow must be counted, not hidden");
}

#[test]
fn a_decompression_bomb_is_caught_as_limit_exceeded_not_a_parse_error() {
    let fixture = RepoFixture::new();
    let huge_desc = format!("{}{}", desc_for("foo", "1.0.0-1"), "x".repeat(10_000));
    let path = fixture.write_gzip_archive(
        "core.db",
        &[(&format!("{}/desc", entry("foo", "1.0.0-1")), huge_desc.as_bytes())],
    );

    let options =
        RepoOpenOptions::new().limits(Limits { repo_inflated_bytes: 1024, ..Limits::default() });
    let err = RepoDatabase::open_with(&path, options).unwrap_err();

    assert!(
        matches!(&err, Error::LimitExceeded { limit: Limit::RepoInflated, .. }),
        "a bomb must be reported as a limit violation, not a truncated-archive parse error; got {err:?}"
    );
}

#[test]
fn an_archive_with_too_many_packages_is_refused() {
    let fixture = RepoFixture::new();
    let members: Vec<(String, Vec<u8>)> = (0..8)
        .map(|i| {
            (
                format!("{}/desc", entry(&format!("pkg{i}"), "1.0.0-1")),
                desc_for(&format!("pkg{i}"), "1.0.0-1").into_bytes(),
            )
        })
        .collect();
    let borrowed: Vec<(&str, &[u8])> =
        members.iter().map(|(p, c)| (p.as_str(), c.as_slice())).collect();
    let path = fixture.write_gzip_archive("core.db", &borrowed);

    let options =
        RepoOpenOptions::new().limits(Limits { repo_max_packages: 4, ..Limits::default() });
    let err = RepoDatabase::open_with(&path, options).unwrap_err();

    assert!(matches!(err, Error::TooManyEntries { max: 4, .. }), "got {err:?}");
}

#[test]
fn an_oversized_member_is_refused() {
    let fixture = RepoFixture::new();
    let huge_desc = format!("{}{}", desc_for("foo", "1.0.0-1"), "x".repeat(1024));
    let path = fixture.write_gzip_archive(
        "core.db",
        &[(&format!("{}/desc", entry("foo", "1.0.0-1")), huge_desc.as_bytes())],
    );

    let options =
        RepoOpenOptions::new().limits(Limits { repo_entry_bytes: 16, ..Limits::default() });
    let err = RepoDatabase::open_with(&path, options).unwrap_err();

    assert!(matches!(&err, Error::LimitExceeded { limit: Limit::RepoEntry, .. }), "got {err:?}");
}

#[cfg(unix)]
#[test]
fn a_fifo_named_like_an_archive_does_not_block() {
    let fixture = RepoFixture::new();
    let path = fixture.path().join("core.db");

    let made = std::process::Command::new("mkfifo").arg(&path).status().is_ok_and(|s| s.success());
    if !made {
        eprintln!("skipping: mkfifo is unavailable");
        return;
    }

    with_timeout(Duration::from_secs(10), move || {
        let err = RepoDatabase::open(&path).unwrap_err();
        assert!(
            matches!(&err, Error::NotARegularFile { .. } | Error::Io { .. }),
            "a FIFO must be refused, not blocked on; got {err:?}"
        );
    });
}

#[test]
fn a_db_only_database_has_no_file_lists() {
    let fixture = RepoFixture::new();
    let path = fixture.write_gzip_archive(
        "core.db",
        &[(&format!("{}/desc", entry("foo", "1.0.0-1")), desc_for("foo", "1.0.0-1").as_bytes())],
    );

    let db = RepoDatabase::open(&path).unwrap();
    assert_eq!(db.variant(), piko_db::repo::Variant::Default);

    let package = db.get_str("foo").unwrap();
    let err = package.file_list().unwrap_err();
    assert!(matches!(&*err, Error::FilesUnavailable { .. }), "got {err:?}");
}

#[test]
fn a_with_files_archive_populates_everything_in_one_pass() {
    let fixture = RepoFixture::new();
    let path = fixture.write_gzip_archive(
        "core.files",
        &[
            (&format!("{}/desc", entry("foo", "1.0.0-1")), desc_for("foo", "1.0.0-1").as_bytes()),
            (&format!("{}/files", entry("foo", "1.0.0-1")), MINIMAL_REPO_FILES.as_bytes()),
        ],
    );

    let db = RepoDatabase::open(&path).unwrap();
    assert_eq!(db.variant(), piko_db::repo::Variant::DefaultWithFiles);

    let package = db.get_str("foo").unwrap();
    let files: Vec<_> = package.file_list().unwrap().collect();
    assert_eq!(files, [Path::new("usr/"), Path::new("usr/bin/"), Path::new("usr/bin/foo")]);
}

/// `RepoDatabase::file_lists`'s targeted walk (`archive::walk_matching`) re-implements the
/// same per-member and total-inflated-size checks as the ordinary eager walk. It runs over a
/// `.files` archive that a `file_lists` caller never explicitly opens, and must be bounded
/// the same way.
#[test]
fn a_targeted_file_lookup_is_also_bounded_by_the_inflated_limit() {
    let fixture = RepoFixture::new();
    fixture.write_gzip_archive(
        "repo.db",
        &[(&format!("{}/desc", entry("foo", "1.0.0-1")), desc_for("foo", "1.0.0-1").as_bytes())],
    );
    let huge_files = format!("{MINIMAL_REPO_FILES}{}", "x".repeat(10_000));
    fixture.write_gzip_archive(
        "repo.files",
        &[(&format!("{}/files", entry("foo", "1.0.0-1")), huge_files.as_bytes())],
    );

    // Comfortably fits `repo.db` (one tiny `desc`, plus tar overhead) but not `repo.files`
    // (its `files` member alone is over 10 000 bytes). The same limit is evaluated fresh for
    // each archive independently, since opening and the later targeted walk each drive their
    // own `BoundedReader`.
    let repo = RepoName::parse("repo").unwrap();
    let options =
        RepoOpenOptions::new().limits(Limits { repo_inflated_bytes: 8192, ..Limits::default() });
    let db = RepoDatabase::open_repo_with(fixture.path(), &repo, options).unwrap();

    let foo = db.get_str("foo").unwrap();
    let mut results = db.file_lists([foo]);

    assert_eq!(results.len(), 1);
    let (_, result) = results.pop().unwrap();
    let err = result.unwrap_err();
    assert!(
        matches!(&*err, Error::LimitExceeded { limit: Limit::RepoInflated, .. }),
        "got {err:?}"
    );
}

/// Every `RepoPackage` a `RepoDatabase` produces shares one `Arc<FilesSource>`. A package
/// from a *different* database must never be resolved against it — that would silently
/// serve one repository's file list under another's name. That is exactly what keying
/// `FilesArena` by name and version exists to prevent, one layer down.
#[test]
fn file_lists_rejects_a_package_that_did_not_come_from_this_database() {
    let fixture = RepoFixture::new();
    let core_path = fixture.write_gzip_archive(
        "core.files",
        &[
            (&format!("{}/desc", entry("foo", "1.0.0-1")), desc_for("foo", "1.0.0-1").as_bytes()),
            (&format!("{}/files", entry("foo", "1.0.0-1")), MINIMAL_REPO_FILES.as_bytes()),
        ],
    );
    let extra_path = fixture.write_gzip_archive(
        "extra.files",
        &[
            (&format!("{}/desc", entry("foo", "1.0.0-1")), desc_for("foo", "1.0.0-1").as_bytes()),
            (&format!("{}/files", entry("foo", "1.0.0-1")), MINIMAL_REPO_FILES.as_bytes()),
        ],
    );

    let core = RepoDatabase::open(&core_path).unwrap();
    let extra = RepoDatabase::open(&extra_path).unwrap();

    let foo_from_extra = extra.get_str("foo").unwrap();
    let mut results = core.file_lists([foo_from_extra]);

    assert_eq!(results.len(), 1);
    let (_, result) = results.pop().unwrap();
    let err = result.unwrap_err();
    assert!(matches!(&*err, Error::ForeignPackage { .. }), "got {err:?}");
}

/// The property the whole `FilesArena` module exists for: `.db` and `.files` are refreshed
/// independently by pacman and routinely disagree about which build is current — measured at
/// 12 of `core`'s 296 real packages. Serving the wrong build's paths must never happen
/// silently.
mod files_version_skew {
    use super::{RepoDatabase, RepoFixture, RepoName, RepoOpenOptions, desc_for, entry};
    use piko_db::{Error, fixture::MINIMAL_REPO_FILES};

    fn build_skewed_repo(fixture: &RepoFixture) -> RepoDatabase {
        fixture.write_gzip_archive(
            "repo.db",
            &[
                // Present in .db at 2-1, but .files only has 1-1 — the drift case.
                (&format!("{}/desc", entry("foo", "2-1")), desc_for("foo", "2-1").as_bytes()),
                // Present in .db only; .files has no entry for it at all.
                (&format!("{}/desc", entry("bar", "1-1")), desc_for("bar", "1-1").as_bytes()),
            ],
        );
        fixture.write_gzip_archive(
            "repo.files",
            &[
                (&format!("{}/desc", entry("foo", "1-1")), desc_for("foo", "1-1").as_bytes()),
                (&format!("{}/files", entry("foo", "1-1")), MINIMAL_REPO_FILES.as_bytes()),
            ],
        );

        let repo = RepoName::parse("repo").unwrap();
        RepoDatabase::open_repo_with(fixture.path(), &repo, RepoOpenOptions::new()).unwrap()
    }

    #[test]
    fn a_version_mismatch_is_a_skew_error_never_a_silent_substitution() {
        let fixture = RepoFixture::new();
        let db = build_skewed_repo(&fixture);

        assert_eq!(db.variant(), piko_db::repo::Variant::Default, "must prefer .db");

        let foo = db.get_str("foo").unwrap();
        assert_eq!(
            foo.version().to_string(),
            "2-1",
            "the .db version is authoritative for the package itself"
        );

        let err = foo.file_list().unwrap_err();
        match &*err {
            Error::FilesVersionSkew { db_version, files_version, .. } => {
                assert_eq!(db_version.to_string(), "2-1");
                assert_eq!(files_version.to_string(), "1-1");
            }
            other => panic!("expected FilesVersionSkew, got {other:?}"),
        }
    }

    #[test]
    fn a_package_absent_from_files_is_missing_not_empty() {
        let fixture = RepoFixture::new();
        let db = build_skewed_repo(&fixture);

        let bar = db.get_str("bar").unwrap();
        let err = bar.file_list().unwrap_err();
        assert!(matches!(&*err, Error::FilesMissingForPackage { .. }), "got {err:?}");
    }

    /// The expensive part — decompressing `.files` — is shared and cached (see
    /// `FilesSource::arena`, backed by `Lazy`). The skew check itself is a cheap lookup
    /// against that cached arena. It is deliberately recomputed on each call rather than
    /// memoized, so this test checks that the reported content stays consistent, not that
    /// the same `Arc` is handed back.
    #[test]
    fn the_skew_error_is_consistent_across_repeated_calls() {
        let fixture = RepoFixture::new();
        let db = build_skewed_repo(&fixture);
        let foo = db.get_str("foo").unwrap();

        let first = foo.file_list().unwrap_err().to_string();
        let second = foo.file_list().unwrap_err().to_string();
        assert_eq!(first, second);
        assert!(first.contains("2-1") && first.contains("1-1"), "{first}");
    }
}
