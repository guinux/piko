//! Security properties of the database reader, exercised through the public API.
//!
//! These test five security claims: bounded reads, no symlink traversal, no blocking on a
//! non-regular file, a bounded entry count, and no configuration another user could change. They run against a real filesystem rather
//! than unit-tested internals. The properties are about what actually happens when the
//! process opens a hostile path.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{path::Path, time::Duration};

use piko_db::{
    Error, Limit, Limits, fixture::DbFixture, fixture::MINIMAL_DESC_V1, fixture::MINIMAL_FILES,
    fixture::gzip_bomb, local::LocalDatabase, local::OpenOptions,
};

/// Creates a FIFO, or returns `false` if the system provides no `mkfifo`.
///
/// `mkfifo(3)` is `unsafe`, and this workspace forbids `unsafe_code`. This function shells
/// out to the `mkfifo` utility instead.
fn make_fifo(path: &Path) -> bool {
    std::process::Command::new("mkfifo").arg(path).status().is_ok_and(|status| status.success())
}

/// Runs `body` on another thread, failing if it does not finish within `timeout`.
///
/// A hang is the failure mode under test. The test must catch it as a failure, not let it
/// stall the suite.
fn with_timeout(timeout: Duration, body: impl FnOnce() + Send + 'static) {
    let (sender, receiver) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        body();
        // A closed channel just means the receiver already gave up.
        let _ = sender.send(());
    });

    match receiver.recv_timeout(timeout) {
        Ok(()) => handle.join().unwrap(),
        Err(_) => panic!("operation did not finish within {timeout:?} — it is blocking"),
    }
}

/// A FIFO open for reading blocks until a writer appears. `O_NONBLOCK` plus the regular-file
/// check turns that into an immediate error instead.
#[test]
fn a_fifo_in_place_of_a_metadata_file_does_not_block() {
    let fixture = DbFixture::new();
    let dir = fixture.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).build();

    if !make_fifo(&dir.join("files")) {
        eprintln!("skipping: mkfifo is unavailable");
        return;
    }

    let root = fixture.path().to_path_buf();
    with_timeout(Duration::from_secs(10), move || {
        let db = LocalDatabase::open(&root).unwrap();
        let package = db.get_str("foo").unwrap();

        let error = package.files().unwrap_err();
        assert!(
            matches!(&*error, Error::NotARegularFile { .. } | Error::Io { .. }),
            "a FIFO must be refused, got {error:?}"
        );

        // The rest of the entry must remain usable.
        assert!(package.desc().is_ok(), "one hostile file must not poison the others");
    });
}

/// `/dev/zero` never reaches EOF. The regular-file check rejects it outright.
#[test]
fn a_character_device_is_refused() {
    let zero = Path::new("/dev/zero");
    if !zero.exists() {
        eprintln!("skipping: /dev/zero is unavailable");
        return;
    }

    let fixture = DbFixture::new();
    let dir = fixture.package("foo-1.0.0-1").build();
    std::os::unix::fs::symlink(zero, dir.join("desc")).unwrap();

    let root = fixture.path().to_path_buf();
    with_timeout(Duration::from_secs(10), move || {
        let db = LocalDatabase::open(&root).unwrap();
        let error = db.get_str("foo").unwrap().desc().unwrap_err();
        assert!(
            matches!(&*error, Error::NotARegularFile { .. } | Error::Io { .. }),
            "got {error:?}"
        );
    });
}

/// A symlink must not be able to redirect a read outside the entry directory.
#[test]
fn a_symlinked_metadata_file_is_not_followed() {
    let fixture = DbFixture::new();
    let outside = fixture.path().join("outside-secret");
    std::fs::write(&outside, MINIMAL_DESC_V1).unwrap();

    let dir = fixture.package("foo-1.0.0-1").build();
    std::os::unix::fs::symlink(&outside, dir.join("desc")).unwrap();

    let db = LocalDatabase::open(fixture.path()).unwrap();
    let error = db.get_str("foo").unwrap().desc().unwrap_err();

    assert!(matches!(&*error, Error::Io { .. }), "O_NOFOLLOW must refuse it, got {error:?}");
}

/// An oversized file is refused rather than silently truncated: a short `files` list would
/// misreport which files a package owns.
#[test]
fn an_oversized_file_is_refused_not_truncated() {
    let fixture = DbFixture::new();
    let huge = format!("%FILES%\n{}\n", "usr/x\n".repeat(200_000));
    fixture.package("foo-1.0.0-1").desc(MINIMAL_DESC_V1).files(&huge).build();

    let db = LocalDatabase::open_with(
        fixture.path(),
        OpenOptions::new().limits(Limits { files_bytes: 4096, ..Limits::default() }),
    )
    .unwrap();

    let error = db.get_str("foo").unwrap().files().unwrap_err();
    assert!(
        matches!(&*error, Error::LimitExceeded { limit: Limit::Files, max: 4096, .. }),
        "got {error:?}"
    );
}

/// This test proves why piko inflates `mtree` itself, instead of letting `alpm-mtree` do it.
#[test]
fn a_compression_bomb_is_refused() {
    let fixture = DbFixture::new();
    fixture
        .package("foo-1.0.0-1")
        .desc(MINIMAL_DESC_V1)
        .mtree_raw(&gzip_bomb(256 * 1024 * 1024))
        .build();

    let db = LocalDatabase::open_with(
        fixture.path(),
        OpenOptions::new()
            .limits(Limits { mtree_inflated_bytes: 1024 * 1024, ..Limits::default() }),
    )
    .unwrap();

    with_timeout(Duration::from_secs(30), move || {
        let error = db.get_str("foo").unwrap().mtree().unwrap_err();
        assert!(
            matches!(&*error, Error::LimitExceeded { limit: Limit::MtreeInflated, .. }),
            "got {error:?}"
        );
    });
}

/// A database with too many entries is a hard failure, not a slow one.
#[test]
fn an_entry_flood_is_refused_early() {
    let fixture = DbFixture::new();
    for index in 0..32 {
        fixture.package(&format!("pkg{index}-1.0.0-1")).build();
    }

    let error = LocalDatabase::open_with(
        fixture.path(),
        OpenOptions::new().limits(Limits { max_entries: 8, ..Limits::default() }),
    )
    .unwrap_err();

    assert!(matches!(error, Error::TooManyEntries { max: 8, .. }), "got {error:?}");
}

/// One unreadable entry must not make the other thousand unreadable.
#[test]
fn a_hostile_entry_does_not_prevent_reading_the_others() {
    let fixture = DbFixture::new();
    fixture.package("good-1.0.0-1").with_defaults().build();
    fixture.package("bad-1.0.0-1").desc("garbage").build();
    fixture.package("also-good-1.0.0-1").with_defaults().build();
    fixture.package("not a valid entry").build();

    let db = LocalDatabase::open(fixture.path()).unwrap();

    assert_eq!(db.len(), 3, "valid entries must still be present");
    assert!(db.get_str("good").unwrap().desc().is_ok());
    assert!(db.get_str("also-good").unwrap().desc().is_ok());
    assert!(db.get_str("bad").unwrap().desc().is_err());
    assert_eq!(db.diagnostics().len(), 1, "{:?}", db.diagnostics());
}

/// The name parser must reject a path escape attempt in an entry name, long before piko
/// builds any path from it.
#[test]
fn entry_names_cannot_escape_the_database_directory() {
    let fixture = DbFixture::new();
    fixture.package("foo-1.0.0-1").with_defaults().build();

    // A traversal needs a component that is exactly `.` or `..`, or a `/` inside the name.
    // None is expressible: `Name` rejects a leading `.`, and `/` is illegal in both halves.
    for hostile in [
        "..-1.0.0-1",      // name would be ".."
        ".-1.0.0-1",       // name would be "."
        "../evil-1.0.0-1", // '/' in the name
        "foo-1.0.0/x-1",   // '/' in the version
        "foo-1.0.0-..",    // pkgrel must be numeric
    ] {
        assert!(piko_db::EntryName::parse(hostile).is_err(), "{hostile:?} should be rejected");
    }

    // `foo-..-1` *is* accepted: `..` is a legal pkgver, and the whole thing is a single
    // path component, so the dots are inert. Confirm it cannot escape.
    let inert = piko_db::EntryName::parse("foo-..-1").unwrap();
    let joined = fixture.path().join(inert.as_str());
    assert_eq!(joined.parent(), Some(fixture.path()), "an entry must stay one level down");
    assert!(joined.starts_with(fixture.path()));

    let db = LocalDatabase::open(fixture.path()).unwrap();
    for package in &db {
        assert!(
            package.path().starts_with(fixture.path()),
            "{} escaped the database directory",
            package.path().display()
        );
    }
}

/// A zero-byte `files` is a real case on live systems and must not be mistaken for damage.
#[test]
fn an_empty_files_file_is_not_treated_as_corruption() {
    let fixture = DbFixture::new();
    fixture.package("base-3-3").desc(MINIMAL_DESC_V1).files("").build();

    let db = LocalDatabase::open(fixture.path()).unwrap();
    assert_eq!(db.get_str("base").unwrap().file_list().unwrap().len(), 0);
}

/// A well-formed database produces no diagnostics at all. That way a diagnostic is always a
/// signal, never noise.
#[test]
fn a_clean_database_produces_no_diagnostics() {
    let fixture = DbFixture::new();
    for entry in ["acl-2.3.2-1", "zlib-1.3.1-2", "pulse-native-provider-1:1.6.8-1"] {
        fixture.package(entry).desc(MINIMAL_DESC_V1).files(MINIMAL_FILES).build();
    }

    let db = LocalDatabase::open(fixture.path()).unwrap();
    assert!(db.diagnostics().is_empty(), "{:?}", db.diagnostics());
    assert_eq!(db.diagnostics_dropped(), 0);
}

/// A directory full of rejected entries yields one diagnostic per entry, and *no* packages.
/// `max_entries` counts packages, so it cannot bound this flood. `max_diagnostics` bounds it
/// instead, without turning the flood into a failure: the readable packages stay readable.
#[test]
fn a_flood_of_unusable_entries_is_bounded_without_failing_the_open() {
    let fixture = DbFixture::new();
    fixture.package("acl-2.3.2-1").desc(MINIMAL_DESC_V1).files(MINIMAL_FILES).build();
    for index in 0..200 {
        fixture.package(&format!("invalid{index}")).build();
    }

    let db = LocalDatabase::open_with(
        fixture.path(),
        OpenOptions::new().limits(Limits { max_diagnostics: 10, ..Limits::default() }),
    )
    .unwrap();

    assert_eq!(db.len(), 1, "the one readable package must still be readable");
    assert_eq!(db.diagnostics().len(), 10, "diagnostics must be bounded");
    assert_eq!(db.diagnostics_dropped(), 190, "the overflow must be counted, not hidden");
}

/// `max_entries` counts packages, not directory entries. A database at exactly the limit must
/// open however many non-package entries sit beside it, and `ALPM_DB_VERSION` always does. It
/// must not depend on the order the filesystem happens to enumerate them in.
#[test]
fn non_package_entries_never_consume_the_package_budget() {
    let fixture = DbFixture::new();
    for entry in ["acl-2.3.2-1", "zlib-1.3.1-2"] {
        fixture.package(entry).desc(MINIMAL_DESC_V1).files(MINIMAL_FILES).build();
    }
    fixture.stray_file("db.lck", "");
    for index in 0..20 {
        fixture.package(&format!("invalid{index}")).build();
    }

    let db = LocalDatabase::open_with(
        fixture.path(),
        OpenOptions::new().limits(Limits { max_entries: 2, ..Limits::default() }),
    )
    .unwrap();

    let names: Vec<&str> = db.iter().map(|package| package.name().as_ref()).collect();
    assert_eq!(names, ["acl", "zlib"]);
}

/// The scan checks that an entry is a real directory, but `desc`, `files` and `mtree` are read
/// later, on first access. An entry swapped for a symlink in between must not redirect those
/// reads: the entry directory is opened by descriptor with `O_NOFOLLOW`, not only the file in
/// it.
#[test]
fn an_entry_swapped_for_a_symlink_after_the_scan_is_not_followed() {
    let db = DbFixture::new();
    db.package("foo-1.0.0-1").with_defaults().build();
    let local = LocalDatabase::open(db.path()).unwrap();
    let package = local.get_str("foo").unwrap();

    // A directory elsewhere holding what the swap wants read: a desc naming a dependency the
    // real one does not have.
    let elsewhere = db.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("desc"), format!("{MINIMAL_DESC_V1}%DEPENDS%\nplanted\n\n"))
        .unwrap();
    std::fs::write(elsewhere.join("files"), MINIMAL_FILES).unwrap();
    std::fs::write(elsewhere.join("install"), "post_install() { :; }\n").unwrap();
    let entry = db.path().join("foo-1.0.0-1");
    std::fs::remove_dir_all(&entry).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &entry).unwrap();

    let desc_error = package.eager().unwrap_err();
    assert!(matches!(&*desc_error, Error::Io { .. }), "got {desc_error:?}");
    let files_error = package.files().unwrap_err();
    assert!(matches!(&*files_error, Error::Io { .. }), "got {files_error:?}");
    assert!(!package.has_install_scriptlet());
}

/// `pacman.conf` and every file it `Include`s name the hook directories, the keyring and the
/// servers root trusts. One another user could change, or one in a directory another user could
/// write, is refused rather than read.
#[test]
fn a_config_file_another_user_could_change_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let chmod = |path: &Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    let dir = tempfile::tempdir().unwrap();
    let included = dir.path().join("extra.conf");
    std::fs::write(&included, "[extra]\nServer = https://example.org\n").unwrap();
    let conf = dir.path().join("pacman.conf");
    std::fs::write(&conf, format!("[options]\nInclude = {}\n", included.display())).unwrap();
    assert!(piko_db::config::PacmanConfig::open(&conf).is_ok());

    chmod(&included, 0o664);
    let err = piko_db::config::PacmanConfig::open(&conf).unwrap_err();
    assert!(matches!(&err, Error::Untrusted { path, .. } if path == &included), "got {err:?}");
    chmod(&included, 0o644);

    chmod(dir.path(), 0o1777);
    let err = piko_db::config::PacmanConfig::open(&conf).unwrap_err();
    chmod(dir.path(), 0o700);
    assert!(matches!(&err, Error::Untrusted { path, .. } if path == dir.path()), "got {err:?}");
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A user who can write any directory above a trusted one can rename it away and put another in
/// its place, so every ancestor is tested. A sticky ancestor passes, as `/tmp` does: only an
/// entry's owner can rename it there. The directory itself gets no such exemption.
#[test]
fn a_directory_below_one_others_can_write_is_not_trusted() {
    use piko_db::fs_util::{Distrust, ensure_trusted_directory};

    let top = tempfile::tempdir().unwrap();
    let parent = top.path().join("parent");
    let leaf = parent.join("leaf");
    std::fs::create_dir_all(&leaf).unwrap();
    ensure_trusted_directory(&leaf).unwrap();

    chmod(&parent, 0o777);
    let err = ensure_trusted_directory(&leaf).unwrap_err();
    assert!(
        matches!(&err, Error::Untrusted { path, distrust: Distrust::GroupOrOtherWritable { .. } }
            if path == &parent),
        "got {err:?}"
    );

    chmod(&parent, 0o1777);
    ensure_trusted_directory(&leaf).unwrap();
    let err = ensure_trusted_directory(&parent).unwrap_err();
    assert!(matches!(&err, Error::Untrusted { path, .. } if path == &parent), "got {err:?}");
    chmod(&parent, 0o755);

    // A relative spelling with `..` resolves to the same directories.
    let relative = leaf.join("..").join("leaf");
    ensure_trusted_directory(&relative).unwrap();
}

/// A symbolic link on the way is followed by hand, so the directories its target passes
/// through are tested too, not only the directory holding the link.
#[test]
fn a_link_through_a_directory_others_can_write_is_not_trusted() {
    use piko_db::fs_util::ensure_trusted_directory;

    let top = tempfile::tempdir().unwrap();
    let shared = top.path().join("shared");
    let target = shared.join("cache");
    std::fs::create_dir_all(&target).unwrap();
    let trusted = top.path().join("trusted");
    std::fs::create_dir(&trusted).unwrap();
    std::os::unix::fs::symlink(&target, trusted.join("cache")).unwrap();
    ensure_trusted_directory(&trusted.join("cache")).unwrap();

    chmod(&shared, 0o777);
    let err = ensure_trusted_directory(&trusted.join("cache")).unwrap_err();
    chmod(&shared, 0o755);
    assert!(matches!(&err, Error::Untrusted { path, .. } if path == &shared), "got {err:?}");

    // A loop ends in an error, not a hang.
    std::os::unix::fs::symlink(top.path().join("b"), top.path().join("a")).unwrap();
    std::os::unix::fs::symlink(top.path().join("a"), top.path().join("b")).unwrap();
    let err = ensure_trusted_directory(&top.path().join("a")).unwrap_err();
    assert!(matches!(&err, Error::Io { .. }), "got {err:?}");
}
