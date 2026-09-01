//! A configured repository's database is verified when it is opened, not only when downloaded.
//!
//! # What this exists to catch
//!
//! piko once had this check, then removed it on the belief that libalpm verifies a sync
//! database only at download. That belief was wrong: `sync_db_validate` (`be_sync.c:71`) runs
//! both at registration (`be_sync.c:758`) and after a download (`be_sync.c:248`). The check is
//! back for that reason. See `docs/libalpm-compat.md` §62.
//!
//! The subtle half is `a_repository_that_declares_no_sig_level_is_still_verified`. A repository
//! section with no `SigLevel` directive keeps the parser's `USE_DEFAULT` sentinel (bit 31) in
//! `RepositoryConfig::sig_level`, rather than the global value. The removed check read that
//! field directly, which resolves a policy whose `check` bit is clear and **silently verifies
//! nothing**. Nothing else in the suite would notice: the command succeeds, which is what it
//! does when a signature is fine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{path::Path, process::Command};

use piko_db::fixture::RepoFixture;

const PIKO: &str = env!("CARGO_BIN_EXE_piko");

/// A `<dbpath>` holding one repository database, `core`, with a single package in it.
fn dbpath_with_core(dir: &Path) {
    let sync = dir.join("sync");
    std::fs::create_dir_all(&sync).unwrap();

    let fixture = RepoFixture::new();
    let built = fixture.write_gzip_archive(
        "core.db",
        &[(
            "acl-2.4.0-1/desc",
            b"%FILENAME%\nacl-2.4.0-1-x86_64.pkg.tar.zst\n\n%NAME%\nacl\n\n%VERSION%\n2.4.0-1\n\n\
              %BASE%\nacl\n\n%DESC%\nAccess control list\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n\
              %MD5SUM%\nd41d8cd98f00b204e9800998ecf8427e\n\n\
              %SHA256SUM%\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n\
              %ARCH%\nx86_64\n\n%BUILDDATE%\n1\n\n%PACKAGER%\nTest <test@example.invalid>\n\n",
        )],
    );
    std::fs::copy(built, sync.join("core.db")).unwrap();
}

/// `sig_level` goes into `[options]`. The `[core]` section deliberately declares none.
fn write_config(dir: &Path, sig_level: &str) -> std::path::PathBuf {
    let path = dir.join("pacman.conf");
    std::fs::write(
        &path,
        format!(
            "[options]\nArchitecture = x86_64\nDBPath = {}\nSigLevel = {sig_level}\n\n\
             [core]\nServer = https://example.invalid/$repo\n",
            dir.display()
        ),
    )
    .unwrap();
    path
}

fn list_repo(config: &Path) -> std::process::Output {
    Command::new(PIKO)
        .arg("--config")
        .arg(config)
        .args(["list", "--repo", "core"])
        .output()
        .unwrap()
}

/// The ordinary Arch case: no `.sig` anywhere. `DatabaseOptional` says that is fine.
#[test]
fn an_unsigned_database_opens_under_database_optional() {
    let dir = tempfile::tempdir().unwrap();
    dbpath_with_core(dir.path());
    let config = write_config(dir.path(), "Required DatabaseOptional");

    let output = list_repo(&config);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("acl 2.4.0-1"));
}

/// `DatabaseOptional` excuses a *missing* signature. It never excuses an invalid one.
#[test]
fn a_database_with_an_unusable_signature_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    dbpath_with_core(dir.path());
    let config = write_config(dir.path(), "Required DatabaseOptional");
    std::fs::write(dir.path().join("sync/core.db.sig"), b"not a real signature").unwrap();

    let output = list_repo(&config);
    assert!(!output.status.success(), "an unusable signature was accepted");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("signature"), "{stderr}");
}

/// The regression that would otherwise be silent.
///
/// `[core]` declares no `SigLevel`, so the global `Required DatabaseOptional` must apply to it.
/// Reading `RepositoryConfig::sig_level` directly yields the `USE_DEFAULT` sentinel instead,
/// whose `DATABASE` bit is clear. The check then does nothing and this command *succeeds*.
/// Sharing `context::effective_sig_level` with the download path keeps it failing correctly.
#[test]
fn a_repository_that_declares_no_sig_level_is_still_verified() {
    let dir = tempfile::tempdir().unwrap();
    dbpath_with_core(dir.path());
    let config = write_config(dir.path(), "Required DatabaseOptional");
    // This confirms the section really carries no SigLevel of its own.
    let text = std::fs::read_to_string(&config).unwrap();
    let core = text.split("[core]").nth(1).unwrap();
    assert!(!core.contains("SigLevel"), "the test config no longer exercises inheritance");

    std::fs::write(dir.path().join("sync/core.db.sig"), b"not a real signature").unwrap();

    let output = list_repo(&config);
    assert!(
        !output.status.success(),
        "a repository inheriting the global SigLevel was not verified"
    );
}

/// `SigLevel = Never` must stay free. It is not merely permissive; it never reaches GnuPG at
/// all. A bogus signature is ignored because nothing looks at it.
#[test]
fn never_does_not_check_the_signature_at_all() {
    let dir = tempfile::tempdir().unwrap();
    dbpath_with_core(dir.path());
    let config = write_config(dir.path(), "Never");
    std::fs::write(dir.path().join("sync/core.db.sig"), b"not a real signature").unwrap();

    let output = list_repo(&config);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}
