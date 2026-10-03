//! Text a mirror chose never reaches the terminal as it was written.
//!
//! Arch signs no repository database, so every free-text field in one is text a mirror can
//! choose: `%DESC%`, `%URL%`, `%GROUPS%`, an optional dependency's description, and every path in
//! a `files` list. A parse error quotes those bytes too. These tests put an OSC 52 clipboard
//! write, a title change and a carriage return in each, and run the real binary.
//!
//! A package file chooses its `.PKGINFO` keys the same way, and the warning that names an
//! unknown one is tested here too.
//!
//! A test output here is never a terminal, so `console` writes no styling of its own. Any escape
//! byte in the output therefore came from the database.

#![expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]

use std::{path::Path, process::Command};

use piko_db::fixture::RepoFixture;

const PIKO: &str = env!("CARGO_BIN_EXE_piko");

/// An OSC 52 clipboard write, then a title change, both ended by a bell.
const PAYLOAD: &str = "\u{1b}]52;c;cHduZWQ=\u{7}\u{1b}]0;PWNED\u{7}";

/// The title change of [`PAYLOAD`] alone.
const TITLE: &str = "\u{1b}]0;PWNED\u{7}";

/// The `desc` of `foo`, with `description` as its `%DESC%` and the payload in every other
/// free-text field a reader keeps.
fn desc(description: &str) -> String {
    format!(
        "%FILENAME%\nfoo-1.0-1-x86_64.pkg.tar.zst\n\n%NAME%\nfoo\n\n%BASE%\nfoo\n\n\
         %VERSION%\n1.0-1\n\n%DESC%\n{description}\n\n%GROUPS%\ngrp{PAYLOAD}\n\n\
         %CSIZE%\n1\n\n%ISIZE%\n1\n\n\
         %SHA256SUM%\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n\
         %URL%\nhttps://example.invalid/{PAYLOAD}\n\n%ARCH%\nx86_64\n\n%BUILDDATE%\n1\n\n\
         %PACKAGER%\nTest <test@example.invalid>\n\n%OPTDEPENDS%\nbar: {PAYLOAD}\n\n"
    )
}

/// A `<dbpath>` holding the repository `evil`, with `foo` described by `description`, and a
/// configuration that names it.
fn setup(dir: &Path, description: &str) -> std::path::PathBuf {
    let sync = dir.join("sync");
    std::fs::create_dir_all(&sync).unwrap();
    let files = format!("%FILES%\nusr/\nusr/bin/\nusr/bin/x{PAYLOAD}\n\n");
    let fixture = RepoFixture::new();
    let built = fixture.write_gzip_archive(
        "evil.db",
        &[("foo-1.0-1/desc", desc(description).as_bytes()), ("foo-1.0-1/files", files.as_bytes())],
    );
    std::fs::copy(built, sync.join("evil.db")).unwrap();

    let config = dir.join("pacman.conf");
    std::fs::write(
        &config,
        format!(
            "[options]\nArchitecture = x86_64\nDBPath = {}\nSigLevel = Never\n\n\
             [evil]\nServer = https://example.invalid/$repo\n",
            dir.display()
        ),
    )
    .unwrap();
    config
}

/// Runs `piko --config <config> <args>`, and returns its stdout and stderr.
fn piko(config: &Path, args: &[&str]) -> (String, String) {
    let output = Command::new(PIKO).arg("--config").arg(config).args(args).output().unwrap();
    (String::from_utf8(output.stdout).unwrap(), String::from_utf8(output.stderr).unwrap())
}

/// No control character but a line feed, so nothing that could drive a terminal.
fn assert_inert(text: &str) {
    assert!(
        !text.chars().any(|character| character.is_control() && character != '\n'),
        "a control character reached the output:\n{text:?}"
    );
}

#[test]
fn info_escapes_every_free_text_field() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path(), &format!("nice {PAYLOAD}"));

    let (stdout, stderr) = piko(&config, &["info", "--repo", "evil", "foo"]);
    assert_inert(&stdout);
    assert_inert(&stderr);
    assert!(stdout.contains("nice \\u{1b}]52;c;cHduZWQ=\\u{7}"), "{stdout}");
    assert!(stdout.contains("grp\\u{1b}]52"), "{stdout}");
    assert!(stdout.contains("bar: \\u{1b}]52"), "{stdout}");
}

#[test]
fn search_escapes_the_description() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path(), &format!("nice {PAYLOAD}"));

    let (stdout, stderr) = piko(&config, &["search", "--repo", "evil", "foo"]);
    assert_inert(&stdout);
    assert_inert(&stderr);
    assert!(stdout.contains("nice \\u{1b}]52"), "{stdout}");
}

#[test]
fn files_escapes_each_path() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path(), "nice");

    let (stdout, stderr) = piko(&config, &["files", "--repo", "evil", "foo"]);
    assert_inert(&stdout);
    assert_inert(&stderr);
    assert!(stdout.contains("/usr/bin/x\\u{1b}]52"), "{stdout}");
}

#[test]
fn a_group_listing_escapes_the_group_name() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path(), "nice");

    let (stdout, stderr) = piko(&config, &["list", "--groups", "--repo", "evil"]);
    assert_inert(&stdout);
    assert_inert(&stderr);
    assert!(stdout.contains("grp\\u{1b}]52"), "{stdout}");
}

/// A `%PGPSIG%` that is not base64 refuses the entry. The parse error quotes the line it
/// refused, payload and carriage return included, and keeps only its own line feeds.
#[test]
fn a_parse_error_escapes_the_bytes_it_quotes() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path(), &format!("nice\n\n%PGPSIG%\n{PAYLOAD}\rfake"));

    let (stdout, stderr) = piko(&config, &["info", "--repo", "evil", "foo"]);
    assert_inert(&stdout);
    assert_inert(&stderr);
    assert!(stderr.contains("\\u{1b}]52"), "{stderr}");
    assert!(stderr.contains("\\r"), "{stderr}");
}

/// A shown field that does not convert is named on stderr, and the value it quotes is escaped.
/// stdout keeps the shape `pacman -Si` prints.
#[test]
fn info_escapes_an_invalid_field_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path(), &format!("nice\n\n%MAKEDEPENDS%\nbar{PAYLOAD}"));

    let (stdout, stderr) = piko(&config, &["info", "--repo", "evil", "foo"]);
    assert_inert(&stdout);
    assert_inert(&stderr);
    assert!(stderr.contains("Warning: foo: "), "{stderr}");
    assert!(stderr.contains("MAKEDEPENDS"), "{stderr}");
    assert!(stderr.contains("\\u{1b}]52"), "{stderr}");
    assert!(!stdout.contains("Warning"), "{stdout}");
}

/// An unknown `.PKGINFO` key is a warning that names it, escaped. A package chose those bytes.
///
/// The key carries the title change alone: a key holds no `=`, and the clipboard write has one.
#[test]
fn plan_escapes_an_unknown_pkginfo_key() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path(), "nice");
    std::fs::create_dir_all(dir.path().join("local")).unwrap();

    let pkginfo =
        format!("pkgname = baz\npkgver = 1.0-1\narch = x86_64\nsize = 1\nkey{TITLE} = 1\n");
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(pkginfo.len() as u64);
    header.set_cksum();
    builder.append_data(&mut header, ".PKGINFO", pkginfo.as_bytes()).unwrap();
    let package = dir.path().join("baz-1.0-1-x86_64.pkg.tar");
    std::fs::write(&package, builder.into_inner().unwrap()).unwrap();

    let (stdout, stderr) = piko(&config, &["plan", package.to_str().unwrap()]);
    assert_inert(&stdout);
    assert_inert(&stderr);
    assert!(stderr.contains("Warning: baz: unknown key \"key\\u{1b}]0;PWNED"), "{stderr}");
}

/// An `%OPTDEPENDS%` line `piko info` reads past is named on stderr, escaped: an installed
/// package's `desc` holds bytes its package chose.
#[test]
fn info_escapes_an_unread_optional_dependency() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path(), "nice");
    let local = dir.path().join("local");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
    for spec in [
        piko_db::fixture::PackageSpec::new("foo", "1.0-1"),
        piko_db::fixture::PackageSpec::new("bar", "1.0-1").optdepends([format!("b{TITLE}ad")]),
    ] {
        let entry = local.join(spec.entry());
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("desc"), spec.local_desc()).unwrap();
        std::fs::write(entry.join("files"), "").unwrap();
    }

    let (stdout, stderr) = piko(&config, &["info", "foo"]);
    assert_inert(&stdout);
    assert_inert(&stderr);
    assert!(
        stderr.contains("Warning: Optional For may be incomplete: bar: "),
        "{stdout}\n{stderr}"
    );
    assert!(stderr.contains("\\u{1b}]0;PWNED"), "{stderr}");
}
