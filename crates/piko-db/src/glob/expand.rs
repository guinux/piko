//! `glob(pattern, GLOB_NOCHECK, NULL, &buf)`, transcribed from glibc 2.44 (`posix/glob.c`).
//!
//! That is the call pacman's `process_include` (`conf.c`) makes for an `Include` directive. The
//! `glob` crate reads another grammar, and walks the tree another way: it lets `*` match a
//! name that starts with `.`, never lists `.` and `..`, and has no `\` escape. So this module
//! is a transcription. `crates/piko-db/tests/glob_real_system.rs` diffs it against the C
//! library's `glob`.
//!
//! # What the transcription keeps
//!
//! - Each name is matched with `fnmatch(pattern, name, FNM_PERIOD)`: a name that starts with a
//!   `.` is selected only by a pattern that starts with a `.`. `.*` selects `.` and `..` too,
//!   because `readdir` lists them.
//! - A pattern that matches nothing is returned as written (`GLOB_NOCHECK`). A part with no
//!   wildcard is not tested at all when that rule makes the answer the same either way.
//! - A pattern that ends in `/` selects directories only, and each one is returned with a
//!   trailing `/`.
//! - A directory part with a wildcard is expanded first, through every symbolic link that leads
//!   to a directory.
//! - The result is sorted with `strcoll`. In `C.UTF-8`, that is the byte order.
//!
//! # The locale is fixed to `C.UTF-8`
//!
//! As for a single pattern, glibc's answer depends on the locale: the order of the result too,
//! which decides the order in which the included files are read. This module answers as glibc
//! answers in `C.UTF-8`.

use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _, path::PathBuf};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

use super::fnmatch::Compiled;

/// What `__glob_pattern_type` finds in a pattern.
mod pattern_type {
    /// No wildcard, no `\`, no `[`.
    pub(super) const NONE: u8 = 0x0;
    /// A `*` or a `?`, or a `[` closed by a `]`.
    pub(super) const SPECIAL: u8 = 0x1;
    /// A `\` escape.
    pub(super) const BACKSLASH: u8 = 0x2;
    /// A `[` with no `]` after it.
    pub(super) const BRACKET: u8 = 0x4;
}

/// The `glob` flags this transcription reaches. Every other flag is clear.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Flags {
    /// `GLOB_NOCHECK`: no match returns the pattern itself.
    nocheck: bool,
    /// `GLOB_ONLYDIR`: select directories only, as far as `readdir` tells.
    onlydir: bool,
    /// `GLOB_MARK`: put a `/` after each directory.
    mark: bool,
    /// `GLOB_NOSORT`: leave the result unsorted.
    nosort: bool,
}

/// Whether a call found something. glibc's other results are errors no `Include` call can get:
/// it passes no error function and no `GLOB_ERR`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Status {
    /// At least one path, or the pattern itself under `GLOB_NOCHECK`.
    Found,
    /// `GLOB_NOMATCH`.
    NoMatch,
}

/// The paths `pattern` names, as `glob(pattern, GLOB_NOCHECK, NULL, &buf)` lists them.
///
/// A pattern that matches nothing is returned as the one path. A directory that cannot be
/// opened is passed over, as glibc passes it over with no error function.
#[must_use]
pub fn expand(pattern: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    glob(pattern, Flags { nocheck: true, ..Flags::default() }, &mut found);
    found.into_iter().map(|path| PathBuf::from(OsStr::from_bytes(&path))).collect()
}

/// glibc's `__glob`. The paths go to the end of `out`.
fn glob(pattern: &str, mut flags: Flags, out: &mut Vec<Vec<u8>>) -> Status {
    // POSIX requires all slashes to be matched, so a trailing slash selects directories only.
    if pattern.ends_with('/') {
        flags.onlydir = true;
    }
    let mut oldcount = out.len();

    let (mut dirname, filename): (String, &str) = match pattern.rfind('/') {
        None => {
            if pattern.is_empty() {
                return no_matches(pattern, flags, out, oldcount);
            }
            (String::new(), pattern)
        }
        Some(0) => ("/".to_owned(), pattern.get(1..).unwrap_or_default()),
        Some(1) if pattern.starts_with('\\') => {
            ("/".to_owned(), pattern.get(2..).unwrap_or_default())
        }
        Some(slash) => {
            let mut dirname = pattern.get(..slash).unwrap_or_default().to_owned();
            let filename = pattern.get(slash.saturating_add(1)..).unwrap_or_default();
            if filename.is_empty() && dirname.len() > 1 {
                // "pattern/": expand "pattern", and mark the directories.
                let orig_flags = flags;
                if ends_in_unquoted_backslash(&dirname) {
                    dirname.pop();
                    flags.nocheck = false;
                }
                // A run of trailing `/` becomes one.
                while dirname.ends_with("//") {
                    dirname.pop();
                }
                let status = glob(&dirname, Flags { mark: true, ..flags }, out);
                if status == Status::NoMatch && flags != orig_flags {
                    oldcount = out.len();
                    return no_matches(pattern, orig_flags, out, oldcount);
                }
                return status;
            }
            (dirname, filename)
        }
    };

    let meta = pattern_type(&dirname);
    if meta & (pattern_type::SPECIAL | pattern_type::BRACKET) != 0 {
        // The directory part holds a wildcard: expand it first, then look in each directory.
        if ends_in_unquoted_backslash(&dirname) {
            dirname.pop();
        }
        let mut dirs = Vec::new();
        let status =
            glob(&dirname, Flags { nosort: true, onlydir: true, ..Flags::default() }, &mut dirs);
        if status == Status::NoMatch {
            if !flags.nocheck {
                return Status::NoMatch;
            }
            return no_matches(pattern, flags, out, oldcount);
        }
        for dir in &dirs {
            let old = out.len();
            if glob_in_dir(filename, dir, Flags { nocheck: false, ..flags }, out) == Status::Found {
                prefix(dir, out.get_mut(old..).unwrap_or_default());
            }
        }
        if out.len() == oldcount {
            return no_matches(pattern, flags, out, oldcount);
        }
    } else {
        let old = out.len();
        let orig_flags = flags;
        if meta & pattern_type::BACKSLASH != 0 {
            dirname = unescape(&dirname);
            flags.nocheck = false;
        }
        let directory = if dirname.is_empty() { "." } else { dirname.as_str() };
        if glob_in_dir(filename, directory.as_bytes(), flags, out) == Status::NoMatch {
            if flags != orig_flags && out.len() == oldcount {
                return no_matches(pattern, orig_flags, out, oldcount);
            }
            return Status::NoMatch;
        }
        if !dirname.is_empty() {
            prefix(dirname.as_bytes(), out.get_mut(old..).unwrap_or_default());
        }
    }

    finish(flags, out, oldcount)
}

/// glibc's `no_matches:` label: the pattern itself under `GLOB_NOCHECK`, nothing otherwise.
fn no_matches(pattern: &str, flags: Flags, out: &mut Vec<Vec<u8>>, oldcount: usize) -> Status {
    if !flags.nocheck {
        return Status::NoMatch;
    }
    out.push(pattern.as_bytes().to_vec());
    finish(flags, out, oldcount)
}

/// The end of `__glob`: marks the directories found since `oldcount`, then sorts them.
fn finish(flags: Flags, out: &mut [Vec<u8>], oldcount: usize) -> Status {
    let added = out.get_mut(oldcount..).unwrap_or_default();
    if flags.mark {
        for path in added.iter_mut() {
            if is_dir(path) {
                path.push(b'/');
            }
        }
    }
    if !flags.nosort {
        // `strcoll` in `C.UTF-8` compares the bytes.
        added.sort_unstable();
    }
    Status::Found
}

/// glibc's `glob_in_dir`: the names in `directory` that `pattern`, one path component, selects.
/// The names go to the end of `out`, without the directory.
fn glob_in_dir(pattern: &str, directory: &[u8], flags: Flags, out: &mut Vec<Vec<u8>>) -> Status {
    let meta = pattern_type(pattern);
    let mut nocheck = flags.nocheck;
    let mut names: Vec<Vec<u8>> = Vec::new();

    if meta == pattern_type::NONE && nocheck {
        // The pattern names one path, and `GLOB_NOCHECK` returns it whether it exists or not.
    } else if meta == pattern_type::NONE {
        let mut full = directory.to_vec();
        full.push(b'/');
        full.extend_from_slice(pattern.as_bytes());
        match rustix::fs::lstat(OsStr::from_bytes(&full)) {
            Ok(_) | Err(rustix::io::Errno::OVERFLOW) => nocheck = true,
            Err(_) => {}
        }
    } else {
        let compiled = Compiled::new(pattern);
        // A directory that cannot be opened is passed over: no error function, no `GLOB_ERR`.
        if let Ok(fd) = rustix::fs::open(
            OsStr::from_bytes(directory),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ) && let Ok(entries) = Dir::read_from(&fd)
        {
            // A read error ends the listing, as `readdir` returning NULL ends glibc's loop.
            for entry in entries.map_while(Result::ok) {
                let name = entry.file_name().to_bytes();
                if flags.onlydir {
                    match entry.file_type() {
                        FileType::Directory => {}
                        FileType::Symlink | FileType::Unknown => {
                            let followed =
                                rustix::fs::statat(&fd, entry.file_name(), AtFlags::empty());
                            if !followed.is_ok_and(|stat| {
                                FileType::from_raw_mode(stat.st_mode) == FileType::Directory
                            }) {
                                continue;
                            }
                        }
                        _ => continue,
                    }
                }
                if compiled.matches_name(name) {
                    names.push(name.to_vec());
                }
            }
        }
    }

    if names.is_empty() && nocheck {
        names.push(pattern.as_bytes().to_vec());
    }
    if names.is_empty() {
        return Status::NoMatch;
    }
    out.extend(names);
    Status::Found
}

/// glibc's `prefix_array`: puts `dir` and a `/` in front of each path. `/` alone gives `/name`.
fn prefix(dir: &[u8], paths: &mut [Vec<u8>]) {
    let dir = if dir == b"/" { &[][..] } else { dir };
    for path in paths {
        let mut prefixed =
            Vec::with_capacity(dir.len().saturating_add(path.len()).saturating_add(1));
        prefixed.extend_from_slice(dir);
        prefixed.push(b'/');
        prefixed.extend_from_slice(path);
        *path = prefixed;
    }
}

/// glibc's `is_dir`: a directory, or a symbolic link to one.
fn is_dir(path: &[u8]) -> bool {
    rustix::fs::stat(OsStr::from_bytes(path))
        .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::Directory)
}

/// glibc's `__glob_pattern_type`, with `\` read as an escape.
fn pattern_type(pattern: &str) -> u8 {
    let mut found = pattern_type::NONE;
    let mut bytes = pattern.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'?' | b'*' => return pattern_type::SPECIAL,
            b'\\' => {
                bytes.next();
                found |= pattern_type::BACKSLASH;
            }
            b'[' => found |= pattern_type::BRACKET,
            b']' if found & pattern_type::BRACKET != 0 => return pattern_type::SPECIAL,
            _ => {}
        }
    }
    found
}

/// Whether `text` ends in a `\` that no other `\` escapes: an odd run of them.
fn ends_in_unquoted_backslash(text: &str) -> bool {
    let run = text.bytes().rev().take_while(|byte| *byte == b'\\').count();
    run % 2 == 1
}

/// `text` with each `\` removed, and the character after it kept as it is.
fn unescape(text: &str) -> String {
    let mut unescaped = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(escaped) = chars.next() {
                unescaped.push(escaped);
            }
        } else {
            unescaped.push(c);
        }
    }
    unescaped
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    /// The paths `pattern`, under `root`, expands to, with `root` taken off.
    fn expanded(root: &std::path::Path, pattern: &str) -> Vec<String> {
        let prefix = root.to_str().unwrap();
        expand(&format!("{prefix}/{pattern}"))
            .iter()
            .map(|path| path.to_str().unwrap().replacen(prefix, "R", 1))
            .collect()
    }

    /// Each answer was measured with glibc 2.44's `glob(pattern, GLOB_NOCHECK)` in `C.UTF-8`.
    /// `tests/glob_real_system.rs` diffs the rule against the C library over a larger tree.
    #[test]
    fn a_pattern_expands_as_glob_does() {
        let tree = tempfile::tempdir().unwrap();
        let root = tree.path();
        for file in ["a.conf", ".h.conf", "c.conf", "B.conf", "sub/c.conf", "sub/.d.conf"] {
            std::fs::create_dir_all(root.join(file).parent().unwrap()).unwrap();
            std::fs::write(root.join(file), b"").unwrap();
        }
        std::os::unix::fs::symlink("sub", root.join("link")).unwrap();

        // A hidden name is selected only by a pattern that starts with a `.`, and `.*` selects
        // `.` and `..` too. The order is the bytes'.
        assert_eq!(expanded(root, "*.conf"), ["R/B.conf", "R/a.conf", "R/c.conf"]);
        assert_eq!(expanded(root, ".*"), ["R/.", "R/..", "R/.h.conf"]);
        assert_eq!(expanded(root, "[.]*"), ["R/[.]*"]);
        // A directory part is expanded through a link to a directory.
        assert_eq!(expanded(root, "*/c.conf"), ["R/link/c.conf", "R/sub/c.conf"]);
        // A trailing `/` selects directories, and marks them.
        assert_eq!(expanded(root, "*/"), ["R/link/", "R/sub/"]);
        // No match returns the pattern as written.
        assert_eq!(expanded(root, "nomatch*"), ["R/nomatch*"]);
        assert_eq!(expanded(root, r"a\*"), [r"R/a\*"]);
        // `\` escapes, and an unclosed `[` is an ordinary character.
        assert_eq!(expanded(root, r"\a.conf"), ["R/a.conf"]);
        assert_eq!(expanded(root, "[*"), ["R/[*"]);
    }
}
