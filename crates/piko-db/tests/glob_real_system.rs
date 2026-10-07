//! Diffs `piko_db::glob::matches` against glibc's `fnmatch(pattern, string, 0)`, and
//! `piko_db::glob::expand` against glibc's `glob(pattern, GLOB_NOCHECK, NULL, &buf)`.
//!
//! libalpm matches every pattern of `pacman.conf`, of a hook and of `--overwrite` with the
//! first call, and pacman expands an `Include` with the second. So the C library is the oracle. This workspace forbids `unsafe` and cannot call it
//! directly. `python3` calls it through `ctypes`, in the `C.UTF-8` locale that
//! `piko_db::glob` fixes.
//!
//! Every test here is `#[ignore]`d, because it needs `python3` and glibc's `C.UTF-8` locale.
//! Run them explicitly:
//!
//! ```text
//! cargo test -p piko-db --test glob_real_system -- --ignored --nocapture
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failing assertion in a test should abort it loudly"
)]

use std::{
    ffi::OsStr,
    io::{BufRead as _, BufReader, BufWriter, Write as _},
    os::unix::ffi::OsStrExt as _,
    path::Path,
    process::{Command, Stdio},
};

use piko_db::glob::{Glob, expand, matches};

/// Reads `pattern\ttext` lines and writes `1` or `0` for each: whether `fnmatch` matches.
///
/// `setlocale(LC_ALL, "")` reads `LC_ALL`, as pacman's own `setlocale` call does.
const ORACLE: &str = r#"
import ctypes, locale, sys
locale.setlocale(locale.LC_ALL, "")
fnmatch = ctypes.CDLL(None).fnmatch
fnmatch.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int)
out = sys.stdout.buffer
for line in sys.stdin.buffer:
    pattern, text = line.rstrip(b"\n").split(b"\t")
    out.write(b"1\n" if fnmatch(pattern, text, 0) == 0 else b"0\n")
out.flush()
"#;

/// glibc's answer for each pair, in order.
fn fnmatch(pairs: &[(String, String)]) -> Vec<bool> {
    let mut child = Command::new("python3")
        .args(["-c", ORACLE])
        .env("LC_ALL", "C.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3 is needed to call glibc's fnmatch");
    let stdin = child.stdin.take().unwrap();
    let lines: Vec<String> = pairs
        .iter()
        .map(|(pattern, text)| {
            assert!(!format!("{pattern}{text}").contains(['\t', '\n', '\0']), "{pattern:?}");
            format!("{pattern}\t{text}\n")
        })
        .collect();
    // Written from a thread of its own, or a full pipe in each direction stops both processes.
    let writer = std::thread::spawn(move || {
        let mut stdin = BufWriter::new(stdin);
        for line in lines {
            stdin.write_all(line.as_bytes()).unwrap();
        }
    });
    let answers: Vec<bool> = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map(|line| line.unwrap() == "1")
        .collect();
    writer.join().unwrap();
    assert!(child.wait().unwrap().success(), "the fnmatch oracle failed");
    assert_eq!(answers.len(), pairs.len(), "the oracle did not answer every pair");
    answers
}

/// Asserts that piko answers every pair as glibc does, and names the first differences.
fn assert_agrees(pairs: &[(String, String)]) {
    let expected = fnmatch(pairs);
    let differences: Vec<String> = pairs
        .iter()
        .zip(&expected)
        .filter(|((pattern, text), glibc)| matches(pattern, text) != **glibc)
        .map(|((pattern, text), glibc)| format!("{pattern:?} against {text:?}: glibc {glibc}"))
        .collect();
    assert!(
        differences.is_empty(),
        "{} of {} pairs differ, first ones:\n{}",
        differences.len(),
        pairs.len(),
        differences.iter().take(40).cloned().collect::<Vec<_>>().join("\n")
    );
    // The compiled form must give the same answers as the free function.
    for (pattern, text) in pairs.iter().step_by(97) {
        assert_eq!(Glob::new(pattern).matches(text), matches(pattern, text), "{pattern:?}");
    }
}

/// Every string over `alphabet` of at most `length` characters, the empty one included.
fn strings(alphabet: &[&str], length: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut previous = vec![String::new()];
    for _ in 0..length {
        let next: Vec<String> = previous
            .iter()
            .flat_map(|prefix| alphabet.iter().map(move |unit| format!("{prefix}{unit}")))
            .collect();
        all.extend(next.iter().cloned());
        previous = next;
    }
    all
}

/// Every pattern in `patterns` against every text in `texts`.
fn product(patterns: &[String], texts: &[String]) -> Vec<(String, String)> {
    patterns
        .iter()
        .flat_map(|pattern| texts.iter().map(move |text| (pattern.clone(), text.clone())))
        .collect()
}

/// Every pattern of at most four characters over the metacharacters, the sigils and two
/// letters, against every text of at most three characters. About 6.5 million pairs.
#[test]
#[ignore = "needs python3 and glibc's C.UTF-8 locale"]
fn every_short_pattern_matches_as_fnmatch_does() {
    let patterns = strings(&["a", "b", "^", "!", "\\", "[", "]", "*", "?", "-"], 4);
    let texts = strings(&["a", "b", "^", "!", "\\", "[", "]", "-"], 3);
    assert_agrees(&product(&patterns, &texts));
}

/// Bracket expressions built from two members each, closed or not, plain or negated: character
/// classes, equivalence classes and collating symbols, well-formed and malformed.
#[test]
#[ignore = "needs python3 and glibc's C.UTF-8 locale"]
fn bracket_expressions_match_as_fnmatch_does() {
    let members = [
        "a",
        "b",
        "-",
        "]",
        "^",
        "!",
        "\\]",
        "\\-",
        "\\",
        "a-c",
        "c-a",
        "--",
        "[",
        "[:",
        "[=",
        "[.",
        "[:alpha:]",
        "[:upper:]",
        "[:lower:]",
        "[:digit:]",
        "[:space:]",
        "[:blank:]",
        "[:punct:]",
        "[:xdigit:]",
        "[:alnum:]",
        "[:graph:]",
        "[:print:]",
        "[:cntrl:]",
        "[:foo:]",
        "[:Alpha:]",
        "[:z:]",
        "[:alph",
        "[::]",
        "[=a=]",
        "[=]=]",
        "[==]",
        "[=a",
        "[.a.]",
        "[.-.]",
        "[.ab.]",
        "[.a",
        "[.a.]-c",
        "a-[.c.]",
        "a-\\]",
    ];
    let mut patterns = Vec::new();
    for sigil in ["", "!", "^"] {
        for first in members {
            for second in members {
                for close in ["]", ""] {
                    let bracket = format!("[{sigil}{first}{second}{close}");
                    patterns.push(bracket.clone());
                    patterns.push(format!("*{bracket}*"));
                }
            }
        }
    }
    let texts: Vec<String> = [
        "", "a", "b", "c", "A", "z", "f", "1", " ", "_", "-", "]", "[", "^", "!", "\\", ":", "=",
        ".", "ab", "[a", "[ab", "a]", "x[a]", "[:", "[=a",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_agrees(&product(&patterns, &texts));
}

/// A class name past glibc's length bound, and one just within it, with no closing `:]`.
#[test]
#[ignore = "needs python3 and glibc's C.UTF-8 locale"]
fn a_long_class_name_is_bounded_as_fnmatch_bounds_it() {
    let mut pairs = Vec::new();
    for length in [2046, 2047, 2048, 2049] {
        let name = "a".repeat(length);
        for pattern in [format!("[[:{name}]"), format!("[[:{name}:]]"), format!("[a[:{name}]")] {
            for text in ["[", "a", ":"] {
                pairs.push((pattern.clone(), text.to_owned()));
            }
        }
    }
    assert_agrees(&pairs);
}

/// Characters past ASCII: the wide reading, and the byte reading glibc falls back on.
#[test]
#[ignore = "needs python3 and glibc's C.UTF-8 locale"]
fn a_character_past_ascii_matches_as_fnmatch_does() {
    let patterns = strings(&["a", "é", "?", "*", "[", "]", "!", "-", "\\"], 3);
    let texts = strings(&["a", "é", "e", "€"], 2);
    let mut pairs = product(&patterns, &texts);

    let classes = [
        "alpha", "lower", "upper", "alnum", "digit", "punct", "print", "graph", "space", "blank",
        "cntrl", "xdigit",
    ];
    let characters = ["é", "É", "€", "ß", "ÿ", "Ω", "ω", "λ", "中", "\u{a0}", "\u{2003}", "©"];
    for class in classes {
        for character in characters {
            pairs.push((format!("[[:{class}:]]"), character.to_owned()));
            pairs.push((format!("[![:{class}:]]"), character.to_owned()));
        }
    }
    for range in ["[à-ê]", "[a-z]", "[é-é]", "[!à-ê]", "[[.é.]]", "[[=é=]]", "[\\é]"] {
        for character in ["é", "e", "à", "ê", "ë", "b"] {
            pairs.push((range.to_owned(), character.to_owned()));
        }
    }
    // A range compares collation sequence values, and `C.UTF-8` gives none to a character past
    // U+00FF. Each start, end and text below is on one side of that bound or the other.
    let starts = ["a", "é", "ÿ", "Ā", "ʒ", "[.a.]", "[.Ā.]"];
    let ends = ["z", "ö", "ÿ", "Ā", "ʒ", "[.z.]", "[.ʒ.]", "\\]", "\\ʒ"];
    let texts = ["b", "a", "é", "ö", "ÿ", "Ā", "ɐ", "ʒ", "z", "]", ".", "ɐ]", "ɐ.", "ɐz]", "é]"];
    for start in starts {
        for end in ends {
            for negation in ["", "!"] {
                for text in texts {
                    pairs.push((format!("[{negation}{start}-{end}]"), text.to_owned()));
                }
            }
        }
    }
    assert_agrees(&pairs);
}

/// Reads one pattern per line and writes the paths `glob(pattern, GLOB_NOCHECK)` lists, one line
/// for each pattern, the paths separated by a tab.
const GLOB_ORACLE: &str = r#"
import ctypes, locale, sys
locale.setlocale(locale.LC_ALL, "")
class Glob(ctypes.Structure):
    _fields_ = [
        ("pathc", ctypes.c_size_t),
        ("pathv", ctypes.POINTER(ctypes.c_char_p)),
        ("offs", ctypes.c_size_t),
        ("flags", ctypes.c_int),
        ("functions", ctypes.c_void_p * 16),
    ]
GLOB_NOCHECK = 1 << 4
libc = ctypes.CDLL(None)
out = sys.stdout.buffer
for line in sys.stdin.buffer:
    found = Glob()
    status = libc.glob(line.rstrip(b"\n"), GLOB_NOCHECK, None, ctypes.byref(found))
    if status != 0:
        out.write(b"error %d\n" % status)
    else:
        out.write(b"\t".join(found.pathv[i] for i in range(found.pathc)) + b"\n")
    libc.globfree(ctypes.byref(found))
out.flush()
"#;

/// glibc's paths for each pattern, in order.
fn glob(patterns: &[String]) -> Vec<Vec<Vec<u8>>> {
    let mut child = Command::new("python3")
        .args(["-c", GLOB_ORACLE])
        .env("LC_ALL", "C.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3 is needed to call glibc's glob");
    let mut stdin = child.stdin.take().unwrap();
    for pattern in patterns {
        assert!(!pattern.contains(['\t', '\n', '\0']), "{pattern:?}");
        writeln!(stdin, "{pattern}").unwrap();
    }
    drop(stdin);
    let answers: Vec<Vec<Vec<u8>>> = BufReader::new(child.stdout.take().unwrap())
        .split(b'\n')
        .map(|line| line.unwrap().split(|byte| *byte == b'\t').map(<[u8]>::to_vec).collect())
        .collect();
    assert!(child.wait().unwrap().success(), "the glob oracle failed");
    assert_eq!(answers.len(), patterns.len(), "the oracle did not answer every pattern");
    answers
}

/// A tree that holds each kind of name a pattern can trip on: hidden names, names that hold a
/// metacharacter or a `\\`, a name past ASCII, a name that is not UTF-8, a link to a directory
/// and a dangling link.
fn probe_tree() -> tempfile::TempDir {
    let tree = tempfile::tempdir().unwrap();
    let root = tree.path();
    for directory in ["sub", ".hid", "sub2/deep", "empty"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    let files: [&[u8]; 22] = [
        b"a.conf",
        b".h.conf",
        b"b",
        b"[x]",
        b"x*",
        b"a\\b",
        b"\xc3\xa9.conf",
        b"c.conf",
        b"ab",
        b"ac",
        b"ad",
        b"^b",
        b"!b",
        b".x",
        b"B.conf",
        b"bad\xff.conf",
        b"sub/c.conf",
        b"sub/.d.conf",
        b".hid/e.conf",
        b"sub2/deep/f.conf",
        b"sub2/g",
        b"*",
    ];
    for file in files {
        std::fs::write(root.join(OsStr::from_bytes(file)), b"").unwrap();
    }
    std::os::unix::fs::symlink("sub", root.join("link")).unwrap();
    std::os::unix::fs::symlink("missing", root.join("dangling.conf")).unwrap();
    std::os::unix::fs::symlink("c.conf", root.join("file-link")).unwrap();
    tree
}

/// Every pattern built from a directory part and a last component, under a tree that holds
/// hidden names, links, escapes and names that are not UTF-8.
#[test]
#[ignore = "needs python3 and glibc's C.UTF-8 locale"]
fn every_include_pattern_expands_as_glob_does() {
    let tree = probe_tree();
    let root = tree.path().to_str().unwrap();
    let directories = [
        "",
        "sub/",
        "*/",
        ".*/",
        "s?b/",
        "[s]ub/",
        "sub*/",
        "l*/",
        "\\s\\ub/",
        "./",
        "sub//",
        "*//",
        "nomatch*/",
        "nomatch/",
        "[^s]*/",
        "sub2/*/",
        "*/*/",
        "file-link/",
        "*\\/",
        "e*/",
        "[/",
        "sub\\/",
    ];
    let leaves = [
        "*",
        ".*",
        "*.conf",
        "?.conf",
        "[a-c]*",
        "[^a]*",
        "[!a]*",
        "a\\b",
        "a\\*",
        "[x]",
        "\\[x]",
        "x\\*",
        "[*",
        "***",
        "[.]*",
        "*[.]conf",
        "nomatch*",
        "nomatch",
        "c.conf",
        ".",
        "..",
        "",
        "deep",
        "deep/",
        "*/",
        "c.conf/",
        "\\*",
        "[",
        "]",
        "a[",
        "*\\",
        "?",
        ".?",
        "*/.",
        "b*",
        "B*",
        "[[:upper:]]*",
        "\\",
        "*.conf\\",
    ];
    let mut patterns = vec![root.to_owned(), format!("{root}/"), format!("{root}//")];
    for directory in directories {
        for leaf in leaves {
            patterns.push(format!("{root}/{directory}{leaf}"));
        }
    }
    let expected = glob(&patterns);
    let differences: Vec<String> = patterns
        .iter()
        .zip(&expected)
        .filter_map(|(pattern, glibc)| {
            let piko: Vec<Vec<u8>> = expand(pattern)
                .iter()
                .map(|path| Path::as_os_str(path).as_bytes().to_vec())
                .collect();
            (piko != *glibc).then(|| {
                let show = |paths: &[Vec<u8>]| {
                    paths
                        .iter()
                        .map(|path| String::from_utf8_lossy(path).replace(root, "R"))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                format!(
                    "{}\n  glibc: {}\n  piko:  {}",
                    pattern.replace(root, "R"),
                    show(glibc),
                    show(&piko)
                )
            })
        })
        .collect();
    assert!(
        differences.is_empty(),
        "{} of {} patterns differ, first ones:\n{}",
        differences.len(),
        patterns.len(),
        differences.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
    );
}
