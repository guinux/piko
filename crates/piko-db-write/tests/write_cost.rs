//! What a transaction's database writes cost, per-file against staged.
//!
//! `#[ignore]`d and pointed at a **real** filesystem, because that is the only place the
//! measurement means anything: the default temporary directory on this machine is `tmpfs`,
//! where `fsync` is a no-op and every variant reports the same number.
//!
//! ```text
//! PIKO_WRITE_BENCH_DIR=~/.cache cargo test --release -p piko-db-write --test write_cost -- --ignored --nocapture
//! ```
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a measurement harness"
)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use piko_db::{EntryName, Limits};
use piko_db_write::{DbLock, LocalDbWriter, Record, RecordKind};

/// A typical `piko update` on the machine this test was written against.
const PACKAGES: usize = 42;
const RUNS: usize = 5;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Where to write. `tmpfs` makes every variant look identical, so this path is explicit.
fn bench_root() -> Option<PathBuf> {
    let base = std::env::var_os("PIKO_WRITE_BENCH_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    base.is_dir().then(|| base.join("piko-write-cost"))
}

fn desc(name: &str, index: usize) -> Record {
    let text = format!("%NAME%\n{name}\n\n%VERSION%\n1.0.{index}-1\n\n%SIZE%\n4096\n\n");
    Record::parse(RecordKind::Desc, &text).unwrap()
}

fn files(index: usize) -> Record {
    let mut text = String::from("%FILES%\n");
    for line in 0..40 {
        text.push_str(&format!("usr/share/pkg-{index}/file-{line}\n"));
    }
    text.push('\n');
    Record::parse(RecordKind::Files, &text).unwrap()
}

fn entries() -> Vec<EntryName> {
    (0..PACKAGES).map(|i| EntryName::parse(&format!("pkg{i}-1.0.{i}-1")).unwrap()).collect()
}

fn fresh(root: &Path) -> DbLock {
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root).unwrap();
    DbLock::acquire(root).unwrap()
}

/// The per-file path. `create_entry` runs, then `write_record`/`write_raw`, each with its own
/// data `fsync` and its own directory `fsync`.
fn per_file(writer: &LocalDbWriter<'_>, mtree: &[u8]) {
    for (index, entry) in entries().iter().enumerate() {
        writer.create_entry(entry).unwrap();
        writer.write_record(entry, &desc(&format!("pkg{index}"), index)).unwrap();
        writer.write_record(entry, &files(index)).unwrap();
        writer.write_raw(entry, "mtree", mtree).unwrap();
    }
}

/// The staged path. `replace_entry` runs, then one `EntryWrite` per entry.
fn staged(writer: &LocalDbWriter<'_>, mtree: &[u8]) {
    for (index, entry) in entries().iter().enumerate() {
        writer.replace_entry(None, entry).unwrap();
        let mut write = writer.entry_write(entry);
        write.record(&desc(&format!("pkg{index}"), index)).unwrap();
        write.record(&files(index)).unwrap();
        write.raw("mtree", mtree).unwrap();
        write.commit().unwrap();
    }
}

fn best(root: &Path, mtree: &[u8], body: fn(&LocalDbWriter<'_>, &[u8])) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..RUNS {
        let lock = fresh(root);
        let writer = LocalDbWriter::new(root, &lock, Limits::default()).unwrap();
        let start = Instant::now();
        body(&writer, mtree);
        let elapsed = start.elapsed();
        if elapsed < best {
            best = elapsed;
        }
    }
    best
}

#[test]
#[ignore = "needs a real (non-tmpfs) filesystem; set PIKO_WRITE_BENCH_DIR"]
fn what_a_transactions_database_writes_cost() {
    let Some(root) = bench_root() else {
        println!("skipping: set PIKO_WRITE_BENCH_DIR to a directory on a real filesystem");
        return;
    };
    if cfg!(debug_assertions) {
        println!("skipping: run with --release");
        return;
    }

    let mtree = vec![0x1f_u8; 2048];
    let per_file_time = best(&root, &mtree, per_file);
    let staged_time = best(&root, &mtree, staged);
    let _ = std::fs::remove_dir_all(&root);

    println!("\n{PACKAGES} entries x (desc + files + mtree), under {}\n", root.display());
    println!("  per-file fsync + per-file dir fsync   {:>7.1} ms", ms(per_file_time));
    println!(
        "  staged EntryWrite + replace_entry     {:>7.1} ms   ({:.2}x)",
        ms(staged_time),
        per_file_time.as_secs_f64() / staged_time.as_secs_f64(),
    );

    assert!(
        staged_time <= per_file_time,
        "staging must not be slower than writing one file at a time",
    );
}
