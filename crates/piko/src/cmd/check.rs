//! `piko check`: directory-name/`desc` consistency plus the `pacman -Qkk`-equivalent
//! file-vs-`ALPM-MTREE` comparison ([`piko_db::local::LocalPackage::verify_files`]).
//!
//! # Several packages at a time
//!
//! A check hashes every file the package owns. So the command is dominated by reads the kernel
//! is servicing, not by anything this process computes. Measured over 1258 packages on this
//! machine: 67 s of wall clock. User time is 13 s and system time 19 s. Half the run is a
//! thread waiting for a disk.
//!
//! The packages are therefore checked several at a time. `LocalDatabase` and `LocalPackage` are
//! `Send + Sync` with lock-free reads. That makes this a scheduling change, not a design one.
//! No lock is introduced, and no shared state is written.
//!
//! **Nothing is printed from a worker.** A worker renders its package's verdict into buffers.
//! The main thread writes them out afterwards, in database order. This is the rule the download
//! pool already follows, and it keeps the output identical to the serial loop's. Two workers
//! cannot interleave their lines. The order does not depend on which disk read finished
//! first.

use std::{
    path::Path,
    process::ExitCode,
    sync::atomic::{AtomicUsize, Ordering},
};

use piko_db::{local::LocalDatabase, local::LocalPackage, resolve::PatternList};

use crate::{
    output::{emit, write_report},
    progress::{Row, StepList},
};

/// Checks each named package, printing every problem found and a final summary line.
///
/// A name that is not currently installed is reported to stderr. That is the same
/// continue-past-a-miss convention `piko files`/`piko info` use for more than one name. Such a
/// name was never checked, so it counts in neither of the summary's totals: "packages checked"
/// and "with problems". It still fails the command.
pub fn check_selected(
    db: &LocalDatabase,
    names: &[String],
    root: &Path,
    no_extract: &PatternList,
    out: &mut impl std::io::Write,
) -> ExitCode {
    // Resolved before any checking starts. A mistyped name is then reported at once, rather
    // than after a run that was never going to cover it.
    let mut packages = Vec::with_capacity(names.len());
    let mut missing = false;
    for name in names {
        match db.get_str(name) {
            Some(package) => packages.push(package),
            None => {
                crate::i18n::print_error!("cli-not-installed", name = name.to_string());
                missing = true;
            }
        }
    }

    let steplist = StepList::new();
    let row = steplist.counted(&crate::i18n::tr!("check-row"), packages.len());
    let checked = run_checks(&packages, root, no_extract, &row);
    row.finish_and_clear();

    let with_problems = print_checked(&steplist, &checked, out);
    let outcome = summary(packages.len(), with_problems, out);
    if missing { ExitCode::FAILURE } else { outcome }
}

/// Checks every installed package, printing a final summary line.
pub fn check_all(
    db: &LocalDatabase,
    root: &Path,
    no_extract: &PatternList,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let packages: Vec<&LocalPackage> = db.into_iter().collect();

    let steplist = StepList::new();
    let row = steplist.counted(&crate::i18n::tr!("check-row"), packages.len());
    let checked = run_checks(&packages, root, no_extract, &row);
    row.finish_and_clear();

    let with_problems = print_checked(&steplist, &checked, out);
    summary(packages.len(), with_problems, out)
}

/// One package's verdict, rendered and waiting to be printed.
struct Checked {
    /// What [`check`] wrote for the user, destined for stdout.
    out: Vec<u8>,
    /// What it wrote as an error, destined for stderr.
    err: Vec<u8>,
    /// Whether anything was wrong with the package.
    failed: bool,
}

/// How many packages to check at a time.
///
/// The bound is the machine's parallelism. More threads than that would still gain on work
/// this I/O-bound. The gain is the kernel's read-ahead, not anything measurable here. And an
/// unbounded count would let a large database spawn a thread per package.
fn workers(packages: usize) -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get).min(packages).max(1)
}

/// Checks every entry of `packages`, several at a time, and returns one verdict each in input
/// order.
///
/// Workers take their next package from a shared cursor, not from a fixed slice each. A
/// package's cost is the size of its file list. That ranges from a handful of files to
/// `linux-firmware`'s thousands, so a fixed split leaves most threads idle.
///
/// A worker that panicked is re-raised rather than absorbed. Nothing here can panic, so one
/// that did would be a bug. Absorbing it would turn that bug into a run that quietly checked
/// fewer packages than it reported.
fn run_checks(
    packages: &[&LocalPackage],
    root: &Path,
    no_extract: &PatternList,
    row: &Row,
) -> Vec<Checked> {
    let cursor = AtomicUsize::new(0);
    let collected: Vec<Vec<(usize, Checked)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers(packages.len()))
            .map(|_| {
                let cursor = &cursor;
                scope.spawn(move || {
                    let mut mine = Vec::new();
                    loop {
                        // `fetch_add` hands each index to exactly one worker. Nothing else is
                        // shared mutably, so `Relaxed` is the whole synchronisation needed.
                        // The results travel back through `join`, which orders them.
                        let index = cursor.fetch_add(1, Ordering::Relaxed);
                        let Some(package) = packages.get(index) else { break };

                        let mut out = Vec::new();
                        let mut err = Vec::new();
                        let failed = check(package, root, no_extract, &mut out, &mut err)
                            == ExitCode::FAILURE;
                        mine.push((index, Checked { out, err, failed }));
                        row.inc(1);
                    }
                    mine
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle.join().unwrap_or_else(|payload| std::panic::resume_unwind(payload))
            })
            .collect()
    });

    let mut verdicts: Vec<Option<Checked>> = (0..packages.len()).map(|_| None).collect();
    for (index, checked) in collected.into_iter().flatten() {
        if let Some(slot) = verdicts.get_mut(index) {
            *slot = Some(checked);
        }
    }
    verdicts.into_iter().flatten().collect()
}

/// Prints every verdict in order, and answers how many packages had a problem.
///
/// A verdict goes through `steplist.suspend`, but only when there is something to print.
/// `suspend` hides and redraws the row on every call, and most packages have nothing to say. A
/// call per package makes the spinner flicker on every one of a thousand-plus clean ones.
fn print_checked(steplist: &StepList, checked: &[Checked], out: &mut impl std::io::Write) -> usize {
    let mut with_problems = 0_usize;
    for package in checked {
        if package.failed {
            with_problems = with_problems.saturating_add(1);
        }
        if package.out.is_empty() && package.err.is_empty() {
            continue;
        }
        // Write failures are ignored here, as `CommitDriver::print_line` does. The final
        // summary's `emit!` call, right after this loop, is what catches a dead stdout.
        steplist.suspend(|| {
            let _ = out.write_all(&package.out);
            let _ = std::io::Write::write_all(&mut std::io::stderr().lock(), &package.err);
        });
    }
    with_problems
}

fn summary(total: usize, with_problems: usize, out: &mut impl std::io::Write) -> ExitCode {
    if with_problems == 0 {
        emit!(out, "{}", crate::i18n::tr!("check-clean", total = total));
        ExitCode::SUCCESS
    } else {
        emit!(
            out,
            "{}",
            crate::i18n::tr!("check-problems", total = total, problems = with_problems)
        );
        ExitCode::FAILURE
    }
}

/// Checks one package, writing what the user should see to `out` and any error to `err`.
///
/// The two streams stay apart. `piko check > report` therefore still puts the errors on the
/// terminal.
fn check(
    package: &LocalPackage,
    root: &Path,
    no_extract: &PatternList,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> ExitCode {
    let mut failed = false;

    match package.check_consistency() {
        Ok(found) => {
            for item in found {
                emit!(out, "{}: {}", package.name(), crate::output::escaped(item));
                failed = true;
            }
        }
        Err(error) => {
            write_report(err, &*error);
            failed = true;
        }
    }

    // An unreadable `files` is left to `verify_files` below, which reads it too and reports it.
    if let Ok(files) = package.files() {
        for defect in files.defects() {
            emit!(out, "{}: {}", package.name(), crate::output::escaped(defect));
            failed = true;
        }
        if files.defects_dropped() > 0 {
            let line = crate::i18n::tr!(
                "check-defects-not-shown",
                package = package.name().to_string(),
                count = files.defects_dropped()
            );
            emit!(out, "{line}");
        }
    }

    match package.verify_files(root, no_extract) {
        Ok(None) => emit!(
            out,
            "{}",
            crate::i18n::tr!("check-no-mtree", package = package.name().to_string())
        ),
        Ok(Some(file_report)) => {
            for problem in file_report.problems.iter().filter(|problem| problem.is_error()) {
                emit!(
                    out,
                    "{}: {} ({})",
                    package.name(),
                    piko_db::printable_path(&problem.path),
                    crate::output::escaped(&problem.error)
                );
            }
            let altered = file_report.altered_files();
            if altered > 0 {
                let line = crate::i18n::tr!(
                    "check-altered",
                    package = package.name().to_string(),
                    total = file_report.total,
                    altered = altered
                );
                emit!(out, "{line}");
            }
            failed = failed || altered > 0;
        }
        Err(error) => {
            write_report(err, &*error);
            failed = true;
        }
    }

    if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    /// A `files` defect that does not refuse the file is named, and fails the check.
    #[test]
    fn a_files_defect_is_named() {
        let db = piko_db::fixture::DbFixture::new();
        db.package("foo-1.0.0-1")
            .desc(piko_db::fixture::MINIMAL_DESC_V1)
            .files("%FILES%\nusr/bin/foo\n\n")
            .build();
        let local = piko_db::local::LocalDatabase::open(db.path()).unwrap();
        let package = local.get_str("foo").unwrap();
        let root = tempfile::tempdir().unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());

        let code = check(package, root.path(), &PatternList::EMPTY, &mut out, &mut err);
        let out = String::from_utf8(out).unwrap();

        assert_eq!(code, ExitCode::FAILURE, "{out}");
        assert!(
            out.contains("foo: %FILES%: the parent directory of usr/bin/foo is not listed"),
            "{out}"
        );
    }
}
