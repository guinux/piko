//! `piko check`: directory-name/`desc` consistency plus the `pacman -Qkk`-equivalent
//! file-vs-`ALPM-MTREE` comparison ([`piko_db::LocalPackage::verify_files`]).

use std::{path::Path, process::ExitCode};

use piko_db::{LocalDatabase, LocalPackage};

use crate::{
    output::{emit, report},
    progress::StepList,
};

/// Checks each named package, printing every problem found and a final summary line. A name
/// that is not currently installed is reported to stderr, the same continue-past-a-miss
/// convention `piko files`/`piko info` use for more than one name — but it was never actually
/// checked, so it is not counted in the summary's "packages checked" or "with problems" totals.
/// It still fails the command.
pub fn check_selected(
    db: &LocalDatabase,
    names: &[String],
    root: &Path,
    no_extract: &[String],
    out: &mut impl std::io::Write,
) -> ExitCode {
    let steplist = StepList::new();
    let row = steplist.counted("Checking packages", names.len());
    let mut checked = 0_usize;
    let mut with_problems = 0_usize;
    let mut missing = false;

    for (index, name) in names.iter().enumerate() {
        row.set_message(format!("Checking {name}"));
        row.set_position(index as u64);

        match db.get_str(name) {
            Some(package) => {
                checked = checked.saturating_add(1);
                if check_and_print(&steplist, package, root, no_extract, out) {
                    with_problems = with_problems.saturating_add(1);
                }
            }
            None => {
                steplist.suspend(|| eprintln!("error: package {name} is not installed"));
                missing = true;
            }
        }
    }
    row.finish_and_clear();

    let outcome = summary(checked, with_problems, out);
    if missing { ExitCode::FAILURE } else { outcome }
}

/// Checks every installed package, printing a final summary line.
pub fn check_all(
    db: &LocalDatabase,
    root: &Path,
    no_extract: &[String],
    out: &mut impl std::io::Write,
) -> ExitCode {
    let steplist = StepList::new();
    let row = steplist.counted("Checking packages", db.len());
    let mut with_problems = 0_usize;

    for (index, package) in db.into_iter().enumerate() {
        row.set_message(format!("Checking {}", package.name()));
        row.set_position(index as u64);

        if check_and_print(&steplist, package, root, no_extract, out) {
            with_problems = with_problems.saturating_add(1);
        }
    }
    row.finish_and_clear();

    summary(db.len(), with_problems, out)
}

/// Runs [`check`] into a buffer, then flushes it to `out` through `steplist.suspend` — but only
/// when there is something to print. `suspend` hides and redraws the row on every call, and
/// most packages have nothing to say; suspending unconditionally made the spinner flicker on
/// every one of a thousand-plus clean packages.
fn check_and_print(
    steplist: &StepList,
    package: &LocalPackage,
    root: &Path,
    no_extract: &[String],
    out: &mut impl std::io::Write,
) -> bool {
    let mut buf = Vec::new();
    let failed = check(package, root, no_extract, &mut buf) == ExitCode::FAILURE;
    if !buf.is_empty() {
        // Write failures are ignored here, as `CommitDriver::print_line` does: the final
        // summary's `emit!` call, right after the loop, is what catches a dead stdout.
        steplist.suspend(|| {
            let _ = out.write_all(&buf);
        });
    }
    failed
}

fn summary(total: usize, with_problems: usize, out: &mut impl std::io::Write) -> ExitCode {
    if with_problems == 0 {
        emit!(out, "{total} packages checked, no problems found");
        ExitCode::SUCCESS
    } else {
        emit!(out, "{total} packages checked, {with_problems} package(s) with problems");
        ExitCode::FAILURE
    }
}

fn check(
    package: &LocalPackage,
    root: &Path,
    no_extract: &[String],
    out: &mut impl std::io::Write,
) -> ExitCode {
    let mut failed = false;

    match package.check_consistency() {
        Ok(found) => {
            for item in found {
                emit!(out, "{}: {item}", package.name());
                failed = true;
            }
        }
        Err(error) => {
            report(&*error);
            failed = true;
        }
    }

    match package.verify_files(root, no_extract) {
        Ok(None) => emit!(out, "{}: no mtree file", package.name()),
        Ok(Some(file_report)) => {
            for problem in file_report.problems.iter().filter(|problem| problem.is_error()) {
                emit!(out, "{}: {} ({})", package.name(), problem.path.display(), problem.error);
            }
            let altered = file_report.altered_files();
            if altered > 0 {
                emit!(
                    out,
                    "{}: {} total files, {altered} altered files",
                    package.name(),
                    file_report.total
                );
            }
            failed = failed || altered > 0;
        }
        Err(error) => {
            report(&*error);
            failed = true;
        }
    }

    if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
