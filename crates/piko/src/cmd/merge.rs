//! `piko merge`: resolving the `.pacnew` and `.pacsave` files transactions leave behind.
//!
//! This is `pacdiff`'s counterpart. `piko_txn::merge` finds the pending files, compares each
//! pair, picks the three-way ancestor and carries out an answer. This module asks the question,
//! writes the temporary files a merge program needs, and starts the programs.
//!
//! # What a finished transaction does
//!
//! [`report_pending`] names the files the transaction left, and stops there. It asks nothing.
//! Resolving a configuration file is a separate act, on the user's own timing, through this
//! command.

use std::{
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use piko_db::LocalDatabase;
use piko_txn::{
    merge::{
        self, Action, BaseLimits, DEFAULT_DIFFPROG, DEFAULT_MERGEPROG, Invocation, Outcome,
        Pending, PendingKind, ScanLimits, Verdict,
    },
    rootfs::RootDir,
};

use crate::output::{choose, confirm, emit, report, report_dropped_diagnostics};

/// Which pending files a run covers.
#[derive(Clone, Debug)]
pub enum Selection {
    /// Everything the scan found.
    All,
    /// Only what the user named, matched loosely.
    ///
    /// A typed path may be absolute or relative, and may name the installed file or the
    /// pending one. All four spellings name one pair.
    Typed(Vec<String>),
}

/// What `piko merge` was asked to do.
#[derive(Clone, Debug)]
pub struct Options {
    /// Print the pending files and change nothing.
    pub output: bool,
    /// The configured `--diffprog`, if the command line carried one.
    pub diffprog: Option<String>,
    /// The configured `--mergeprog`, if the command line carried one.
    pub mergeprog: Option<String>,
    /// Show a three-way difference rather than a two-way one, when an ancestor is available.
    pub threeway: bool,
    /// Which pending files to cover.
    pub selection: Selection,
}

/// The programs a run may start, already split into words.
#[derive(Clone, Debug)]
struct Programs {
    diffprog: Vec<OsString>,
    mergeprog: Vec<OsString>,
    threeway: bool,
}

/// `piko merge`: resolve the pending files one at a time.
pub fn merge(
    root: &Path,
    db: &LocalDatabase,
    cache_dirs: &[PathBuf],
    options: Options,
    out: &mut impl Write,
) -> ExitCode {
    let root_dir = match RootDir::open(root) {
        Ok(root_dir) => root_dir,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    let scan = merge::scan(&root_dir, db, &ScanLimits::default());
    for problem in scan.problems() {
        eprintln!("Warning: {problem}");
    }
    report_dropped_diagnostics(scan.problems_dropped());
    if scan.pending_dropped() > 0 {
        eprintln!("Warning: {} more pending files were not listed", scan.pending_dropped());
    }

    let pending: Vec<&Pending> =
        scan.pending().iter().filter(|entry| covered(entry, &options.selection)).collect();

    if options.output {
        for entry in &pending {
            emit!(out, "{}", root.join(&entry.pacfile).display());
        }
        return ExitCode::SUCCESS;
    }

    // Both programs are validated once, before anything is touched. An unbalanced quote is a
    // mistake in the command line, and finding it after the first file is resolved would be
    // finding it too late.
    let programs = match self::programs(&options) {
        Ok(programs) => programs,
        Err(failure) => {
            eprintln!("Error: {failure}");
            return ExitCode::FAILURE;
        }
    };

    self::resolve_all(&root_dir, root, cache_dirs, &pending, &programs, out)
}

/// Names the configuration files a finished transaction left behind.
///
/// This reports; it asks nothing. Resolving a pair is an irreversible act with no safe
/// default, and a transaction that has just finished is the wrong moment to press for one: the
/// user came to install a package. `piko merge` is the command that asks, whenever they choose
/// to run it.
///
/// Only this transaction's files are named. A `.pacnew` from three months ago is not something
/// this transaction did, and folding it in would turn a visible consequence into a list of
/// chores.
///
/// Printed whatever the flags say, `--noconfirm` included, because it is a report rather than a
/// question. It never changes the transaction's exit code.
pub fn report_pending(root: &Path, report: &piko_txn::Report, out: &mut impl Write) {
    if report.pacnews.is_empty() && report.pacsaves.is_empty() {
        return;
    }

    let _ = writeln!(out, "\nConfiguration files need attention:");
    for path in &report.pacnews {
        let _ = writeln!(
            out,
            "  {} installed as {}",
            root.join(self::strip(path, ".pacnew")).display(),
            root.join(path).display()
        );
    }
    for path in &report.pacsaves {
        let _ = writeln!(
            out,
            "  {} saved as {}",
            root.join(self::strip(path, ".pacsave")).display(),
            root.join(path).display()
        );
    }
    let _ = writeln!(out, "Run 'piko merge' to resolve them.");
    let _ = out.flush();
}

/// Walks the pending files, asking about each one.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct input; bundling them would only hide the count"
)]
fn resolve_all(
    root_dir: &RootDir,
    root: &Path,
    cache_dirs: &[PathBuf],
    pending: &[&Pending],
    programs: &Programs,
    out: &mut impl Write,
) -> ExitCode {
    let mut numbered: Vec<String> = Vec::new();
    let mut failed = false;

    for entry in pending {
        if let PendingKind::NumberedPacsave(_) = entry.kind {
            // A historical copy with no current version to merge it against. `pacdiff`
            // collects these and warns once at the end; so does this.
            numbered.push(root.join(&entry.pacfile).display().to_string());
            continue;
        }

        let decided = match entry.verdict {
            Verdict::Unreadable => {
                // The scan already said why on stderr. No destructive action is offered for a
                // pair piko could not read.
                emit!(
                    out,
                    "{}: skipped, it could not be read",
                    root.join(&entry.pacfile).display()
                );
                continue;
            }
            Verdict::Identical => self::drop_identical(root_dir, root, entry, out),
            Verdict::TargetMissing => self::offer_removal(root_dir, root, entry, out),
            Verdict::Differs => self::ask(root_dir, root, cache_dirs, entry, programs, out),
        };
        match decided {
            Decided::Done => {}
            Decided::Failed => failed = true,
            Decided::Quit => break,
        }
    }

    for path in &numbered {
        eprintln!("Warning: ignoring {path}, it has no current version to merge against");
    }

    if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

/// What resolving one pending file settled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Decided {
    /// Move on to the next file.
    Done,
    /// Move on, but the run ends in failure.
    Failed,
    /// Stop asking.
    Quit,
}

/// Deletes a pending file that carries nothing, without asking.
///
/// This is `pacdiff`'s `cmp -s` branch. The removal re-reads both files through one descriptor
/// rather than trusting the scan, because it is the one act taken without an answer.
fn drop_identical(
    root_dir: &RootDir,
    root: &Path,
    entry: &Pending,
    out: &mut impl Write,
) -> Decided {
    match merge::remove_if_identical(root_dir, entry, piko_txn::hash::MAX_BACKUP_BYTES) {
        Ok(Outcome::Removed { .. }) => {
            let _ = writeln!(
                out,
                "{}: removed, it holds the same bytes as {}",
                root.join(&entry.pacfile).display(),
                root.join(&entry.target).display()
            );
            Decided::Done
        }
        Ok(_) => {
            let _ = writeln!(
                out,
                "{}: kept, it changed since the scan",
                root.join(&entry.pacfile).display()
            );
            Decided::Done
        }
        Err(error) => {
            report(&error);
            Decided::Failed
        }
    }
}

/// Offers to delete a pending file whose target is gone.
///
/// The default is to keep it. `pacdiff` reaches for `rm -i` here, whose default is also no.
fn offer_removal(
    root_dir: &RootDir,
    root: &Path,
    entry: &Pending,
    out: &mut impl Write,
) -> Decided {
    let prompt = format!(
        "{} does not exist. Remove {}? [y/N] ",
        root.join(&entry.target).display(),
        root.join(&entry.pacfile).display()
    );
    if !confirm(out, &prompt, false) {
        return Decided::Done;
    }
    self::carry_out(root_dir, root, entry, Action::Remove, out)
}

/// Asks what to do with one pair, and does it.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct input; bundling them would only hide the count"
)]
fn ask(
    root_dir: &RootDir,
    root: &Path,
    cache_dirs: &[PathBuf],
    entry: &Pending,
    programs: &Programs,
    out: &mut impl Write,
) -> Decided {
    let label = entry.kind.label();
    let target = root.join(&entry.target);
    let pacfile = root.join(&entry.pacfile);
    let _ = writeln!(
        out,
        "\n{} and {} differ ({}).",
        target.display(),
        pacfile.display(),
        entry.package
    );

    let letters = ['v', 'm', 's', 'r', 'o', 'q'];
    let prompt =
        format!("(V)iew, (M)erge, (S)kip, (R)emove {label}, (O)verwrite with {label}, (Q)uit: ");
    loop {
        // No `SIGINT` handler is installed here. `piko merge` downloads nothing, so there is
        // nothing to cancel gracefully, and Ctrl+C keeps the default disposition: it kills
        // this process at the prompt, and reaches a merge program through the foreground
        // process group once one is running.
        match choose(out, &prompt, &letters, 5) {
            // (V)iew. The pair is compared again afterwards. The user may have edited the two
            // into agreement inside the difference program, which leaves nothing to ask about.
            0 => {
                if !self::view(root, cache_dirs, entry, programs, out) {
                    return Decided::Failed;
                }
                if self::now_identical(root_dir, entry) {
                    return self::drop_identical(root_dir, root, entry, out);
                }
            }
            // (M)erge.
            1 => match self::merge_one(root_dir, root, cache_dirs, entry, programs, out) {
                Some(decided) => return decided,
                None => continue,
            },
            2 => return Decided::Done,
            3 => return self::carry_out(root_dir, root, entry, Action::Remove, out),
            4 => return self::carry_out(root_dir, root, entry, Action::Overwrite, out),
            _ => return Decided::Quit,
        }
    }
}

/// Shows the difference between a pair, three ways when an ancestor is available.
///
/// Returns whether the program started. Its exit status is ignored, as `pacdiff` ignores it: a
/// difference program reports whether the files differ, which is already known.
fn view(
    root: &Path,
    cache_dirs: &[PathBuf],
    entry: &Pending,
    programs: &Programs,
    out: &mut impl Write,
) -> bool {
    let target = root.join(&entry.target);
    let pacfile = root.join(&entry.pacfile);

    let scratch = programs.threeway.then(|| self::write_base(cache_dirs, entry, out)).flatten();
    let invocation = match scratch.as_ref() {
        Some((_dir, base)) => merge::three_way_diff(&programs.diffprog, &pacfile, base, &target),
        None => merge::two_way_diff(&programs.diffprog, &pacfile, &target),
    };
    let Some(invocation) = invocation else {
        return false;
    };
    self::run(&invocation, None, out).is_some()
}

/// Merges a pair three ways, shows the result, and keeps it if the user agrees.
///
/// `None` means the merge did not happen and the prompt should be asked again.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct input; bundling them would only hide the count"
)]
fn merge_one(
    root_dir: &RootDir,
    root: &Path,
    cache_dirs: &[PathBuf],
    entry: &Pending,
    programs: &Programs,
    out: &mut impl Write,
) -> Option<Decided> {
    let (scratch, base) = self::write_base(cache_dirs, entry, out)?;
    let target = root.join(&entry.target);
    let pacfile = root.join(&entry.pacfile);
    let merged = scratch.path().join("merged");

    // The installed file, the ancestor, then the pending one. `piko_txn::merge::program` owns
    // that order; reversing the first and the last keeps the wrong side.
    let invocation = merge::three_way_merge(&programs.mergeprog, &target, &base, &pacfile)?;
    let destination = match std::fs::File::create(&merged) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Error: {} cannot be written: {error}", merged.display());
            return Some(Decided::Failed);
        }
    };
    let status = self::run(&invocation, Some(destination), out)?;

    // A non-zero status means the merge program wrote conflict markers, and the file it wrote
    // is exactly the one to look at. Only a program that never started is a failure.
    if status.success() {
        let _ = writeln!(out, "Merged without conflicts.");
    } else {
        let _ = writeln!(out, "Merged with conflicts. Review them before keeping the result.");
    }

    let review = merge::review_diff(&programs.diffprog, &target, &merged)?;
    self::run(&review, None, out)?;

    if !confirm(out, "Keep the merged file? [y/N] ", false) {
        return None;
    }
    let contents = match std::fs::read(&merged) {
        Ok(contents) => contents,
        Err(error) => {
            eprintln!("Error: {} cannot be read back: {error}", merged.display());
            return Some(Decided::Failed);
        }
    };
    Some(self::carry_out(root_dir, root, entry, Action::UseMerged { contents: &contents }, out))
}

/// Extracts the three-way ancestor into a private scratch directory.
///
/// `None` when no older build is cached, or when the file cannot be read out of it. Both are
/// ordinary: a cache gets cleaned, and a package can stop shipping a file.
fn write_base(
    cache_dirs: &[PathBuf],
    entry: &Pending,
    out: &mut impl Write,
) -> Option<(tempfile::TempDir, PathBuf)> {
    let limits = BaseLimits::default();
    let candidate =
        match merge::find_base(cache_dirs, &entry.package, &entry.installed_version, &limits) {
            Ok(Some(candidate)) => candidate,
            Ok(None) => {
                let _ = writeln!(
                    out,
                    "No cached build of {} older than {} was found, so there is no base to \
                     merge against.",
                    entry.package, entry.installed_version
                );
                return None;
            }
            Err(error) => {
                report(&error);
                return None;
            }
        };

    let contents = match merge::extract_member(&candidate.path, &entry.target, &limits) {
        Ok(Some(contents)) => contents,
        Ok(None) => {
            let _ = writeln!(
                out,
                "{} does not ship {}, so there is no base to merge against.",
                candidate.file_name,
                entry.target.display()
            );
            return None;
        }
        Err(error) => {
            report(&error);
            return None;
        }
    };

    let scratch = match tempfile::Builder::new().prefix("piko-merge-").tempdir() {
        Ok(scratch) => scratch,
        Err(error) => {
            eprintln!("Error: a scratch directory cannot be created: {error}");
            return None;
        }
    };
    let base = scratch.path().join("base");
    if let Err(error) = std::fs::write(&base, &contents) {
        eprintln!("Error: {} cannot be written: {error}", base.display());
        return None;
    }
    Some((scratch, base))
}

/// Starts one program, with this terminal.
///
/// The descriptors are inherited on purpose. A full-screen editor needs the terminal, which is
/// also why `piko_txn::exec::Runner` is wrong here: it enters the root by `chroot` and captures
/// output into a pipe. A merge program is a program on the host, configured by the user, given
/// paths on the host.
///
/// `None` means the program did not start, which is the one real failure.
fn run(
    invocation: &Invocation,
    stdout: Option<std::fs::File>,
    out: &mut impl Write,
) -> Option<std::process::ExitStatus> {
    // The prompt above ends without a newline, because it waits on the same line. A program
    // that prints rather than clearing the screen would start on that line. So the child gets
    // a line of its own.
    //
    // The flush matters for a second reason: whatever piko has buffered must reach the
    // terminal before the child takes it over.
    let _ = writeln!(out);
    let _ = out.flush();

    let mut command = Command::new(&invocation.program);
    command.args(&invocation.arguments);
    if let Some(file) = stdout {
        command.stdout(Stdio::from(file));
        command.stderr(Stdio::inherit());
    }

    match command.status() {
        Ok(status) => Some(status),
        Err(error) => {
            eprintln!("Error: {} cannot be started: {error}", invocation.program.to_string_lossy());
            None
        }
    }
}

/// Applies `action` and reports what it did.
fn carry_out(
    root_dir: &RootDir,
    root: &Path,
    entry: &Pending,
    action: Action<'_>,
    out: &mut impl Write,
) -> Decided {
    match merge::apply(root_dir, entry, action) {
        Ok(outcome) => {
            let _ = writeln!(out, "{}", self::describe(root, &outcome));
            Decided::Done
        }
        Err(error) => {
            report(&error);
            Decided::Failed
        }
    }
}

/// What one outcome reads as.
///
/// Every path is joined onto the root, so one run never mixes the two spellings. An outcome
/// carries the root-relative form, which is the one the library acts on.
fn describe(root: &Path, outcome: &Outcome) -> String {
    match outcome {
        Outcome::Skipped => "Left both files in place.".to_owned(),
        Outcome::Removed { pacfile } => format!("Removed {}.", root.join(pacfile).display()),
        Outcome::Overwritten { target, .. } => {
            format!("Overwrote {}.", root.join(target).display())
        }
        Outcome::Merged { target, .. } => {
            format!("Wrote the merged file to {}.", root.join(target).display())
        }
        _ => "Done.".to_owned(),
    }
}

/// Whether the pair holds the same bytes right now.
///
/// Asked after a difference program ran, because the user may have edited them into agreement
/// inside it.
fn now_identical(root_dir: &RootDir, entry: &Pending) -> bool {
    let Ok(resolved) = root_dir.resolve_parent(&entry.target) else {
        return false;
    };
    let mut pacname = resolved.name().to_os_string();
    pacname.push(entry.kind.suffix());
    piko_txn::hash::same_contents_at(
        resolved.dir(),
        resolved.name(),
        &pacname,
        piko_txn::hash::MAX_BACKUP_BYTES,
    )
    .ok()
    .flatten()
    .unwrap_or(false)
}

/// The programs to start, from the command line, then the environment, then the defaults.
///
/// Read from those two places only. A value that came out of a file the package manager itself
/// writes would let a package choose what runs.
fn programs(options: &Options) -> Result<Programs, String> {
    let diffprog = self::configured(options.diffprog.as_deref(), "DIFFPROG", DEFAULT_DIFFPROG)?;
    let mergeprog = self::configured(options.mergeprog.as_deref(), "MERGEPROG", DEFAULT_MERGEPROG)?;
    Ok(Programs { diffprog, mergeprog, threeway: options.threeway })
}

/// One program value, split into words.
fn configured(flag: Option<&str>, variable: &str, default: &str) -> Result<Vec<OsString>, String> {
    let from_environment = std::env::var(variable).ok();
    let value = flag.or(from_environment.as_deref()).unwrap_or(default);
    merge::parse_program(value).map_err(|error| format!("{variable} cannot be read: {error}"))
}

/// Whether `entry` is in the run's selection.
fn covered(entry: &Pending, selection: &Selection) -> bool {
    match selection {
        Selection::All => true,
        Selection::Typed(typed) => typed.iter().any(|raw| {
            let wanted = Path::new(raw.trim_end_matches('/'));
            let wanted = wanted.strip_prefix("/").unwrap_or(wanted);
            wanted == entry.pacfile || wanted == entry.target
        }),
    }
}

/// `path` without `suffix`, or `path` unchanged if it does not carry one.
///
/// A numbered `.pacsave` is matched at its last `.pacsave`, not at the end of the string.
fn strip(path: &Path, suffix: &str) -> PathBuf {
    let text = path.to_string_lossy();
    match text.rfind(suffix) {
        Some(index) => PathBuf::from(text.get(..index).unwrap_or_default()),
        None => path.to_path_buf(),
    }
}
