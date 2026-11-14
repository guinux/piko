//! `piko merge`: resolving the `.pacnew` and `.pacsave` files transactions leave behind.
//!
//! This is `pacdiff`'s counterpart. `piko_txn::merge` finds the pending files, compares each
//! pair, picks the three-way ancestor and carries out an answer. This module asks the question,
//! writes the temporary files a merge program needs, and starts the programs.
//!
//! Every pending path it prints is escaped by `piko_db::printable_path`. A package chose the
//! name of the file its `%BACKUP%` entry names.
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

use piko_db::local::LocalDatabase;
use piko_txn::{
    merge::{
        self, Action, BaseContents, BaseLimits, DEFAULT_DIFFPROG, DEFAULT_MERGEPROG, Invocation,
        Outcome, Pending, ScanLimits, Verdict,
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
    /// The global `SigLevel` a cached build must satisfy to serve as a merge base, and the
    /// keyring it is checked against. `None` when the configuration cannot be read: every
    /// merge is then two-way.
    pub signing: Option<crate::context::SigningPolicy>,
}

/// The programs a run may start, already split into words.
#[derive(Clone, Debug)]
struct Programs {
    diffprog: Vec<OsString>,
    mergeprog: Vec<OsString>,
    threeway: bool,
    /// How a cached build's signature is checked before it serves as a base. `None` when the
    /// keyring could not be opened: every merge is then two-way.
    bases: Option<merge::BaseCheck>,
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
        crate::output::warn(problem);
    }
    report_dropped_diagnostics(scan.problems_dropped());
    if scan.pending_dropped() > 0 {
        eprintln!("Warning: {} more pending files were not listed", scan.pending_dropped());
    }

    let pending: Vec<&Pending> =
        scan.pending().iter().filter(|entry| covered(entry, root, &options.selection)).collect();
    // A typed path that names no pending file is a mistake to report. Without this line, the
    // run would end in silence and in success, which reads as "resolved".
    let unmatched = self::unmatched(scan.pending(), root, &options.selection);
    for raw in &unmatched {
        eprintln!("Error: {} names no pending file", piko_db::printable(raw));
    }

    if options.output {
        for entry in &pending {
            emit!(out, "{}", piko_db::printable_path(&root.join(&entry.pacfile)));
        }
        return if unmatched.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE };
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

    let code = self::resolve_all(&root_dir, root, cache_dirs, &pending, &programs, out);
    if unmatched.is_empty() { code } else { ExitCode::FAILURE }
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
            piko_db::printable_path(&root.join(self::strip(path, ".pacnew"))),
            piko_db::printable_path(&root.join(path))
        );
    }
    for path in &report.pacsaves {
        let _ = writeln!(
            out,
            "  {} saved as {}",
            piko_db::printable_path(&root.join(self::strip(path, ".pacsave"))),
            piko_db::printable_path(&root.join(path))
        );
    }
    let _ = writeln!(out, "Run 'piko merge' to resolve them.");
    let _ = out.flush();
}

/// Walks the pending files, asking about each one.
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
        if !entry.kind.is_mergeable() {
            // A historical copy with no current version to merge it against. `pacdiff`
            // collects these and warns once at the end; so does this.
            numbered.push(piko_db::printable_path(&root.join(&entry.pacfile)));
            continue;
        }

        let decided = match entry.verdict {
            Verdict::Unreadable => {
                // The scan already said why on stderr. No destructive action is offered for a
                // pair piko could not read.
                emit!(
                    out,
                    "{}: skipped, it could not be read",
                    piko_db::printable_path(&root.join(&entry.pacfile))
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
                piko_db::printable_path(&root.join(&entry.pacfile)),
                piko_db::printable_path(&root.join(&entry.target))
            );
            Decided::Done
        }
        Ok(_) => {
            let _ = writeln!(
                out,
                "{}: kept, it changed since the scan",
                piko_db::printable_path(&root.join(&entry.pacfile))
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
        piko_db::printable_path(&root.join(&entry.target)),
        piko_db::printable_path(&root.join(&entry.pacfile))
    );
    if !confirm(out, &prompt, false) {
        return Decided::Done;
    }
    self::carry_out(root_dir, root, entry, Action::Remove, out)
}

/// Asks what to do with one pair, and does it.
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
        piko_db::printable_path(&target),
        piko_db::printable_path(&pacfile),
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

    let scratch = programs
        .threeway
        .then(|| self::write_base(cache_dirs, entry, programs.bases.as_ref(), out))
        .flatten();
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
fn merge_one(
    root_dir: &RootDir,
    root: &Path,
    cache_dirs: &[PathBuf],
    entry: &Pending,
    programs: &Programs,
    out: &mut impl Write,
) -> Option<Decided> {
    let (scratch, base) = self::write_base(cache_dirs, entry, programs.bases.as_ref(), out)?;
    let target = root.join(&entry.target);
    let pacfile = root.join(&entry.pacfile);
    let merged = scratch.path().join("merged");

    // The installed file, the ancestor, then the pending one. `piko_txn::merge::program` owns
    // that order; reversing the first and the last keeps the wrong side.
    let invocation = merge::three_way_merge(&programs.mergeprog, &target, &base, &pacfile)?;
    let destination = match self::create_private(&merged) {
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
    let contents = match self::read_private(&merged, piko_txn::hash::MAX_BACKUP_BYTES) {
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
    bases: Option<&merge::BaseCheck>,
    out: &mut impl Write,
) -> Option<(tempfile::TempDir, PathBuf)> {
    let Some(check) = bases else {
        let _ = writeln!(
            out,
            "No signature policy can check a cached build, so there is no base to merge against."
        );
        return None;
    };
    let lookup = match merge::base_contents(cache_dirs, entry, &BaseLimits::default(), check) {
        Ok(lookup) => lookup,
        Err(error) => {
            report(&error);
            return None;
        }
    };
    for refused in &lookup.refused {
        let _ = writeln!(
            out,
            "Not using {} as a base: {}",
            piko_db::printable_path(&refused.path),
            piko_db::printable(&refused.reason)
        );
    }
    let contents = match lookup.contents {
        BaseContents::Found { contents, .. } => contents,
        BaseContents::NoBase => {
            let _ = writeln!(
                out,
                "No signed cached build of {} older than {} was found, so there is no base to \
                 merge against.",
                entry.package, entry.installed_version
            );
            return None;
        }
        BaseContents::NotShipped { base } => {
            let _ = writeln!(
                out,
                "{} does not ship {}, so there is no base to merge against.",
                base.file_name,
                piko_db::printable_path(&entry.target)
            );
            return None;
        }
        BaseContents::Unreadable { error, .. } => {
            report(&error);
            return None;
        }
        // An answer this frontend does not know yet: no base it can use.
        _ => {
            let _ = writeln!(out, "There is no base to merge against.");
            return None;
        }
    };

    let scratch = match self::scratch_dir() {
        Ok(scratch) => scratch,
        Err(error) => {
            eprintln!("Error: a scratch directory cannot be used: {error}");
            return None;
        }
    };
    let base = scratch.path().join("base");
    if let Err(error) = self::create_private(&base).and_then(|mut file| file.write_all(&contents)) {
        eprintln!("Error: {} cannot be written: {error}", base.display());
        return None;
    }
    Some((scratch, base))
}

/// Creates the private directory that holds a merge's base and result, under `$TMPDIR`.
///
/// piko writes the base there, the merge program writes the result there, and piko reads the
/// result back from there into a file root owns. So no other user may be able to change the
/// directory, nor any directory above it. `mkdtemp` makes the directory `0700`, and
/// `fs_util::ensure_trusted_directory` tests the whole path. A sticky ancestor such as `/tmp`
/// passes. A `$TMPDIR` that others can write and that is not sticky fails: its writers could
/// rename the directory away and put their own in its place, between the review and the keep.
fn scratch_dir() -> Result<tempfile::TempDir, String> {
    self::scratch_dir_in(&std::env::temp_dir())
}

/// [`scratch_dir`], under `parent` rather than `$TMPDIR`.
fn scratch_dir_in(parent: &Path) -> Result<tempfile::TempDir, String> {
    let scratch = tempfile::Builder::new()
        .prefix("piko-merge-")
        .tempdir_in(parent)
        .map_err(|error| error.to_string())?;
    piko_db::fs_util::ensure_trusted_directory(scratch.path())
        .map_err(|error| crate::output::escaped(&error))?;
    Ok(scratch)
}

/// Creates `path` for writing, `0600`, and fails if anything already has that name.
///
/// `O_EXCL` also refuses a symbolic link at `path`, rather than following it.
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::File::options().write(true).create_new(true).mode(0o600).open(path)
}

/// Reads the regular file at `path`, refusing a symbolic link, a FIFO or a device, and anything
/// larger than `max` bytes.
///
/// The merge program wrote this file. It is read back by name, not through the descriptor the
/// program wrote into, because the review step may have edited it in an editor that saves by
/// renaming.
fn read_private(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Read as _;

    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = std::fs::File::from(rustix::fs::open(path, flags, Mode::empty())?);
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut contents = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut contents)?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > max {
        return Err(std::io::Error::other(format!("larger than {max} bytes")));
    }
    Ok(contents)
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
        Outcome::Removed { pacfile } => {
            format!("Removed {}.", piko_db::printable_path(&root.join(pacfile)))
        }
        Outcome::Overwritten { target, .. } => {
            format!("Overwrote {}.", piko_db::printable_path(&root.join(target)))
        }
        Outcome::Merged { target, .. } => {
            format!("Wrote the merged file to {}.", piko_db::printable_path(&root.join(target)))
        }
        _ => "Done.".to_owned(),
    }
}

/// Whether the pair holds the same bytes right now.
///
/// Asked after a difference program ran, because the user may have edited them into agreement
/// inside it.
///
/// A pair that cannot be compared counts as different, so nothing is deleted on its account.
fn now_identical(root_dir: &RootDir, entry: &Pending) -> bool {
    merge::is_identical(root_dir, entry, piko_txn::hash::MAX_BACKUP_BYTES).unwrap_or(false)
}

/// The programs to start, from the command line, then the environment, then the defaults.
///
/// Read from those two places only. A value that came out of a file the package manager itself
/// writes would let a package choose what runs.
fn programs(options: &Options) -> Result<Programs, String> {
    let diffprog = self::configured(options.diffprog.as_deref(), "DIFFPROG", DEFAULT_DIFFPROG)?;
    let mergeprog = self::configured(options.mergeprog.as_deref(), "MERGEPROG", DEFAULT_MERGEPROG)?;
    // A base is optional, so a keyring that cannot be opened costs the three-way view, and
    // nothing else.
    let bases = options.signing.as_ref().and_then(|signing| {
        match merge::BaseCheck::new(signing.sig_level, &signing.gpg_dir) {
            Ok(check) => Some(check),
            Err(error) => {
                crate::output::warn(format_args!(
                    "{error}; no cached build can serve as a merge base"
                ));
                None
            }
        }
    });
    Ok(Programs { diffprog, mergeprog, threeway: options.threeway, bases })
}

/// One program value, split into words.
fn configured(flag: Option<&str>, variable: &str, default: &str) -> Result<Vec<OsString>, String> {
    let from_environment = std::env::var(variable).ok();
    let value = flag.or(from_environment.as_deref()).unwrap_or(default);
    merge::parse_program(value).map_err(|error| format!("{variable} cannot be read: {error}"))
}

/// Whether `entry` is in the run's selection.
fn covered(entry: &Pending, root: &Path, selection: &Selection) -> bool {
    match selection {
        Selection::All => true,
        Selection::Typed(typed) => typed.iter().any(|raw| self::names(raw, root, entry)),
    }
}

/// Whether the typed path `raw` names `entry`, by its installed file or its pending one.
///
/// Three spellings name one path: the host path under `root`, which `--output` prints, the
/// absolute path inside the root, and the path relative to the root.
fn names(raw: &str, root: &Path, entry: &Pending) -> bool {
    let typed = Path::new(raw.trim_end_matches('/'));
    let inside = typed.strip_prefix("/").unwrap_or(typed);
    [typed.strip_prefix(root).ok(), Some(inside)]
        .into_iter()
        .flatten()
        .any(|wanted| wanted == entry.pacfile || wanted == entry.target)
}

/// The typed paths of `selection` that name no entry of `pending`.
fn unmatched<'a>(pending: &[Pending], root: &Path, selection: &'a Selection) -> Vec<&'a str> {
    match selection {
        Selection::All => Vec::new(),
        Selection::Typed(typed) => typed
            .iter()
            .filter(|raw| !pending.iter().any(|entry| self::names(raw, root, entry)))
            .map(String::as_str)
            .collect(),
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A parent others can write is refused unless it is sticky, as `/tmp` is.
    #[test]
    fn a_scratch_directory_needs_a_parent_no_other_user_can_swap() {
        let parent = tempfile::tempdir().unwrap();
        set_mode(parent.path(), 0o777);
        let error = scratch_dir_in(parent.path()).unwrap_err();
        assert!(error.contains("writable by its group or others"), "{error}");

        set_mode(parent.path(), 0o1777);
        assert!(scratch_dir_in(parent.path()).is_ok());
        set_mode(parent.path(), 0o700);
    }

    /// A name that already exists, a symbolic link included, is never written through.
    #[test]
    fn a_private_file_is_never_created_through_an_existing_name() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"kept").unwrap();
        let link = dir.path().join("merged");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        assert!(create_private(&link).is_err());
        assert!(create_private(&victim).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"kept");

        let fresh = dir.path().join("base");
        create_private(&fresh).unwrap();
        assert_eq!(std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// The merged result is read only from a regular file, and only up to its bound.
    #[test]
    fn a_merged_result_is_read_back_bounded_and_without_following_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let merged = dir.path().join("merged");
        std::fs::write(&merged, b"12345").unwrap();
        assert_eq!(read_private(&merged, 5).unwrap(), b"12345");
        assert!(read_private(&merged, 4).is_err());

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&merged, &link).unwrap();
        assert!(read_private(&link, 5).is_err());
        assert!(read_private(dir.path(), 5).is_err());
    }

    /// A pending path is spelled by a package, so what a resolution reports is escaped.
    #[test]
    fn an_outcome_escapes_what_could_drive_a_terminal() {
        let pacfile = PathBuf::from("etc/\u{1b}]52;c;cHduZWQ=\u{7}.pacnew");
        let target = PathBuf::from("etc/\u{1b}[2J");
        let root = Path::new("/");
        assert_eq!(
            describe(root, &Outcome::Removed { pacfile: pacfile.clone() }),
            "Removed /etc/\\u{1b}]52;c;cHduZWQ=\\u{7}.pacnew."
        );
        assert_eq!(
            describe(
                root,
                &Outcome::Overwritten { target: target.clone(), pacfile: pacfile.clone() }
            ),
            "Overwrote /etc/\\u{1b}[2J."
        );
        assert_eq!(
            describe(root, &Outcome::Merged { target, pacfile }),
            "Wrote the merged file to /etc/\\u{1b}[2J."
        );
    }
}
