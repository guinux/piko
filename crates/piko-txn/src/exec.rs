//! Runs a command inside the installation root.
//!
//! Scriptlets and hooks need the same thing: start a program, make it see the transaction's
//! root as `/`, feed it input on stdin, and collect its output. libalpm does this in
//! `_alpm_run_chroot` (`util.c:610`) with `fork` + `chroot` + `execv` and a `poll` loop over two
//! socketpairs. This module does the same, without `unsafe`.
//!
//! # Why piko re-executes itself
//!
//! Entering a chroot must happen **between `fork` and `exec`**, in the child process. Three ways
//! reach that window. All three are closed here:
//!
//! - `Command::pre_exec` is `unsafe`. The workspace forbids `unsafe_code`.
//! - `libc::chroot` is `unsafe` for the same reason.
//! - `std::os::unix::process::CommandExt::chroot` needs no `unsafe` and would fit exactly. It
//!   is still nightly-only (`process_chroot`, rust#141298), and the MSRV here is a stable 1.90.
//!
//! So piko starts *itself* instead. [`HELPER_ARG`] is a hidden subcommand. The helper process
//! calls `chroot` and `umask` — safe functions, in its own process, with no `fork` window to
//! guard. It then `exec`s the real program over itself with `CommandExt::exec`, which is stable
//! and safe. The cost is one extra `fork`/`exec` per command, on the order of a millisecond
//! against a hook that runs `locale-gen`.
//!
//! The helper runs even when the root is `/` and no `chroot` is needed. One path is simpler than
//! two, and it matters here: the umask, the environment, and the stdio wiring cannot differ
//! between the case every test exercises and the case that only appears with `--root /mnt`.
//!
//! # What is *not* a sandbox
//!
//! A chroot confines paths and nothing else. A scriptlet or hook runs with piko's own
//! privileges and can do anything they permit. That is what these files are *for*, and pacman
//! works the same way. piko does not implement libalpm's `sandbox.c` (landlock + seccomp for
//! the download process). That is a separate mechanism for a separate purpose, not something
//! this module claims to provide.

use std::{
    ffi::{OsStr, OsString},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::Stdio,
};

use crate::error::{Error, IoAction, Result};

/// The hidden argument that turns a `piko` process into the exec helper.
///
/// It is deliberately not a documented subcommand. It exists only for [`Runner`] to call. An
/// unprivileged caller gains nothing from it (`chroot` needs `CAP_SYS_CHROOT`), and a privileged
/// one gains nothing that `chroot(8)` does not already give them.
pub const HELPER_ARG: &str = "__exec-in-root";

/// The umask a scriptlet or hook runs under.
///
/// libalpm sets exactly this in the child before `execv` (`util.c:695`). Without it, a command
/// inherits whatever the invoking shell had. A hook creating a file could then produce a
/// different mode depending on who ran the transaction.
const CHILD_UMASK: u32 = 0o022;

/// How much of a command's output is kept.
///
/// The stream is always drained to the end regardless. Stopping the read early would block the
/// child on a full pipe forever. So this bounds memory, not the command.
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// What a command did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Status {
    /// It ran to completion with this exit code.
    Exited(i32),
    /// It was killed by this signal.
    Signalled(i32),
    /// It never started, and why.
    ///
    /// This is a separate variant rather than a synthetic non-zero exit code. "The hook's
    /// `Exec` does not exist inside the root" and "the hook ran and returned 1" are different
    /// problems for whoever has to fix them. libalpm's single `retval` conflates the two.
    NotStarted(String),
}

/// The result of running one command.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// How it ended.
    pub status: Status,
    /// Its merged stdout and stderr, split into lines.
    ///
    /// This is returned rather than printed, per the workspace's diagnostics rule. The caller
    /// decides whether a scriptlet's chatter belongs on the terminal.
    pub output: Vec<String>,
    /// Whether output was dropped for exceeding [`MAX_OUTPUT_BYTES`].
    pub truncated: bool,
}

impl Outcome {
    /// Whether the command ran and exited zero.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.status == Status::Exited(0)
    }

    /// A one-line summary of how it ended, for a report.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.status {
            Status::Exited(0) => "succeeded".to_owned(),
            Status::Exited(code) => format!("exited with status {code}"),
            Status::Signalled(signal) => format!("was killed by signal {signal}"),
            Status::NotStarted(reason) => format!("could not be started: {reason}"),
        }
    }
}

/// A command to run inside the root.
#[derive(Clone, Debug)]
pub struct Command {
    /// The program, as an absolute path **inside the root**.
    pub program: PathBuf,
    /// Its arguments, not including the program itself.
    pub args: Vec<OsString>,
    /// Bytes to feed on stdin, if any. `None` connects stdin to `/dev/null`.
    pub stdin: Option<Vec<u8>>,
}

impl Command {
    /// A command with no arguments and no stdin.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self { program: program.into(), args: Vec::new(), stdin: None }
    }

    /// Appends an argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Feeds `bytes` on stdin.
    #[must_use]
    pub fn stdin(mut self, bytes: Vec<u8>) -> Self {
        self.stdin = Some(bytes);
        self
    }
}

/// Runs commands inside one root.
#[derive(Debug)]
pub struct Runner {
    /// The root to enter, exactly as it will be handed to the helper.
    root: PathBuf,
    /// piko's own executable, resolved once.
    helper: PathBuf,
}

impl Runner {
    /// Prepares to run commands inside `root`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if piko's own executable cannot be located — that executable is the
    /// helper. This check runs here rather than at the first command on purpose. A transaction
    /// that cannot run a scriptlet should find that out before it starts changing files.
    pub fn new(root: &Path) -> Result<Self> {
        let helper = std::env::current_exe()
            .map_err(|source| Error::io(Path::new("/proc/self/exe"), IoAction::Read, source))?;
        Ok(Self { root: root.to_path_buf(), helper })
    }

    /// The root commands are run inside.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Runs `command`, returning what it did.
    ///
    /// `on_line` is called with each line of merged stdout/stderr as soon as it is available,
    /// not only once the command exits. The returned [`Outcome::output`] carries the same lines
    /// again, buffered, for a caller that only wants the whole thing at the end.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] only for a failure on piko's own side: a pipe that cannot be created, or a
    /// wait that fails. Everything the *command* can do wrong, including not existing, comes
    /// back as a [`Status`] instead.
    pub fn run(&self, command: &Command, on_line: &mut dyn FnMut(&str)) -> Result<Outcome> {
        let (mut reader, writer) =
            std::io::pipe().map_err(|source| Error::io(&self.helper, IoAction::Create, source))?;
        let second = writer
            .try_clone()
            .map_err(|source| Error::io(&self.helper, IoAction::Create, source))?;

        // This block is scoped so both of the parent's copies of the write end close before
        // the read below. Leaving one open means the read never sees end-of-file, and the
        // transaction hangs with no output — the hardest possible shape of bug to diagnose.
        let child = {
            let mut spawn = std::process::Command::new(&self.helper);
            spawn
                .arg(HELPER_ARG)
                .arg(&self.root)
                .arg(&command.program)
                .args(&command.args)
                .stdout(Stdio::from(writer))
                .stderr(Stdio::from(second))
                .stdin(if command.stdin.is_some() { Stdio::piped() } else { Stdio::null() });
            apply_environment(&mut spawn);

            match spawn.spawn() {
                Ok(child) => child,
                Err(source) => {
                    return Ok(Outcome {
                        status: Status::NotStarted(source.to_string()),
                        output: Vec::new(),
                        truncated: false,
                    });
                }
            }
        };
        let mut child = child;

        // This write runs on its own thread. A command is free to ignore its stdin, and an
        // inline write would then block once the pipe filled while nothing drained the output
        // side.
        let feeder = command.stdin.clone().and_then(|payload| {
            let mut handle = child.stdin.take()?;
            Some(std::thread::spawn(move || {
                // A command that exits without reading gives `EPIPE`. This is ordinary — it is
                // how libalpm's poll loop ends too.
                let _ = handle.write_all(&payload);
            }))
        });

        let (output, truncated) = drain(&mut reader, on_line);

        let status =
            child.wait().map_err(|source| Error::io(&command.program, IoAction::Read, source))?;
        if let Some(handle) = feeder {
            drop(handle.join());
        }

        Ok(Outcome { status: classify(&status), output, truncated })
    }
}

/// The environment adjustments libalpm makes before `execv` (`util.c:688`).
fn apply_environment(spawn: &mut std::process::Command) {
    // bash treats itself as a login shell when stdin is a socket, and sources `~/.bashrc`. A
    // non-zero `SHLVL` tells it otherwise. libalpm uses `setenv(..., overwrite = 0)`, so an
    // inherited value stays as is rather than getting replaced.
    if std::env::var_os("SHLVL").is_none() {
        spawn.env("SHLVL", "1");
    }
    // bash sources `$BASH_ENV` when run non-interactively. Left alone, this would let the
    // environment of whoever started piko inject code into every scriptlet.
    spawn.env_remove("BASH_ENV");
}

/// Reads `reader` to end-of-file, keeping at most [`MAX_OUTPUT_BYTES`], and calls `on_line`
/// with each line as soon as it is complete.
///
/// Draining continues past the limit rather than stopping there, on purpose. A command that
/// keeps printing after the cap would otherwise block on a full pipe and never exit. `on_line`
/// stops being called once the cap is reached, and `kept` stops growing at the same point: both
/// read from the same capped buffer, so live output and the final [`Outcome::output`] never
/// disagree about where the cut is.
fn drain(reader: &mut std::io::PipeReader, on_line: &mut dyn FnMut(&str)) -> (Vec<String>, bool) {
    let mut kept: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    // How much of `kept` has already been split into a line and handed to `on_line`. This is
    // always a `\n` boundary, or `kept.len()` once the trailing partial line is flushed below.
    let mut reported = 0_usize;

    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        let chunk = buffer.get(..read).unwrap_or_default();
        let room = MAX_OUTPUT_BYTES.saturating_sub(kept.len());
        if room < chunk.len() {
            truncated = true;
        }
        kept.extend_from_slice(chunk.get(..room.min(chunk.len())).unwrap_or_default());

        while let Some(offset) =
            kept.get(reported..).and_then(|unreported| unreported.iter().position(|&b| b == b'\n'))
        {
            let end = reported.saturating_add(offset);
            on_line(&String::from_utf8_lossy(kept.get(reported..end).unwrap_or_default()));
            reported = end.saturating_add(1);
        }
    }
    if reported < kept.len() {
        on_line(&String::from_utf8_lossy(kept.get(reported..).unwrap_or_default()));
    }

    let text = String::from_utf8_lossy(&kept);
    let lines = text.lines().map(str::to_owned).collect();
    (lines, truncated)
}

/// Turns an `ExitStatus` into a [`Status`].
fn classify(status: &std::process::ExitStatus) -> Status {
    use std::os::unix::process::ExitStatusExt as _;
    match (status.code(), status.signal()) {
        (Some(code), _) => Status::Exited(code),
        (None, Some(signal)) => Status::Signalled(signal),
        // Neither an exit code nor a signal is unreachable on Unix. Inventing a zero here would
        // still report a vanished command as a success, so this branch stays explicit.
        (None, None) => Status::NotStarted("it ended in an unrecognised way".to_owned()),
    }
}

/// The helper half: enters `root`, then becomes `program`.
///
/// `piko` calls this when its first argument is [`HELPER_ARG`]. It never returns on success,
/// because [`std::os::unix::process::CommandExt::exec`] replaces this process.
///
/// `arguments` is everything after [`HELPER_ARG`]: the root, the program, then the program's
/// own arguments.
///
/// # Errors
///
/// A message describing what failed. The caller should print it to stderr before exiting
/// non-zero. It reaches [`Runner::run`] through the same pipe as the command's own output.
pub fn helper_main(
    arguments: &[OsString],
) -> std::result::Result<std::convert::Infallible, String> {
    let Some((root, rest)) = arguments.split_first() else {
        return Err("no root was given to the exec helper".to_owned());
    };
    let Some((program, args)) = rest.split_first() else {
        return Err("no program was given to the exec helper".to_owned());
    };

    // libalpm skips the `chroot` when the root is `/`. This lets a caller who already placed
    // the process in the right location run with fewer capabilities (`util.c:677`). The
    // comparison uses the resolved path, not the spelling, so `/.` and a trailing slash behave
    // the same way.
    //
    // The `chdir("/")` that follows is *not* conditional on that same test (`util.c:683`). It
    // runs even when the chroot itself was skipped. A scriptlet is free to use a path relative
    // to the root instead of an absolute one — gstreamer's `post_upgrade` does exactly that,
    // running `setcap` on `usr/lib/gstreamer-1.0/gst-ptp-helper` with no leading slash. Such a
    // path only resolves correctly when the working directory is guaranteed to be `/`,
    // regardless of whether `--root /` needed an actual `chroot(2)` call. Nesting the `chdir`
    // inside the `if` leaves it running from whatever directory launched piko, which breaks
    // any scriptlet that relies on a root-relative path when `--root` is `/`.
    let resolved = std::fs::canonicalize(root).map_err(|error| {
        format!("could not resolve the root {}: {error}", Path::new(root).display())
    })?;
    if resolved != Path::new("/") {
        rustix::process::chroot(&resolved)
            .map_err(|error| format!("could not enter the root {}: {error}", resolved.display()))?;
    }
    std::env::set_current_dir("/")
        .map_err(|error| format!("could not change directory inside the root: {error}"))?;

    rustix::process::umask(rustix::fs::Mode::from_raw_mode(CHILD_UMASK));

    // `exec` is safe and stable. It returns only on failure.
    let error = {
        use std::os::unix::process::CommandExt as _;
        std::process::Command::new(program).args(args).exec()
    };
    Err(format!("could not run {}: {error}", Path::new(program).display()))
}

/// Whether `argument` is the hidden helper marker.
#[must_use]
pub fn is_helper_argument(argument: &OsStr) -> bool {
    argument == OsStr::new(HELPER_ARG)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// The helper is `piko` itself, and the unit tests are not `piko`. Anything that needs a
    /// *working* helper runs from `crates/piko/tests/`, where the binary exists. These tests
    /// cover only the parts that are testable without one.
    #[test]
    fn a_zero_exit_is_the_only_success() {
        let ok = Outcome { status: Status::Exited(0), output: Vec::new(), truncated: false };
        assert!(ok.succeeded());

        for status in
            [Status::Exited(1), Status::Signalled(9), Status::NotStarted("no such file".to_owned())]
        {
            let outcome = Outcome { status, output: Vec::new(), truncated: false };
            assert!(!outcome.succeeded(), "{outcome:?}");
        }
    }

    /// "It did not start" must not read as "it returned an error". The fix differs: one is a
    /// broken hook file, the other is a broken hook.
    #[test]
    fn a_command_that_never_started_says_so() {
        let outcome = Outcome {
            status: Status::NotStarted("No such file or directory".to_owned()),
            output: Vec::new(),
            truncated: false,
        };
        let text = outcome.describe();
        assert!(text.contains("could not be started"), "{text}");
        assert!(text.contains("No such file"), "{text}");
    }

    #[test]
    fn a_signal_is_reported_as_a_signal() {
        let outcome =
            Outcome { status: Status::Signalled(9), output: Vec::new(), truncated: false };
        assert_eq!(outcome.describe(), "was killed by signal 9");
    }

    /// The helper refuses a malformed invocation rather than doing something arbitrary.
    #[test]
    fn the_helper_needs_a_root_and_a_program() {
        assert!(helper_main(&[]).is_err());
        assert!(helper_main(&[OsString::from("/")]).is_err());
    }

    /// A root that does not exist is refused before any `chroot` is attempted.
    #[test]
    fn the_helper_refuses_a_root_that_is_not_there() {
        let arguments =
            [OsString::from("/nonexistent-root-for-a-test"), OsString::from("/bin/true")];
        let error = helper_main(&arguments).unwrap_err();
        assert!(error.contains("could not resolve the root"), "{error}");
    }

    /// Output is split into lines and bounded. The bound is reported rather than hiding the
    /// loss.
    #[test]
    fn output_is_line_split_and_the_cap_is_reported() {
        let (mut reader, mut writer) = std::io::pipe().unwrap();
        let payload = vec![b'x'; MAX_OUTPUT_BYTES + 4096];
        let feeder = std::thread::spawn(move || {
            let _ = writer.write_all(b"first\nsecond\n");
            let _ = writer.write_all(&payload);
        });

        let mut streamed: Vec<String> = Vec::new();
        let (lines, truncated) = drain(&mut reader, &mut |line| streamed.push(line.to_owned()));
        drop(feeder.join());

        assert_eq!(lines.first().map(String::as_str), Some("first"));
        assert_eq!(lines.get(1).map(String::as_str), Some("second"));
        assert!(truncated, "the cap was exceeded but not reported");
        let total: usize = lines.iter().map(String::len).sum();
        assert!(total <= MAX_OUTPUT_BYTES, "kept {total} bytes");
        // The truncated tail lands in one final callback line, matching `lines`'s last entry.
        // Streamed and buffered output read from the same capped bytes, so they never disagree.
        assert_eq!(streamed, lines, "streamed lines diverged from the buffered ones");
    }

    /// A command that ends cleanly with no output yields no lines, not one empty line.
    #[test]
    fn no_output_is_no_lines() {
        let (mut reader, writer) = std::io::pipe().unwrap();
        drop(writer);
        let (lines, truncated) = drain(&mut reader, &mut |_| {});
        assert!(lines.is_empty(), "{lines:?}");
        assert!(!truncated);
    }
}
