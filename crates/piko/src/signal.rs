//! A handler for `SIGINT`, `SIGHUP` and `SIGTERM` that lets a download or a commit stop cleanly.
//!
//! The first signal raises a flag, [`piko_net::Cancel`]. Three places read it. A download reads
//! it per queued file, per request, and per 64 KiB chunk. `cmd::txn::run` reads it once,
//! between verification and the commit. The commit reads it before each step, through
//! `piko_txn::Transaction::cancel`.
//!
//! So one signal stops the run at the next of those points. Before the commit, nothing is
//! applied. Inside it, the step already running finishes and the journal names what was done.
//! A second Ctrl+C is still the way out of a step that will not end. It leaves both the
//! journal and `db.lck` behind. The handler's message names no phase, because the handler
//! covers all of them.
//!
//! A hangup and a terminate request only ever raise the flag. Neither one forces the exit,
//! however many arrive. pacman's soft interrupt handler takes `SIGHUP` the same way: during a
//! commit, it marks the transaction interrupted and returns (`sighandler.c:52`). A closed SSH
//! session commonly delivers the hangup twice, once from the kernel and once from the shell.
//! A second hangup that forced the exit would stop the extraction of a package half-way. Only a
//! second Ctrl+C does that, because only a person at the terminal sends it.
//!
//! A hangup also points standard output and standard error at `/dev/null`, unless the stream
//! is a regular file. A write to a terminal that hung up fails, and `eprintln!` panics on a
//! failed write. The run then goes on without a terminal, and the history records the outcome.
//!
//! This is not installed unconditionally at process start. A registration cannot be taken
//! back, and a second one would receive the same signals as the first. So an early install
//! would do two unwanted things. It would replace Ctrl+C's instant-kill behavior everywhere in
//! the process for the rest of the run. And it would rule out a later caller installing its own.
//!
//! That cost reaches the `[Y/n]` confirmation prompt, which blocks on `stdin` and has nothing
//! in flight to cancel gracefully. Ctrl+C there should kill the process on the first press,
//! exactly as it does with no handler installed at all.
//!
//! Instead, a caller installs this only once it is about to download or to commit. It
//! then passes the resulting [`Handoff`] on to whatever comes after it in the same run, rather
//! than installing a second time:
//!
//! - `Command::Refresh`'s dispatch arm (`main.rs`) installs it and passes the `Cancel` half
//!   into `cmd::refresh::refresh`. `refresh` has no confirmation prompt, so the `PromptMode`
//!   half goes unused there.
//! - `main::sync`'s pre-refresh step installs it, when `update` is refreshing, and passes the
//!   whole `Handoff` into `cmd::txn::InstallOptions::pre_cancel`. `cmd::txn::install` brackets
//!   its confirmation prompt in `PromptMode::during_prompt`. So Ctrl+C kills the process
//!   immediately right there. The same handler stays installed for the refresh that already
//!   ran, and for the download phase that follows an accepted prompt.
//! - `cmd::txn::install` installs one before it fetches a package named by URL. That download
//!   necessarily precedes the plan, and therefore the prompt. It then brackets the prompt in
//!   `PromptMode::during_prompt` through the same `pre_cancel` slot. So Ctrl+C there still
//!   kills the process on the first press.
//! - Failing all of the above, `cmd::txn::install` installs its own handler right after its
//!   confirmation gate passes. Nothing is installed yet while that prompt is up, so Ctrl+C
//!   already kills the process by the OS's default disposition.
//! - `cmd::txn::remove` installs one after its prompts too. A removal downloads nothing, but
//!   its commit stops between two steps in the same way.

use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

/// Whether the installed handler ends the process on the very first signal. The alternative
/// requests a graceful stop that only a second Ctrl+C escalates.
///
/// Cheap to [`Clone`] — every clone shares the same underlying flag.
#[derive(Clone, Debug)]
pub(crate) struct PromptMode(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl PromptMode {
    /// Runs `f` with a signal ending the process immediately, then restores graceful mode.
    ///
    /// For a window with nothing in flight to cancel gracefully — a confirmation prompt
    /// blocked on `stdin`, concretely. No unwind-safety concern: production code in this
    /// workspace never panics (`panic = "deny"`), so a plain store after `f()` is enough.
    pub(crate) fn during_prompt<T>(&self, f: impl FnOnce() -> T) -> T {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        let result = f();
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
        result
    }
}

/// A signal handler already installed by an earlier step, threaded to a later one instead of
/// installing a second. A second registration would receive every signal the first one does.
#[derive(Clone, Debug)]
pub(crate) struct Handoff {
    pub(crate) cancel: piko_net::Cancel,
    pub(crate) mode: PromptMode,
}

/// Installs a handler for `SIGINT`, `SIGHUP` and `SIGTERM`.
///
/// In graceful mode, the first signal requests a stop. A second Ctrl+C force-exits. A hangup or
/// a terminate request never does. The module documentation lists what reads the flag, and
/// where the run stops. [`PromptMode::during_prompt`] switches this to ending the process on
/// the very first signal instead, for a window with nothing to cancel gracefully. The handler
/// runs on a thread of its own rather than in raw signal-handler context, so printing from it
/// is safe.
///
/// Two of the messages go through [`crate::progress::suspend_active`] and
/// [`crate::progress::clear_active`]. A live row redraws every 100 ms. It would overdraw a
/// bare `eprintln!` mid-line. The cost is that the handler waits for indicatif's draw lock. A
/// blocked `stdout` under `CommitDriver::print_line` therefore delays Ctrl+C for as long as the
/// reader of that pipe takes.
pub(crate) fn install_cancel_handler() -> (piko_net::Cancel, PromptMode) {
    let cancel = piko_net::Cancel::new();
    let instant_kill = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handler =
        Handler { cancel: cancel.clone(), instant_kill: std::sync::Arc::clone(&instant_kill) };
    #[expect(clippy::expect_used, reason = "the only registration reachable in one process run")]
    handler.spawn().expect("installing the signal handler cannot fail here");
    (cancel, PromptMode(instant_kill))
}

/// What the handler thread reads on each signal.
struct Handler {
    cancel: piko_net::Cancel,
    instant_kill: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Handler {
    /// Registers the three signals and starts the thread that answers them.
    fn spawn(self) -> std::io::Result<()> {
        let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGHUP, SIGTERM])?;
        std::thread::Builder::new().name("signals".to_owned()).spawn(move || {
            for signal in signals.forever() {
                self.answer(signal);
            }
        })?;
        Ok(())
    }

    /// Answers one signal.
    fn answer(&self, signal: std::ffi::c_int) {
        if signal == SIGHUP {
            detach_from_terminal();
        }
        if self.instant_kill.load(std::sync::atomic::Ordering::SeqCst) {
            // The one message that prints on its own. Instant-kill mode marks a prompt.
            // `cmd::txn`'s provider question holds the draw lock across that prompt. A request
            // for the lock here would wait for the answer the signal just refused to give. The
            // prompt's own `suspend` hides the rows already, so nothing can overdraw this.
            eprintln!("{}", if signal == SIGINT { "Interrupted" } else { "Terminated" });
            std::process::exit(128_i32.saturating_add(signal));
        }
        if self.cancel.is_requested() {
            if signal != SIGINT {
                return;
            }
            // This clears the rows rather than suspending them. The process ends on the next
            // line, so the rows have no reason to come back.
            crate::progress::clear_active();
            eprintln!("Still stopping -- forcing exit");
            std::process::exit(130);
        }
        if signal != SIGHUP {
            crate::progress::suspend_active(|| {
                // Named for what the flag does, not for a phase. One handler covers
                // downloading, verification and the commit, and all three stop on it. A phase
                // named here would be the wrong one for every signal that lands in the others.
                if signal == SIGINT {
                    eprintln!("Stopping (press Ctrl+C again to force quit)...");
                } else {
                    eprintln!("Stopping: terminate request received...");
                }
            });
        }
        self.cancel.request();
    }
}

/// Points standard output and standard error at `/dev/null`, unless the stream is a regular
/// file.
///
/// A write to a terminal that hung up fails with `EIO`, and `eprintln!` panics on a failed
/// write. A pipe fails the same way once its reader is gone, and a hangup usually ends that
/// reader too. A regular file keeps working, so a run redirected to a file keeps its output.
/// A failure here leaves the stream as it was: nothing better is left to try.
fn detach_from_terminal() {
    let Ok(null) = rustix::fs::open(
        "/dev/null",
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) else {
        return;
    };
    if !is_regular_file(std::io::stdout()) {
        let _ = rustix::stdio::dup2_stdout(&null);
    }
    if !is_regular_file(std::io::stderr()) {
        let _ = rustix::stdio::dup2_stderr(&null);
    }
}

/// Whether `stream` is a regular file.
fn is_regular_file(stream: impl std::os::fd::AsFd) -> bool {
    rustix::fs::fstat(stream)
        .is_ok_and(|stat| rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file())
}
