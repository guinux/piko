//! A `SIGINT` handler that lets a download in progress stop cleanly.
//!
//! The first press raises a flag, [`piko_net::Cancel`]. Three places read it. A download reads
//! it per queued file, per request, and per 64 KiB chunk. `cmd::txn::run` reads it once,
//! between verification and the commit. The commit reads it before each step, through
//! `piko_txn::Transaction::cancel`.
//!
//! So one press stops the run at the next of those points. Before the commit, nothing is
//! applied. Inside it, the step already running finishes and the journal names what was done.
//! A second press is still the way out of a step that will not end. It leaves both the
//! journal and `db.lck` behind. The handler's message names no phase, because the handler
//! covers all of them.
//!
//! This is not installed unconditionally at process start. `ctrlc::set_handler` cannot be
//! un-registered, and accepts only one registration per process. So an early install would do
//! two unwanted things. It would replace Ctrl+C's instant-kill behavior everywhere in the
//! process for the rest of the run. And it would rule out a later caller installing its own.
//!
//! That cost reaches the `[Y/n]` confirmation prompt, which blocks on `stdin` and has nothing
//! in flight to cancel gracefully. Ctrl+C there should kill the process on the first press,
//! exactly as it does with no handler installed at all.
//!
//! Instead, a caller installs this only once it is about to do something that can download. It
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

/// Whether the installed `SIGINT` handler kills the process on the very first press. The
/// alternative requests a graceful stop that only a second press escalates.
///
/// Cheap to [`Clone`] — every clone shares the same underlying flag.
#[derive(Clone, Debug)]
pub(crate) struct PromptMode(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl PromptMode {
    /// Runs `f` with Ctrl+C killing the process immediately, then restores graceful mode.
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

/// A `SIGINT` handler already installed by an earlier step, threaded to a later one instead of
/// installing a second. `ctrlc::set_handler` accepts only one registration per process.
#[derive(Clone, Debug)]
pub(crate) struct Handoff {
    pub(crate) cancel: piko_net::Cancel,
    pub(crate) mode: PromptMode,
}

/// Installs a `SIGINT` handler.
///
/// In graceful mode, the first press requests a stop and a second press force-exits. The
/// module documentation lists what reads the flag, and where the run stops.
/// [`PromptMode::during_prompt`] switches this
/// to killing the process on the very first press instead, for a window with nothing to
/// cancel gracefully. Each press prints which happened. `ctrlc`'s handler runs on its own
/// thread rather than in raw signal-handler context, so printing from it is safe.
///
/// Two of the three messages go through [`crate::progress::suspend_active`] and
/// [`crate::progress::clear_active`]. A live row redraws every 100 ms. It would overdraw a
/// bare `eprintln!` mid-line. The cost is that the handler waits for indicatif's draw lock. A
/// blocked `stdout` under `CommitDriver::print_line` therefore delays Ctrl+C for as long as the
/// reader of that pipe takes.
pub(crate) fn install_cancel_handler() -> (piko_net::Cancel, PromptMode) {
    let cancel = piko_net::Cancel::new();
    let for_handler = cancel.clone();
    let instant_kill = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let for_handler_kill = std::sync::Arc::clone(&instant_kill);
    #[allow(clippy::expect_used, reason = "the only registration reachable in one process run")]
    ctrlc::set_handler(move || {
        if for_handler_kill.load(std::sync::atomic::Ordering::SeqCst) {
            // The one message that prints on its own. Instant-kill mode marks a prompt.
            // `cmd::txn`'s provider question holds the draw lock across that prompt. A request
            // for the lock here would wait for the answer Ctrl+C just refused to give. The
            // prompt's own `suspend` hides the rows already, so nothing can overdraw this.
            eprintln!("Interrupted");
            std::process::exit(130);
        }
        if for_handler.is_requested() {
            // This clears the rows rather than suspending them. The process ends on the next
            // line, so the rows have no reason to come back.
            crate::progress::clear_active();
            eprintln!("Still stopping -- forcing exit");
            std::process::exit(130);
        }
        crate::progress::suspend_active(|| {
            // Named for what the flag does, not for a phase. One handler covers downloading,
            // verification and the commit, and all three stop on it. A phase named here would
            // be the wrong one for every press that lands in one of the other two.
            eprintln!("Stopping (press Ctrl+C again to force quit)...");
        });
        for_handler.request();
    })
    .expect("installing the SIGINT handler cannot fail here");
    (cancel, PromptMode(instant_kill))
}
