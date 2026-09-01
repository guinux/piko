//! A `SIGINT` handler that lets a download in progress stop cleanly.
//!
//! This is not installed unconditionally at process start. `ctrlc::set_handler` cannot be
//! un-registered, and accepts only one registration per process, so an early install would
//! both replace Ctrl+C's instant-kill behavior everywhere in the process for the rest of the
//! run, and rule out a later caller installing its own. That includes the `[Y/n]`
//! confirmation prompt, which blocks on `stdin` and has nothing in flight to cancel
//! gracefully — Ctrl+C there should kill the process on the first press, exactly as it does
//! with no handler installed at all. Instead, a caller installs this only once it is about to
//! do something that can download, and passes the resulting [`Handoff`] on to whatever comes
//! after it in the same run rather than installing a second time:
//!
//! - `Command::Refresh`'s dispatch arm (`main.rs`) installs it and passes the `Cancel` half
//!   into `cmd::refresh::refresh`. `refresh` has no confirmation prompt, so the `PromptMode`
//!   half goes unused there.
//! - `main::sync`'s pre-refresh step installs it, when `update` is refreshing, and passes the
//!   whole `Handoff` into `cmd::txn::InstallOptions::pre_cancel`. `cmd::txn::install` brackets
//!   its confirmation prompt in `PromptMode::during_prompt`, so Ctrl+C kills the process
//!   immediately right there even though the same handler stays installed for the refresh
//!   that already ran and the download phase that follows if the prompt is accepted.
//! - `cmd::txn::install` installs its own handler only when `InstallOptions::pre_cancel` is
//!   `None` (a plain `install`, or `update --norefresh`), right after its confirmation gate
//!   passes — so nothing is installed yet while that prompt is up, and Ctrl+C already kills
//!   the process by the OS's default disposition.

/// Whether the installed `SIGINT` handler kills the process on the very first press, instead
/// of requesting a graceful stop that only a second press escalates.
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

/// A `SIGINT` handler already installed by an earlier step, threaded to a later one instead
/// of installing a second — `ctrlc::set_handler` accepts only one registration per process.
#[derive(Clone, Debug)]
pub(crate) struct Handoff {
    pub(crate) cancel: piko_net::Cancel,
    pub(crate) mode: PromptMode,
}

/// Installs a `SIGINT` handler.
///
/// In graceful mode, the first press requests cancellation of whatever download is in
/// flight; a second press force-exits. [`PromptMode::during_prompt`] switches it to killing
/// the process on the very first press instead, for a window with nothing to cancel
/// gracefully. Each press prints which happened. `ctrlc`'s handler runs on its own thread
/// rather than in raw signal-handler context, so printing from it is safe.
pub(crate) fn install_cancel_handler() -> (piko_net::Cancel, PromptMode) {
    let cancel = piko_net::Cancel::new();
    let for_handler = cancel.clone();
    let instant_kill = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let for_handler_kill = std::sync::Arc::clone(&instant_kill);
    #[allow(clippy::expect_used, reason = "the only registration reachable in one process run")]
    ctrlc::set_handler(move || {
        if for_handler_kill.load(std::sync::atomic::Ordering::SeqCst) {
            eprintln!("piko: interrupted");
            std::process::exit(130);
        }
        if for_handler.is_requested() {
            eprintln!("piko: still stopping -- forcing exit");
            std::process::exit(130);
        }
        eprintln!("piko: stopping the download (press Ctrl+C again to force quit)...");
        for_handler.request();
    })
    .expect("installing the SIGINT handler cannot fail here");
    (cancel, PromptMode(instant_kill))
}
