//! A live, stacked list of transaction steps: a spinner on stderr while an item runs, replaced
//! by a plain checkmark line the moment it finishes.
//!
//! A row is never left as a permanently kept `indicatif` bar. `MultiProgress` redraws its
//! whole managed stack together on every tick and assumes that stack fits on screen. A
//! transaction touching hundreds of packages (or, for [`VerifyDriver`], a long download/verify
//! phase ahead of one) would leave that many finished bars behind, overflow the terminal, and
//! corrupt the redraw: dropped lines, checkmarks that never appear. Instead, at most a handful
//! of rows are ever alive in the `indicatif::MultiProgress` at once. A finished one is cleared
//! (`finish_and_clear()`, never bare `finish()`) and its text reprinted as a plain line through
//! [`StepList::suspend`], which lands in ordinary scrollback that `indicatif` has no further
//! say over. `print_step_result` (stdout) still exists for what a row cannot show: a
//! `.pacnew`/`.pacsave` notice, or a warning.

use std::{collections::BTreeSet, str::FromStr, sync::Mutex};

use alpm_types::PackageFileName;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::style::checkmark;

/// The three shapes a row can take, each with its own running/finished template pair.
#[derive(Clone, Copy)]
enum Kind {
    /// No progress information at all: a spinner and a message, nothing else.
    Spinner,
    /// A countable total, known up front: `n/total` next to the message.
    Counted,
    /// A byte total, known up front: a mini bar plus `bytes/total_bytes` next to the message.
    Download,
}

/// Fixed, hand-written templates, known good at compile time.
#[allow(clippy::expect_used, reason = "a constant template string cannot fail to parse")]
fn style(kind: Kind, finished: bool) -> ProgressStyle {
    let template = match (kind, finished) {
        (Kind::Spinner, false) => "{spinner:.cyan} {msg}".to_owned(),
        (Kind::Spinner, true) => format!("{} {{msg}}", checkmark()),
        (Kind::Counted, false) => "{spinner:.cyan} {msg} ({pos}/{len})".to_owned(),
        (Kind::Counted, true) => format!("{} {{msg}} ({{pos}}/{{len}})", checkmark()),
        (Kind::Download, false) => {
            "{spinner:.cyan} {msg} [{bar:20.cyan/blue}] {bytes}/{total_bytes}".to_owned()
        }
        (Kind::Download, true) => format!("{} {{msg}} {{bytes}}/{{total_bytes}}", checkmark()),
    };
    ProgressStyle::with_template(&template).expect("valid template").progress_chars("=> ")
}

/// One line of the live display: a spinner-or-bar that starts running and ends up checked off.
#[derive(Clone)]
pub(crate) struct Row {
    bar: ProgressBar,
    kind: Kind,
}

impl Row {
    /// Changes the message shown next to the spinner.
    ///
    /// Used for a row whose description evolves: the file currently downloading, the package
    /// currently being installed.
    pub(crate) fn set_message(&self, text: impl Into<String>) {
        self.bar.set_message(text.into());
    }

    /// Moves a [`Kind::Counted`] or [`Kind::Download`] row's position: `n` for the former,
    /// bytes received for the latter.
    pub(crate) fn set_position(&self, position: u64) {
        self.bar.set_position(position);
    }

    /// Advances a [`Kind::Download`] row by `delta` bytes.
    ///
    /// The counterpart of [`Row::set_position`] for a row several transfers report into at
    /// once. `piko_net::Event::Progress` carries a per-file delta precisely so that adding
    /// them up is correct without the sink tracking who last said what.
    pub(crate) fn inc(&self, delta: u64) {
        self.bar.inc(delta);
    }

    /// Sets a [`Kind::Download`] row's total.
    ///
    /// Used for the case where the total is not known until the download's own `Started`
    /// event reports it: a single-file `piko refresh` row, unlike the grouped multi-file
    /// install-download row.
    pub(crate) fn set_length(&self, len: u64) {
        self.bar.set_length(len);
    }

    /// Leaves the message in place, swaps the spinner for a green check, and freezes whatever
    /// count or byte total the row last showed, permanently.
    ///
    /// For a caller with a small, bounded number of rows it intends to keep on screen for the
    /// whole run: `cmd::refresh`'s one row per configured repository. [`Self::finish_and_clear`]
    /// is what [`VerifyDriver`] and [`CommitDriver`] use instead. A row that could number in
    /// the hundreds (one package, one hook) cannot be kept this way; see this module's doc
    /// comment.
    pub(crate) fn finish(self) {
        self.bar.set_style(style(self.kind, true));
        self.bar.finish();
    }

    /// As [`Row::finish`], but replaces the message first.
    ///
    /// Used for a row whose text evolved while running (the file currently downloading, the
    /// package currently being installed) and should settle back on its phase's plain name
    /// once there is no longer a "current" one.
    pub(crate) fn finish_as(self, text: impl Into<String>) {
        self.set_message(text);
        self.finish();
    }

    /// As [`Row::finish_as`], but drops whatever bytes/count template the row started with.
    ///
    /// Used for an outcome (e.g. "up to date") that measured nothing.
    pub(crate) fn finish_plain(self, text: impl Into<String>) {
        self.bar.set_style(style(Kind::Spinner, true));
        self.bar.set_message(text.into());
        self.bar.finish();
    }

    /// Removes the row from the display entirely, rather than leaving it checked off.
    ///
    /// What [`VerifyDriver`] and [`CommitDriver`] call on every row they open, immediately
    /// followed by printing its final text as a plain line; see this module's doc comment.
    /// [`VerifyDriver::finish_download`] also uses this bare (no reprint) for the head row
    /// naming in-flight downloads. That row has nothing worth freezing once nothing is left in
    /// flight; the byte total the download row itself settled on already says what was
    /// fetched.
    pub(crate) fn finish_and_clear(self) {
        self.bar.finish_and_clear();
    }
}

/// The stack of live rows for one transaction, each added as its phase starts.
pub(crate) struct StepList {
    mp: MultiProgress,
}

impl StepList {
    pub(crate) fn new() -> Self {
        Self { mp: MultiProgress::new() }
    }

    fn add(&self, kind: Kind, text: &str, len: u64) -> Row {
        let bar = self.mp.add(ProgressBar::new(len));
        bar.enable_steady_tick(std::time::Duration::from_millis(100));
        bar.set_style(style(kind, false));
        bar.set_message(text.to_owned());
        Row { bar, kind }
    }

    /// A row with no progress information — just a spinner and a message.
    pub(crate) fn spinner(&self, text: &str) -> Row {
        self.add(Kind::Spinner, text, 0)
    }

    /// A row counting up to a known total.
    pub(crate) fn counted(&self, text: &str, total: usize) -> Row {
        self.add(Kind::Counted, text, total as u64)
    }

    /// A row counting bytes up to a known total.
    pub(crate) fn download(&self, text: &str, total_bytes: u64) -> Row {
        self.add(Kind::Download, text, total_bytes)
    }

    /// Runs `body` with the live rows hidden, so what it writes to the terminal is not
    /// overdrawn by a spinner tick mid-line.
    pub(crate) fn suspend<R>(&self, body: impl FnOnce() -> R) -> R {
        self.mp.suspend(body)
    }
}

/// What the head row says while `live` files are being fetched.
///
/// Package file names carry a version, a pkgrel, and an architecture. Three of those side by
/// side is a line nobody can read, so each is reduced to the package name it starts with. A
/// name that does not parse (a database, `core.db`) is shown as it is.
fn in_flight(live: &BTreeSet<String>) -> String {
    let names: Vec<String> = live
        .iter()
        .take(3)
        .map(|file| {
            PackageFileName::from_str(file)
                .map_or_else(|_| file.clone(), |parsed| parsed.name().to_string())
        })
        .collect();
    match live.len().saturating_sub(names.len()) {
        0 if names.is_empty() => "Downloading".to_owned(),
        0 => format!("Downloading {}", names.join(", ")),
        rest => format!("Downloading {} (+{rest})", names.join(", ")),
    }
}

/// The sink that drives the grouped download rows as each file's bytes arrive.
///
/// `row` counts every package's bytes into one total; `head` names the transfers currently in
/// flight. They are separate because with `ParallelDownloads > 1` there is no single "the file
/// being downloaded" to put beside a bar. The byte total is the only thing that still adds up
/// to one number.
///
/// The in-flight set is the one piece of mutable state here, and a `Mutex` is the right tool
/// for it. This is terminal display state touched twice per file.
pub(crate) fn download_sink(
    row: Row,
    head: Row,
) -> impl Fn(piko_net::Event) + Send + Sync + 'static {
    let live = Mutex::new(BTreeSet::new());
    move |event: piko_net::Event| {
        use piko_net::{Event as E, Kind};
        // A signature is a few hundred bytes and finishes before a human perceives it. Naming
        // it would flicker. Adding its bytes to a total measured from `%CSIZE%` would also
        // push the bar past its own end.
        match event {
            E::Started { file, kind, .. } if kind != Kind::Signature => {
                if let Ok(mut live) = live.lock() {
                    live.insert(file);
                    head.set_message(in_flight(&live));
                }
            }
            E::Progress { kind, bytes } if kind != Kind::Signature => row.inc(bytes),
            E::Downloaded { file, kind } if kind != Kind::Signature => {
                if let Ok(mut live) = live.lock() {
                    live.remove(&file);
                    head.set_message(in_flight(&live));
                }
            }
            // `Event` is `#[non_exhaustive]`.
            _ => {}
        }
    }
}

/// Everything `install` needs to hand a `DownloadingSource` its progress sink.
///
/// Bundled so the call site does not have to spell out the sink's own (`Send + Sync` trait
/// object) type.
pub(crate) struct DownloadRig {
    /// The row naming what is in flight, above the bar.
    pub(crate) head: Option<Row>,
    /// The live row, if there is anything to download at all.
    pub(crate) row: Option<Row>,
    /// The `Send + Sync + 'static` sink `DownloadingSource::new` takes.
    pub(crate) sink: Box<dyn Fn(piko_net::Event) + Send + Sync>,
}

/// Builds a [`DownloadRig`] for a plan whose total download size is `total_bytes`.
///
/// Builds no row at all when `total_bytes` is zero, since `download_sink`'s row would then
/// never see a single byte move.
pub(crate) fn download_rig(steplist: &StepList, total_bytes: u64) -> DownloadRig {
    if total_bytes == 0 {
        return DownloadRig { head: None, row: None, sink: Box::new(|_: piko_net::Event| {}) };
    }
    // Added first, so it renders above the bar it describes.
    let head = steplist.spinner("Downloading");
    let row = steplist.download("Downloading packages", total_bytes);
    let sink = download_sink(row.clone(), head.clone());
    DownloadRig { head: Some(head), row: Some(row), sink: Box::new(sink) }
}

/// Drives a per-repository download [`Row`] for `piko refresh`.
///
/// Unlike the grouped multi-file install-download row (whose total comes from the plan, up
/// front), each `piko refresh` row covers exactly one database file, so its total is not known
/// until the download's own `Started` event reports it.
pub(crate) fn database_download_sink(row: Row) -> impl Fn(piko_net::Event) + Send + Sync + 'static {
    move |event: piko_net::Event| {
        use piko_net::{Event as E, Kind};
        match event {
            E::Started { kind, total, .. } if kind != Kind::Signature => {
                row.set_length(total.unwrap_or(0));
                row.set_position(0);
            }
            E::Progress { kind, bytes } if kind != Kind::Signature => row.inc(bytes),
            // `Event` is `#[non_exhaustive]`. A signature download gets no visible progress:
            // it is a few hundred bytes, over before a human perceives it.
            _ => {}
        }
    }
}

/// Clears `row` and reprints `text` as a plain, checked-off line, through [`StepList::suspend`]
/// so it lands in ordinary scrollback rather than `indicatif`'s managed area. This is the
/// convention this module's doc comment explains. Every caller with a row that could recur
/// many times (a resolved dependency set, a package, a hook, a download/verify phase) uses
/// this instead of [`Row::finish`].
pub(crate) fn settle_row(steplist: &StepList, out: &mut impl std::io::Write, row: Row, text: &str) {
    row.finish_and_clear();
    steplist.suspend(|| {
        let _ = writeln!(out, "{} {text}", checkmark());
        let _ = out.flush();
    });
}

/// A one-line description of a step, for the row this step's progress prints under.
///
/// Named by package name alone: `foo`, not `foo-1.0.0-1-x86_64.pkg.tar.zst` or even
/// `foo-1.0.0-1`. The version is implicit in "installing" a package that had none, or visible
/// in the packager's own scriptlet/hook output right underneath. Repeating it here would only
/// widen the line.
///
/// `replaces` is the entry [`piko_txn::progress::Event::StepStarted`] says this step's install
/// will replace, if any. It is what tells "installing" from "updating" apart before the step
/// has run; `Step::Remove` never carries one. `replaces` alone is `alpm-hooks(5)`'s "upgrade"
/// ("was already there"), not a version-direction comparison: it is `Some` for a plain
/// reinstall too. So this compares versions itself rather than trusting `is_some()`. A
/// reinstall displays as "installing", matching what it actually changes on disk.
fn describe_step(step: &piko_txn::Step, replaces: Option<&piko_db::EntryName>) -> String {
    match step {
        piko_txn::Step::Install { package, .. } => {
            if replaces.is_some_and(|old| old.version() != package.version()) {
                format!("Updating {}", package.name())
            } else {
                format!("Installing {}", package.name())
            }
        }
        piko_txn::Step::Remove { entry, .. } => format!("Removing {}", entry.name_str()),
    }
}

/// Drives the "Downloading packages" → "Verifying signatures" → "Verifying packages" →
/// "Checking file conflicts" rows through one `Transaction::verify_with_progress` call.
///
/// The four rows are mutually exclusive in time. `verify_with_progress`'s own two loops run
/// one after the other, never interleaved.
/// `SignatureChecked`and `PackageVerified` both fire from the first loop, one right after the other per package.
/// So this only ever has at most one row open at once: each event finishes whatever came
/// before it starts.
///
/// As [`CommitDriver`], a finished phase is cleared and reprinted as a plain checkmark line
/// rather than left as a permanent `indicatif` row. See that struct's doc comment for why.
pub(crate) struct VerifyDriver<'a, W> {
    steplist: &'a StepList,
    out: &'a mut W,
    download_row: Option<Row>,
    download_head: Option<Row>,
    signature_row: Option<Row>,
    verify_row: Option<Row>,
    conflict_row: Option<Row>,
}

impl<'a, W: std::io::Write> VerifyDriver<'a, W> {
    /// `download_row`/`download_head`, if any, are the rows `install`'s `DownloadingSource`
    /// sink is already updating live. This driver only decides when they are done, never how
    /// they move.
    pub(crate) fn new(
        steplist: &'a StepList,
        out: &'a mut W,
        download_row: Option<Row>,
        download_head: Option<Row>,
    ) -> Self {
        Self {
            steplist,
            out,
            download_row,
            download_head,
            signature_row: None,
            verify_row: None,
            conflict_row: None,
        }
    }

    pub(crate) fn handle(&mut self, event: piko_txn::progress::VerifyEvent) {
        use piko_txn::progress::VerifyEvent as E;
        match event {
            E::SignatureChecked { index, total } => {
                self.finish_download();
                let steplist = self.steplist;
                let row = self
                    .signature_row
                    .get_or_insert_with(|| steplist.counted("Verifying signatures", total));
                row.set_position(index as u64);
            }
            E::PackageVerified { index, total } => {
                self.finish_download();
                self.settle_signature();
                let steplist = self.steplist;
                let row = self
                    .verify_row
                    .get_or_insert_with(|| steplist.counted("Verifying packages", total));
                row.set_position(index as u64);
            }
            E::ConflictCheckStarted => {
                self.finish_download();
                self.settle_signature();
                self.settle_verify();
                self.conflict_row = Some(self.steplist.spinner("Checking file conflicts"));
            }
            // `VerifyEvent` is `#[non_exhaustive]`.
            _ => {}
        }
    }

    /// The download row settles as "Downloading packages" once nothing is currently
    /// downloading. The head row naming in-flight files is cleared outright instead. It has
    /// nothing worth freezing once nothing is left in flight; the byte total the download row
    /// itself settled on already says what was fetched.
    fn finish_download(&mut self) {
        if let Some(row) = self.download_row.take() {
            self.settle(row, "Downloading packages");
        }
        if let Some(head) = self.download_head.take() {
            head.finish_and_clear();
        }
    }

    fn settle_signature(&mut self) {
        if let Some(row) = self.signature_row.take() {
            self.settle(row, "Verifying signatures");
        }
    }

    fn settle_verify(&mut self) {
        if let Some(row) = self.verify_row.take() {
            self.settle(row, "Verifying packages");
        }
    }

    fn settle(&mut self, row: Row, text: &str) {
        settle_row(self.steplist, self.out, row, text);
    }

    /// Closes off whatever row is still open once `verify_with_progress` has returned, success
    /// or failure alike. A row left spinning after the call it belonged to ended would be a
    /// lie either way.
    pub(crate) fn finish(mut self) {
        self.finish_download();
        self.settle_signature();
        self.settle_verify();
        if let Some(row) = self.conflict_row.take() {
            self.settle(row, "Checking file conflicts");
        }
    }
}

/// Drives one line per package and one line per hook through a `Staged::commit_with_progress`
/// call: a spinner while that item runs, replaced by a plain checkmark line once it finishes,
/// with `(n/total)` on the right while running. Also prints whatever [`print_step_result`] has
/// to say about `out` as each install/remove step finishes.
///
/// Each finished item becomes an ordinary printed line, not a permanently kept `indicatif` row.
/// `MultiProgress` redraws its whole managed stack together on every tick and assumes it fits
/// on screen, so a transaction touching hundreds of packages would leave hundreds of finished
/// bars behind, overflow the terminal, and corrupt the redraw: dropped lines and lost
/// checkmarks. At most one package-or-hook row and one nested scriptlet row are ever alive at
/// once. A finished one is cleared and its text reprinted as a plain line via
/// [`StepList::suspend`], which lands in ordinary scrollback that `indicatif` no longer has any
/// say over.
pub(crate) struct CommitDriver<'a, W> {
    steplist: &'a StepList,
    out: &'a mut W,
    /// The currently running package-or-hook row and the text it was opened with. At most one
    /// at a time: `commit_with_progress` emits step and hook events strictly one after
    /// another, never interleaved.
    current: Option<(Row, String)>,
    /// As `current`, for the nested "Running … script" row. Opens and closes at most twice
    /// within a package row's lifetime (once per scriptlet function), never overlapping
    /// itself.
    scriptlet: Option<(Row, String)>,
}

impl<'a, W: std::io::Write> CommitDriver<'a, W> {
    pub(crate) fn new(steplist: &'a StepList, out: &'a mut W) -> Self {
        Self { steplist, out, current: None, scriptlet: None }
    }

    pub(crate) fn handle(&mut self, event: piko_txn::progress::Event<'_>) {
        use piko_txn::progress::Event as E;
        match event {
            E::HookStarted { index, total, name, description } => {
                self.current = Some(self.open_counted(description.unwrap_or(name), index, total));
            }
            E::HookOutputLine { line, .. } => self.print_line(&format!("  {line}")),
            E::HookFinished { .. } => self.close(|driver| &mut driver.current),
            E::ScriptletStarted { kind, .. } => {
                let text = format!("Running {} script", kind.as_str().replace('_', " "));
                self.scriptlet = Some((self.steplist.spinner(&text), text));
            }
            E::ScriptletOutputLine { line, .. } => self.print_line(line),
            E::ScriptletFinished { .. } => self.close(|driver| &mut driver.scriptlet),
            E::StepStarted { index, total, step, replaces } => {
                let text = describe_step(step, replaces);
                self.current = Some(self.open_counted(&text, index, total));
            }
            E::StepFinished { step, outcome } => {
                self.close(|driver| &mut driver.current);
                print_step_result(self.out, step, &outcome);
            }
            // `Event` is `#[non_exhaustive]`.
            _ => {}
        }
    }

    /// Opens a transient [`Kind::Counted`] row for `text` at 1-based position `index + 1` of
    /// `total`, keeping `text` alongside it for [`Self::close`] to print once it finishes.
    fn open_counted(&self, text: &str, index: usize, total: usize) -> (Row, String) {
        let row = self.steplist.counted(text, total);
        row.set_position(index.saturating_add(1) as u64);
        (row, text.to_owned())
    }

    /// Clears whichever row `slot` names and reprints its text as a plain, checked-off line.
    fn close(&mut self, slot: impl FnOnce(&mut Self) -> &mut Option<(Row, String)>) {
        if let Some((row, text)) = slot(self).take() {
            settle_row(self.steplist, self.out, row, &text);
        }
    }

    /// Writes and immediately flushes one line.
    ///
    /// `out` is a `BufWriter` (`main.rs`; `piko list` writes over a thousand lines, and wants
    /// it buffered). That is exactly wrong for a line meant to appear the instant it happens.
    /// Without an explicit flush it sits in the buffer until 8 KiB accumulates or the process
    /// exits, so a live transaction would print in bursts instead of one line at a time.
    fn print_line(&mut self, text: &str) {
        let out = &mut *self.out;
        self.steplist.suspend(|| {
            let _ = writeln!(out, "{text}");
            let _ = out.flush();
        });
    }

    /// Closes off whichever row is still open once `commit_with_progress` has returned. This
    /// is not expected in the ordinary case, since every `*Started` this module opens is
    /// matched by a `*Finished` it closes live from inside `handle`. But a row left spinning
    /// after the call it belonged to ended would be a lie either way.
    pub(crate) fn finish(mut self) {
        self.close(|driver| &mut driver.scriptlet);
        self.close(|driver| &mut driver.current);
    }
}

/// Prints what a finished step needs said in words rather than shown on its row: a warning, a
/// `.pacnew` or a `.pacsave` notice. The plain "installed X"/"removed X" fact is the row itself
/// once it is checked off — nothing here repeats it.
///
/// Write failures are ignored here rather than turned into an early return. This runs inside
/// the progress callback, from the middle of a live commit, where aborting on a broken pipe
/// would leave the transaction part-way applied. A dead stdout is instead caught by the next
/// `emit!` call after the commit finishes.
fn print_step_result(
    out: &mut impl std::io::Write,
    step: &piko_txn::Step,
    outcome: &piko_txn::progress::StepOutcome<'_>,
) {
    use piko_txn::progress::StepOutcome;
    match (step, outcome) {
        (piko_txn::Step::Install { .. }, StepOutcome::Installed { extraction, pacsaves, .. }) => {
            for path in &extraction.unreadable {
                let _ = writeln!(out, "  warning: could not hash {}", path.display());
            }
            // A `.pacnew` the user is never told about is a configuration change that never
            // happens, silently.
            for (_, step_outcome) in &extraction.outcomes {
                if let piko_txn::install::Outcome::Backup(
                    piko_txn::extract::BackupOutcome::KeptBoth { pacnew },
                ) = step_outcome
                {
                    let _ = writeln!(out, "  installed as {} -- merge it", pacnew.display());
                }
            }
            for pacsave in *pacsaves {
                let _ = writeln!(out, "  saved {} as .pacsave", pacsave.display());
            }
        }
        (piko_txn::Step::Remove { .. }, StepOutcome::Removed { pacsaves }) => {
            for pacsave in *pacsaves {
                let _ = writeln!(out, "  saved {} as .pacsave", pacsave.display());
            }
        }
        // `Step`/`StepOutcome` are reported together by construction (`Event::StepFinished`),
        // so an `Install` step never pairs with a `Removed` outcome or vice versa.
        _ => {}
    }
    // `out` is buffered (see `CommitDriver::print_line`). Without this flush, a `.pacnew`
    // notice would sit unseen until the buffer fills or the transaction ends.
    let _ = out.flush();
}
