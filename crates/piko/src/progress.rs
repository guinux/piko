//! A live, stacked list of transaction steps. A spinner runs on stderr while an item runs, and a
//! plain checkmark line on stdout names it.
//!
//! That checkmark line is written as soon as the item has something to print underneath, and
//! otherwise when the item finishes. So a name always comes before the output it frames. That
//! holds in a captured log as much as on a terminal. stderr and its spinner are not there to fill
//! the gap. The glyph marks the line that names whatever follows it. How the item ended is
//! reported separately by `cmd::txn::report_side_effects`, which never reads the glyph.
//!
//! Lines nest by two spaces per level. A package step or a hook sits at column zero. A scriptlet
//! sits under its step, and each item's own output one level further in again.
//!
//! A row is never left as a permanently kept `indicatif` bar. `MultiProgress` redraws its whole
//! managed stack together on every tick, and assumes that stack fits on screen. A transaction
//! touching hundreds of packages would leave that many finished bars behind. It would overflow the
//! terminal and corrupt the redraw: dropped lines, checkmarks that never appear. For
//! [`VerifyDriver`] the same holds of a long download or verify phase ahead of one. Instead, at
//! most a handful of rows are ever alive in the `indicatif::MultiProgress` at once. A finished one
//! is cleared with `finish_and_clear()`, never bare `finish()`. Its text is reprinted as a plain
//! line through [`StepList::suspend`], which lands in ordinary scrollback that `indicatif` has no
//! further say over. `print_step_result` (stdout) still exists for what a row cannot show: a
//! `.pacnew`/`.pacsave` notice, or a warning.

use std::{
    collections::BTreeSet,
    str::FromStr,
    sync::{Mutex, PoisonError},
};

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
    /// Used where the total is not known until the download's own `Started` event reports it.
    /// That is a single-file `piko refresh` row, unlike the grouped multi-file install-download
    /// row.
    pub(crate) fn set_length(&self, len: u64) {
        self.bar.set_length(len);
    }

    /// Leaves the message in place and swaps the spinner for a green check. It freezes whatever
    /// count or byte total the row last showed, permanently.
    ///
    /// For a caller with a small, bounded number of rows it intends to keep on screen for the
    /// whole run. `cmd::refresh`'s one row per configured repository is that caller.
    /// [`Self::finish_and_clear`] is what [`VerifyDriver`] and [`CommitDriver`] use instead. A row
    /// that could number in the hundreds, one package or one hook, cannot be kept this way. See
    /// this module's doc comment.
    pub(crate) fn finish(self) {
        self.bar.set_style(style(self.kind, true));
        self.bar.finish();
    }

    /// As [`Row::finish`], but replaces the message first. It also drops whatever bytes or
    /// count template the row started with.
    ///
    /// Used for an outcome (e.g. "up to date") that measured nothing.
    pub(crate) fn finish_plain(self, text: impl Into<String>) {
        self.bar.set_style(style(Kind::Spinner, true));
        self.bar.set_message(text.into());
        self.bar.finish();
    }

    /// Removes the row from the display entirely, rather than leaving it checked off.
    ///
    /// What [`VerifyDriver`] and [`CommitDriver`] call on every row they open. Printing its final
    /// text as a plain line follows immediately; see this module's doc comment.
    /// [`VerifyDriver::finish_download`] also uses this bare, with no reprint, for the head row
    /// naming in-flight downloads. That row has nothing worth freezing once nothing is left in
    /// flight. The byte total the download row itself settled on already says what was fetched.
    pub(crate) fn finish_and_clear(self) {
        self.bar.finish_and_clear();
    }
}

/// The draw handle of the most recently built [`StepList`].
///
/// `ctrlc` runs its handler on a thread of its own. That thread has no path to the `StepList`
/// the command built. This static is that path. See [`suspend_active`].
///
/// The newest list wins. Nothing ever unregisters. A `MultiProgress` whose rows are all
/// finished draws nothing. So a stale handle costs one lock and a redraw of an empty stack.
/// `Mutex::new` is `const`, so this needs no `OnceLock` around it.
static ACTIVE: Mutex<Option<MultiProgress>> = Mutex::new(None);

/// Runs `body` with the live rows of the current [`StepList`] hidden.
///
/// The counterpart of [`StepList::suspend`] for a caller holding no list: the `SIGINT` handler,
/// concretely. It runs `body` unchanged when no list exists yet.
///
/// This waits for indicatif's draw lock. Two holders are brief: a row update, and one line
/// through [`CommitDriver::print_line`]. One is not. A caller that suspends around a blocking
/// read holds the lock for as long as that read takes. `cmd::txn`'s provider question does
/// exactly that. So the handler's instant-kill path prints without this function.
pub(crate) fn suspend_active<R>(body: impl FnOnce() -> R) -> R {
    let active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner).clone();
    match active {
        Some(mp) => mp.suspend(body),
        None => body(),
    }
}

/// Clears the current [`StepList`]'s rows permanently.
///
/// For a caller that is about to end the process. Unlike [`suspend_active`], the rows never
/// come back. This also releases the draw lock before it returns.
pub(crate) fn clear_active() {
    let active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner).clone();
    if let Some(mp) = active {
        let _ = mp.clear();
    }
}

/// The stack of live rows for one transaction, each added as its phase starts.
pub(crate) struct StepList {
    mp: MultiProgress,
}

impl StepList {
    /// Builds a list. It becomes the one [`suspend_active`] writes around.
    ///
    /// This registers the list here rather than at each call site. A command cannot forget it
    /// that way. A `MultiProgress` clone shares the state of the one it came from.
    pub(crate) fn new() -> Self {
        let mp = MultiProgress::new();
        *ACTIVE.lock().unwrap_or_else(PoisonError::into_inner) = Some(mp.clone());
        Self { mp }
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
/// Package file names carry a version, a pkgrel, and an architecture. Three of those side by side
/// is a line nobody can read. So each is reduced to the package name it starts with. A name that
/// does not parse, such as the database `core.db`, is shown as it is.
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

/// Clears the download rows of a run that stops before anything is fetched.
///
/// This clears the rows rather than settling them. A checked-off "Downloading packages" line
/// would claim work that never happened. The clear also stops the steady tick, so the caller's
/// refusal reaches the terminal whole. A live row redraws over a bare `eprintln!` mid-line.
///
/// Two call sites hand these rows to [`VerifyDriver`] once the run reaches it. Both report
/// refusals before that point. One function keeps their answer to "clear or settle" the same.
pub(crate) fn clear_download_rows(row: Option<Row>, head: Option<Row>) {
    for row in [row, head].into_iter().flatten() {
        row.finish_and_clear();
    }
}

/// Drives a per-repository download [`Row`] for `piko refresh`.
///
/// Each `piko refresh` row covers exactly one database file, so its total is not known until the
/// download's own `Started` event reports it. The grouped multi-file install-download row differs:
/// its total comes from the plan, up front.
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

/// Clears `row` and reprints `text` as a plain, checked-off line. It goes through
/// [`StepList::suspend`], so it lands in ordinary scrollback rather than `indicatif`'s managed
/// area. This is the convention this module's doc comment explains. Every caller with a row that
/// could recur many times uses this instead of [`Row::finish`]. Those are a resolved dependency
/// set, a package, a hook, and a download or verify phase.
pub(crate) fn settle_row(steplist: &StepList, out: &mut impl std::io::Write, row: Row, text: &str) {
    settle_row_indented(steplist, out, row, "", text);
}

/// As [`settle_row`], with `indent` ahead of the check.
///
/// [`CommitDriver`] nests its lines, and prints this same line from two places. One is the moment
/// the item first has output to frame. The other is when it finishes having said nothing. Both go
/// through here, so the two positions cannot drift into two different formats.
pub(crate) fn settle_row_indented(
    steplist: &StepList,
    out: &mut impl std::io::Write,
    row: Row,
    indent: &str,
    text: &str,
) {
    row.finish_and_clear();
    steplist.suspend(|| {
        let _ = writeln!(out, "{indent}{} {text}", checkmark());
        let _ = out.flush();
    });
}

/// The plain-line indent for a row nested `depth` levels deep: two spaces per level.
fn indent_for(depth: usize) -> String {
    "  ".repeat(depth)
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
    space_row: Option<Row>,
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
            space_row: None,
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
            E::DiskSpaceCheckStarted => {
                self.finish_download();
                self.settle_signature();
                self.settle_verify();
                self.settle_conflict();
                self.space_row = Some(self.steplist.spinner("Checking available disk space"));
            }
            // `VerifyEvent` is `#[non_exhaustive]`.
            _ => {}
        }
    }

    /// The download row settles as "Downloading packages" once nothing is currently downloading.
    /// The head row naming in-flight files is cleared outright instead. It has nothing worth
    /// freezing once nothing is left in flight. The byte total the download row itself settled on
    /// already says what was fetched.
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

    fn settle_conflict(&mut self) {
        if let Some(row) = self.conflict_row.take() {
            self.settle(row, "Checking file conflicts");
        }
    }

    fn settle_space(&mut self) {
        if let Some(row) = self.space_row.take() {
            self.settle(row, "Checking available disk space");
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
        self.settle_conflict();
        self.settle_space();
    }
}

/// Drives one line per package and one line per hook through a `Staged::commit_with_progress`
/// call. A spinner with `(n/total)` on the right runs while that item runs, and a plain checkmark
/// line names it. It also prints whatever [`print_step_result`] has to say about `out` as each
/// install or remove step finishes.
///
/// The checkmark line is written by [`Self::announce`] the moment the item produces its first
/// line of output, and by [`Self::close`] otherwise. Announcing cascades outwards first, so a
/// scriptlet's chatter lands under the scriptlet's name, which lands under its package's. An item
/// that announced early is only cleared when it finishes. Printing its name a second time would
/// say the same thing twice.
///
/// This keeps at most two rows alive at once: one package-or-hook row, and one nested scriptlet
/// row. Each finished item becomes an ordinary printed line instead, through
/// [`StepList::suspend`]. See this module's doc comment for why no row is ever kept.
pub(crate) struct CommitDriver<'a, W> {
    steplist: &'a StepList,
    out: &'a mut W,
    /// The currently running package-or-hook row. At most one at a time:
    /// `commit_with_progress` emits step and hook events strictly one after another, never
    /// interleaved.
    current: Option<OpenRow>,
    /// As `current`, for the nested "Running … script" row. Opens and closes at most twice
    /// within a package row's lifetime (once per scriptlet function), never overlapping
    /// itself.
    scriptlet: Option<OpenRow>,
}

/// One live [`CommitDriver`] row, with what its plain line says and whether it has said it.
struct OpenRow {
    /// The live row on stderr. Cleared by whichever of the two positions prints the plain line.
    row: Row,
    /// The text the row was opened with, and what its plain line reads.
    text: String,
    /// How deep the row nests: zero for a package step or a hook, one for a scriptlet under a
    /// step. Its own output takes one level more.
    depth: usize,
    /// Whether the plain line has been written already, ahead of the output it frames.
    announced: bool,
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
            E::HookOutputLine { line, .. } => self.print_line(line),
            E::HookFinished { .. } => self.close(|driver| &mut driver.current),
            E::ScriptletStarted { kind, .. } => {
                let text = format!("Running {} script", kind.as_str().replace('_', " "));
                let row = self.steplist.spinner(&text);
                self.scriptlet = Some(OpenRow { row, text, depth: 1, announced: false });
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

    /// Opens a transient [`Kind::Counted`] row for `text`, at 1-based position `index + 1` of
    /// `total`. It keeps `text` alongside the row, for the plain line that will name it.
    fn open_counted(&self, text: &str, index: usize, total: usize) -> OpenRow {
        let row = self.steplist.counted(text, total);
        row.set_position(index.saturating_add(1) as u64);
        OpenRow { row, text: text.to_owned(), depth: 0, announced: false }
    }

    /// Clears whichever row `slot` names, printing its plain line first if nothing else has.
    fn close(&mut self, slot: impl FnOnce(&mut Self) -> &mut Option<OpenRow>) {
        if let Some(open) = slot(self).take() {
            if open.announced {
                open.row.finish_and_clear();
            } else {
                let indent = indent_for(open.depth);
                settle_row_indented(self.steplist, self.out, open.row, &indent, &open.text);
            }
        }
    }

    /// Writes the plain line of every open row that has not written one yet, outermost first.
    /// Output then lands under the thing that produced it.
    fn announce(&mut self) {
        Self::announce_row(self.steplist, &mut *self.out, self.current.as_mut());
        Self::announce_row(self.steplist, &mut *self.out, self.scriptlet.as_mut());
    }

    /// Writes one row's plain line, if it has not been written already.
    ///
    /// This takes `steplist`, `out` and the row separately rather than `&mut self`. It borrows two
    /// fields of the driver at once. The borrow checker needs to see them as the distinct fields
    /// they are.
    fn announce_row(steplist: &StepList, out: &mut W, slot: Option<&mut OpenRow>) {
        let Some(open) = slot else { return };
        if open.announced {
            return;
        }
        open.announced = true;
        // Retiring the spinner here is what keeps the phrase on screen once rather than twice.
        // Twice means checked off in the scrollback, and still spinning at the foot of the
        // display. An item with output of its own needs no spinner to show it is working.
        let indent = indent_for(open.depth);
        settle_row_indented(steplist, out, open.row.clone(), &indent, &open.text);
    }

    /// Names whatever is running, then writes and immediately flushes one line of its output.
    ///
    /// The indent comes from the innermost open row. So the one decision about how deep a line
    /// sits is made here, rather than at each event arm.
    ///
    /// `out` is a `BufWriter` (`main.rs`). `piko list` writes over a thousand lines and wants it
    /// buffered. That is exactly wrong for a line meant to appear the instant it happens. Without
    /// an explicit flush it sits in the buffer until 8 KiB accumulates or the process exits. A live
    /// transaction would then print in bursts instead of one line at a time.
    fn print_line(&mut self, text: &str) {
        self.announce();
        let innermost = self.scriptlet.as_ref().or(self.current.as_ref());
        let indent =
            innermost.map_or_else(String::new, |open| indent_for(open.depth.saturating_add(1)));
        let out = &mut *self.out;
        self.steplist.suspend(|| {
            let _ = writeln!(out, "{indent}{text}");
            let _ = out.flush();
        });
    }

    /// Closes off whichever row is still open once `commit_with_progress` has returned. This is
    /// not expected in the ordinary case. Every `*Started` this module opens is matched by a
    /// `*Finished` it closes live from inside `handle`. But a row left spinning after the call it
    /// belonged to ended would be a lie either way.
    pub(crate) fn finish(mut self) {
        self.close(|driver| &mut driver.scriptlet);
        self.close(|driver| &mut driver.current);
    }
}

/// Prints what a finished step needs said in words rather than shown on its row. That is a
/// warning, or a `.pacnew` or `.pacsave` notice. The plain "installed X"/"removed X" fact is the
/// row itself
/// once it is checked off — nothing here repeats it.
///
/// Write failures are ignored here rather than turned into an early return. This runs inside the
/// progress callback, from the middle of a live commit. Aborting there on a broken pipe would
/// leave the transaction part-way applied. A dead stdout is instead caught by the next
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
                let _ = writeln!(out, "  Warning: could not hash {}", path.display());
            }
            // A `.pacnew` the user is never told about is a configuration change that never
            // happens, silently.
            for (_, step_outcome) in &extraction.outcomes {
                if let piko_txn::install::Outcome::Backup(
                    piko_txn::extract::BackupOutcome::KeptBoth { pacnew },
                ) = step_outcome
                {
                    let _ = writeln!(out, "  Installed as {} -- merge it", pacnew.display());
                }
            }
            for pacsave in *pacsaves {
                let _ = writeln!(out, "  Saved {} as .pacsave", pacsave.display());
            }
        }
        (piko_txn::Step::Remove { .. }, StepOutcome::Removed { pacsaves }) => {
            for pacsave in *pacsaves {
                let _ = writeln!(out, "  Saved {} as .pacsave", pacsave.display());
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    reason = "a test that cannot unwrap or assert is not a test"
)]
mod tests {
    use piko_txn::{
        exec::{Outcome, Status},
        progress::Event,
        scriptlet::Kind as ScriptletKind,
    };

    use super::*;

    /// A scriptlet or hook that ran and exited zero. None of these tests read it: the driver
    /// renders the row it opened, not the outcome, which `cmd::txn::report_side_effects` owns.
    fn succeeded() -> Outcome {
        Outcome { status: Status::Exited(0), output: Vec::new(), truncated: false }
    }

    fn started() -> Event<'static> {
        Event::ScriptletStarted { package: "foo", kind: ScriptletKind::PostInstall }
    }

    fn output(line: &str) -> Event<'_> {
        Event::ScriptletOutputLine { package: "foo", kind: ScriptletKind::PostInstall, line }
    }

    fn finished(outcome: &Outcome) -> Event<'_> {
        Event::ScriptletFinished { package: "foo", kind: ScriptletKind::PostInstall, outcome }
    }

    /// Returns what a driver wrote, with styling removed.
    ///
    /// `console` decides on color by testing file descriptor 1, never the sink it is handed. So a
    /// suite run from a terminal styles the ✓ these tests capture into a `Vec<u8>`, and a piped one
    /// does not. The subject here is which lines come out, in which order, at which indent. The
    /// colors are [`crate::style`]'s to test.
    fn rendered(out: Vec<u8>) -> String {
        let text = String::from_utf8(out).unwrap();
        console::strip_ansi_codes(&text).into_owned()
    }

    /// The `SIGINT` handler runs `body` whether or not a command has built a list yet.
    ///
    /// `ACTIVE` is process-wide. These tests share a process with every other test in this
    /// module. So this pins what the handler needs and nothing more. The closure runs, and its
    /// value comes back. Which list is registered does not change that.
    #[test]
    fn suspending_around_the_active_list_runs_the_body_either_way() {
        assert_eq!(suspend_active(|| 1 + 1), 2);

        let _steplist = StepList::new();
        assert_eq!(suspend_active(|| 1 + 1), 2);
    }

    /// `clear_active` is safe with no list registered, and with one holding a live row.
    ///
    /// The handler calls it on a path that exits the process straight after. A panic there
    /// would replace an exit code of 130 with one of 101.
    #[test]
    fn clearing_the_active_list_is_safe_with_and_without_a_row() {
        clear_active();

        let steplist = StepList::new();
        let row = steplist.spinner("Downloading packages");
        clear_active();
        row.finish_and_clear();
    }

    #[test]
    fn a_silent_scriptlet_is_named_once_it_finishes() {
        let steplist = StepList::new();
        let mut out = Vec::new();
        let mut driver = CommitDriver::new(&steplist, &mut out);
        let outcome = succeeded();
        driver.handle(started());
        driver.handle(finished(&outcome));
        driver.finish();
        assert_eq!(rendered(out), "  ✓ Running post install script\n");
    }

    #[test]
    fn a_scriptlet_that_prints_is_named_before_its_output_and_not_again_after() {
        let steplist = StepList::new();
        let mut out = Vec::new();
        let mut driver = CommitDriver::new(&steplist, &mut out);
        let outcome = succeeded();
        driver.handle(started());
        driver.handle(output("Updating icon cache"));
        driver.handle(finished(&outcome));
        driver.finish();
        assert_eq!(rendered(out), "  ✓ Running post install script\n    Updating icon cache\n");
    }

    /// The cascade: the package step is named before the scriptlet nested under it, although
    /// the scriptlet is what asked for a line. `open_counted` stands in for
    /// `Event::StepStarted`, whose `Step` needs a whole package to build.
    #[test]
    fn a_nested_scriptlet_names_its_step_before_itself() {
        let steplist = StepList::new();
        let mut out = Vec::new();
        let mut driver = CommitDriver::new(&steplist, &mut out);
        let outcome = succeeded();
        driver.current = Some(driver.open_counted("Installing foo", 0, 1));
        driver.handle(started());
        driver.handle(output("Updating icon cache"));
        driver.handle(finished(&outcome));
        driver.finish();
        assert_eq!(
            rendered(out),
            "✓ Installing foo\n  ✓ Running post install script\n    Updating icon cache\n"
        );
    }

    #[test]
    fn a_hook_is_named_by_its_description_before_its_output() {
        let steplist = StepList::new();
        let mut out = Vec::new();
        let mut driver = CommitDriver::new(&steplist, &mut out);
        let run = piko_txn::hook::Run {
            name: "10-foo.hook".to_owned(),
            description: Some("Reloading system manager configuration".to_owned()),
            outcome: Some(succeeded()),
            unsatisfied: None,
            fatal: false,
        };
        driver.handle(Event::HookStarted {
            index: 0,
            total: 1,
            name: "10-foo.hook",
            description: Some("Reloading system manager configuration"),
        });
        driver.handle(Event::HookOutputLine { index: 0, total: 1, line: "Running in chroot" });
        driver.handle(Event::HookFinished { index: 0, total: 1, run: &run });
        driver.finish();
        assert_eq!(
            rendered(out),
            "✓ Reloading system manager configuration\n  Running in chroot\n"
        );
    }
}
