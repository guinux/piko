//! Progress events for a transaction's verification and committing steps. An optional,
//! caller-supplied callback reports them.

use std::path::PathBuf;

use piko_db::EntryName;

use crate::{exec, hook, install::Extraction, scriptlet, transaction::Step};

/// One thing happening while [`crate::transaction::Staged::commit_with_progress`] applies a
/// plan.
///
/// This is `#[non_exhaustive]`. Unlike `piko_net::progress::Event`, it carries a borrowed
/// [`Step`] rather than duplicating its fields, because the plan already has everything worth
/// displaying.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Event<'a> {
    /// Step `index` of `total` (both 0-based/absolute, `index < total`) is starting.
    StepStarted {
        /// 0-based position in the plan.
        index: usize,
        /// The plan's total step count. It is known entirely up front, unlike a download's
        /// byte total, because the plan already has the whole list.
        total: usize,
        /// What the step will do.
        step: &'a Step,
        /// For a [`Step::Install`], the entry it will replace, if any. This is `None` for a
        /// fresh install and always `None` for a [`Step::Remove`]. `Transaction::verify`
        /// already worked this out for every candidate, so a caller can tell an update from a
        /// fresh install before the step runs, not only from [`StepOutcome::Installed`]'s
        /// `replaced` once it has run.
        replaces: Option<&'a EntryName>,
    },
    /// The step most recently started completed without error. Its journal entry is durably
    /// recorded.
    ///
    /// A step that fails surfaces through `commit_with_progress`'s `Result` instead. This
    /// event is never emitted for a step that did not finish, and it is never the only record
    /// that a step did finish — see [`crate::Report`].
    StepFinished {
        /// The step that just finished — the same value the matching [`Event::StepStarted`]
        /// carried.
        step: &'a Step,
        /// What actually happened.
        outcome: StepOutcome<'a>,
    },
    /// A `PreTransaction` or `PostTransaction` hook phase found at least one triggered hook
    /// and is about to run it.
    ///
    /// This never fires when nothing triggered. [`Event::StepStarted`]/[`Event::StepFinished`]'s
    /// `total` is likewise never zero, since a plan with no steps is `Report::default()` before
    /// `commit_with_progress` is even called. The same "do not report an empty phase" rule
    /// applies here.
    HooksStarted {
        /// How many hooks triggered for this phase.
        total: usize,
    },
    /// One hook of the phase [`Event::HooksStarted`] is about to run.
    ///
    /// This fires before the hook's command starts, from the same `Hook` data that
    /// [`Event::HookFinished`]'s `run` later carries in finished form. A caller does not need
    /// to wait for the hook to exit to show its name or description.
    HookStarted {
        /// 0-based position among this phase's triggered hooks.
        index: usize,
        /// The same total [`Event::HooksStarted`] carried.
        total: usize,
        /// The hook's file name.
        name: &'a str,
        /// Its `Description`, if it had one.
        description: Option<&'a str>,
    },
    /// One line of the running hook's merged stdout/stderr, as it was produced.
    ///
    /// This fires zero or more times between the matching [`Event::HookStarted`] and
    /// [`Event::HookFinished`], never after. [`hook::Run::outcome`]'s own copy of the same
    /// text is already complete by then.
    HookOutputLine {
        /// 0-based position among this phase's triggered hooks.
        index: usize,
        /// The same total [`Event::HooksStarted`] carried.
        total: usize,
        /// The line, without its trailing newline.
        line: &'a str,
    },
    /// One hook of the phase [`Event::HooksStarted`] finished running.
    HookFinished {
        /// 0-based position among this phase's triggered hooks.
        index: usize,
        /// The same total [`Event::HooksStarted`] carried.
        total: usize,
        /// What it did.
        run: &'a hook::Run,
    },
    /// A package's `.INSTALL` scriptlet function is about to run.
    ///
    /// This fires only when the scriptlet actually declares `kind`'s function — see
    /// [`scriptlet::declares`]. A package that defines two of the six functions fires this
    /// event (and the matching [`Event::ScriptletFinished`]) exactly twice, not six times.
    ScriptletStarted {
        /// The package whose scriptlet this is.
        package: &'a str,
        /// Which of the six functions.
        kind: scriptlet::Kind,
    },
    /// One line of the running scriptlet's merged stdout/stderr, as it was produced.
    ///
    /// This fires zero or more times between the matching [`Event::ScriptletStarted`] and
    /// [`Event::ScriptletFinished`].
    ScriptletOutputLine {
        /// The package whose scriptlet this is.
        package: &'a str,
        /// Which of the six functions.
        kind: scriptlet::Kind,
        /// The line, without its trailing newline.
        line: &'a str,
    },
    /// The scriptlet function most recently started ([`Event::ScriptletStarted`]) finished
    /// running.
    ScriptletFinished {
        /// The package whose scriptlet this is.
        package: &'a str,
        /// Which of the six functions.
        kind: scriptlet::Kind,
        /// What it did.
        outcome: &'a exec::Outcome,
    },
}

/// What one finished step did. It carries only what [`Event::StepFinished`]'s `step` does not
/// already say.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum StepOutcome<'a> {
    /// A [`Step::Install`] finished.
    Installed {
        /// The entry it was recorded under.
        entry: &'a EntryName,
        /// The entry it replaced, if a version of this package was already installed. This is
        /// `alpm-hooks(5)`'s "upgrade" sense ("was already there"), not a version-direction
        /// comparison.
        replaced: Option<&'a EntryName>,
        /// What extraction did.
        extraction: &'a Extraction,
        /// `.pacsave` files this step created, if any (from the fake removal of a replaced
        /// version's modified backup files).
        pacsaves: &'a [PathBuf],
    },
    /// A [`Step::Remove`] finished.
    Removed {
        /// `.pacsave` files this step created, if any.
        pacsaves: &'a [PathBuf],
    },
}

/// One thing happening while [`crate::transaction::Transaction::verify_with_progress`] locates,
/// verifies, and reads every package a plan needs.
///
/// This is the same exception as [`Event`]; see this module's doc comment. It is
/// `#[non_exhaustive]` for the same reason `Event` is: a caller must not be able to
/// exhaustively match today and break on the next variant this module adds.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum VerifyEvent {
    /// One install candidate has been located (downloaded if it was not already cached) and
    /// had its signature checked. Its archive has not been opened yet.
    ///
    /// This fires only for [`Step::Install`], for the same reason as
    /// [`PackageVerified`](Self::PackageVerified). It exists because signature checking hashes
    /// the whole package file and can be the slowest single step in `verify_with_progress` for
    /// a large package. Without it, nothing is reported between the last download finishing
    /// and the first [`PackageVerified`](Self::PackageVerified), which also waits on the
    /// archive read.
    SignatureChecked {
        /// How many install candidates have had their signature checked so far, this one
        /// included (1-based, `index <= total`).
        index: usize,
        /// The plan's total install-candidate count, known up front from the plan itself.
        total: usize,
    },
    /// One install candidate has been located (downloaded if it was not already cached),
    /// had its signature checked, and had its archive opened and parsed.
    ///
    /// This fires only for [`Step::Install`]. A [`Step::Remove`] neither downloads nor
    /// verifies anything, so it does not count toward `total`.
    PackageVerified {
        /// How many install candidates have been verified so far, this one included (1-based,
        /// `index <= total`). Unlike [`Event::StepStarted`]'s `index`, there is no matching
        /// "started" event to pair a 0-based position with.
        index: usize,
        /// The plan's total install-candidate count, known up front from the plan itself.
        total: usize,
    },
    /// Every candidate has been verified. The single whole-plan file-conflict check is about
    /// to run.
    ///
    /// This is not itself countable: `conflict::check` walks the filesystem once for the whole
    /// plan, not once per package. So, unlike [`PackageVerified`](VerifyEvent::PackageVerified),
    /// this is a start marker with no matching "finished" event. The caller learns it ended
    /// when `verify_with_progress` returns.
    ConflictCheckStarted,
}
