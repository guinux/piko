//! Driving GnuPG's `gpgme_op_interact` protocol with a fixed, pre-built response script.

use std::collections::VecDeque;

/// Answers a fixed sequence of GnuPG edit-key prompts, in order, decided entirely before the
/// interaction starts.
///
/// The sequence GnuPG will ask for is fully determined by which operation was requested — a
/// `trust` command always asks for a trust digit next, a `disable` command always just needs
/// confirmation to `quit`. This is the same idea as a batch `gpg --command-fd 0` pipe, driven
/// through GPGME's structured callback instead of a subprocess's stdin. It does not read
/// GnuPG's prompt keyword at all: every real prompt (`out: Some`, as opposed to an
/// informational status line) consumes the next scripted answer, in order.
///
/// # Errors
///
/// [`gpgme::Error::GENERAL`] if GnuPG asks for more responses than were scripted — a sign the
/// assumed prompt sequence for that operation is wrong, not something a caller can recover
/// from.
pub(crate) struct ScriptedInteractor(VecDeque<&'static str>);

impl ScriptedInteractor {
    /// Builds an interactor that answers `script`, in order, one response per prompt.
    pub(crate) fn new(script: impl IntoIterator<Item = &'static str>) -> Self {
        Self(script.into_iter().collect())
    }

    /// The script for `trust <level>`, ending the session with `quit`.
    ///
    /// `edit_ownertrust.set_ultimate.okay` only fires when the level being set is Ultimate
    /// (GnuPG's own extra confirmation for the one level that self-certifies), so the `"y"` is
    /// included only then.
    pub(crate) fn set_owner_trust(level_digit: &'static str, is_ultimate: bool) -> Self {
        let mut script = vec!["trust", level_digit];
        if is_ultimate {
            script.push("y");
        }
        script.push("quit");
        Self::new(script)
    }

    /// The script for `disable`.
    pub(crate) fn disable() -> Self {
        Self::new(["disable", "quit"])
    }
}

impl gpgme::Interactor for ScriptedInteractor {
    fn interact(
        &mut self,
        _status: gpgme::InteractionStatus<'_>,
        out: Option<&mut dyn std::io::Write>,
    ) -> gpgme::Result<()> {
        let Some(out) = out else {
            // An informational status line, not a prompt — nothing to answer.
            return Ok(());
        };
        let Some(line) = self.0.pop_front() else {
            return Err(gpgme::Error::GENERAL);
        };
        out.write_all(line.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .map_err(gpgme::Error::from)
    }
}
