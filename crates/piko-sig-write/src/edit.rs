//! Driving GnuPG's `gpgme_op_interact` protocol with a fixed, pre-built response script.

use std::collections::VecDeque;

/// GnuPG's top-level `--edit-key` menu prompt.
const KEYEDIT_PROMPT: &str = "keyedit.prompt";

/// The trust-level digit prompt the `trust` command opens.
const OWNERTRUST_VALUE: &str = "edit_ownertrust.value";

/// The extra confirmation GnuPG asks for Ultimate, and for no other level.
const SET_ULTIMATE_OKAY: &str = "edit_ownertrust.set_ultimate.okay";

/// One scripted answer: the prompt GnuPG must be asking, and the text to send it.
type Answer = (&'static str, &'static str);

/// Answers a fixed sequence of GnuPG edit-key prompts, decided before the interaction starts.
///
/// The sequence is fully determined by the requested operation. A `trust` command always asks
/// for a trust digit next, and a `disable` command always just needs `quit`. This is the same
/// idea as a batch `gpg --command-fd 0` pipe, driven through GPGME's structured callback rather
/// than a subprocess's stdin.
///
/// Each answer names the prompt it belongs to, and this interactor refuses a prompt that does
/// not match. A script that answers by position alone holds only while GnuPG's sequence holds.
/// Any change in that sequence then sends a wrong answer to a real prompt. For a tool that
/// edits trust, a refusal is the safe direction.
///
/// The prompt name is `gpgme_interact`'s *args* field, not its *keyword* field. `keyword()`
/// carries the status code, which is `GET_LINE` or `GET_BOOL` and does not identify the
/// question. Measured against GnuPG 2.4.9, `args()` carries [`KEYEDIT_PROMPT`],
/// [`OWNERTRUST_VALUE`], and [`SET_ULTIMATE_OKAY`].
///
/// # Errors
///
/// [`gpgme::Error::INV_VALUE`] if GnuPG asks a prompt the script does not expect at that point.
/// [`gpgme::Error::GENERAL`] if it asks for more answers than the script holds. Neither is
/// recoverable by a caller: both mean the assumed sequence for that operation is wrong.
pub(crate) struct ScriptedInteractor(VecDeque<Answer>);

impl ScriptedInteractor {
    /// Builds an interactor that answers `script`, in order, one answer per prompt.
    pub(crate) fn new(script: impl IntoIterator<Item = Answer>) -> Self {
        Self(script.into_iter().collect())
    }

    /// The script for `trust <level>`, ending the session with `quit`.
    ///
    /// GnuPG asks [`SET_ULTIMATE_OKAY`] only when the level being set is Ultimate. That is
    /// its own extra confirmation for the one level that self-certifies. The `"y"` therefore
    /// belongs in the script only then.
    pub(crate) fn set_owner_trust(level_digit: &'static str, is_ultimate: bool) -> Self {
        let mut script = vec![(KEYEDIT_PROMPT, "trust"), (OWNERTRUST_VALUE, level_digit)];
        if is_ultimate {
            script.push((SET_ULTIMATE_OKAY, "y"));
        }
        script.push((KEYEDIT_PROMPT, "quit"));
        Self::new(script)
    }

    /// The script for `disable`.
    pub(crate) fn disable() -> Self {
        Self::new([(KEYEDIT_PROMPT, "disable"), (KEYEDIT_PROMPT, "quit")])
    }
}

impl gpgme::Interactor for ScriptedInteractor {
    fn interact(
        &mut self,
        status: gpgme::InteractionStatus<'_>,
        out: Option<&mut dyn std::io::Write>,
    ) -> gpgme::Result<()> {
        let Some(out) = out else {
            // An informational status line, not a prompt. Nothing to answer.
            return Ok(());
        };
        let Some((expected, response)) = self.0.pop_front() else {
            return Err(gpgme::Error::GENERAL);
        };
        if !status.args().is_ok_and(|prompt| prompt == expected) {
            return Err(gpgme::Error::INV_VALUE);
        }
        out.write_all(response.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .map_err(gpgme::Error::from)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    /// GPGME builds an `InteractionStatus` itself and exposes no constructor, so the callback
    /// cannot be driven from here. The scripts can. An answer paired with the wrong prompt is
    /// the worst failure available. It sends a trust digit to the menu, or a menu command to
    /// the digit prompt. `admin`'s own `set_owner_trust` and `disable` tests drive the real
    /// protocol, and fail outright if a name here is wrong.
    #[test]
    fn each_answer_is_paired_with_the_prompt_it_belongs_to() {
        let full = ScriptedInteractor::set_owner_trust("4", false);
        assert_eq!(
            full.0.into_iter().collect::<Vec<_>>(),
            vec![
                ("keyedit.prompt", "trust"),
                ("edit_ownertrust.value", "4"),
                ("keyedit.prompt", "quit"),
            ]
        );

        let ultimate = ScriptedInteractor::set_owner_trust("5", true);
        assert_eq!(
            ultimate.0.into_iter().collect::<Vec<_>>(),
            vec![
                ("keyedit.prompt", "trust"),
                ("edit_ownertrust.value", "5"),
                ("edit_ownertrust.set_ultimate.okay", "y"),
                ("keyedit.prompt", "quit"),
            ]
        );

        let disable = ScriptedInteractor::disable();
        assert_eq!(
            disable.0.into_iter().collect::<Vec<_>>(),
            vec![("keyedit.prompt", "disable"), ("keyedit.prompt", "quit")]
        );
    }

    /// Only Ultimate carries the extra confirmation.
    #[test]
    fn only_ultimate_answers_the_extra_confirmation() {
        for digit in ["2", "3", "4"] {
            let script = ScriptedInteractor::set_owner_trust(digit, false);
            assert!(
                script.0.iter().all(|(prompt, _)| *prompt != SET_ULTIMATE_OKAY),
                "level {digit} must not answer {SET_ULTIMATE_OKAY}"
            );
        }
    }
}
