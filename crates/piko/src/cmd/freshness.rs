//! Printing what piko learned about how recent a repository database is.
//!
//! Every decision is made in a library. `piko_net` decides what a refresh installs and returns
//! [`FreshnessNote`]s. `piko_db::repo::freshness` judges an age. This module only turns those
//! values into lines on stderr.
//!
//! A note about a mirror that is merely behind is a `Note:`, because it is common and the
//! refresh already worked around it. A note that may be an attack, or that leaves the system on
//! an old database, is a `Warning:`.

use std::time::{Duration, SystemTime};

use piko_db::repo::{
    RepoName,
    freshness::{self, Comparison, DEFAULT_MAX_AGE, Publication, Staleness, Tier},
};
use piko_net::FreshnessNote;

/// Seconds in a day, the unit `--max-age` is given in.
const DAY: u64 = 86_400;

/// `--max-age`'s default, in days: [`DEFAULT_MAX_AGE`].
pub const DEFAULT_MAX_AGE_DAYS: u64 = DEFAULT_MAX_AGE.as_secs() / DAY;

/// Turns `--max-age <DAYS>` into an age limit. `0` turns the limit off.
#[must_use]
pub fn max_age(days: u64) -> Option<Duration> {
    (days > 0).then(|| Duration::from_secs(days.saturating_mul(DAY)))
}

/// The line to print for one note about `file`, prefix included.
pub fn render_note(file: &str, note: &FreshnessNote, offset: piko_txn::LocalOffset) -> String {
    match note {
        FreshnessNote::Behind { server, last_modified } => format!(
            "Note: {server} is older than the installed {file} (last modified {}). Piko tried \
             the next server.",
            date(*last_modified, offset)
        ),
        FreshnessNote::RefusedOlder { server, candidate, installed, comparison } => {
            match comparison {
                Comparison::LostAuthentication => format!(
                    "Warning: Piko refused the {file} from {server}. It has no valid signature, \
                     and the installed one is signed ({}). A mirror can do this to hold back \
                     updates.",
                    describe(*installed, offset)
                ),
                _ if candidate.is_some_and(|candidate| candidate.tier == Tier::Authenticated) => {
                    format!(
                        "Warning: Piko refused a signed {file} from {server} that is older than \
                         the installed one ({}, installed {}). A mirror can do this to hold back \
                         updates.",
                        describe(*candidate, offset),
                        describe(*installed, offset)
                    )
                }
                _ => format!(
                    "Note: {server} has an older {file} than the installed one ({}, installed \
                     {}). Piko tried the next server.",
                    describe(*candidate, offset),
                    describe(*installed, offset)
                ),
            }
        }
        FreshnessNote::AcceptedOlder { server, candidate, replaced } => format!(
            "Warning: Piko installed an older {file} from {server} ({}, the previous one {}), \
             because you gave --accept-older.",
            describe(*candidate, offset),
            describe(*replaced, offset)
        ),
        FreshnessNote::Stale { publication, age, max_age, probed } => {
            let checked = match probed {
                0 => "No other server was available to check it against.".to_owned(),
                1 => "1 other server has nothing newer.".to_owned(),
                many => format!("{many} other servers have nothing newer."),
            };
            format!(
                "Warning: {file} is {} old ({}). {checked} A mirror may be out of date, or may \
                 hold back updates. The limit is {} (--max-age).",
                human_age(*age),
                describe(Some(*publication), offset),
                human_age(*max_age)
            )
        }
        FreshnessNote::FromTheFuture { publication, ahead } => {
            future(file, *publication, *ahead, offset)
        }
        // `FreshnessNote` is non-exhaustive. A kind this build does not know is still worth a
        // line, rather than silence.
        other => format!("Note: {file}: {other:?}"),
    }
}

/// The line for a refresh that kept the installed database because every server was older.
pub fn render_kept(
    file: &str,
    installed: Option<Publication>,
    offset: piko_txn::LocalOffset,
) -> String {
    format!(
        "Warning: No server has a {file} as new as the installed one ({}). Piko keeps the \
         installed database.",
        describe(installed, offset)
    )
}

/// Warns about each repository database that is too old, or dated in the future.
///
/// For a command that reads the databases on disk without refreshing them: `piko plan -u`,
/// `piko update --norefresh`, and `piko check-updates`. They cannot ask a mirror for anything
/// newer, so each warning ends by pointing at `piko refresh`.
pub fn report_stale<'a>(
    databases: impl IntoIterator<Item = (&'a RepoName, Option<Publication>)>,
    now: SystemTime,
    max_age: Option<Duration>,
    offset: piko_txn::LocalOffset,
) {
    for (repo, publication) in databases {
        let Some(publication) = publication else { continue };
        let file = format!("{repo}.db");
        match freshness::staleness(publication, now, max_age) {
            Staleness::Fresh => {}
            Staleness::Stale { age } => eprintln!(
                "Warning: {file} is {} old ({}). The limit is {} (--max-age). Run 'piko \
                 refresh' to check the mirrors for a newer one.",
                human_age(age),
                describe(Some(publication), offset),
                human_age(max_age.unwrap_or_default())
            ),
            Staleness::FromTheFuture { ahead } => {
                eprintln!("{}", future(&file, publication, ahead, offset));
            }
        }
    }
}

fn future(
    file: &str,
    publication: Publication,
    ahead: Duration,
    offset: piko_txn::LocalOffset,
) -> String {
    format!(
        "Warning: {file} is dated {} in the future ({}). Check the system clock.",
        human_age(ahead),
        describe(Some(publication), offset)
    )
}

/// Says when a database was published, and whether a signature vouches for the date.
fn describe(publication: Option<Publication>, offset: piko_txn::LocalOffset) -> String {
    match publication {
        Some(Publication { at, tier: Tier::Authenticated }) => {
            format!("signed {}", date(at, offset))
        }
        Some(Publication { at, tier: Tier::Unauthenticated }) => {
            format!("published {}", date(at, offset))
        }
        None => "undated".to_owned(),
    }
}

fn date(seconds: u64, offset: piko_txn::LocalOffset) -> String {
    crate::output::human_date(i64::try_from(seconds).unwrap_or(i64::MAX), offset)
}

/// Renders a duration in the largest whole unit that fits: days, then hours, then minutes.
fn human_age(age: Duration) -> String {
    let seconds = age.as_secs();
    let (count, unit) = if seconds >= DAY {
        (seconds / DAY, "day")
    } else if seconds >= 3_600 {
        (seconds / 3_600, "hour")
    } else {
        (seconds / 60, "minute")
    };
    if count == 1 { format!("1 {unit}") } else { format!("{count} {unit}s") }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    fn utc() -> piko_txn::LocalOffset {
        piko_txn::LocalOffset::UTC
    }

    #[test]
    fn zero_days_turns_the_limit_off() {
        assert_eq!(max_age(0), None);
        assert_eq!(max_age(14), Some(DEFAULT_MAX_AGE));
        assert_eq!(DEFAULT_MAX_AGE_DAYS, 14);
    }

    #[test]
    fn ages_use_the_largest_whole_unit() {
        assert_eq!(human_age(Duration::from_secs(16 * DAY + 3_600)), "16 days");
        assert_eq!(human_age(Duration::from_secs(DAY)), "1 day");
        assert_eq!(human_age(Duration::from_secs(7_200)), "2 hours");
        assert_eq!(human_age(Duration::from_secs(90)), "1 minute");
    }

    /// A mirror that is behind is common and already worked around, so it is a note. A signed
    /// database that goes backwards may be an attack, so it is a warning.
    #[test]
    fn a_signed_rollback_warns_and_a_lagging_mirror_notes() {
        let old = Some(Publication { at: 1_000, tier: Tier::Authenticated });
        let new = Some(Publication { at: 2_000, tier: Tier::Authenticated });
        let signed = FreshnessNote::RefusedOlder {
            server: "https://a.example/core.db".to_owned(),
            candidate: old,
            installed: new,
            comparison: Comparison::Older,
        };
        assert!(render_note("core.db", &signed, utc()).starts_with("Warning: "));

        let unsigned = FreshnessNote::RefusedOlder {
            server: "https://a.example/core.db".to_owned(),
            candidate: Some(Publication { at: 1_000, tier: Tier::Unauthenticated }),
            installed: Some(Publication { at: 2_000, tier: Tier::Unauthenticated }),
            comparison: Comparison::Older,
        };
        let line = render_note("core.db", &unsigned, utc());
        assert!(line.starts_with("Note: "), "{line}");
        assert!(line.contains("tried the next server"), "{line}");
    }

    #[test]
    fn a_stale_note_names_the_age_and_the_limit() {
        let note = FreshnessNote::Stale {
            publication: Publication { at: 0, tier: Tier::Unauthenticated },
            age: Duration::from_secs(16 * DAY),
            max_age: DEFAULT_MAX_AGE,
            probed: 3,
        };
        let line = render_note("core.db", &note, utc());
        assert!(line.contains("16 days old"), "{line}");
        assert!(line.contains("3 other servers"), "{line}");
        assert!(line.contains("The limit is 14 days"), "{line}");
    }
}
