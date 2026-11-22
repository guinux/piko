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
use crate::i18n::{tr, warning};

const DAY: u64 = 86_400;

/// `--max-age`'s default, in days: [`DEFAULT_MAX_AGE`].
pub const DEFAULT_MAX_AGE_DAYS: u64 = DEFAULT_MAX_AGE.as_secs() / DAY;

/// Turns `--max-age <DAYS>` into an age limit. `0` turns the limit off.
#[must_use]
pub fn max_age(days: u64) -> Option<Duration> {
    (days > 0).then(|| Duration::from_secs(days.saturating_mul(DAY)))
}

/// The line to print for one note about `file`, prefix included.
pub fn render_note(file: &str, note: &FreshnessNote, zone: piko_txn::history::LocalZone) -> String {
    match note {
        FreshnessNote::Behind { server, last_modified } => crate::i18n::note(&tr!(
            "fresh-behind",
            server = server.to_string(),
            file = file,
            date = date(*last_modified, zone)
        )),
        FreshnessNote::RefusedOlder { server, candidate, installed, comparison } => {
            match comparison {
                Comparison::LostAuthentication => warning(&tr!(
                    "fresh-lost-signature",
                    file = file,
                    server = server.to_string(),
                    installed = describe(*installed, zone)
                )),
                _ if candidate.is_some_and(|candidate| candidate.tier == Tier::Authenticated) => {
                    warning(&tr!(
                        "fresh-refused-older",
                        file = file,
                        server = server.to_string(),
                        candidate = describe(*candidate, zone),
                        installed = describe(*installed, zone)
                    ))
                }
                _ => crate::i18n::note(&tr!(
                    "fresh-older",
                    server = server.to_string(),
                    file = file,
                    candidate = describe(*candidate, zone),
                    installed = describe(*installed, zone)
                )),
            }
        }
        FreshnessNote::AcceptedOlder { server, candidate, replaced } => warning(&tr!(
            "fresh-accepted-older",
            file = file,
            server = server.to_string(),
            candidate = describe(*candidate, zone),
            replaced = describe(*replaced, zone)
        )),
        FreshnessNote::Stale { publication, age, max_age, probed } => {
            let checked = match probed {
                0 => tr!("fresh-no-other-server"),
                many => tr!("fresh-other-servers", count = *many),
            };
            warning(&tr!(
                "fresh-stale",
                file = file,
                age = human_age(*age),
                publication = describe(Some(*publication), zone),
                checked = checked,
                limit = human_age(*max_age)
            ))
        }
        FreshnessNote::FromTheFuture { publication, ahead } => {
            future(file, *publication, *ahead, zone)
        }
        FreshnessNote::FutureBaselineIgnored { installed, ahead } => warning(&tr!(
            "fresh-future-baseline",
            file = file,
            ahead = human_age(*ahead),
            publication = describe(Some(*installed), zone)
        )),
        // `FreshnessNote` is non-exhaustive. A kind this build does not know is still worth a
        // line, rather than silence.
        other => crate::i18n::note(&format!("{file}: {other:?}")),
    }
}

/// The line for a refresh that kept the installed database because every server was older.
pub fn render_kept(
    file: &str,
    installed: Option<Publication>,
    zone: piko_txn::history::LocalZone,
) -> String {
    warning(&tr!("fresh-kept", file = file, installed = describe(installed, zone)))
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
    zone: piko_txn::history::LocalZone,
) {
    for (repo, publication) in databases {
        let Some(publication) = publication else { continue };
        let file = format!("{repo}.db");
        match freshness::staleness(publication, now, max_age) {
            Staleness::Fresh => {}
            Staleness::Stale { age } => crate::i18n::print_warning!(
                "fresh-stale-local",
                file = file.as_str(),
                age = human_age(age),
                publication = describe(Some(publication), zone),
                limit = human_age(max_age.unwrap_or_default())
            ),
            Staleness::FromTheFuture { ahead } => {
                eprintln!("{}", future(&file, publication, ahead, zone));
            }
        }
    }
}

fn future(
    file: &str,
    publication: Publication,
    ahead: Duration,
    zone: piko_txn::history::LocalZone,
) -> String {
    warning(&tr!(
        "fresh-future",
        file = file,
        ahead = human_age(ahead),
        publication = describe(Some(publication), zone)
    ))
}

/// Says when a database was published, and whether a signature vouches for the date.
fn describe(publication: Option<Publication>, zone: piko_txn::history::LocalZone) -> String {
    match publication {
        Some(Publication { at, tier: Tier::Authenticated }) => {
            tr!("fresh-signed", date = date(at, zone))
        }
        Some(Publication { at, tier: Tier::Unauthenticated }) => {
            tr!("fresh-published", date = date(at, zone))
        }
        None => tr!("fresh-undated"),
    }
}

fn date(seconds: u64, zone: piko_txn::history::LocalZone) -> String {
    crate::output::human_date(i64::try_from(seconds).unwrap_or(i64::MAX), zone)
}

/// Renders a duration in the largest whole unit that fits: days, then hours, then minutes.
fn human_age(age: Duration) -> String {
    let seconds = age.as_secs();
    if seconds >= DAY {
        tr!("fresh-days", count = seconds / DAY)
    } else if seconds >= 3_600 {
        tr!("fresh-hours", count = seconds / 3_600)
    } else {
        tr!("fresh-minutes", count = seconds / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc() -> piko_txn::history::LocalZone {
        piko_txn::history::LocalZone::UTC
    }

    #[test]
    fn zero_days_turns_the_limit_off() {
        assert_eq!(max_age(0), None);
        assert_eq!(max_age(DEFAULT_MAX_AGE_DAYS), Some(DEFAULT_MAX_AGE));
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
            age: Duration::from_secs(46 * DAY),
            max_age: DEFAULT_MAX_AGE,
            probed: 3,
        };
        let line = render_note("core.db", &note, utc());
        assert!(line.contains("46 days old"), "{line}");
        assert!(line.contains("3 other servers"), "{line}");
        assert!(line.contains("The limit is 40 days"), "{line}");
    }

    /// An ignored baseline changes what the rollback check did, so it is a warning, and it
    /// points at the clock.
    #[test]
    fn an_ignored_future_baseline_warns_and_names_the_clock() {
        let note = FreshnessNote::FutureBaselineIgnored {
            installed: Publication { at: 40 * DAY, tier: Tier::Unauthenticated },
            ahead: Duration::from_secs(30 * DAY),
        };
        let line = render_note("core.db", &note, utc());
        assert!(line.starts_with("Warning: "), "{line}");
        assert!(line.contains("30 days in the future"), "{line}");
        assert!(line.contains("Check the system clock"), "{line}");
    }
}
