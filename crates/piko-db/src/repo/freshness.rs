//! How recent a repository database is, and whether a newer one may replace it.
//!
//! A valid signature proves who produced a database. It does not prove that the database is
//! current. A mirror can serve an old, correctly signed `core.db`, which rolls the client back.
//! It can also serve the same one for ever, which freezes the client. Either way, the client
//! stops seeing security updates. This module dates a database, compares two dates, and judges
//! an age. It performs no I/O except [`newest_member_time`], and it reads no clock: the caller
//! supplies the current time.

use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{error::Result, limits::Limits, repo::archive};

/// How old a database may be before [`staleness`] reports it: 14 days.
///
/// Measured over the last 90 days of Arch's own publishing, `core` once went 7.8 days without a
/// new package, and `extra` never went a full day. A week would report a quiet `core` as frozen.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(1_209_600);

/// How far in the future a publication may be before [`staleness`] reports it: one day.
///
/// This absorbs time zones and ordinary clock drift on either side.
pub const FUTURE_TOLERANCE: Duration = Duration::from_secs(86_400);

/// How far a publication date can be trusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tier {
    /// The creation time of a signature that verified.
    ///
    /// Only the key holder can make it. So a mirror cannot make an old database look new, and
    /// comparing two such dates catches a malicious mirror.
    Authenticated,
    /// The newest member time of an archive with no verified signature.
    ///
    /// The mirror chose these bytes, so it chose the date too. Comparing two such dates catches
    /// a mirror that is merely behind, never one that lies. Every Arch database is in this tier,
    /// because Arch does not sign its databases.
    Unauthenticated,
}

/// When a repository database was published, and how far that can be trusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Publication {
    /// Seconds since the Unix epoch.
    pub at: u64,
    /// Where the date came from.
    pub tier: Tier,
}

impl Publication {
    /// Dates a database from what its checks found.
    ///
    /// `signed_at` is the creation time of a signature that verified, if one did. It wins
    /// whenever it is present. `newest_member` is the archive's newest member time (see
    /// [`newest_member_time`]). A time of zero from either source dates nothing.
    #[must_use]
    pub fn new(signed_at: Option<SystemTime>, newest_member: Option<u64>) -> Option<Self> {
        let signed = signed_at
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|since| since.as_secs())
            .filter(|seconds| *seconds > 0);
        match (signed, newest_member.filter(|seconds| *seconds > 0)) {
            (Some(at), _) => Some(Self { at, tier: Tier::Authenticated }),
            (None, Some(at)) => Some(Self { at, tier: Tier::Unauthenticated }),
            (None, None) => None,
        }
    }

    /// The publication date as a [`SystemTime`].
    #[must_use]
    pub fn time(self) -> SystemTime {
        UNIX_EPOCH.checked_add(Duration::from_secs(self.at)).unwrap_or(UNIX_EPOCH)
    }
}

/// How a candidate database compares with the installed one.
///
/// Only two dates of the same [`Tier`] are compared. A signature time and an archive member time
/// come from different clocks and mean different things.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Comparison {
    /// No installed database, or one that carries no date. Any candidate is an improvement.
    NoBaseline,
    /// The candidate is newer than the installed database.
    Newer,
    /// The candidate has the same date: the same publication, perhaps compressed again.
    Same,
    /// The candidate is authenticated and the installed database is not. The dates are not
    /// comparable, and gaining a signature is never a step back.
    GainedAuthentication,
    /// The candidate is older than the installed database.
    Older,
    /// The installed database is authenticated, and the candidate is not.
    ///
    /// Under `DatabaseOptional`, a mirror can simply leave out the signature. If that made the
    /// dates incomparable and so acceptable, leaving out the signature would bypass the whole
    /// authenticated check. So it counts as a step back.
    LostAuthentication,
    /// The installed database carries a date and the candidate does not.
    ///
    /// Counted as a step back for the same reason as [`Comparison::LostAuthentication`].
    Undated,
}

impl Comparison {
    /// Whether the candidate may replace the installed database without an override.
    #[must_use]
    pub const fn is_acceptable(self) -> bool {
        matches!(self, Self::NoBaseline | Self::Newer | Self::Same | Self::GainedAuthentication)
    }
}

/// Compares a `candidate` database with the `installed` one.
///
/// This reads no clock. A rollback is refused on the two dates alone, so a wrong system clock
/// cannot make piko accept an older database, nor refuse a newer one.
#[must_use]
pub fn compare(candidate: Option<Publication>, installed: Option<Publication>) -> Comparison {
    let Some(installed) = installed else { return Comparison::NoBaseline };
    let Some(candidate) = candidate else { return Comparison::Undated };
    match (candidate.tier, installed.tier) {
        (Tier::Unauthenticated, Tier::Authenticated) => Comparison::LostAuthentication,
        (Tier::Authenticated, Tier::Unauthenticated) => Comparison::GainedAuthentication,
        _ => match candidate.at.cmp(&installed.at) {
            std::cmp::Ordering::Greater => Comparison::Newer,
            std::cmp::Ordering::Equal => Comparison::Same,
            std::cmp::Ordering::Less => Comparison::Older,
        },
    }
}

/// What the age of a database says, judged against the local clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Staleness {
    /// Within the allowed age, or no age limit applies.
    Fresh,
    /// Published longer ago than the allowed age.
    ///
    /// A quiet repository and a frozen mirror look the same by age alone. So this is a reason
    /// to look at other mirrors and to warn, never a reason to refuse.
    Stale {
        /// How long ago the database was published.
        age: Duration,
    },
    /// Published further in the future than [`FUTURE_TOLERANCE`] allows.
    ///
    /// Either the local clock is behind (a board with no hardware clock starts in 1970), or the
    /// publisher's clock is ahead. Neither is a reason to refuse the database.
    FromTheFuture {
        /// How far ahead of the local clock the date is.
        ahead: Duration,
    },
}

/// Judges how old `publication` is at `now`.
///
/// `max_age` of `None` turns the age limit off. A date in the future is reported either way,
/// because it says something about the clock rather than about the mirror.
#[must_use]
pub fn staleness(
    publication: Publication,
    now: SystemTime,
    max_age: Option<Duration>,
) -> Staleness {
    match now.duration_since(publication.time()) {
        Ok(age) => match max_age {
            Some(max_age) if age > max_age => Staleness::Stale { age },
            _ => Staleness::Fresh,
        },
        Err(ahead) => {
            let ahead = ahead.duration();
            if ahead > FUTURE_TOLERANCE {
                Staleness::FromTheFuture { ahead }
            } else {
                Staleness::Fresh
            }
        }
    }
}

/// Returns the newest modification time of any member of the repository archive at `path`,
/// in seconds since the Unix epoch.
///
/// This is the same value [`crate::repo::RepoDatabase::newest_member_time`] records during an
/// open, for a caller that only needs the date. It reads tar headers only, and parses no
/// `desc`. The whole stream is still inflated, because a compressed tar has no index. So it
/// costs about one decompression of the archive, bounded by the same [`Limits`] as an open.
///
/// `None` means every member carries time zero.
///
/// # Errors
///
/// Returns [`crate::Error`] if the archive cannot be opened, is not a supported compressed
/// tar, or exceeds [`Limits::repo_compressed_bytes`] or [`Limits::repo_inflated_bytes`].
pub fn newest_member_time(path: impl AsRef<Path>, limits: &Limits) -> Result<Option<u64>> {
    archive::newest_member_time(path.as_ref(), limits)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;
    use crate::fixture::{MINIMAL_REPO_DESC_V2, RepoFixture, gzip};
    use crate::repo::RepoDatabase;

    const DESC_PATH: &str = "foo-1.0.0-1/desc";

    const fn signed(at: u64) -> Option<Publication> {
        Some(Publication { at, tier: Tier::Authenticated })
    }

    const fn unsigned(at: u64) -> Option<Publication> {
        Some(Publication { at, tier: Tier::Unauthenticated })
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds)).unwrap()
    }

    #[test]
    fn a_signature_time_wins_over_the_archive_time() {
        assert_eq!(Publication::new(Some(at(50)), Some(90)), signed(50));
        assert_eq!(Publication::new(None, Some(90)), unsigned(90));
        assert_eq!(Publication::new(None, Some(0)), None);
        assert_eq!(Publication::new(Some(UNIX_EPOCH), None), None);
    }

    /// Every pair of tiers, and every order within one tier.
    #[test]
    fn comparisons_follow_the_tier_rules() {
        let cases = [
            (signed(1), None, Comparison::NoBaseline),
            (None, None, Comparison::NoBaseline),
            (signed(2), signed(1), Comparison::Newer),
            (signed(1), signed(1), Comparison::Same),
            (signed(1), signed(2), Comparison::Older),
            (unsigned(2), unsigned(1), Comparison::Newer),
            (unsigned(1), unsigned(2), Comparison::Older),
            // A newer archive time does not make up for a missing signature.
            (unsigned(9), signed(1), Comparison::LostAuthentication),
            // An older signature time is not a step back from an unsigned database.
            (signed(1), unsigned(9), Comparison::GainedAuthentication),
            (None, unsigned(1), Comparison::Undated),
            (None, signed(1), Comparison::Undated),
        ];
        for (candidate, installed, expected) in cases {
            assert_eq!(compare(candidate, installed), expected, "{candidate:?} vs {installed:?}");
        }
    }

    #[test]
    fn only_a_step_back_is_unacceptable() {
        for comparison in [
            Comparison::NoBaseline,
            Comparison::Newer,
            Comparison::Same,
            Comparison::GainedAuthentication,
        ] {
            assert!(comparison.is_acceptable(), "{comparison:?}");
        }
        for comparison in [Comparison::Older, Comparison::LostAuthentication, Comparison::Undated] {
            assert!(!comparison.is_acceptable(), "{comparison:?}");
        }
    }

    #[test]
    fn age_is_judged_against_the_limit() {
        let published = Publication { at: 1_000_000, tier: Tier::Unauthenticated };
        let limit = Some(Duration::from_secs(100));
        assert_eq!(staleness(published, at(1_000_100), limit), Staleness::Fresh);
        assert_eq!(
            staleness(published, at(1_000_101), limit),
            Staleness::Stale { age: Duration::from_secs(101) }
        );
        assert_eq!(staleness(published, at(9_000_000), None), Staleness::Fresh);
    }

    /// A clock that is behind must never read as a stale mirror. It is reported for what it is.
    #[test]
    fn a_date_in_the_future_is_reported_beyond_the_tolerance() {
        let published = Publication { at: 1_000_000, tier: Tier::Authenticated };
        let within = 1_000_000 - FUTURE_TOLERANCE.as_secs();
        assert_eq!(staleness(published, at(within), None), Staleness::Fresh);
        assert_eq!(
            staleness(published, at(within - 1), Some(Duration::from_secs(1))),
            Staleness::FromTheFuture { ahead: FUTURE_TOLERANCE + Duration::from_secs(1) }
        );
    }

    /// `repo-add` keeps an older entry's time and stamps a new one with its own, so members of
    /// one archive carry different times. The newest one dates the archive.
    #[test]
    fn the_newest_member_time_is_the_largest_one() {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, mtime) in [(DESC_PATH, 2_000), ("bar-1.0.0-1/desc", 1_000)] {
            let body = MINIMAL_REPO_DESC_V2.as_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(mtime);
            header.set_cksum();
            builder.append_data(&mut header, path, body).unwrap();
        }
        let fixture = RepoFixture::new();
        let path = fixture.write_archive("core.db", &gzip(&builder.into_inner().unwrap()));

        assert_eq!(newest_member_time(&path, &Limits::default()).unwrap(), Some(2_000));
    }

    /// Time zero dates nothing, so it must not read as "published in 1970".
    #[test]
    fn an_archive_written_at_time_zero_has_no_date() {
        let fixture = RepoFixture::new();
        let path = fixture.write_gzip_archive("core.db", &[(DESC_PATH, b"x")]);
        assert_eq!(newest_member_time(&path, &Limits::default()).unwrap(), None);
    }

    /// The open records the same value the header-only walk computes, so the two callers
    /// cannot date one archive two ways.
    #[test]
    fn an_open_records_the_same_value_as_the_header_walk() {
        let fixture = RepoFixture::new();
        let path = fixture.write_gzip_archive_at(
            "core.db",
            &[(DESC_PATH, MINIMAL_REPO_DESC_V2.as_bytes())],
            1_758_480_000,
        );
        let database = RepoDatabase::open(&path).unwrap();
        assert_eq!(database.newest_member_time(), Some(1_758_480_000));
        assert_eq!(
            newest_member_time(&path, &Limits::default()).unwrap(),
            database.newest_member_time()
        );
    }

    /// A member that the reader skips still dates the archive. The date says when the archive
    /// was written, not which members piko could use.
    #[test]
    fn a_skipped_member_still_counts() {
        let fixture = RepoFixture::new();
        let path = fixture.write_gzip_archive_at("core.db", &[("stray-file", b"x")], 5_000);
        assert_eq!(newest_member_time(&path, &Limits::default()).unwrap(), Some(5_000));
        assert_eq!(RepoDatabase::open(&path).unwrap().newest_member_time(), Some(5_000));
    }
}
