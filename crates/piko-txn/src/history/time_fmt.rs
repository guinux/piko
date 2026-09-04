//! Timestamps, in the one spelling `pacman.log` and the history store both use.
//!
//! `%FT%T%z` in the machine's own time zone — `2026-09-04T10:11:12+0200`. That is
//! `_alpm_log_leader`'s format (`log.c`), and reproducing it is what lets one file hold lines
//! from pacman and from piko without a reader having to know which wrote which.
//!
//! Rendering is done by hand rather than through `time`'s formatting machinery, the same way
//! `piko`'s own `human_date` does it. The format is fixed, so a format description bought at
//! runtime would only add a failure mode and a feature.

use std::fmt::Write as _;

/// The UTC offset timestamps are rendered in.
///
/// # Why this is captured rather than read where it is needed
///
/// `time` refuses to read the local offset from a process that has more than one thread: the
/// C library's time-zone state is not thread-safe against a concurrent `setenv`, and `time`
/// will not paper over that. piko is multi-threaded by the time a transaction runs —
/// `EntryWrite::commit` fsyncs in parallel, and `piko-net` downloads in parallel — so a late
/// call returns `IndeterminateOffset` and nothing else.
///
/// So the offset is read once, at the top of `main`, while the process is still single
/// threaded, and carried from there. [`LocalOffset::UTC`] is the fallback, and it is a correct
/// answer rather than a broken one: the offset is part of every timestamp written, so a line
/// stamped `+0000` is as unambiguous as one stamped `+0200`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalOffset {
    seconds: i32,
}

impl LocalOffset {
    /// UTC. The fallback when the local offset cannot be determined.
    pub const UTC: Self = Self { seconds: 0 };

    /// Reads the machine's current UTC offset.
    ///
    /// **Call this before spawning any thread**, and once. See the type's documentation.
    /// Falls back to [`LocalOffset::UTC`] rather than failing.
    #[must_use]
    pub fn capture() -> Self {
        time::UtcOffset::current_local_offset()
            .map_or(Self::UTC, |offset| Self { seconds: offset.whole_seconds() })
    }

    /// The offset east of UTC, in seconds.
    #[must_use]
    pub const fn seconds(self) -> i32 {
        self.seconds
    }

    /// Builds an offset from a whole number of seconds east of UTC.
    ///
    /// Out-of-range values become [`LocalOffset::UTC`], matching `capture`'s posture: a
    /// timestamp is better stamped UTC than not written at all.
    #[must_use]
    pub fn from_seconds(seconds: i32) -> Self {
        time::UtcOffset::from_whole_seconds(seconds).map_or(Self::UTC, |_| Self { seconds })
    }
}

/// Seconds since the epoch, honoring `SOURCE_DATE_EPOCH`.
///
/// libalpm does the same (`add.c:415`), so a reproducible build environment produces a
/// reproducible `%INSTALLDATE%`. The same clock stamps every log line and history block, so a
/// line and the `%INSTALLDATE%` it corresponds to cannot disagree.
#[must_use]
pub fn now() -> i64 {
    if let Some(value) = std::env::var_os("SOURCE_DATE_EPOCH")
        && let Some(parsed) = value.to_str().and_then(|text| text.trim().parse::<i64>().ok())
    {
        return parsed;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(0))
}

/// Renders `epoch` in `offset` as `2026-09-04T10:11:12+0200`.
///
/// A timestamp `time` cannot represent renders as the raw epoch seconds. That keeps a line
/// readable and machine-parseable-as-a-number rather than dropping it: nothing here may fail
/// a transaction.
#[must_use]
pub fn render(epoch: i64, offset: LocalOffset) -> String {
    let Ok(utc_offset) = time::UtcOffset::from_whole_seconds(offset.seconds()) else {
        return epoch.to_string();
    };
    let Ok(instant) = time::OffsetDateTime::from_unix_timestamp(epoch) else {
        return epoch.to_string();
    };
    let local = instant.to_offset(utc_offset);

    let total = offset.seconds();
    let sign = if total < 0 { '-' } else { '+' };
    let magnitude = total.unsigned_abs();
    let hours = magnitude / 3600;
    let minutes = (magnitude % 3600) / 60;

    let mut rendered = String::with_capacity(24);
    // Writing into a `String` cannot fail; the result is discarded rather than unwrapped
    // because `unwrap` is denied workspace-wide.
    let _ = write!(
        rendered,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{sign}{hours:02}{minutes:02}",
        local.year(),
        u8::from(local.month()),
        local.day(),
        local.hour(),
        local.minute(),
        local.second(),
    );
    rendered
}

/// Parses what [`render`] wrote, back to epoch seconds.
///
/// Accepts the offset spelled `+0200` or `+02:00`, and a trailing `Z`. Returns `None` for
/// anything else, including a bare epoch [`render`] fell back to — a reader that cannot date a
/// line is better off saying so than guessing.
#[must_use]
pub fn parse(text: &str) -> Option<i64> {
    let text = text.trim();
    let (date, rest) = text.split_once('T')?;
    let (year, month, day) = {
        let mut parts = date.split('-');
        (
            parts.next()?.parse::<i32>().ok()?,
            parts.next()?.parse::<u8>().ok()?,
            parts.next()?.parse::<u8>().ok()?,
        )
    };

    // The offset is whatever follows the clock. `Z`, `+HHMM` and `+HH:MM` are all spellings a
    // real `pacman.log` can hold, since the file outlives the tool that wrote any given line.
    let (clock, offset_seconds) = if let Some(clock) = rest.strip_suffix('Z') {
        (clock, 0_i32)
    } else {
        let split = rest.rfind(['+', '-'])?;
        let (clock, offset) = rest.split_at_checked(split)?;
        (clock, self::parse_offset(offset)?)
    };

    let mut clock_parts = clock.split(':');
    let hour = clock_parts.next()?.parse::<u8>().ok()?;
    let minute = clock_parts.next()?.parse::<u8>().ok()?;
    let second = clock_parts.next().unwrap_or("0").parse::<u8>().ok()?;

    let month = time::Month::try_from(month).ok()?;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let clock = time::Time::from_hms(hour, minute, second).ok()?;
    let offset = time::UtcOffset::from_whole_seconds(offset_seconds).ok()?;
    Some(date.with_time(clock).assume_offset(offset).unix_timestamp())
}

/// Parses `+0200`, `-05:00`, or `+02`.
fn parse_offset(text: &str) -> Option<i32> {
    let (sign, digits) = match text.split_at_checked(1)? {
        ("+", rest) => (1_i32, rest),
        ("-", rest) => (-1_i32, rest),
        _ => return None,
    };
    let digits: String = digits.chars().filter(|c| *c != ':').collect();
    let (hours, minutes) = match digits.len() {
        2 => (digits.parse::<i32>().ok()?, 0_i32),
        4 => (digits.get(..2)?.parse::<i32>().ok()?, digits.get(2..)?.parse::<i32>().ok()?),
        _ => return None,
    };
    let magnitude = hours.checked_mul(3600)?.checked_add(minutes.checked_mul(60)?)?;
    sign.checked_mul(magnitude)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_epoch_in_utc() {
        assert_eq!(render(0, LocalOffset::UTC), "1970-01-01T00:00:00+0000");
    }

    #[test]
    fn renders_in_a_positive_offset() {
        // The same instant, seen from CEST.
        assert_eq!(render(0, LocalOffset::from_seconds(7200)), "1970-01-01T02:00:00+0200");
    }

    #[test]
    fn renders_in_a_negative_offset() {
        assert_eq!(render(0, LocalOffset::from_seconds(-18000)), "1969-12-31T19:00:00-0500");
    }

    /// A half-hour zone is not a curiosity; India and Newfoundland both use one.
    #[test]
    fn renders_a_half_hour_offset() {
        assert_eq!(render(0, LocalOffset::from_seconds(19800)), "1970-01-01T05:30:00+0530");
    }

    #[test]
    fn round_trips_through_parse() {
        for offset in [0_i32, 7200, -18000, 19800] {
            let rendered = render(1_757_000_000, LocalOffset::from_seconds(offset));
            assert_eq!(parse(&rendered), Some(1_757_000_000), "{rendered}");
        }
    }

    /// The format a real `pacman.log` holds, written by libalpm rather than by piko.
    #[test]
    fn parses_a_real_pacman_log_timestamp() {
        assert!(parse("2026-09-03T16:19:47+0200").is_some());
        assert!(parse("2026-05-17T13:53:41+0000").is_some());
    }

    #[test]
    fn parses_the_colon_and_zulu_spellings() {
        let plain = parse("2026-09-03T16:19:47+0200").unwrap();
        assert_eq!(parse("2026-09-03T16:19:47+02:00"), Some(plain));
        assert_eq!(parse("2026-09-03T14:19:47Z"), Some(plain));
    }

    #[test]
    fn refuses_what_it_cannot_date() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("1757000000"), None);
        assert_eq!(parse("2026-13-03T16:19:47+0200"), None);
        assert_eq!(parse("not a timestamp"), None);
    }

    /// An out-of-range instant must not panic, and must not silently render as some other
    /// time.
    #[test]
    fn renders_an_impossible_timestamp_as_its_epoch() {
        assert_eq!(render(i64::MAX, LocalOffset::UTC), i64::MAX.to_string());
    }
}
