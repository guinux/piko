//! Timestamps, in the one spelling `pacman.log` and the history store both use.
//!
//! `%FT%T%z` in the machine's own time zone, spelled `2026-09-04T10:11:12+0200`. That is
//! `_alpm_log_leader`'s format (`log.c`). Reproducing it lets one file hold lines from pacman
//! and from piko. A reader never has to know which wrote which.
//!
//! Rendering is done by hand rather than through `time`'s formatting machinery, the same way
//! `piko`'s own `human_date` does it. The format is fixed, so a format description bought at
//! runtime would only add a failure mode and a feature.

use std::{
    ffi::OsStr,
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::OnceLock,
};

/// The time zone timestamps are rendered in: the machine's own, or a fixed offset.
///
/// The machine's zone gives each instant the offset that applied at that instant, as
/// `localtime` does. A build date in winter reads `+0100` in Paris, and an install date in
/// summer `+0200`. One offset for every instant would move half of them by an hour.
///
/// [`LocalZone::capture`] reads the zone once, and keeps it for the rest of the process.
/// The value is `Copy`, so it travels to every renderer like a number.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalZone(Zone);

#[derive(Clone, Copy, Debug)]
enum Zone {
    /// A fixed offset east of UTC, in seconds.
    Fixed(i32),
    /// The rules [`LocalZone::capture`] read.
    Rules(&'static jiff::tz::TimeZone),
}

impl Default for Zone {
    fn default() -> Self {
        Self::Fixed(0)
    }
}

/// The machine's zone, read on the first [`LocalZone::capture`]. `None` when it could not be
/// read, which renders as UTC.
static SYSTEM: OnceLock<Option<jiff::tz::TimeZone>> = OnceLock::new();

/// Where the zone is read when `TZ` is not set: glibc's `TZDEFAULT`.
const LOCALTIME: &str = "/etc/localtime";

/// Where a zone name in `TZ` is looked up when `TZDIR` is not set: glibc's default.
const ZONEINFO: &str = "/usr/share/zoneinfo";

impl LocalZone {
    /// UTC. The fallback when the local zone cannot be read.
    pub const UTC: Self = Self(Zone::Fixed(0));

    /// Reads the machine's time zone, the way glibc's `tzset` finds it.
    ///
    /// `TZ` unset means `/etc/localtime`, and an empty `TZ` means UTC. Otherwise `TZ` names a
    /// file, after an optional `:`: an absolute path, or a zone name under `TZDIR`
    /// (`/usr/share/zoneinfo` by default). A `TZ` that names no readable file, and has no `:`,
    /// is read as a POSIX rule such as `CET-1CEST,M3.5.0,M10.5.0/3`.
    ///
    /// Every file goes through `piko_db::fs_util::read_capped_following`: a regular file,
    /// never a FIFO, and at most `Limits::time_zone_bytes`. A zone that cannot be read falls back to
    /// [`LocalZone::UTC`] rather than failing. Every timestamp written carries its offset, so
    /// a line stamped `+0000` is as unambiguous as one stamped `+0200`.
    ///
    /// The zone is read on the first call only. Later calls return the same zone.
    #[must_use]
    pub fn capture() -> Self {
        SYSTEM.get_or_init(system_zone).as_ref().map_or(Self::UTC, |zone| Self(Zone::Rules(zone)))
    }

    /// A zone with one fixed offset, `seconds` east of UTC.
    ///
    /// Out-of-range values become [`LocalZone::UTC`], matching `capture`'s posture: a
    /// timestamp is better stamped UTC than not written at all.
    #[must_use]
    pub fn from_seconds(seconds: i32) -> Self {
        time::UtcOffset::from_whole_seconds(seconds)
            .map_or(Self::UTC, |_| Self(Zone::Fixed(seconds)))
    }

    /// The offset east of UTC, in seconds, that applies at `epoch`.
    #[must_use]
    pub fn offset_at(self, epoch: i64) -> i32 {
        match self.0 {
            Zone::Fixed(seconds) => seconds,
            // An instant outside jiff's range is outside `time`'s too, and renders as a
            // number whatever offset it is given.
            Zone::Rules(zone) => jiff::Timestamp::from_second(epoch)
                .map_or(0, |instant| zone.to_offset(instant).seconds()),
        }
    }

    /// The instant at which the clock of this zone reads `wall`, given in seconds since the
    /// epoch as if the clock were UTC.
    ///
    /// The offset is the one that applies at that instant, found in two steps: the offset at
    /// `wall` itself gives an instant near the answer, and the offset at that instant gives the
    /// answer. A wall clock a transition skips or repeats resolves to an instant next to it.
    #[must_use]
    pub fn instant_of(self, wall: i64) -> i64 {
        let near = wall.saturating_sub(i64::from(self.offset_at(wall)));
        wall.saturating_sub(i64::from(self.offset_at(near)))
    }
}

/// The zone the process environment describes: `TZ`, `TZDIR`, or `/etc/localtime`.
fn system_zone() -> Option<jiff::tz::TimeZone> {
    zone_from(std::env::var_os("TZ").as_deref(), std::env::var_os("TZDIR").as_deref())
}

/// The zone the values of `TZ` and `TZDIR` describe, as [`LocalZone::capture`] reads them.
/// `None` when there is none to read.
fn zone_from(tz: Option<&OsStr>, tzdir: Option<&OsStr>) -> Option<jiff::tz::TimeZone> {
    let Some(value) = tz else {
        return zone_file(Path::new(LOCALTIME));
    };
    let value = value.to_str()?;
    if value.is_empty() {
        return Some(jiff::tz::TimeZone::UTC);
    }
    let (name, file_only) = match value.strip_prefix(':') {
        Some(name) => (name, true),
        None => (value, false),
    };
    let path = if name.starts_with('/') {
        PathBuf::from(name)
    } else {
        Path::new(tzdir.unwrap_or(OsStr::new(ZONEINFO))).join(name)
    };
    zone_file(&path)
        .or_else(|| if file_only { None } else { jiff::tz::TimeZone::posix(value).ok() })
}

/// The zone the TZif file at `path` holds, read bounded. `None` if it is not one.
fn zone_file(path: &Path) -> Option<jiff::tz::TimeZone> {
    let limit = piko_db::Limit::TimeZone;
    let bytes =
        piko_db::fs_util::read_capped_following(path, limit, piko_db::Limits::default().get(limit))
            .ok()?;
    jiff::tz::TimeZone::tzif(&path.to_string_lossy(), &bytes).ok()
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

/// Renders `epoch` in `zone` as `2026-09-04T10:11:12+0200`, with the offset that applies at
/// `epoch`.
///
/// A timestamp `time` cannot represent renders as the raw epoch seconds. That keeps a line
/// readable and machine-parseable-as-a-number rather than dropping it: nothing here may fail
/// a transaction.
#[must_use]
pub fn render(epoch: i64, zone: LocalZone) -> String {
    let total = zone.offset_at(epoch);
    let Ok(utc_offset) = time::UtcOffset::from_whole_seconds(total) else {
        return epoch.to_string();
    };
    let Ok(instant) = time::OffsetDateTime::from_unix_timestamp(epoch) else {
        return epoch.to_string();
    };
    let local = instant.to_offset(utc_offset);

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
/// anything else, including a bare epoch [`render`] fell back to. A reader that cannot date a
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

    // The offset is whatever follows the clock. `Z`, `+HHMM` and `+HH:MM` are all spellings
    // a real `pacman.log` can hold. The file outlives the tool that wrote any given line.
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
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    #[test]
    fn renders_the_epoch_in_utc() {
        assert_eq!(render(0, LocalZone::UTC), "1970-01-01T00:00:00+0000");
    }

    #[test]
    fn renders_in_a_positive_offset() {
        // The same instant, seen from CEST.
        assert_eq!(render(0, LocalZone::from_seconds(7200)), "1970-01-01T02:00:00+0200");
    }

    #[test]
    fn renders_in_a_negative_offset() {
        assert_eq!(render(0, LocalZone::from_seconds(-18000)), "1969-12-31T19:00:00-0500");
    }

    /// A half-hour zone is not a curiosity; India and Newfoundland both use one.
    #[test]
    fn renders_a_half_hour_offset() {
        assert_eq!(render(0, LocalZone::from_seconds(19800)), "1970-01-01T05:30:00+0530");
    }

    #[test]
    fn round_trips_through_parse() {
        for offset in [0_i32, 7200, -18000, 19800] {
            let rendered = render(1_757_000_000, LocalZone::from_seconds(offset));
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
        assert_eq!(render(i64::MAX, LocalZone::UTC), i64::MAX.to_string());
    }

    /// Paris's rules, as a POSIX `TZ` string: `+0100` in winter, `+0200` in summer.
    const PARIS: &str = "CET-1CEST,M3.5.0,M10.5.0/3";

    fn paris() -> LocalZone {
        let zone = zone_from(Some(OsStr::new(PARIS)), Some(OsStr::new("/nonexistent"))).unwrap();
        LocalZone(Zone::Rules(Box::leak(Box::new(zone))))
    }

    /// Each instant gets the offset that applied at that instant, not the one that applies
    /// now. A winter date and a summer date in one zone differ by an hour of offset.
    #[test]
    fn renders_each_instant_in_its_own_offset() {
        let zone = paris();
        assert_eq!(render(1_772_988_236, zone), "2026-03-08T17:43:56+0100");
        assert_eq!(render(1_779_026_032, zone), "2026-05-17T15:53:52+0200");
    }

    /// The day the clocks go forward lasts 23 hours, from one local midnight to the next.
    #[test]
    fn a_local_midnight_takes_its_own_offset() {
        let zone = paris();
        let day = parse("2026-03-29T00:00:00+0000").unwrap();
        let next = parse("2026-03-30T00:00:00+0000").unwrap();
        assert_eq!(zone.instant_of(day), parse("2026-03-29T00:00:00+0100").unwrap());
        assert_eq!(zone.instant_of(next), parse("2026-03-30T00:00:00+0200").unwrap());
        assert_eq!(zone.instant_of(next) - zone.instant_of(day), 23 * 3600);
    }

    /// `TZ` is read as glibc reads it. An empty value is UTC. A value with no readable file
    /// is a POSIX rule, unless a `:` says it names a file.
    #[test]
    fn tz_is_read_as_glibc_reads_it() {
        let none = Some(OsStr::new("/nonexistent"));
        let utc = zone_from(Some(OsStr::new("")), none).unwrap();
        assert_eq!(utc.to_offset(jiff::Timestamp::UNIX_EPOCH).seconds(), 0);

        let rule = zone_from(Some(OsStr::new(PARIS)), none).unwrap();
        assert_eq!(rule.to_offset(jiff::Timestamp::UNIX_EPOCH).seconds(), 3600);

        assert!(zone_from(Some(OsStr::new(":Europe/Nowhere")), none).is_none());
        assert!(zone_from(Some(OsStr::new(&format!(":{PARIS}"))), none).is_none());
    }

    /// A zone file is read through the bounded door: a FIFO is refused without blocking, and
    /// a file that is not TZif is no zone.
    #[test]
    fn a_zone_file_that_is_not_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        assert!(zone_file(&fifo).is_none());

        let text = dir.path().join("text");
        std::fs::write(&text, b"not a zone").unwrap();
        assert!(zone_file(&text).is_none());
        assert!(zone_from(Some(text.as_os_str()), None).is_none());
    }
}
