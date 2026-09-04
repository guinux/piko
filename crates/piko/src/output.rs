//! Error reporting and the value renderers every subcommand's output is built from.
//!
//! Nothing here reads the database; these turn values that are already in hand into the exact
//! bytes pacman would have printed, which is what makes `piko list`/`piko files`/`piko conf`
//! diffable against `pacman -Q`/`pacman -Ql`/`pacman-conf`.

use piko_db::config::{CleanMethod, DbUsage, SigLevel};

/// Prints an error and its whole cause chain.
///
/// Without the chain, "failed to parse .../desc" would omit the reason it failed to parse.
pub fn report(error: &dyn std::error::Error) {
    eprintln!("piko: error: {error}");

    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}

/// Reports how many diagnostics the `max_diagnostics` bound withheld, if any.
///
/// Printed rather than swallowed so the output is never mistaken for the complete list.
pub fn report_dropped_diagnostics(dropped: usize) {
    if dropped > 0 {
        eprintln!("piko: warning: {dropped} further problem(s) not shown");
    }
}

/// Writes `result`, turning an I/O failure into an exit code rather than a panic.
///
/// Every path is fully qualified, so a call site needs nothing in scope but [`std::io::Write`]
/// (which `writeln!` itself requires). The macro is used from every `cmd` module.
macro_rules! emit {
    ($out:expr, $($arg:tt)*) => {
        if let Err(error) = ::std::writeln!($out, $($arg)*) {
            if error.kind() == ::std::io::ErrorKind::BrokenPipe {
                return ::std::process::ExitCode::SUCCESS;
            }
            eprintln!("piko: error: failed to write output: {error}");
            return ::std::process::ExitCode::FAILURE;
        }
    };
}

pub(crate) use emit;

/// Prints `prompt` and waits for a yes/no answer, defaulting to `default` on an empty line.
///
/// This is pacman's `question` (`util.c:1705`), whose two wrappers differ by exactly this
/// parameter: `yesno` passes a preset of 1, `noyes` a preset of 0. piko needs both. The
/// transaction prompts are `yesno`; the `HoldPkg` guard is `noyes` (see
/// [`crate::cmd::removal::hold_pkg_allows`]). The default is a parameter here rather than two
/// near-identical functions.
///
/// An empty line (the user just pressed Enter) answers `default`. `y`/`yes` accepts, and
/// anything else declines, both case-insensitively. A closed or empty stdin is treated as a
/// decline rather than as `default`. `read_line` returning zero bytes signals this; an
/// answered Enter never does that, since it always yields at least the newline. An unattended
/// run should refuse to proceed, not silently proceed because nobody was there to answer.
/// pacman ends `question` the same way, with a bare `return 0` after the read.
///
/// `out` is flushed before the prompt is written to it, so the plan already printed there is
/// guaranteed to be visible first, even though `out` may be a buffered writer.
pub fn confirm(out: &mut impl std::io::Write, prompt: &str, default: bool) -> bool {
    if write!(out, "{prompt}").and_then(|()| out.flush()).is_err() {
        return false;
    }
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
        return false;
    }
    let answer = line.trim();
    if answer.is_empty() {
        return default;
    }
    answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")
}

/// Renders `method` as the `CleanMethod` keyword(s) that produced it, mirroring
/// `show_cleanmethod` in `pacman-conf.c`.
pub fn clean_method_lines(method: CleanMethod) -> Vec<&'static str> {
    let mut lines = Vec::new();
    if method.contains(CleanMethod::KEEP_INSTALLED) {
        lines.push("KeepInstalled");
    }
    if method.contains(CleanMethod::KEEP_CURRENT) {
        lines.push("KeepCurrent");
    }
    lines
}

/// Renders `usage` as the `Usage` keyword(s) that produced it, mirroring `show_usage` in
/// `pacman-conf.c`.
pub fn usage_lines(usage: DbUsage) -> Vec<&'static str> {
    if usage == DbUsage::ALL {
        return vec!["All"];
    }
    let mut lines = Vec::new();
    if usage.contains(DbUsage::SYNC) {
        lines.push("Sync");
    }
    if usage.contains(DbUsage::SEARCH) {
        lines.push("Search");
    }
    if usage.contains(DbUsage::INSTALL) {
        lines.push("Install");
    }
    if usage.contains(DbUsage::UPGRADE) {
        lines.push("Upgrade");
    }
    lines
}

/// Renders `level` as the `SigLevel` keyword(s) that produced it, mirroring `show_siglevel`
/// in `pacman-conf.c`. Returns nothing for `SigLevel::USE_DEFAULT`, matching
/// `pacman-conf`'s own "do not print an unresolved LocalFileSigLevel/RemoteFileSigLevel"
/// behavior. That sentinel means "inherit dynamically"; nothing was actually configured.
pub fn sig_level_lines(level: SigLevel, package_only: bool) -> Vec<&'static str> {
    if level == SigLevel::USE_DEFAULT {
        return Vec::new();
    }

    let mut lines = Vec::new();
    if level.contains(SigLevel::PACKAGE) {
        lines.push(if level.contains(SigLevel::PACKAGE_OPTIONAL) {
            "PackageOptional"
        } else {
            "PackageRequired"
        });
        lines.push(if level.contains(SigLevel::PACKAGE_UNKNOWN_OK) {
            "PackageTrustAll"
        } else {
            "PackageTrustedOnly"
        });
    } else {
        lines.push("PackageNever");
    }

    if package_only {
        return lines;
    }

    if level.contains(SigLevel::DATABASE) {
        lines.push(if level.contains(SigLevel::DATABASE_OPTIONAL) {
            "DatabaseOptional"
        } else {
            "DatabaseRequired"
        });
        lines.push(if level.contains(SigLevel::DATABASE_UNKNOWN_OK) {
            "DatabaseTrustAll"
        } else {
            "DatabaseTrustedOnly"
        });
    } else {
        lines.push("DatabaseNever");
    }

    lines
}

/// Renders a list as a space-separated line, or `None` when empty, as pacman does.
pub fn join<T: ToString>(items: &[T]) -> String {
    if items.is_empty() {
        return "None".to_owned();
    }
    items.iter().map(ToString::to_string).collect::<Vec<_>>().join("  ")
}

/// Renders a byte count using binary (1024-based) units, e.g. `"5.04 MiB"`.
///
/// Matches pacman's own `-Qi` output, which uses the same binary prefixes.
pub fn human_size(bytes: u64) -> String {
    indicatif::BinaryBytes(bytes).to_string()
}

/// Renders a Unix timestamp as a date and time in `offset`, e.g.
/// `"Mon 09 Dec 2024 10:40:42 +0100"`.
///
/// `offset` is the machine's own UTC offset, captured at the top of `main` — see
/// [`piko_txn::LocalOffset`] for why it is read there and carried, rather than read here.
/// pacman renders the same two fields through `localtime` (`package.c`), so this prints the
/// wall clock a `pacman -Qi` on the same machine prints.
///
/// The zone is spelled as a numeric offset rather than an abbreviation. An abbreviation needs
/// a time-zone database piko does not carry, and it is ambiguous on top of that: `CST` names
/// three different zones. A numeric offset never is.
pub fn human_date(timestamp: i64, offset: piko_txn::LocalOffset) -> String {
    let Ok(instant) = time::OffsetDateTime::from_unix_timestamp(timestamp) else {
        return format!("{timestamp} (timestamp out of range)");
    };
    // A timestamp near the end of the representable range can leave it once shifted into the
    // local zone. That is a rendering failure, not a reason to panic, so it reports itself the
    // same way an unrepresentable timestamp above does.
    let Some(date_time) = time::UtcOffset::from_whole_seconds(offset.seconds())
        .ok()
        .and_then(|zone| instant.checked_to_offset(zone))
    else {
        return format!("{timestamp} (timestamp out of range)");
    };

    format!(
        "{} {:02} {} {} {:02}:{:02}:{:02} {}",
        short_weekday(date_time.weekday()),
        date_time.day(),
        short_month(date_time.month()),
        date_time.year(),
        date_time.hour(),
        date_time.minute(),
        date_time.second(),
        numeric_offset(offset),
    )
}

/// Renders a UTC offset as `+0100`, the spelling `date`(1) and ISO 8601 both use.
fn numeric_offset(offset: piko_txn::LocalOffset) -> String {
    let seconds = offset.seconds();
    let sign = if seconds < 0 { '-' } else { '+' };
    let magnitude = seconds.unsigned_abs();
    let hours = magnitude / 3600;
    let minutes = (magnitude % 3600) / 60;
    format!("{sign}{hours:02}{minutes:02}")
}

/// The three-letter English abbreviation of `day`.
fn short_weekday(day: time::Weekday) -> &'static str {
    match day {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    }
}

/// The three-letter English abbreviation of `month`.
fn short_month(month: time::Month) -> &'static str {
    match month {
        time::Month::January => "Jan",
        time::Month::February => "Feb",
        time::Month::March => "Mar",
        time::Month::April => "Apr",
        time::Month::May => "May",
        time::Month::June => "Jun",
        time::Month::July => "Jul",
        time::Month::August => "Aug",
        time::Month::September => "Sep",
        time::Month::October => "Oct",
        time::Month::November => "Nov",
        time::Month::December => "Dec",
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use piko_txn::LocalOffset;

    use super::*;

    #[test]
    fn human_size_uses_bare_bytes_below_1024() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
    }

    #[test]
    fn human_size_switches_units_at_1024() {
        assert_eq!(human_size(1024), "1.00 KiB");
        assert_eq!(human_size(1536), "1.50 KiB");
    }

    /// pacman's own installed size for `pacman` on the real system this was built against.
    /// This doubles as a sanity check against a known-real value.
    #[test]
    fn human_size_matches_a_real_installed_size() {
        assert_eq!(human_size(5_283_285), "5.04 MiB");
    }

    #[test]
    fn human_size_never_panics_at_the_top_of_the_range() {
        let rendered = human_size(u64::MAX);
        assert!(rendered.ends_with("EiB"), "{rendered}");
    }

    /// The offset is part of the output, so a `+0000` reading is as unambiguous as any other.
    #[test]
    fn human_date_renders_the_unix_epoch() {
        assert_eq!(human_date(0, LocalOffset::UTC), "Thu 01 Jan 1970 00:00:00 +0000");
    }

    /// The build date from `fixture::MINIMAL_DESC_V1`.
    #[test]
    fn human_date_renders_a_real_timestamp() {
        assert_eq!(human_date(1_733_737_242, LocalOffset::UTC), "Mon 09 Dec 2024 09:40:42 +0000");
    }

    /// The install date of `pacman` on the real system this was built against.
    #[test]
    fn human_date_renders_another_real_timestamp() {
        assert_eq!(human_date(1_778_057_192, LocalOffset::UTC), "Wed 06 May 2026 08:46:32 +0000");
    }

    /// The same instant as the test above, read in Paris summer time: two hours later on the
    /// clock, and the same second on the wire.
    #[test]
    fn human_date_shifts_the_clock_into_the_offset() {
        assert_eq!(
            human_date(1_778_057_192, LocalOffset::from_seconds(7200)),
            "Wed 06 May 2026 10:46:32 +0200"
        );
    }

    /// A negative offset crosses back over midnight, so it exercises the date as well as the
    /// clock.
    #[test]
    fn human_date_renders_a_negative_offset() {
        assert_eq!(
            human_date(0, LocalOffset::from_seconds(-18000)),
            "Wed 31 Dec 1969 19:00:00 -0500"
        );
    }

    /// A half-hour zone (`Asia/Kolkata`) has minutes in its offset, which a whole-hour
    /// rendering would drop.
    #[test]
    fn human_date_renders_an_offset_with_minutes() {
        assert_eq!(
            human_date(0, LocalOffset::from_seconds(19800)),
            "Thu 01 Jan 1970 05:30:00 +0530"
        );
    }

    #[test]
    fn human_date_reports_out_of_range_timestamps_without_panicking() {
        let rendered = human_date(i64::MAX, LocalOffset::UTC);
        assert!(rendered.contains("out of range"), "{rendered}");
    }
}
