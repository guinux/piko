//! Error reporting, the confirmation prompt, and the `emit!` writer.
//!
//! Duplicated from `crates/piko/src/output.rs` rather than shared: this is generic CLI
//! plumbing with no ALPM semantics — a future GUI key-management frontend needs neither a
//! stdout macro nor a stdin prompt loop. Not worth a shared crate for the two binaries.

/// Prints an error and its whole cause chain.
pub fn report(error: &dyn std::error::Error) {
    eprintln!("error: {error}");

    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}

/// Writes `result`, turning an I/O failure into an exit code rather than a panic.
macro_rules! emit {
    ($out:expr, $($arg:tt)*) => {
        if let Err(error) = ::std::writeln!($out, $($arg)*) {
            if error.kind() == ::std::io::ErrorKind::BrokenPipe {
                return ::std::process::ExitCode::SUCCESS;
            }
            eprintln!("error: failed to write output: {error}");
            return ::std::process::ExitCode::FAILURE;
        }
    };
}

pub(crate) use emit;

/// Prints `prompt` and waits for a yes/no answer, defaulting to `default` on an empty line.
///
/// Same shape as `crates/piko`'s own `confirm` — see its doc comment for the reasoning behind
/// treating a closed/empty stdin as a decline rather than as `default`.
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
