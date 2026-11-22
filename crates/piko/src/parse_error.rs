//! An error in the command line itself, in the language of the user.
//!
//! clap reports an unknown option, a missing value or a conflict through its `RichFormatter`,
//! in English. [`Formatter`] writes the same report from the messages of `locales/*/cli.ftl`.
//! It follows `clap_builder`'s `RichFormatter` line for line, and a test checks that its English
//! output is byte for byte clap's own, styles included.
//!
//! Three parts stay English: a reason a value parser gave (`invalid digit found in string`), a
//! tip clap writes itself (`to pass '--x' as a value, use '-- --x'`), and the usage line, which
//! is a list of names.

use std::fmt::Write as _;

use clap::builder::StyledStr;
use clap::builder::Styles;
use clap::builder::styling::Style;
use clap::error::{ContextKind, ContextValue, ErrorFormatter, ErrorKind};

use crate::i18n::tr;

/// The indentation clap puts before a line of a list.
const TAB: &str = "  ";

/// The [`ErrorFormatter`] of piko's command line.
#[derive(Debug)]
pub struct Formatter;

/// `text` in `style`.
fn styled(style: &Style, text: impl std::fmt::Display) -> String {
    format!("{style}{text}{style:#}")
}

/// `value` as clap quotes it in a list: written as it is, or as a Rust string when it is empty
/// or holds white space.
fn escaped(value: &str) -> String {
    if value.is_empty() || value.contains(char::is_whitespace) {
        format!("{value:?}")
    } else {
        value.to_owned()
    }
}

/// The text of `kind`, for an error with no context to say more.
fn kind_text(kind: ErrorKind) -> Option<String> {
    Some(match kind {
        ErrorKind::InvalidValue => tr!("cli-clap-kind-invalid-value"),
        ErrorKind::UnknownArgument => tr!("cli-clap-kind-unknown-argument"),
        ErrorKind::InvalidSubcommand => tr!("cli-clap-kind-invalid-subcommand"),
        ErrorKind::NoEquals => tr!("cli-clap-kind-no-equals"),
        ErrorKind::ValueValidation => tr!("cli-clap-kind-value-validation"),
        ErrorKind::TooManyValues => tr!("cli-clap-kind-too-many-values"),
        ErrorKind::TooFewValues => tr!("cli-clap-kind-too-few-values"),
        ErrorKind::WrongNumberOfValues => tr!("cli-clap-kind-wrong-number-of-values"),
        ErrorKind::ArgumentConflict => tr!("cli-clap-kind-argument-conflict"),
        ErrorKind::MissingRequiredArgument => tr!("cli-clap-kind-missing-required-argument"),
        ErrorKind::MissingSubcommand => tr!("cli-clap-kind-missing-subcommand"),
        ErrorKind::InvalidUtf8 => tr!("cli-clap-kind-invalid-utf8"),
        _ => return None,
    })
}

impl ErrorFormatter for Formatter {
    fn format_error(error: &clap::error::Error<Self>) -> StyledStr {
        let styles = Styles::default();
        let valid = styles.get_valid();

        let mut out = String::new();
        out.push_str(&styled(styles.get_error(), tr!("cli-clap-error")));
        out.push(' ');

        match context(error, &styles) {
            Some(text) => out.push_str(&text),
            None => match (kind_text(error.kind()), std::error::Error::source(error)) {
                (Some(text), _) => out.push_str(&text),
                (None, Some(source)) => out.push_str(&source.to_string()),
                (None, None) => out.push_str(&tr!("cli-clap-unknown-cause")),
            },
        }

        let mut suggested = false;
        let similar = [
            (ContextKind::SuggestedSubcommand, Similar::Subcommand),
            (ContextKind::SuggestedArg, Similar::Argument),
            (ContextKind::SuggestedValue, Similar::Value),
        ];
        for (kind, what) in similar {
            if let Some(possible) = error.get(kind) {
                out.push('\n');
                if !suggested {
                    out.push('\n');
                    suggested = true;
                }
                out.push_str(&did_you_mean(&styles, what, possible));
            }
        }
        if let Some(ContextValue::StyledStrs(tips)) = error.get(ContextKind::Suggested) {
            if !suggested {
                out.push('\n');
            }
            for tip in tips {
                out.push_str(&format!(
                    "\n{TAB}{} {}",
                    styled(valid, tr!("cli-clap-tip")),
                    tip.ansi()
                ));
            }
        }

        if let Some(ContextValue::StyledStr(usage)) = error.get(ContextKind::Usage) {
            let usage = usage.ansi().to_string().replacen("Usage:", &tr!("cli-help-usage"), 1);
            out.push_str("\n\n");
            out.push_str(&usage);
        }

        let help = styled(styles.get_literal(), "--help");
        out.push_str("\n\n");
        out.push_str(&tr!("cli-clap-try-help", flag = help));
        out.push('\n');

        let mut text = StyledStr::new();
        let _ = write!(text, "{out}");
        text
    }
}

/// What a suggestion names.
#[derive(Clone, Copy, Debug)]
enum Similar {
    Subcommand,
    Argument,
    Value,
}

/// The `tip:` line that names what the user may have meant.
fn did_you_mean(styles: &Styles, what: Similar, possible: &ContextValue) -> String {
    let valid = styles.get_valid();
    let quoted = |value: &String| format!("'{}'", styled(valid, value));
    let (values, count) = match possible {
        ContextValue::String(value) => (quoted(value), 1),
        ContextValue::Strings(values) => {
            (values.iter().map(quoted).collect::<Vec<_>>().join(", "), values.len())
        }
        _ => (String::new(), 0),
    };
    let text = match what {
        Similar::Subcommand => tr!("cli-clap-similar-subcommand", count = count, values = values),
        Similar::Argument => tr!("cli-clap-similar-argument", count = count, values = values),
        Similar::Value => tr!("cli-clap-similar-value", count = count, values = values),
    };
    format!("{TAB}{} {text}", styled(valid, tr!("cli-clap-tip")))
}

/// `values` as a bracketed list on a line of its own, or nothing for an empty list.
fn values_list(styles: &Styles, values: Option<&ContextValue>, subcommands: bool) -> String {
    let Some(ContextValue::Strings(values)) = values else { return String::new() };
    if values.is_empty() {
        return String::new();
    }
    let valid = styles.get_valid();
    let values =
        values.iter().map(|value| styled(valid, escaped(value))).collect::<Vec<_>>().join(", ");
    let list = if subcommands {
        tr!("cli-clap-subcommands-list", values = values)
    } else {
        tr!("cli-clap-possible-values", values = values)
    };
    format!("\n{TAB}{list}")
}

/// A string of the context of `error`.
fn string(error: &clap::error::Error<Formatter>, kind: ContextKind) -> Option<&String> {
    match error.get(kind) {
        Some(ContextValue::String(value)) => Some(value),
        _ => None,
    }
}

/// A number of the context of `error`.
fn number(error: &clap::error::Error<Formatter>, kind: ContextKind) -> Option<isize> {
    match error.get(kind) {
        Some(ContextValue::Number(value)) => Some(*value),
        _ => None,
    }
}

/// The sentence the context of `error` makes, or `None` when the context does not hold what the
/// kind needs.
fn context(error: &clap::error::Error<Formatter>, styles: &Styles) -> Option<String> {
    let invalid = styles.get_invalid();
    let literal = styles.get_literal();
    let valid = styles.get_valid();
    let arg = || string(error, ContextKind::InvalidArg);
    let value = || string(error, ContextKind::InvalidValue);

    match error.kind() {
        ErrorKind::ArgumentConflict => Some(conflict(error, styles)),
        ErrorKind::NoEquals => Some(tr!("cli-clap-no-equals", arg = styled(invalid, arg()?))),
        ErrorKind::InvalidValue => {
            let (arg, value) = (arg()?, value()?);
            let sentence = if value.is_empty() {
                tr!("cli-clap-value-required", arg = styled(invalid, arg))
            } else {
                tr!(
                    "cli-clap-invalid-value",
                    value = styled(invalid, value),
                    arg = styled(literal, arg)
                )
            };
            let list = values_list(styles, error.get(ContextKind::ValidValue), false);
            Some(format!("{sentence}{list}"))
        }
        ErrorKind::InvalidSubcommand => {
            let subcommand = string(error, ContextKind::InvalidSubcommand)?;
            Some(tr!("cli-clap-unrecognized-subcommand", subcommand = styled(invalid, subcommand)))
        }
        ErrorKind::MissingRequiredArgument => {
            let Some(ContextValue::Strings(args)) = error.get(ContextKind::InvalidArg) else {
                return None;
            };
            let list: String =
                args.iter().map(|each| format!("\n{TAB}{}", styled(valid, each))).collect();
            Some(tr!("cli-clap-missing-required", list = list))
        }
        ErrorKind::MissingSubcommand => {
            let subcommand = string(error, ContextKind::InvalidSubcommand)?;
            let sentence =
                tr!("cli-clap-missing-subcommand", subcommand = styled(invalid, subcommand));
            let list = values_list(styles, error.get(ContextKind::ValidSubcommand), true);
            Some(format!("{sentence}{list}"))
        }
        ErrorKind::TooManyValues => Some(tr!(
            "cli-clap-too-many-values",
            value = styled(invalid, value()?),
            arg = styled(literal, arg()?)
        )),
        ErrorKind::TooFewValues => {
            let arg = arg()?;
            let actual = number(error, ContextKind::ActualNumValues)?;
            let min = number(error, ContextKind::MinValues)?;
            Some(tr!(
                "cli-clap-too-few-values",
                min = styled(valid, min),
                arg = styled(literal, arg),
                actual = styled(invalid, actual),
                count = actual.unsigned_abs()
            ))
        }
        ErrorKind::ValueValidation => {
            let (arg, value) = (arg()?, value()?);
            let (value, arg) = (styled(invalid, value), styled(literal, arg));
            Some(match std::error::Error::source(error) {
                Some(source) => tr!(
                    "cli-clap-invalid-value-because",
                    value = value,
                    arg = arg,
                    reason = source.to_string()
                ),
                None => tr!("cli-clap-invalid-value", value = value, arg = arg),
            })
        }
        ErrorKind::WrongNumberOfValues => {
            let arg = arg()?;
            let actual = number(error, ContextKind::ActualNumValues)?;
            let expected = number(error, ContextKind::ExpectedNumValues)?;
            Some(tr!(
                "cli-clap-wrong-number-of-values",
                expected = styled(valid, expected),
                arg = styled(literal, arg),
                actual = styled(invalid, actual),
                count = actual.unsigned_abs()
            ))
        }
        ErrorKind::UnknownArgument => {
            Some(tr!("cli-clap-unexpected-argument", arg = styled(invalid, arg()?)))
        }
        _ => None,
    }
}

/// The sentence of an [`ErrorKind::ArgumentConflict`].
fn conflict(error: &clap::error::Error<Formatter>, styles: &Styles) -> String {
    let invalid = styles.get_invalid();
    let prior = error.get(ContextKind::PriorArg);
    let (subject, argument) = match (
        string(error, ContextKind::InvalidArg),
        string(error, ContextKind::InvalidSubcommand),
    ) {
        (Some(arg), _) => {
            if prior == Some(&ContextValue::String(arg.clone())) {
                return tr!("cli-clap-used-multiple-times", arg = styled(invalid, arg));
            }
            (styled(invalid, arg), true)
        }
        (None, Some(subcommand)) => (styled(invalid, subcommand), false),
        // clap names the argument of every conflict it reports.
        (None, None) => return kind_text(ErrorKind::ArgumentConflict).unwrap_or_default(),
    };
    match (prior, argument) {
        (Some(ContextValue::String(other)), true) => {
            tr!("cli-clap-conflict-one", arg = subject, other = styled(invalid, other))
        }
        (Some(ContextValue::String(other)), false) => {
            tr!(
                "cli-clap-subcommand-conflict-one",
                subcommand = subject,
                other = styled(invalid, other)
            )
        }
        (Some(ContextValue::Strings(others)), argument) => {
            let list: String =
                others.iter().map(|each| format!("\n{TAB}{}", styled(invalid, each))).collect();
            if argument {
                tr!("cli-clap-conflict-many", arg = subject, list = list)
            } else {
                tr!("cli-clap-subcommand-conflict-many", subcommand = subject, list = list)
            }
        }
        (Some(_), true) => tr!("cli-clap-conflict-other", arg = subject),
        (Some(_), false) => tr!("cli-clap-subcommand-conflict-other", subcommand = subject),
        (None, true) => tr!("cli-clap-conflict-none", arg = subject),
        (None, false) => tr!("cli-clap-subcommand-conflict-none", subcommand = subject),
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;
    use clap::error::{Error, RichFormatter};

    use super::*;
    use crate::cli::Cli;

    /// The text `error` renders, escape sequences included.
    fn ansi<F: ErrorFormatter>(error: &Error<F>) -> String {
        error.render().ansi().to_string()
    }

    /// An error of `kind` for `piko`, with `context`, as `F` formats it.
    fn built<F: ErrorFormatter>(
        kind: ErrorKind,
        context: &[(ContextKind, ContextValue)],
    ) -> Error<F> {
        let mut error = Error::<F>::new(kind).with_cmd(&Cli::command());
        for (kind, value) in context {
            error.insert(*kind, value.clone());
        }
        error
    }

    fn text(value: &str) -> ContextValue {
        ContextValue::String(value.to_owned())
    }

    fn texts(values: &[&str]) -> ContextValue {
        ContextValue::Strings(values.iter().map(|value| (*value).to_owned()).collect())
    }

    /// Every context shape `RichFormatter` reads, for every kind it formats.
    fn every_shape() -> Vec<(ErrorKind, Vec<(ContextKind, ContextValue)>)> {
        use ContextKind as K;
        let usage = ContextValue::StyledStr(Cli::command().render_usage());
        let mut shapes = vec![
            (
                ErrorKind::ArgumentConflict,
                vec![(K::InvalidArg, text("--a")), (K::PriorArg, text("--b"))],
            ),
            (
                ErrorKind::ArgumentConflict,
                vec![(K::InvalidArg, text("--a")), (K::PriorArg, texts(&["--b", "--c"]))],
            ),
            (
                ErrorKind::ArgumentConflict,
                vec![(K::InvalidArg, text("--a")), (K::PriorArg, ContextValue::Number(1))],
            ),
            (ErrorKind::ArgumentConflict, vec![(K::InvalidArg, text("--a"))]),
            (
                ErrorKind::ArgumentConflict,
                vec![(K::InvalidArg, text("--a")), (K::PriorArg, text("--a"))],
            ),
            (
                ErrorKind::ArgumentConflict,
                vec![(K::InvalidSubcommand, text("list")), (K::PriorArg, text("--b"))],
            ),
            (
                ErrorKind::ArgumentConflict,
                vec![(K::InvalidSubcommand, text("list")), (K::PriorArg, texts(&["--b"]))],
            ),
            (
                ErrorKind::ArgumentConflict,
                vec![(K::InvalidSubcommand, text("list")), (K::PriorArg, ContextValue::Number(1))],
            ),
            (ErrorKind::ArgumentConflict, vec![(K::InvalidSubcommand, text("list"))]),
            (ErrorKind::NoEquals, vec![(K::InvalidArg, text("--a"))]),
            (
                ErrorKind::InvalidValue,
                vec![(K::InvalidArg, text("--a")), (K::InvalidValue, text(""))],
            ),
            (
                ErrorKind::InvalidValue,
                vec![
                    (K::InvalidArg, text("--a")),
                    (K::InvalidValue, text("x")),
                    (K::ValidValue, texts(&["one", "two words", ""])),
                    (K::SuggestedValue, text("one")),
                ],
            ),
            (
                ErrorKind::InvalidSubcommand,
                vec![
                    (K::InvalidSubcommand, text("lst")),
                    (K::SuggestedSubcommand, texts(&["ls", "list"])),
                ],
            ),
            (
                ErrorKind::InvalidSubcommand,
                vec![(K::InvalidSubcommand, text("lst")), (K::SuggestedSubcommand, text("ls"))],
            ),
            (
                ErrorKind::MissingRequiredArgument,
                vec![(K::InvalidArg, texts(&["<A>", "--b <B>"])), (K::Usage, usage.clone())],
            ),
            (
                ErrorKind::MissingSubcommand,
                vec![
                    (K::InvalidSubcommand, text("key")),
                    (K::ValidSubcommand, texts(&["init", "add"])),
                ],
            ),
            (
                ErrorKind::TooManyValues,
                vec![(K::InvalidArg, text("--a")), (K::InvalidValue, text("x"))],
            ),
            (
                ErrorKind::ValueValidation,
                vec![(K::InvalidArg, text("--a")), (K::InvalidValue, text("x"))],
            ),
            (
                ErrorKind::UnknownArgument,
                vec![
                    (K::InvalidArg, text("--bogus")),
                    (K::SuggestedArg, text("--groups")),
                    (
                        K::Suggested,
                        ContextValue::StyledStrs(vec![
                            "to pass '--bogus' as a value, use '-- --bogus'".into(),
                        ]),
                    ),
                    (K::Usage, usage),
                ],
            ),
            (
                ErrorKind::UnknownArgument,
                vec![
                    (K::InvalidArg, text("--bogus")),
                    (K::Suggested, ContextValue::StyledStrs(vec!["a tip".into()])),
                ],
            ),
        ];
        for actual in [0, 1, 2] {
            for kind in [ErrorKind::TooFewValues, ErrorKind::WrongNumberOfValues] {
                let expected = if kind == ErrorKind::TooFewValues {
                    K::MinValues
                } else {
                    K::ExpectedNumValues
                };
                shapes.push((
                    kind,
                    vec![
                        (K::InvalidArg, text("--a")),
                        (K::ActualNumValues, ContextValue::Number(actual)),
                        (expected, ContextValue::Number(3)),
                    ],
                ));
            }
        }
        // With no context, a kind is reported by its own text.
        for kind in [
            ErrorKind::InvalidValue,
            ErrorKind::UnknownArgument,
            ErrorKind::InvalidSubcommand,
            ErrorKind::NoEquals,
            ErrorKind::ValueValidation,
            ErrorKind::TooManyValues,
            ErrorKind::TooFewValues,
            ErrorKind::WrongNumberOfValues,
            ErrorKind::ArgumentConflict,
            ErrorKind::MissingRequiredArgument,
            ErrorKind::MissingSubcommand,
            ErrorKind::InvalidUtf8,
            ErrorKind::Io,
        ] {
            shapes.push((kind, Vec::new()));
        }
        shapes
    }

    #[test]
    fn the_english_report_is_clap_s_own() {
        for (kind, context) in every_shape() {
            let clap = ansi(&built::<RichFormatter>(kind, &context));
            let piko = ansi(&built::<Formatter>(kind, &context));
            assert_eq!(piko, clap, "{kind:?} {context:?}");
        }
    }

    /// The same, for errors clap raises on piko's own command line.
    #[test]
    fn a_real_command_line_is_reported_as_clap_reports_it() {
        let lines: &[&[&str]] = &[
            &["piko", "lst"],
            &["piko", "zzz"],
            &["piko", "list", "-i", "--repos"],
            &["piko", "list", "--bogus"],
            &["piko", "list", "--repo"],
            &["piko", "history", "--last", "x"],
            &["piko", "history", "--since", "a", "--since", "b"],
            &["piko", "info"],
            &["piko", "why", "a", "b"],
            &["piko", "key"],
            &["piko", "--dbpath", "/nonexistent/piko", "list"],
            &["piko", "list", "-"],
        ];
        for line in lines {
            let Err(error) = Cli::command().try_get_matches_from(*line) else { continue };
            let clap = ansi(&error);
            let piko = ansi(&error.apply::<Formatter>());
            assert_eq!(piko, clap, "{line:?}");
        }
    }
}
