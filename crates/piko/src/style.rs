//! The one piece of the CLI's visual language shared verbatim across command modules.
//!
//! See `docs/cli-style.md` for the full set of conventions this, [`crate::progress`], and
//! [`crate::cmd::plan`] follow. Most conventions are domain-specific and stay local to the
//! module that draws them.

/// Returns the green check for "this is done", "this is already the case", or "this is the
/// line naming what follows".
///
/// Used for a [`progress`](crate::progress) row's plain line, and for an installed package in
/// `piko search`/`piko list`. A commit's rows print that line as soon as they have output to
/// frame, so the glyph marks the name of an item as much as the end of it; how the item ended
/// is reported separately. Auto-detects terminal support the way every `console` style in this
/// CLI does: piped output, and every test capturing into a `Vec<u8>`, gets plain text with no
/// ANSI codes.
pub(crate) fn checkmark() -> console::StyledObject<&'static str> {
    console::Style::new().green().apply_to("✓")
}

/// Dims a fixed-width field label, e.g. `"Name            :"`, for `piko info`'s label:value
/// grid.
///
/// Shared between [`crate::cmd::local::info`] and [`crate::cmd::repo::repo_info`], which draw
/// the same grid over two different package sources. Dimming the label rather than the value
/// keeps the value, not its caption, as the visually dominant part of the line.
pub(crate) fn info_label(text: &'static str) -> console::StyledObject<&'static str> {
    console::Style::new().dim().apply_to(text)
}

/// Dims `value` when it is `piko`'s "nothing here" placeholder (`"None"` or `"Unknown"`), so an
/// absent field recedes instead of matching the visual weight of real data.
///
/// Shared for the same reason as [`info_label`]: both `info` renderers list fields that fall
/// back to one of these two placeholders.
pub(crate) fn info_value(value: String) -> console::StyledObject<String> {
    let style = if value == "None" || value == "Unknown" {
        console::Style::new().dim()
    } else {
        console::Style::new()
    };
    style.apply_to(value)
}

/// Renders the `URL` field of `piko info`, in blue, or a dimmed `"None"`.
///
/// `normalized` is `%URL%` as `url::Url` parsed it, `raw` the bytes the `desc` holds. The two
/// disagree only when the value does not parse at all: piko keeps reading such a `desc`
/// and libalpm prints the value verbatim, so reporting the field as absent would be a lie
/// about the file's contents. Preferring the normalized form keeps the common line identical
/// to what this CLI has always printed.
///
/// Shared for the same reason as [`info_label`]: both `info` renderers draw this field.
pub(crate) fn info_url(
    normalized: Option<String>,
    raw: Option<&str>,
) -> console::StyledObject<String> {
    match normalized.or_else(|| raw.map(str::to_owned)) {
        Some(url) => console::Style::new().blue().apply_to(url),
        None => info_value("None".to_owned()),
    }
}

/// What a transaction does to one package.
///
/// The icon and the color, and nothing else. The *word* stays with each command module:
/// `piko plan` conjugates in the present ("upgrade", about to happen) and `piko history` in
/// the past ("upgraded", already done). Sharing the glyph is what makes a plan line and a
/// history line read alike; sharing the word would make one of them lie about its tense.
///
/// This is the second thing in this module, after [`checkmark`], that more than one command
/// module needs with the exact same meaning. `cmd::search`'s green ✓ and `cmd::files`'s dimmed
/// name are still local vocabularies, and stay where they are.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChangeKind {
    /// Nothing of this name was installed.
    Install,
    /// A lower version was installed.
    Upgrade,
    /// A higher version was installed.
    Downgrade,
    /// The same version was installed.
    Reinstall,
    /// The package is no longer installed.
    Remove,
}

impl ChangeKind {
    /// The one glyph a line starts with.
    pub(crate) const fn icon(self) -> &'static str {
        match self {
            Self::Install => "+",
            Self::Upgrade => "↑",
            Self::Downgrade => "↓",
            Self::Reinstall => "↻",
            Self::Remove => "-",
        }
    }

    /// A reinstall changes nothing, so it stays dim instead of taking its own color. A
    /// downgrade is a regression worth flagging, not just narrating, so it gets amber instead
    /// of a neutral tone. This detects terminal support the same way [`checkmark`] does:
    /// piped output, and every test that captures into a `Vec<u8>`, gets plain text with no
    /// ANSI codes.
    pub(crate) fn style(self) -> console::Style {
        let style = console::Style::new();
        match self {
            Self::Install => style.green(),
            Self::Upgrade => style.blue(),
            Self::Downgrade => style.yellow(),
            Self::Reinstall => style.dim(),
            Self::Remove => style.red(),
        }
    }

    /// The colored `"{icon} {word}"` a line starts with.
    ///
    /// `word` is the caller's, already padded to its module's column width — the tense differs
    /// between the two callers, and so does the width the longest word in each set demands.
    pub(crate) fn prefix(self, word: &str) -> console::StyledObject<String> {
        self.style().apply_to(format!("{} {word}", self.icon()))
    }
}

/// Prints a `piko info` list field, wrapping `items` at `per_line` per line.
///
/// A line past the first is indented to the column [`info_label`]'s value starts at, not to
/// column zero, so a wrapped list still reads as one field rather than as loose trailing lines.
/// An empty list prints `"None"`, dimmed via [`info_value`].
pub(crate) fn render_list_field<T: std::fmt::Display>(
    out: &mut impl std::io::Write,
    label: &'static str,
    items: &[T],
    per_line: usize,
) -> std::process::ExitCode {
    use crate::output::emit;

    if items.is_empty() {
        emit!(out, "{} {}", info_label(label), info_value("None".to_owned()));
        return std::process::ExitCode::SUCCESS;
    }

    let indent = " ".repeat(label.chars().count().saturating_add(1));
    for (index, chunk) in items.chunks(per_line.max(1)).enumerate() {
        let rendered = chunk.iter().map(ToString::to_string).collect::<Vec<_>>().join("  ");
        if index == 0 {
            emit!(out, "{} {rendered}", info_label(label));
        } else {
            emit!(out, "{indent}{rendered}");
        }
    }
    std::process::ExitCode::SUCCESS
}

/// Calls [`render_list_field`] and returns from the enclosing function (which must return
/// [`std::process::ExitCode`]) if the write failed.
///
/// Both `piko info` renderers print several list fields in a row; this keeps each call site a
/// single line instead of repeating the "check the code, return on failure" boilerplate that
/// [`crate::output::emit`] already inlines for a single line.
macro_rules! field_list {
    ($out:expr, $label:expr, $items:expr, $per_line:expr) => {{
        let code = $crate::style::render_list_field($out, $label, $items, $per_line);
        if code != ::std::process::ExitCode::SUCCESS {
            return code;
        }
    }};
}

pub(crate) use field_list;
