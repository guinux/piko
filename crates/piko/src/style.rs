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
/// frame. So the glyph marks the name of an item as much as the end of it. How the item ended
/// is reported separately.
///
/// This auto-detects terminal support the way every `console` style in this CLI does, by
/// testing file descriptor 1. Piped output gets plain text with no ANSI codes. The sink a
/// caller writes into is not consulted. So a test capturing into a `Vec<u8>` still sees the
/// codes when the suite runs from a terminal. Such a test strips them before asserting.
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

/// Dims `value` when it is `piko`'s "nothing here" placeholder, `"None"` or `"Unknown"`. An
/// absent field then recedes instead of matching the visual weight of real data.
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
/// disagree only when the value does not parse at all. piko keeps reading such a `desc`, and
/// libalpm prints the value verbatim. So reporting the field as absent would be a lie about
/// the file's contents. Preferring the normalized form keeps the common line unchanged.
///
/// The raw value is free text a mirror or a package chose, so it is escaped by
/// [`fn@piko_db::printable`].
///
/// Shared for the same reason as [`info_label`]: both `info` renderers draw this field.
pub(crate) fn info_url(
    normalized: Option<String>,
    raw: Option<&str>,
) -> console::StyledObject<String> {
    match normalized.or_else(|| raw.map(str::to_owned)) {
        Some(url) => console::Style::new().blue().apply_to(piko_db::printable(&url)),
        None => info_value("None".to_owned()),
    }
}

/// What a transaction does to one package.
///
/// The icon and the color, and nothing else. The *word* stays with each command module.
/// `piko plan` conjugates in the present ("upgrade", about to happen). `piko history` uses the
/// past ("upgraded", already done). Sharing the glyph is what makes a plan line and a history
/// line read alike. Sharing the word would make one of them lie about its tense.
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
    /// of a neutral tone. This detects terminal support the same way [`checkmark`] does.
    /// Piped output gets plain text with no ANSI codes, as does every test that captures into
    /// a `Vec<u8>`.
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
    /// `word` is the caller's, already padded to its module's column width. The tense differs
    /// between the two callers. So does the width the longest word in each set demands.
    pub(crate) fn prefix(self, word: &str) -> console::StyledObject<String> {
        self.style().apply_to(format!("{} {word}", self.icon()))
    }
}

/// Prints a `piko info` list field, wrapping `items` at `per_line` per line.
///
/// A line past the first is indented to the column [`info_label`]'s value starts at, not to
/// column zero. A wrapped list then still reads as one field rather than as loose trailing
/// lines. An empty list prints `"None"`, dimmed via [`info_value`].
///
/// Each item is escaped by [`crate::output::escaped`]. A group name, a license or an optional
/// dependency's description is free text a mirror or a package chose.
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
        let rendered = chunk.iter().map(crate::output::escaped).collect::<Vec<_>>().join("  ");
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
/// Both `piko info` renderers print several list fields in a row. This keeps each call site a
/// single line. Otherwise each repeats the "check the code, return on failure" boilerplate
/// that [`crate::output::emit`] already inlines for a single line.
macro_rules! field_list {
    ($out:expr, $label:expr, $items:expr, $per_line:expr) => {{
        let code = $crate::style::render_list_field($out, $label, $items, $per_line);
        if code != ::std::process::ExitCode::SUCCESS {
            return code;
        }
    }};
}

pub(crate) use field_list;

/// Renders a date field of `piko info`: `typed` in the local time zone, or the section's lines
/// `raw` as the `desc` holds them when they are not a timestamp.
pub(crate) fn info_date<E>(
    typed: Result<i64, E>,
    raw: &[&str],
    zone: piko_txn::LocalZone,
) -> String {
    match typed {
        Ok(timestamp) => crate::output::human_date(timestamp, zone),
        Err(_) => crate::output::escaped(raw.join(" ")),
    }
}

/// The `Optional Deps` entries of `piko info`, one per optional dependency.
///
/// `typed` is `%OPTDEPENDS%` as parsed, and `raw` its lines as written, shown when the parse
/// failed. An entry `installed` answers `true` for is marked ` [installed]`, as pacman's
/// `optdeplist_display` marks it (`package.c:163`). pacman marks only an installed package's
/// entries, so the repository side passes a test that answers `false`.
pub(crate) fn optional_deps<E>(
    typed: Result<&[alpm_types::OptionalDependency], E>,
    raw: Vec<&str>,
    mut installed: impl FnMut(&alpm_types::OptionalDependency) -> bool,
) -> Vec<String> {
    match typed {
        Ok(optional) => optional
            .iter()
            .map(|dep| if installed(dep) { format!("{dep} [installed]") } else { dep.to_string() })
            .collect(),
        Err(_) => raw.into_iter().map(str::to_owned).collect(),
    }
}

/// Prints the `piko info` fields from `Name` to `Optional Deps`, which `pacman -Qi` and
/// `pacman -Si` print alike. `$optional` holds the `Optional Deps` entries, built by
/// [`optional_deps`].
///
/// This is a macro rather than a function because a local `DescView` and a repository
/// `RepoDescView` have the same accessors and no trait in common. Like `field_list!`, it returns
/// from the enclosing function if a write fails.
macro_rules! info_description_fields {
    ($out:expr, $package:expr, $desc:expr, $optional:expr) => {{
        use $crate::output::{emit, escaped};
        use $crate::style::{field_list, info_label, info_url};

        let (package, desc) = ($package, $desc);
        let bold = console::Style::new().bold();
        let version = console::Style::new().cyan().bold();
        let url = info_url(desc.url().map(ToString::to_string), desc.url_raw());

        emit!($out, "{} {}", info_label("Name            :"), bold.apply_to(package.name()));
        emit!($out, "{} {}", info_label("Version         :"), version.apply_to(package.version()));
        emit!($out, "{} {}", info_label("Description     :"), escaped(desc.description()));
        emit!($out, "{} {}", info_label("Architecture    :"), escaped(desc.architecture()));
        emit!($out, "{} {url}", info_label("URL             :"));
        match desc.licenses() {
            Ok(licenses) => field_list!($out, "Licenses        :", licenses, 5),
            Err(_) => field_list!($out, "Licenses        :", &desc.section_values("LICENSE"), 5),
        }
        field_list!($out, "Groups          :", desc.groups(), 5);
        field_list!($out, "Provides        :", desc.provides(), 5);
        field_list!($out, "Depends On      :", desc.depends(), 5);
        field_list!($out, "Optional Deps   :", $optional, 1);
    }};
}

pub(crate) use info_description_fields;

/// Prints the `piko info` fields `Installed Size`, `Packager` and `Build Date`, which
/// `pacman -Qi` and `pacman -Si` print alike. See `info_description_fields!` for why this is a
/// macro.
macro_rules! info_build_fields {
    ($out:expr, $desc:expr, $zone:expr) => {{
        use $crate::output::{emit, escaped, human_size};
        use $crate::style::{info_date, info_label};

        let desc = $desc;
        emit!($out, "{} {}", info_label("Installed Size  :"), human_size(desc.installed_size()));
        emit!(
            $out,
            "{} {}",
            info_label("Packager        :"),
            escaped(desc.packager_raw().unwrap_or_default())
        );
        let build_date = info_date(desc.build_date(), &desc.section_values("BUILDDATE"), $zone);
        emit!($out, "{} {build_date}", info_label("Build Date      :"));
    }};
}

pub(crate) use info_build_fields;

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    /// A payload no `console` style ever emits: an OSC 52 clipboard write, ended by a bell.
    const CLIPBOARD: &str = "\u{1b}]52;c;cHduZWQ=\u{7}";

    #[test]
    fn a_raw_url_is_escaped() {
        let url = info_url(None, Some(&format!("https://x.invalid/{CLIPBOARD}"))).to_string();
        assert!(!url.contains('\u{7}'), "{url}");
        assert!(url.contains("\\u{1b}]52"), "{url}");
    }

    /// A group name, a license or an optional dependency's description is escaped item by item.
    #[test]
    fn a_list_field_escapes_each_item() {
        let items = vec!["plain".to_owned(), format!("bar: {CLIPBOARD}")];
        let mut out = Vec::new();
        assert_eq!(
            render_list_field(&mut out, "Optional Deps   :", &items, 1),
            std::process::ExitCode::SUCCESS
        );
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains('\u{7}'), "{text}");
        assert!(text.contains("plain"), "{text}");
        assert!(text.contains("bar: \\u{1b}]52"), "{text}");
    }
}
