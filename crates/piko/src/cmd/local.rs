//! Subcommands reading the local (installed) database: the local-side rendering for `info`
//! ([`info`], also used as `info`'s installed-first fallback source).
//!
//! `list`, `search`, and `files`' installed-side file listing live in [`crate::cmd::list`],
//! [`crate::cmd::search`], and [`crate::cmd::files`], which also read repositories.

use std::{cell::OnceCell, process::ExitCode};

use alpm_types::{PackageInstallReason, PackageValidation};
use piko_db::{local::LocalDatabase, local::LocalPackage, solve::DependentsIndex};

use crate::output::{emit, escaped, join, report};
use crate::style::{
    field_list, info_build_fields, info_date, info_description_fields, info_label, optional_deps,
};

/// Builds `pacman -Qi`'s "Install Reason" text.
///
/// Mirrors `dump_pkg_full`'s switch (`pacman/src/pacman/package.c`) rather than
/// [`PackageInstallReason`]'s own `Display`, which renders the on-disk numeral (`"0"`/`"1"`)
/// instead of a human sentence.
fn install_reason_label(reason: PackageInstallReason) -> &'static str {
    match reason {
        PackageInstallReason::Explicit => "Explicitly installed",
        PackageInstallReason::Depend => "Installed as a dependency for another package",
    }
}

/// Colors [`install_reason_label`]. An explicit install is bold, being the state a user
/// actually chose. A dependency is dim, being a consequence of that choice.
fn styled_install_reason(reason: PackageInstallReason) -> console::StyledObject<&'static str> {
    let style = match reason {
        PackageInstallReason::Explicit => console::Style::new().bold(),
        PackageInstallReason::Depend => console::Style::new().dim(),
    };
    style.apply_to(install_reason_label(reason))
}

/// Builds `pacman -Qi`'s "Validated By" text.
///
/// Mirrors `dump_pkg_full`'s validation switch rather than [`PackageValidation`]'s own
/// `Display`. That `Display` renders the on-disk keyword (`"pgp"`, `"sha256"`, ...) instead of
/// pacman's label (`"Signature"`, `"SHA-256 Sum"`, ...). An empty list means no `%VALIDATION%`
/// section at all. It renders as `"Unknown"`, matching pacman's own fallback for a zero
/// validation value.
fn validation_label(validation: &[PackageValidation]) -> String {
    if validation.is_empty() {
        return "Unknown".to_owned();
    }
    let labels: Vec<&str> = validation
        .iter()
        .map(|value| match value {
            PackageValidation::None => "None",
            PackageValidation::Md5 => "MD5 Sum",
            PackageValidation::Sha256 => "SHA-256 Sum",
            PackageValidation::Pgp => "Signature",
        })
        .collect();
    join(&labels)
}

/// Colors [`validation_label`] by trust. A signature among the methods is green. A
/// checksum-only validation is yellow. `"Unknown"`, meaning no `%VALIDATION%` section, is
/// dim.
fn styled_validation(validation: &[PackageValidation]) -> console::StyledObject<String> {
    let text = validation_label(validation);
    let style = if text.contains("Signature") {
        console::Style::new().green()
    } else if text == "Unknown" {
        console::Style::new().dim()
    } else {
        console::Style::new().yellow()
    };
    style.apply_to(text)
}

fn yes_no(value: bool) -> &'static str {
    if value { "Yes" } else { "No" }
}

/// The installed database, with its "Required By" and "Optional For" index built on first use.
///
/// One value serves every package an `info` command shows. Building the index reads the whole
/// installed set, so it is built once, and only once a package from the installed database is
/// shown: a lookup that ends in a repository builds nothing.
#[derive(Debug)]
pub struct Installed<'a> {
    local: &'a LocalDatabase,
    dependents: OnceCell<piko_db::Result<DependentsIndex>>,
}

impl<'a> Installed<'a> {
    /// The installed database `local`, with no index built yet.
    pub const fn new(local: &'a LocalDatabase) -> Self {
        Self { local, dependents: OnceCell::new() }
    }

    /// The installed database.
    pub const fn local(&self) -> &'a LocalDatabase {
        self.local
    }

    /// The dependents index, built on the first call.
    fn dependents(&self) -> Result<&DependentsIndex, &piko_db::Error> {
        self.dependents.get_or_init(|| DependentsIndex::build(self.local)).as_ref()
    }
}

/// `zone` is the time zone the two date fields are rendered in, read in `main`.
///
/// See [`crate::output::human_date`].
pub fn info(
    installed: &Installed<'_>,
    package: &LocalPackage,
    zone: piko_txn::history::LocalZone,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let local = installed.local();
    let desc = match package.desc() {
        Ok(desc) => desc,
        Err(error) => {
            report(&*error);
            return ExitCode::FAILURE;
        }
    };

    let dependents = match installed.dependents() {
        Ok(index) => index.get(package.name().as_ref()),
        Err(error) => {
            report(error);
            return ExitCode::FAILURE;
        }
    };

    // An installed package's optional dependency is marked when something installed satisfies
    // it, by name or `%PROVIDES%`, as `alpm_find_satisfier` over the local database answers.
    let mut unanswered = None;
    let optional =
        optional_deps(desc.optional_depends(), desc.section_values("OPTDEPENDS"), |dep| {
            match piko_db::resolve::installed_satisfier(local, dep.package_relation()) {
                Ok(found) => found.is_some(),
                Err(error) => {
                    unanswered.get_or_insert(error);
                    false
                }
            }
        });
    info_description_fields!(out, package, desc, &optional);
    field_list!(out, "Required By     :", &dependents.required_by, 5);
    field_list!(out, "Optional For    :", &dependents.optional_for, 5);
    field_list!(out, "Conflicts With  :", desc.conflicts(), 5);
    field_list!(out, "Replaces        :", desc.replaces(), 5);
    info_build_fields!(out, desc, zone);
    let install_date = info_date(desc.install_date(), &desc.section_values("INSTALLDATE"), zone);
    emit!(out, "{} {install_date}", info_label("Install Date    :"));
    emit!(
        out,
        "{} {}",
        info_label("Install Reason  :"),
        styled_install_reason(desc.install_reason())
    );
    emit!(out, "{} {}", info_label("Install Script  :"), yes_no(package.has_install_scriptlet()));
    let validation = match desc.validation() {
        Ok(validation) => styled_validation(validation),
        Err(_) => console::Style::new()
            .dim()
            .apply_to(escaped(desc.section_values("VALIDATION").join(" "))),
    };
    emit!(out, "{} {}", info_label("Validated By    :"), validation);
    // A field shown as written above is named on stderr, so stdout stays what pacman prints.
    for reason in desc.invalid_fields() {
        crate::output::warn(format!("{}: {reason}", package.name()));
    }
    if let Some(error) = unanswered {
        crate::output::warn(format!(
            "{}: the optional dependencies marked [installed] may be incomplete: {error}",
            package.name()
        ));
    }
    for unread in &dependents.unread {
        crate::output::warn(format!(
            "Optional For may be incomplete: {}: {}",
            unread.package, unread.reason
        ));
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use piko_db::fixture::{PackageSpec, Scenario};

    use super::*;

    /// An optional dependency something installed satisfies is marked, by name or by
    /// `%PROVIDES%`, as `pacman -Qi` marks it. A version the installed package does not meet,
    /// or a name nothing provides, is not.
    #[test]
    fn an_installed_optional_dependency_is_marked() {
        let scenario = Scenario::new()
            .installed(PackageSpec::new("app", "1.0.0-1").optdepends([
                "cups: printing",
                "pdf-tool: viewing",
                "libfoo>=2: plugins",
                "absent: nothing",
            ]))
            .installed(PackageSpec::new("cups", "2.4.0-1"))
            .installed(PackageSpec::new("viewer", "1.0.0-1").provides(["pdf-tool"]))
            .installed(PackageSpec::new("libfoo", "1.0.0-1"))
            .build();
        let local = scenario.local();
        let package = local.get_str("app").unwrap();

        let mut out = Vec::new();
        let installed = Installed::new(local);
        assert_eq!(
            info(&installed, package, piko_txn::history::LocalZone::UTC, &mut out),
            ExitCode::SUCCESS
        );
        let text = String::from_utf8(out).unwrap();
        let text = console::strip_ansi_codes(&text);
        let lines: Vec<&str> = text
            .lines()
            .skip_while(|line| !line.starts_with("Optional Deps"))
            .take(4)
            .map(|line| line.strip_prefix("Optional Deps   :").unwrap_or(line).trim())
            .collect();

        assert_eq!(
            lines,
            [
                "cups: printing [installed]",
                "pdf-tool: viewing [installed]",
                "libfoo>=2: plugins",
                "absent: nothing"
            ]
        );
    }
}
