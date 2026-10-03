//! Subcommands reading the local (installed) database: the local-side rendering for `info`
//! ([`info`], also used as `info`'s installed-first fallback source).
//!
//! `list`, `search`, and `files`' installed-side file listing live in [`crate::cmd::list`],
//! [`crate::cmd::search`], and [`crate::cmd::files`], which also read repositories.

use std::process::ExitCode;

use alpm_types::{PackageInstallReason, PackageValidation};
use piko_db::{LocalDatabase, LocalPackage};

use crate::output::{emit, escaped, join, report};
use crate::style::{field_list, info_build_fields, info_date, info_description_fields, info_label};

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

/// `offset` is the UTC offset the two date fields are rendered in, captured in `main`.
///
/// See [`crate::output::human_date`].
pub fn info(
    local: &LocalDatabase,
    package: &LocalPackage,
    offset: piko_txn::LocalOffset,
    out: &mut impl std::io::Write,
) -> ExitCode {
    let desc = match package.desc() {
        Ok(desc) => desc,
        Err(error) => {
            report(&*error);
            return ExitCode::FAILURE;
        }
    };

    let dependents = match piko_db::solve::dependents(local, package.name().as_ref()) {
        Ok(dependents) => dependents,
        Err(error) => {
            report(&error);
            return ExitCode::FAILURE;
        }
    };

    info_description_fields!(out, package, desc);
    field_list!(out, "Required By     :", &dependents.required_by, 5);
    field_list!(out, "Optional For    :", &dependents.optional_for, 5);
    field_list!(out, "Conflicts With  :", desc.conflicts(), 5);
    field_list!(out, "Replaces        :", desc.replaces(), 5);
    info_build_fields!(out, desc, offset);
    let install_date = info_date(desc.install_date(), &desc.section_values("INSTALLDATE"), offset);
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
    for unread in &dependents.unread {
        crate::output::warn(format!(
            "Optional For may be incomplete: {}: {}",
            unread.package, unread.reason
        ));
    }

    ExitCode::SUCCESS
}
