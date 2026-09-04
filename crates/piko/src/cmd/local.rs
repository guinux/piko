//! Subcommands reading the local (installed) database: the local-side rendering for `info`
//! ([`info`], also used as `info`'s installed-first fallback source).
//!
//! `list`, `search`, and `files`' installed-side file listing live in [`crate::cmd::list`],
//! [`crate::cmd::search`], and [`crate::cmd::files`], which also read repositories.

use std::process::ExitCode;

use alpm_types::{PackageInstallReason, PackageValidation};
use piko_db::{LocalDatabase, LocalPackage};

use crate::output::{emit, human_date, human_size, join, report};
use crate::style::{field_list, info_label, info_url};

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

/// Colors [`install_reason_label`]: bold for an explicit install (the state a user actually
/// chose), dim for a dependency (a consequence of that choice, not a choice of its own).
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
/// `Display`, which renders the on-disk keyword (`"pgp"`, `"sha256"`, ...) instead of pacman's
/// label (`"Signature"`, `"SHA-256 Sum"`, ...). An empty list, meaning no `%VALIDATION%`
/// section at all, renders as `"Unknown"`, matching pacman's own fallback for a zero
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

/// Colors [`validation_label`] by trust: green once a signature is among the methods, yellow
/// for a checksum-only validation, dim for `"Unknown"` (no `%VALIDATION%` section at all).
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

/// `offset` is the UTC offset the two date fields are rendered in, captured in `main`. See
/// [`crate::output::human_date`].
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

    let bold = console::Style::new().bold();
    let version = console::Style::new().cyan().bold();
    let url = info_url(desc.url().map(ToString::to_string), desc.url_raw());

    emit!(out, "{} {}", info_label("Name            :"), bold.apply_to(package.name()));
    emit!(out, "{} {}", info_label("Version         :"), version.apply_to(package.version()));
    emit!(out, "{} {}", info_label("Description     :"), desc.description());
    emit!(out, "{} {}", info_label("Architecture    :"), desc.architecture());
    emit!(out, "{} {url}", info_label("URL             :"));
    field_list!(out, "Licenses        :", desc.licenses(), 5);
    field_list!(out, "Groups          :", desc.groups(), 5);
    field_list!(out, "Provides        :", desc.provides(), 5);
    field_list!(out, "Depends On      :", desc.depends(), 5);
    field_list!(out, "Optional Deps   :", desc.optional_depends(), 1);
    field_list!(out, "Required By     :", &dependents.required_by, 5);
    field_list!(out, "Optional For    :", &dependents.optional_for, 5);
    field_list!(out, "Conflicts With  :", desc.conflicts(), 5);
    field_list!(out, "Replaces        :", desc.replaces(), 5);
    emit!(out, "{} {}", info_label("Installed Size  :"), human_size(desc.installed_size()));
    emit!(out, "{} {}", info_label("Packager        :"), desc.packager());
    emit!(out, "{} {}", info_label("Build Date      :"), human_date(desc.build_date(), offset));
    emit!(out, "{} {}", info_label("Install Date    :"), human_date(desc.install_date(), offset));
    emit!(
        out,
        "{} {}",
        info_label("Install Reason  :"),
        styled_install_reason(desc.install_reason())
    );
    emit!(out, "{} {}", info_label("Install Script  :"), yes_no(package.has_install_scriptlet()));
    emit!(out, "{} {}", info_label("Validated By    :"), styled_validation(desc.validation()));

    ExitCode::SUCCESS
}
