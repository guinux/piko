//! The repository-side rendering for `piko info`: [`repo_info`].
//!
//! `list`, `search`, and `files`' repository-side file listing live in [`crate::cmd::list`],
//! [`crate::cmd::search`], and [`crate::cmd::files`].

use std::process::ExitCode;

use piko_db::repo::{RepoDatabase, RepoPackage};

use crate::output::{emit, human_size, join, report};
use crate::style::{
    field_list, info_build_fields, info_description_fields, info_label, optional_deps,
};

/// Builds `pacman -Si`'s "Validated By" label.
///
/// `"SHA-256 Sum"` is always present, since a repository `desc` always carries `%SHA256SUM%`.
/// `"Signature"` is added when a `%PGPSIG%` was published. This reproduces libalpm's own
/// `_sync_get_validation` (`be_sync.c`); it is not a new rule.
fn validation_label(has_signature: bool) -> String {
    if has_signature { join(&["SHA-256 Sum", "Signature"]) } else { "SHA-256 Sum".to_owned() }
}

/// Colors [`validation_label`]: green once a signature was published, yellow for
/// checksum-only, matching [`crate::cmd::local::info`]'s trust palette.
fn styled_validation(has_signature: bool) -> console::StyledObject<String> {
    let style =
        if has_signature { console::Style::new().green() } else { console::Style::new().yellow() };
    style.apply_to(validation_label(has_signature))
}

/// `zone` is the time zone `Build Date` is rendered in, read in `main`.
///
/// See [`crate::output::human_date`].
pub fn repo_info(
    db: &RepoDatabase,
    package: &RepoPackage,
    zone: piko_txn::history::LocalZone,
    out: &mut impl std::io::Write,
) -> ExitCode {
    // `info`'s repository-side rendering prints every field, so it needs the deferred parse.
    // It reports a failure rather than printing a partial entry.
    let desc = match package.desc() {
        Ok(desc) => desc,
        Err(error) => {
            report(&*error);
            return ExitCode::FAILURE;
        }
    };

    let bold = console::Style::new().bold();
    emit!(out, "{} {}", info_label("Repository      :"), bold.apply_to(db.name()));
    let optional =
        optional_deps(desc.optional_depends(), desc.section_values("OPTDEPENDS"), |_| false);
    info_description_fields!(out, package, desc, &optional);
    field_list!(out, "Conflicts With  :", desc.conflicts(), 5);
    field_list!(out, "Replaces        :", desc.replaces(), 5);
    emit!(out, "{} {}", info_label("Download Size   :"), human_size(desc.compressed_size()));
    info_build_fields!(out, desc, zone);
    emit!(
        out,
        "{} {}",
        info_label("Validated By    :"),
        styled_validation(desc.pgp_signature().is_some())
    );
    // A field shown as written above is named on stderr, so stdout stays what pacman prints.
    for reason in desc.invalid_fields() {
        crate::output::warn(format!("{}: {reason}", package.name()));
    }

    ExitCode::SUCCESS
}
