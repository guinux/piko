//! The repository-side rendering for `piko info`: [`repo_info`].
//!
//! `list`, `search`, and `files`' repository-side file listing live in [`crate::cmd::list`],
//! [`crate::cmd::search`], and [`crate::cmd::files`].

use std::process::ExitCode;

use piko_db::repo::{RepoDatabase, RepoPackage};

use crate::output::{emit, human_date, human_size, join, report};
use crate::style::{field_list, info_label, info_url};

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

/// `offset` is the UTC offset `Build Date` is rendered in, captured in `main`. See
/// [`crate::output::human_date`].
pub fn repo_info(
    db: &RepoDatabase,
    package: &RepoPackage,
    offset: piko_txn::LocalOffset,
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
    let version = console::Style::new().cyan().bold();
    let url = info_url(desc.url().map(ToString::to_string), desc.url_raw());

    emit!(out, "{} {}", info_label("Repository      :"), bold.apply_to(db.name()));
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
    field_list!(out, "Conflicts With  :", desc.conflicts(), 5);
    field_list!(out, "Replaces        :", desc.replaces(), 5);
    emit!(out, "{} {}", info_label("Download Size   :"), human_size(desc.compressed_size()));
    emit!(out, "{} {}", info_label("Installed Size  :"), human_size(desc.installed_size()));
    emit!(out, "{} {}", info_label("Packager        :"), desc.packager_raw().unwrap_or_default());
    emit!(out, "{} {}", info_label("Build Date      :"), human_date(desc.build_date(), offset));
    emit!(
        out,
        "{} {}",
        info_label("Validated By    :"),
        styled_validation(desc.pgp_signature().is_some())
    );

    ExitCode::SUCCESS
}
