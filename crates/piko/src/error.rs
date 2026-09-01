//! The error type every subcommand dispatch path propagates.
//!
//! The CLI fails in ways no library crate has a type for: a `pacman.conf` that a subcommand
//! about the configuration cannot fall back from, a repository name typed wrong on the
//! command line, and a repository archive whose signature the configured `SigLevel` refuses.
//! None of those is a `piko_db::Error`, so borrowing that enum to carry them cost the CLI
//! twice over. Every helper returning a different type needed a hand-written `match` instead
//! of `?`, and a signature verdict had to be disguised as [`piko_db::Error::Io`]. That made
//! `piko` report a rejected `core.db` as "failed to open" when the archive had opened fine.
//!
//! One enum with a `From` for each fixes both problems: [`crate::main`]'s dispatch is `?`
//! throughout, and a rejection says what it is.
//!
//! Rendering is [`crate::output::report`]'s job. It prints this and then walks
//! [`std::error::Error::source`]. That is why the variants that wrap another error keep it as
//! a `#[source]` rather than folding it into their own message.

use std::path::PathBuf;

/// Anything that stops a `piko` subcommand before it can print its answer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A database, an archive, or a configuration file could not be read.
    ///
    /// Transparent: `piko_db::Error` already names the path and the operation, and its own
    /// `source` chain carries the reason, so wrapping it in a second message would only
    /// repeat one of them.
    #[error(transparent)]
    Db(#[from] piko_db::Error),

    /// The `pacman.conf` a subcommand cannot proceed without could not be read.
    ///
    /// Distinct from [`Error::Db`] because it is not a read failure the caller can retry
    /// differently — see [`crate::context::require_pacman_config`] for which subcommands can
    /// fall back to a default instead and which cannot.
    #[error(transparent)]
    Config(#[from] crate::context::ConfigUnavailable),

    /// A `--repo` argument is not a syntactically valid repository name.
    #[error("{name} is not a valid repository name")]
    InvalidRepoName {
        /// What was typed.
        name: String,
    },

    /// A repository archive's signature was checked and refused.
    ///
    /// Carries [`piko_sig::Rejection`] itself rather than a rendered string. It is a small
    /// `Clone` enum. Keeping it typed means the reason stays inspectable by anything that
    /// matches on this error, rather than only printable.
    #[error("the signature on {} was rejected: {rejection}", archive.display())]
    SignatureRejected {
        /// The archive that was refused.
        archive: PathBuf,
        /// Why the configured `SigLevel` refused it.
        rejection: piko_sig::Rejection,
    },

    /// A repository archive's signature could not be checked at all.
    ///
    /// Separate from [`Error::SignatureRejected`] because the two send the user to different
    /// places: a rejection is a mirror problem, an uncheckable signature is usually a keyring
    /// one. `piko_sig::Error`'s own message says which. It is kept as a `#[source]` so
    /// [`crate::output::report`] prints it on its own `caused by:` line.
    #[error("cannot check the signature on {}", archive.display())]
    SignatureUncheckable {
        /// The archive whose signature could not be checked.
        archive: PathBuf,
        /// What stopped the check.
        #[source]
        source: piko_sig::Error,
    },
}
