//! The `piko-key` command line interface: pacman-key's role for piko.
//!
//! Bootstrapping and administering a keyring is a distinct concern from verifying against one
//! — see `piko-sig-write`'s crate doc for why that split runs one way, and why every real
//! operation here happens through GPGME rather than a `gpg` subprocess.

mod cli;
mod commands;
mod output;

use std::{io::Write as _, path::PathBuf, process::ExitCode};

use clap::Parser as _;

use crate::cli::{Cli, Command};
use crate::output::report;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut out = std::io::BufWriter::new(std::io::stdout());

    let code = run(&cli, &mut out);
    if let Err(error) = out.flush()
        && error.kind() != std::io::ErrorKind::BrokenPipe
    {
        report(&error);
        return ExitCode::FAILURE;
    }
    code
}

fn run(cli: &Cli, out: &mut impl std::io::Write) -> ExitCode {
    let gpgdir = resolve_gpgdir(cli);

    match &cli.command {
        Command::Init => commands::init(&gpgdir, out),
        Command::Populate { keyrings } => {
            commands::populate(&gpgdir, &cli.keyring_dir, keyrings, out)
        }
        Command::Add { files } => commands::add(&gpgdir, files, out),
        Command::LsignKey { keyids, noconfirm } => {
            commands::lsign_key(&gpgdir, keyids, *noconfirm, out)
        }
        Command::ListKeys { keyids } => commands::list_keys(&gpgdir, keyids, out),
        Command::Delete { keyids, secret, noconfirm } => {
            commands::delete(&gpgdir, keyids, *secret, *noconfirm, out)
        }
        Command::Verify { signature, file } => {
            commands::verify(&gpgdir, signature, file.as_deref(), out)
        }
        Command::Updatedb => commands::updatedb(&gpgdir, out),
    }
}

/// Resolves the effective GnuPG home: `--gpgdir` if given, else `GPGDir` from the parsed
/// `--config`, else pacman's own default with a warning if the config cannot be read.
///
/// The same fallback chain `crates/piko/src/context.rs`'s `signing_policy` already implements
/// — read directly here rather than shared, since it is six lines and this is only the second
/// call site; worth factoring into `piko_db::config` if a third binary ever needs it.
fn resolve_gpgdir(cli: &Cli) -> PathBuf {
    if let Some(gpgdir) = &cli.gpgdir {
        return gpgdir.clone();
    }

    match piko_db::config::PacmanConfig::open(&cli.config) {
        Ok(config) => config.options.gpg_dir,
        Err(error) => {
            eprintln!(
                "piko-key: warning: failed to read {} ({error}); falling back to {}",
                cli.config.display(),
                piko_db::config::DEFAULT_GPG_DIR
            );
            PathBuf::from(piko_db::config::DEFAULT_GPG_DIR)
        }
    }
}
