//! Command line argument definitions.
//!
//! Every doc comment on a [`Command`] variant is its `--help` text.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// The default `pacman.conf` path, matching `piko`'s own default.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/pacman.conf";

/// Where `populate` reads vendor keyrings from by default — pacman-key's own
/// `--populate-from` default, the directory the `archlinux-keyring` package ships into.
pub const DEFAULT_KEYRINGS_DIR: &str = "/usr/share/pacman/keyrings/";

/// Bootstraps and administers the GnuPG keyring piko verifies ALPM signatures against.
#[derive(Debug, Parser)]
#[command(name = "piko-key", version, about, long_about = None)]
pub struct Cli {
    /// The GnuPG home directory to administer. Defaults to `GPGDir` from the parsed
    /// pacman.conf (see `--config`); falls back to `/etc/pacman.d/gnupg` with a warning if
    /// that cannot be read.
    #[arg(long, global = true, value_name = "DIR")]
    pub gpgdir: Option<PathBuf>,

    /// Path to the pacman.conf-style configuration file `--gpgdir` is resolved from.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH, value_name = "PATH")]
    pub config: PathBuf,

    /// Where `populate` reads `<name>.gpg`/`<name>-trusted`/`<name>-revoked` from.
    #[arg(long, global = true, default_value = DEFAULT_KEYRINGS_DIR, value_name = "DIR")]
    pub keyring_dir: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

/// A subcommand of `piko-key`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the keyring if it does not exist, and generate piko's local master signing key
    /// if none exists yet. Safe to run again; a second run changes nothing.
    Init,

    /// Import and locally trust one or more named keyrings from `--keyring-dir`. With no
    /// names given, every keyring found there is populated.
    Populate {
        /// Keyring names (e.g. `archlinux`), matching `<name>.gpg` under `--keyring-dir`.
        keyrings: Vec<String>,
    },

    /// Import OpenPGP key material from one or more files.
    Add {
        /// Files to import, armored or binary.
        files: Vec<PathBuf>,
    },

    /// Locally (non-exportably) sign one or more keys, establishing them in the web of trust.
    LsignKey {
        /// Fingerprints (or any GnuPG-accepted identifier) of the keys to sign.
        keyids: Vec<String>,

        /// Skip the confirmation prompt and proceed as if the user answered yes.
        #[arg(long)]
        noconfirm: bool,
    },

    /// List keys in the keyring.
    ListKeys {
        /// Only list keys matching these identifiers. With none given, every key is listed.
        keyids: Vec<String>,
    },

    /// Delete one or more keys from the keyring.
    Delete {
        /// Fingerprints (or any GnuPG-accepted identifier) of the keys to delete.
        keyids: Vec<String>,

        /// Skip the confirmation prompt and proceed as if the user answered yes.
        #[arg(long)]
        noconfirm: bool,
    },

    /// Verify a detached signature.
    Verify {
        /// The `.sig`/`.asc` file.
        signature: PathBuf,

        /// The signed file. Defaults to `signature` with its extension removed.
        file: Option<PathBuf>,
    },

    /// Force GnuPG to recompute key validity from the current trust database.
    Updatedb,
}
