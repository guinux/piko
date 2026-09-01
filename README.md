# piko

[![CI](https://github.com/nuxgui/piko/actions/workflows/ci.yml/badge.svg)](https://github.com/nuxgui/piko/actions/workflows/ci.yml)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](#license)

piko is a package manager for ALPM-based systems, such as Arch Linux.
It reads and writes the same database and package formats as pacman.

## Why piko

Following the write of the official ALPM [specifications](https://alpm.archlinux.page/) and their implementation in Rust,
piko was written to take advantage of a modern programming language and its ecosystem.

Here are some principles used :
- **Memory-safe code.** The workspace forbids unsafe Rust everywhere.
- **Bounded reads.** Every file piko reads has a size limit. A corrupt or hostile
  database, archive, or compressed file cannot exhaust memory.
- **No symlink traversal.** The local database never follows a symlink where pacman's
  reader would. Package extraction confines every write inside the target root.
- **Interrupted transactions are visible.** A journal records intent before the first
  file changes. `piko report` reports an unfinished transaction.

Overall the aim is to make piko **secure**, **robust** and **simple**.

## Status

piko is stil an **Alpha software.** Do not run transactions with piko on a production system yet.

It can:
- read local database and repositories
- refresh databases and download packages
- run transaction including signatures verification, and running hooks and scriptlets.

Some features are not yet built: 
 - resume downloads
 - disk-space check
 
## Quick start

You can run these read-only commands against your installed system. None of them change anything:

```bash
piko list --i          # like pacman -Q
piko search firefox    # like pacman -Ss firefox
piko why systemd                # shortest dependency chain keeping it installed
piko plan -u                    # preview a sysupgrade; changes nothing
```

See [Main commands](#main-commands) below for the full command reference.

## Main commands

Read databases:

| Command | Alias | Purpose |
|---|---|---|
| `piko list [--installed\|--repos\|--repo [name]] [-f <names>...]` | `ls` | List installed packages (default), a repository's packages, or configured repository names; `-f` lists the named packages' files instead. |
| `piko info <package>... [--installed\|--repo <name>]` | `if` | Show one or more packages' metadata, from the installed database or a repository. |
| `piko search <terms>... [--installed\|--repos\|--repo <name>]` | `se` | Search installed packages, repositories, or both together. |
| `piko check-updates` | `cu` | List packages with a pending upgrade. |
| `piko why <package>` | Show the shortest dependency chain that keeps a package installed. |
| `piko conf` | | Parse and print the effective `pacman.conf`. |

Transaction:

| Command | Alias | Purpose |
|---|---|---|
| `piko refresh [repos]...` | `rf` | Download and verify repository databases. |
| `piko plan <targets>...` | Preview an install, removal (`-R`), or upgrade (`-u`) plan. |
| `piko install <packages>...` | `in` | Install packages and their dependencies. |
| `piko update [targets]...` | `up` | Upgrade the system, or the given targets. |
| `piko remove <packages>...` | `rm` | Remove packages. Supports `-s`/`--recursive`, `-c`/`--cascade`. |
| `piko report` | | Report an unfinished transaction. |

Keyring management (`piko-key`):

| Command | Purpose |
|---|---|
| `piko-key init` | Create the keyring and piko's local master signing key, if either is missing. |
| `piko-key populate [names]...` | Import and locally trust vendor keyrings (e.g. `archlinux`) from `/usr/share/pacman/keyrings`. |
| `piko-key add <files>...` | Import OpenPGP key material from files. |
| `piko-key lsign-key <keyids>...` | Locally sign one or more keys, establishing them in the web of trust. |
| `piko-key list-keys [keyids]...` | List keys in the keyring. |
| `piko-key delete <keyids>...` | Delete one or more keys. |
| `piko-key verify <sig> [file]` | Verify a detached signature. |

## Building the project

piko needs Rust edition 2024 and MSRV 1.90.

Build the workspace: `cargo build --workspace --release`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the build and lint workflow. Report a security
issue through [SECURITY.md](SECURITY.md), not a public issue.

## License

piko is licensed under Apache-2.0 OR MIT, at your option. See
[LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
