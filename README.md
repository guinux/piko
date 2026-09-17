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

piko is still **alpha software**. Do not run transactions with piko on a production
system yet.

It can:
- read the local database and the repositories
- refresh databases and download packages
- run a transaction, with signature verification, hooks and scriptlets

Some features are not yet built:
- resumed downloads

## Quick start

You can run these read-only commands against your installed system. None of them change
anything:

```bash
piko list -i           # like pacman -Q
piko search firefox    # like pacman -Ss firefox
piko files bash        # like pacman -Ql bash
piko why systemd       # shortest dependency chain keeping it installed
piko plan -u           # preview a sysupgrade; changes nothing
```

See [Main commands](#main-commands) below for the full command reference.

## Main commands

Read databases. None of these write anything:

| Command | Alias | Purpose |
|---|---|---|
| `piko list [-i\|--repos\|--repo <name>] [-g [names]...]` | `ls` | List installed packages (default), a repository's packages, or the configured repository names. `-g` lists groups instead. |
| `piko files <packages>... [-i\|--repo <name>]` | | List the files one or more packages own, like `pacman -Ql`. |
| `piko info <packages>... [-i\|--repo <name>]` | `if` | Show one or more packages' metadata, from the installed database or a repository. |
| `piko search <terms>... [-i\|--repos\|--repo <name>]` | `se` | Search installed packages, repositories, or both together. |
| `piko check [packages]...` | | Check that installed files still match the package's `ALPM-MTREE` data. |
| `piko check-updates` | `cu` | List packages with a pending upgrade. |
| `piko why <package>` | | Show the shortest dependency chain that keeps a package installed. |
| `piko resolve <dependency>` | | Print the repository package(s) that satisfy a dependency string. |
| `piko conf [directive]` | | Parse and print the effective `pacman.conf`, or one directive's value. |
| `piko history [-n <count>]` | | Show the transactions this system has run. It reads pacman's log too, so it covers both tools. |
| `piko report` | | Report an unfinished transaction, if the database records one. |

Transaction:

| Command | Alias | Purpose |
|---|---|---|
| `piko refresh [repos]...` | `rf` | Download and verify repository databases. |
| `piko plan [targets]...` | | Preview an install, a removal (`-R`), or an upgrade (`-u`) plan. Changes nothing. |
| `piko install <targets>...` | `in` | Install packages and their dependencies. A target may also be a package file or a URL. `--needed` skips a target already at that version; `-w` downloads without installing. |
| `piko update [targets]...` | `up` | Upgrade the system, or the given targets. |
| `piko remove <packages>...` | `rm` | Remove packages. Supports `-s`/`--recursive`, `-c`/`--cascade`. |

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
