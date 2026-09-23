# piko

[![CI](https://github.com/nuxgui/piko/actions/workflows/ci.yml/badge.svg)](https://github.com/nuxgui/piko/actions/workflows/ci.yml)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](#license)

piko is a package manager for ALPM-based systems, such as Arch Linux.
It reads and writes the same database and package formats as pacman.

## Why piko

The ALPM [specifications](https://alpm.archlinux.page/) now have an official definition and a Rust
implementation. piko uses them to take advantage of a modern programming language and its ecosystem.

piko follows these principles:
- **Memory-safe code.** The workspace forbids unsafe Rust everywhere.
- **Bounded reads.** Every file piko reads has a size limit. A corrupt or hostile
  database, archive, or compressed file cannot exhaust memory.
- **No symlink traversal.** The local database never follows a symlink where pacman's
  reader would. Package extraction confines every write inside the target root.
- **Verify before replace.** A downloaded database or package is checked against its
  `SigLevel` before it replaces anything on disk. A database older than the installed one
  is refused.
- **Interrupted transactions are visible.** A journal records intent before the first
  file changes. `piko report` reports an unfinished transaction.

Overall the aim is to make piko **secure**, **robust** and **simple**.

## Status

piko is **beta software**. Every planned feature for a full package manager is built:
install, removal, upgrade and sysupgrade, with signature verification, hooks, scriptlets
and parallel downloads. Each feature is tested against a real Arch Linux system.

Tests and bug reports are welcome. Keep pacman available as a fallback, and do not use
piko on a critical system yet.

A command that changes the system (`install`, `update`, `remove`, `refresh`, and the
keyring changes of `piko key`) must run as root. Pass `--root`, `--dbpath` or `--gpgdir`
to a directory you own to run it as an ordinary user.

## Quick start

You can run these read-only commands against your installed system. None of them change
anything:

```bash
piko list -i           # like pacman -Q
piko search firefox    # like pacman -Ss firefox
piko files bash        # like pacman -Ql bash
piko owns /usr/bin/vi  # like pacman -Qo /usr/bin/vi
piko why systemd       # shortest dependency chain keeping it installed
piko plan -u           # preview a sysupgrade; changes nothing
```

See [Main commands](#main-commands) below for the full command reference. Run
`piko <command> --help` for every option of a command.

## Main commands

Read databases. None of these write anything:

| Command | Alias | Purpose |
|---|---|---|
| `piko list [-i\|--repos\|--repo <name>] [-e\|-o\|-m] [-g [names]...]` | `ls` | List installed packages (default), a repository's packages, or the configured repository names. `-e`, `-o` and `-m` list explicit, orphan and foreign packages. `-g` lists groups instead. |
| `piko files <packages>... [-i\|--repo <name>]` | | List the files one or more packages own, like `pacman -Ql`. |
| `piko owns <paths>...` | | Name the installed package that owns a file, like `pacman -Qo`. |
| `piko info <packages>... [-i\|--repo <name>]` | `if` | Show one or more packages' metadata, from the installed database or a repository. |
| `piko search <terms>... [-i\|--repos\|--repo <name>]` | `se` | Search installed packages, repositories, or both together. A term can be a glob pattern. |
| `piko check [packages]...` | | Check that installed files still match the package's `ALPM-MTREE` data. |
| `piko check-updates` | `cu` | List packages with a pending upgrade, like `pacman -Qu`. |
| `piko why <package>` | | Show the shortest dependency chain that keeps a package installed. |
| `piko resolve <dependency>` | | Print the repository package(s) that satisfy a dependency string. |
| `piko conf [directive]` | | Parse and print the effective `pacman.conf`, or one directive's value. |
| `piko history [-n <count>\|-a] [-p <package>] [--since <when>] [--until <when>]` | | Show the transactions this system has run. It reads pacman's log too, so it covers both tools. |
| `piko report` | | Report an unfinished transaction, if the database records one. |

Transaction:

| Command | Alias | Purpose |
|---|---|---|
| `piko refresh [repos]... [--files]` | `rf` | Download and verify repository databases. `--files` also downloads the `.files` databases, like `pacman -Fy`. |
| `piko plan [targets]...` | | Preview an install, a removal (`-R`), or an upgrade (`-u`) plan. `--explain` says why each step is in the plan. Changes nothing. |
| `piko install <targets>...` | `in` | Install packages and their dependencies. A target can be a name, a group, a glob pattern, a package file or a URL. `--needed` skips a target already at that version; `-w` downloads without installing. |
| `piko update [targets]...` | `up` | Refresh the databases, then upgrade the system, like `pacman -Syu`. `--norefresh` skips the refresh. |
| `piko remove <packages>...` | `rm` | Remove packages. Supports `-s`/`--recursive`, `-c`/`--cascade`. |
| `piko merge [paths]...` | `mg` | Resolve the `.pacnew` and `.pacsave` files that transactions left, like `pacdiff`. `-o` lists them and changes nothing. |

Keyring management (`piko key`, like `pacman-key`):

| Command | Purpose |
|---|---|
| `piko key init` | Create the keyring and piko's local master signing key, if either is missing. |
| `piko key populate [names]...` | Import and locally trust vendor keyrings (e.g. `archlinux`) from `/usr/share/pacman/keyrings`. |
| `piko key add <files>...` | Import OpenPGP key material from files. |
| `piko key lsign-key <keyids>...` | Locally sign one or more keys, establishing them in the web of trust. |
| `piko key list-keys [keyids]...` | List keys in the keyring. |
| `piko key delete <keyids>...` | Delete one or more keys. |
| `piko key verify <sig> [file]` | Verify a detached signature. |
| `piko key updatedb` | Recompute key validity from the current trust database. |

## Building the project

piko needs Rust edition 2024 and MSRV 1.90.

Build the workspace: `cargo build --workspace --release`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the build and lint workflow. Report a security
issue through [SECURITY.md](SECURITY.md), not a public issue.

## License

piko is licensed under Apache-2.0 OR MIT, at your option. See
[LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
