# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Local database reader: directory-name-based scanning, lazy `desc`/`files`/`mtree`.
- Repository database reader: `desc` parsing, archive handling.
- Multi-repository dependency resolution (literal name, `%PROVIDES%`, soname matching).
- `pacman.conf`-style configuration parsing, printed by `piko conf`.
- Transaction planner with a CDCL solver: install, remove (`-R`/`-Rs`/`-Rc`/`-Rcs`),
  sysupgrade (`-u`), `HoldPkg`, `piko why`.
- Local database writer, matching pacman's `db.lck` locking semantics.
- Commit engine: install, upgrade, removal, file-conflict detection, scriptlets and hooks.
- OpenPGP signature verification (GPGME-backed) for packages and repository databases.
- Installing a package file named by a path or a URL, pacman's `-U`, spelled as an ordinary
  `piko install` target.
- Keyring administration through `piko-key`, pacman-key's counterpart.
- Repository database refresh and package download, with signature verification before a
  download replaces anything on disk. Downloads run in parallel, and `SIGINT` cancels them.
- `piko refresh --files`: each selected repository's `<repo>.files` archive is fetched beside
  its `<repo>.db`, in the same pass. pacman splits this across `-Sy` and `-Fy`, which is what
  lets the two describe different builds. `piko files --repo <NAME>` reads the result.
- Transaction history, written to `pacman.log` and to `<dbpath>/piko-history`, and merged
  by `piko history`.
- Package groups as targets: `piko install <group>` installs the group's members, and
  `piko remove <group>` removes every installed member. pacman's `-S <group>` and
  `-R <group>`.
- Group listings: `piko list -g` lists the groups installed packages belong to. `--repos`, or
  `--repo <NAME>`, lists the repositories' groups instead, and `--with-members` lists each
  group with its members. pacman's `-Qg`, `-Sg` and `-Sgg`.
- Glob targets: a `piko install`, `piko remove` or `piko plan` target carrying `*`, `?` or `[`
  is a pattern, expanded against package names and `%GROUPS%` group names. Each pattern's
  expansion is printed before the plan it produced. pacman has no equivalent — its `-S` and
  `-R` targets are literal.
- Glob search terms: a `piko search` term carrying `*`, `?` or `[` is matched against the whole
  package name, `%PROVIDES%` name or `%GROUPS%` entry. pacman matches a `-Ss` term with an
  unanchored POSIX extended regular expression instead.
- `CheckSpace`: a transaction is weighed against free disk space before anything is written.
  Every filesystem it writes to must hold its peak occupancy — not its net growth, which an
  upgrade can answer with zero while still needing a gigabyte half-way through — and a
  filesystem it merely touches must not be mounted read only. Downloads are weighed separately,
  against the cache directory, before the first byte is fetched. Off unless `pacman.conf` sets
  the directive, and there is no flag for it, exactly as in pacman. See
  `docs/libalpm-compat.md` §133.
- Group member selection: `piko install <group>` and `piko update <group>` list the group's
  members numbered and ask which ones to install, reading pacman's own selection grammar
  (numbers, `N-M` ranges, `^` to exclude, empty line for all). `--noconfirm` takes every
  member, and `piko plan` states on stderr that it did the same. pacman's `-S <group>`
  question. See `docs/libalpm-compat.md` §130.
