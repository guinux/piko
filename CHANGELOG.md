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
