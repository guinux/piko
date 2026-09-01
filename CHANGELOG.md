# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Local database reader: directory-name-based scanning, lazy `desc`/`files`/`mtree`.
- Repository database reader: `desc` parsing, archive handling.
- Multi-repository dependency resolution (literal name, `%PROVIDES%`, soname matching).
- Transaction planner with a CDCL solver: install, remove (`-R`/`-Rs`/`-Rc`/`-Rcs`),
  sysupgrade (`-u`), `HoldPkg`, `piko why`.
- Local database writer, matching pacman's `db.lck` locking semantics.
- Commit engine: install, upgrade, removal, file-conflict detection, scriptlets and hooks.
- OpenPGP signature verification (GPGME-backed) for packages and repository databases.
- Repository database refresh and package download, with signature verification before a
  download replaces anything on disk.
