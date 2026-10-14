# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- `--max-age` defaults to 40 days, up from 14. A database older than that is reported as
  stale. `--max-age 0` still turns the check off.
- `piko-sig` and `piko-sig-write` export their items from the crate root only. Their modules
  are private, so each item has one path.
- No `gpgme` type is part of the stable interface of either crate. `piko_sig::open_context` is
  hidden from the documentation, and `piko-sig-write` has no `From` impl for a `gpgme` type.
- The result types of both crates are `#[non_exhaustive]`, so a later release can add a
  variant or a field without a breaking change. `Verdict`, `Policy` and `OwnerTrust` stay
  exhaustive on purpose: each is an input or a decision that every caller must handle in
  full.
- `piko_sig::newest_creation` and `piko_sig_write::VERIFY_POLICY` are no longer public.
- `piko-db-write` and `piko-net` export their items from the crate root only, as the two
  signature crates do. `piko_net::without_credentials` and `piko_net::Limits` are now exported
  there, and the `fuzzing` module is `piko_net::fuzzing`.
- `piko-net`'s `Outcome`, `Refreshed` and `PackageFetch` are `#[non_exhaustive]`.
  `PackageFetch::new`, with `with_cache_servers` and `with_size`, builds a download request.
  `RepoRefresh` stays exhaustive with public fields, because each of its fields is required.
  `RepoRefresh::new` builds it too. `FreshnessPolicy` has `with_accept_older` and
  `with_max_age`. `RecordKind` of `piko-db-write` stays exhaustive, because it is a closed
  set.
- `piko-db` gives each public item one path. Shared items are exported from the crate root
  (`EntryName`, `Error`, `Lazy`, `Limits`, `DescFieldError`, the `printable` functions). The
  items of a domain are exported from its module only: `local::LocalDatabase`,
  `resolve::SyncRepos`, `search::MatchKind`, `updates::Updates`, `glob::Glob`.
  `local::schema_version::check` is now `local::check_schema_version`.
- `piko-db` no longer exports the internals of its CDCL solver (`Problem`, `Clause`, `Lit`,
  `Solver`, `Solution`), nor the helpers no other crate uses.
- `piko-db`'s results, reports and failures are `#[non_exhaustive]`, and so are
  `config::Options`, `config::RepositoryConfig` (built with `RepositoryConfig::new`) and
  `solve::GroupTarget`. The crate documentation states the rules under "Stability". The same
  rules keep `piko_net::Limits`, `FreshnessPolicy` and `DatabaseKind` exhaustive.
- `piko-txn` gives each public item one path. The commit engine's items are exported from
  the crate root (`Transaction`, `TransactionPlan`, `Report`, `PackageSource`), and the
  submodules of `conflict`, `extract`, `hook`, `merge` and `space` are private. Its results,
  reports and failures are `#[non_exhaustive]`, and the helpers no other crate uses are no
  longer public. The removal decision (`decide_removal`, `pacsave_rotation`) is one of them.
- `piko_db_write::STAGING_DIR` and `piko_net`'s `HELPER_ARG` are no longer public.
  `piko_net::confine_self` and `piko_net::FALLBACK_USER` stay public for the tests, but are
  hidden from the documentation.

### Fixed

- `piko report` tells the user to remove `db.lck` first when a killed run left it, and only if
  no piko or pacman is running. Before, the first recovery command failed on the lock.
- A download works when piko runs in a PID namespace that kept the host's `/proc`, as
  `pikostrap` starts it (`unshare --fork --pid`). Before, every download failed with "the
  download helper inherited open descriptors", which named the helper's own listing of
  `/proc/self/fd`.

## [0.9.0] - 2026-10-10

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
- Keyring administration through `piko key`, pacman-key's counterpart.
- Repository database refresh and package download, with signature verification before a
  download replaces anything on disk. Downloads run in parallel, and `SIGINT` cancels them.
  A refresh holds `db.lck`, as `pacman -Sy` does.
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
  the directive, and there is no flag for it, exactly as in pacman.
- Group member selection: `piko install <group>` and `piko update <group>` list the group's
  members numbered and ask which ones to install, reading pacman's own selection grammar
  (numbers, `N-M` ranges, `^` to exclude, empty line for all). `--noconfirm` takes every
  member, and `piko plan` states on stderr that it did the same. pacman's `-S <group>`
  question.
- `piko report` prints the commands that finish an interrupted transaction: remove the journal,
  reinstall the package whose install was cut with `--overwrite '*'`, then remove and install
  what is left, with each package's install reason. The journal now records install reasons.
- A transaction journal that exists but cannot be read (no header, an unknown format version, or
  not text) refuses every transaction, as a readable one does. `piko report` and `piko history`
  report it as there and unreadable, not as absent.
