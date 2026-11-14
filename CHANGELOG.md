# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.0.0-rc.1] - 2026-11-14

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

- `--root` with no `--dbpath` and no `DBPath` directive now uses the database inside that root
  (`<root>/var/lib/pacman`), as pacman does. Before, `install`, `update`, `remove` and `merge`
  used the database of the running system. The transaction log follows the same rule
  (`<root>/var/log/pacman.log`) when no `--logfile` and no `LogFile` directive is set. Pass
  `--dbpath` to keep the earlier behavior.
- A group name that a glob target matched, the group that an `IgnoreGroup` entry matched, and
  each package name and version in `piko history` are escaped before they are printed. A
  mirror or a package chooses that text, and it could hold a terminal escape sequence.
- The command line that `LogFile` and the transaction history record no longer holds the user
  name and password of a package URL.
- `piko remove` stops between two packages on Ctrl+C, a hangup or a terminate request, as
  `piko install` does. Before, a signal ended it in the middle of a package and left `db.lck`.
- `piko merge` accepts a path as `piko merge --output` prints it when `--root` is not `/`. A
  path that names no pending file is now an error, and the command exits with a failure.
- `piko info` and `piko files` show an installed package when pacman.conf cannot be read.
  Before, they failed, although they opened no repository.
- `piko refresh` writes no line to `LogFile` when it cannot read pacman.conf.
- `piko install <url>` prints its `Fetching` line before the download, not after it.
- The commands that `piko report` prints repeat `--config` when the report was run with one.
- A transaction that must remove an installed package to resolve a conflict removes only the
  packages that cannot stay. Before, it removed every installed package that took part in the
  conflict: both packages when the removal of one was enough, and a package whose dependency
  was upgraded and not removed.
- `piko remove --nodeps` removes a package once when two targets name it, as `pacman -Rdd`
  does. Before, a name given twice, or two patterns that select the same package, stopped the
  transaction after the first removal and left a journal that refused every later
  transaction.
- The planner lists the providers of a name in a time that grows with their number, not with
  its square. Before, a repository database in which very many packages provide one name
  made `piko plan`, `piko install` and `piko update` run for hours.
- The planner finds what a `%CONFLICTS%` entry names through its name index. Before, it
  tested each entry against every package it could select, so the time to plan a transaction
  grew with the square of the number of packages that declare a conflict.
- A repository database that holds a tar extension header (a GNU long name or a PAX record
  list) larger than 64 KiB is refused. Before, such a header was read whole into memory
  whatever the limit on one member said, and a refused member was reported with its whole
  path. `Limits::repo_extension_bytes` sets the bound, and a refused member is now reported by
  the first 256 characters of its path.
- `piko_db_write::LocalDbWriter::write_raw` and `EntryWrite::raw` refuse a member name that
  is not one plain file name, with `Error::InvalidMemberName`. Before, a name with a `/` or a
  `..` wrote the file outside the entry. piko itself gives these two only fixed names.
- A package whose entry would hold a NUL byte in a `desc` or `files` value is refused before
  anything is written. Before, piko wrote the value. pacman reads a line up to its first NUL,
  so a group named `%REASON%`, a NUL and any text read back there as a section header.
- A package member that a PAX `size` record sizes is measured by that record. Before, the
  disk-space check counted the size field of the header, and such a member cut short by the
  end of the file was read as complete.
- A package that ships a directory where a file is, and that conflict detection lets through,
  now replaces the file with the directory. Before, the file stayed and the installed entry
  listed it as a directory.
- A package whose archive holds a hard link to a file it does not ship is refused before
  anything is written. A hard link whose target `NoExtract` skipped is skipped too, and the
  commit no longer stops there.
- A hook file that cannot be read or parsed refuses the transaction before it starts, as
  pacman does. Correct the file or remove it. Such a file also keeps its name, so the hook of
  the same name in a lower priority directory does not run in its place.
- A package whose archive holds a member path that is not UTF-8 is refused before anything
  is written. Before, such a member replaced a file of the same name with no conflict
  report, and the removal of the package left that file on disk.
- A removal, or an upgrade, keeps an empty directory that a package installed in the same
  transaction ships. Before, the directory was removed although the new package listed it.
- A download that takes longer than 60 seconds no longer fails. Before, one timeout covered the
  whole transfer, so a large package on a slow link failed on every server. Now a name lookup and
  a connection get 10 seconds each, the response must begin within `Limits::timeout`, and a
  transfer is given up only after `Limits::stall_timeout` (10 seconds) with no bytes.
  `piko_net::Limits` has the new field `stall_timeout`; a struct literal without
  `..Limits::default()` must set it.
- `DisableDownloadTimeout` is applied: a transfer that receives nothing is no longer given up
  after 10 seconds. Before, the option was read and had no effect. `piko_net::DownloadSettings`
  holds the sandbox and the limits of a download, and `DownloadingSource::new`,
  `TransactionPlan::source` and `file_target::fetch_url` take it in place of a `Sandbox`.
- A parallel download asks every `CacheServer` before any `Server`. Before, with
  `ParallelDownloads` above 2, some transfers started on a `Server` and never asked the cache.
- The download helper can no longer connect to a UNIX socket that a path names, such as a
  session bus or a key agent, on a kernel with Landlock ABI 9. The resolver's sockets under
  `/run/systemd/resolve` stay reachable. `piko_net::confine_self` now returns
  `piko_net::Confined`, which holds the Landlock ABI the kernel enforces.
- A `Server` password that holds a quote or a bracket no longer appears in an error message.
- A server that answers `304 Not Modified` to a request with no `If-Modified-Since` is treated
  as failed, and the next server is asked. Before, a refresh with no installed database reported
  "up to date" and installed nothing.
- `piko_sig::Policy::for_package` and `Policy::for_database` hold a `SigLevel` that still
  carries `USE_DEFAULT` to a required signature from a fully trusted key. Before, such a level
  gave a policy that checked nothing. A frontend that passed a raw field of the configuration
  (`Options::remote_file_sig_level`, `RepositoryConfig::sig_level`) installed an unsigned
  package. piko itself reads the resolved levels, so no `piko` command changes.
- Every `piko key` subcommand refuses a keyring that another user could change: the directory,
  a directory on the way to it, or an entry directly in it. Before, only a signature check
  refused it. GnuPG starts the agent that the keyring's `gpg.conf` names, so `piko key init`
  run by root over such a keyring ran a program another user chose. Repair the keyring with
  `chown` and `chmod` first. `piko_sig_write::KeyringAdmin::init` and `KeyringAdmin::open`
  return `Error::KeyringUnusable`.
- `piko key init` keeps an option apart from a `gpg.conf` or `gpg-agent.conf` whose last line
  has no newline. Before, it joined the two (`trust-model pgpno-greeting`), and every later
  GnuPG call over that keyring failed.
- A package file named by path or by URL is held to the global `SigLevel` when `pacman.conf`
  sets no `LocalFileSigLevel` or no `RemoteFileSigLevel`, as pacman holds it. Before, piko
  checked no signature on such a file. The `pacman.conf` Arch ships sets no
  `RemoteFileSigLevel`, so `piko install <url>` installed an unsigned package. A frontend
  reads `Options::effective_local_file_sig_level` and
  `Options::effective_remote_file_sig_level`, never the two fields.
- A repository entry that provides an unversioned soname with a run of twenty digits or more
  (`libx.so=lib99999999999999999999.so-64`) is refused when the database is opened. Before, a
  dependency check that compared it with another soname of the same name stopped piko with a
  panic, so one such entry on a mirror stopped every plan that reached it.
- A version that holds a control character is refused where piko reads it: an entry name, a
  `%VERSION%`, a relation, a `.PKGINFO`. Before, a mirror could put an escape sequence in the
  version of a repository entry, and `piko search`, `piko list`, `piko info` and `piko plan`
  printed it to the terminal as it was. Such an entry is now reported and not listed.
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
