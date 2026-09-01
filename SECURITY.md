# Security Policy

## Reporting a vulnerability

Report a security issue privately through
[GitHub Security Advisories](https://github.com/nuxgui/piko/security/advisories/new)
(the repository's Security tab, "Report a vulnerability"). Do not open a public issue for a
suspected vulnerability.

Include what you found, the affected version or commit, and steps to reproduce. There is no
fixed response-time guarantee at this stage of the project, but reports are read and
triaged as they arrive.

## Scope

piko runs with root privileges during a transaction, extracts tar archives onto the target
root, and verifies OpenPGP signatures on packages and repository databases. Findings in any
of the following are especially high priority:

- `piko-txn` — package extraction, root confinement, file-conflict detection, scriptlets
  and hooks.
- `piko-sig` — signature verification.
- `piko-db-write` — the local database writer and its locking.
- `piko-net` — repository database and package download.

A finding in dependency resolution or the local/repository database readers (`piko-db`) is
also in scope, particularly anything that reads attacker-controlled disk state (a crafted
database, archive, or metadata file) without bound.
