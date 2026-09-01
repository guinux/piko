# Contributing to piko

## Building

```bash
cargo build --workspace
cargo test --workspace
```

Some tests are `#[ignore]`d because they read the real system (`/var/lib/pacman`,
`/etc/pacman.conf`) rather than a fixture. They only make sense on an actual installation:

```bash
cargo test --workspace -- --ignored
```

## Before opening a pull request

All of the following must pass:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

This is not a style preference — it is enforced by the workspace lint configuration
(`unsafe_code = "forbid"`, and `unwrap_used`/`panic`/`expect_used`/`todo`/`unimplemented`
all denied outside test modules). piko performs a transaction while running as root; a
panic partway through one is close to the worst possible failure mode, so the lints exist
to keep that class of bug out of production code paths.

## Where code belongs

Business logic belongs in the library crates (`piko-db`, `piko-db-write`, `piko-net`,
`piko-sig`, `piko-txn`), never in the CLI crate (`piko`). The CLI's job is argument
parsing, prompts, and rendering values that a library crate already decided.
