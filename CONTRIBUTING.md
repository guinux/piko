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
