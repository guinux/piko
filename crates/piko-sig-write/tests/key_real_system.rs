//! Exercises the one operation the hermetic unit tests deliberately avoid: generating a real
//! RSA-4096 master key, the way `piko-key init` actually does it.
//!
//! `#[ignore]`d for the same reason `piko-db/tests/real_system.rs` is — real cost, real
//! environment dependency (a functioning `gpg-agent`), not something every `cargo test` run
//! should pay for. Run explicitly with `cargo test --workspace -- --ignored`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion in a test should abort it loudly"
)]

use piko_sig_write::KeyringAdmin;

#[test]
#[ignore = "generates a real RSA-4096 key; run with --ignored"]
fn init_generates_a_usable_rsa4096_master_key() {
    let home = tempfile::tempdir().unwrap();

    let (admin, outcome) = KeyringAdmin::init(home.path()).unwrap();
    assert!(outcome.master_key_created, "a fresh directory must generate a new master key");

    let keys = admin.list_keys().unwrap();
    assert_eq!(keys.len(), 1, "{keys:?}");
    let master = &keys[0];
    assert!(
        master.user_ids.iter().any(|uid| uid.contains("piko@localhost")),
        "the master key must carry piko's own identity: {:?}",
        master.user_ids
    );
    assert!(!master.is_disabled);
    assert!(!master.is_revoked);
    assert!(!master.is_expired);

    // Idempotent against the key it just generated.
    let (_, second) = KeyringAdmin::init(home.path()).unwrap();
    assert!(!second.master_key_created, "a second init must find the existing master key");
}
