//! DB integration test for nie-7766: tree_state_migration.
//!
//! Separated from witness_tracking.rs because save_tree_state / load_tree_state
//! are not yet implemented on WalletStore.  This file will fail to compile until
//! those methods exist.
//!
//! Oracle: round-trip correctness — bytes written must equal bytes read.

/// DB integration test: save_tree_state / load_tree_state round-trip.
///
/// Oracle: round-trip correctness — bytes written must equal bytes read.
///
/// NOTE: This test exercises save_tree_state and load_tree_state methods that
/// are planned but not yet implemented on WalletStore (nie-7766).
/// It is expected to fail to compile until those methods are added.
#[tokio::test]
async fn tree_state_migration() {
    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let store = nie_wallet::db::WalletStore::new(tmpfile.path())
        .await
        .unwrap();

    let state_bytes: &[u8] = &[1, 2, 3, 4];
    store
        .save_tree_state(state_bytes)
        .await
        .expect("save_tree_state must not fail");

    let loaded = store
        .load_tree_state()
        .await
        .expect("load_tree_state must not fail");

    assert_eq!(
        loaded.as_deref(),
        Some(state_bytes),
        "loaded tree state must equal saved bytes"
    );
}
