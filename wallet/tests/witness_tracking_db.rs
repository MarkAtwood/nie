//! DB integration test for nie-7766: tree_state_migration.
//!
//! Oracle: round-trip correctness — bytes written must equal bytes read.
//!
//! save_tree_state was removed (nie-kef6.12) because it was dead code
//! superseded by save_block_state, which wraps tree_state + witnesses + tip
//! in a single atomic transaction.  This test now exercises save_block_state
//! (with an empty witness list) + load_tree_state.

/// DB integration test: save_block_state / load_tree_state round-trip.
///
/// Oracle: round-trip correctness — bytes written must equal bytes read.
#[tokio::test]
async fn tree_state_migration() {
    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let store = nie_wallet::db::WalletStore::new(tmpfile.path())
        .await
        .unwrap();

    let state_bytes: &[u8] = &[1, 2, 3, 4];
    store
        .save_block_state(state_bytes, &[], 0)
        .await
        .expect("save_block_state must not fail");

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
