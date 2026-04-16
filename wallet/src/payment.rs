//! Top-level payment orchestration: sync-lag check → build → broadcast → record.
//!
//! [`send_payment`] is the single entry point for sending a shielded ZEC
//! payment.  It composes the individual building blocks:
//!
//! 1. Sync-lag guard (wallet must be current)
//! 2. Note selection and transaction building
//! 3. Broadcast via lightwalletd
//! 4. Best-effort DB recording (mark notes spent, insert tx record)
//!
//! Sapling proving parameters (`SpendParameters`, `OutputParameters`) must be
//! loaded once at startup by the caller and passed in as a reference.  Loading
//! them inside [`send_payment`] would read and hash ~51 MB from disk on every
//! payment — unacceptable latency on cold page cache.
//!
//! # Security note
//!
//! Never log `to_address`, note plaintext fields, or any spending key bytes.
//! Only amounts, session IDs, and txids are safe to log.

use std::fmt;

use tracing::{info, warn};
use uuid::Uuid;

use sapling::circuit::{OutputParameters, SpendParameters};

use crate::{
    address::{SaplingExtendedSpendingKey, ZcashNetwork},
    client::BroadcastError,
    db::{TxDirection, TxRecord, WalletStore},
    memo::session_id_to_memo,
    sync_guard::{check_lag, SyncLagError, MAX_SYNC_LAG},
    tx_builder::build_shielded_tx,
    tx_error::TxBuildError,
};

/// Account index for the nie payment wallet (ZIP-32 account 0).
pub const PAYMENT_ACCOUNT: u32 = 0;

/// All failure modes for [`send_payment`].
#[derive(Debug)]
pub enum SendPaymentError {
    /// The wallet's scan is too far behind the chain tip.
    SyncLag(SyncLagError),
    /// Transaction building failed (note selection, proof generation, etc.).
    Build(TxBuildError),
    /// The lightwalletd node rejected or could not process the broadcast.
    Broadcast(BroadcastError),
    /// Could not connect to the lightwalletd endpoint (TLS failure, unreachable, etc.).
    Connect(anyhow::Error),
    /// A wallet store operation failed (note queries, tx record insertion, etc.).
    Db(anyhow::Error),
}

impl fmt::Display for SendPaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyncLag(e) => write!(f, "payment blocked: {e}"),
            Self::Build(e) => write!(f, "transaction build failed: {e}"),
            Self::Broadcast(e) => write!(f, "broadcast failed: {e}"),
            Self::Connect(e) => write!(f, "could not connect to lightwalletd: {e}"),
            Self::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for SendPaymentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SyncLag(e) => Some(e),
            Self::Build(e) => Some(e),
            Self::Broadcast(e) => Some(e),
            Self::Connect(_) | Self::Db(_) => None,
        }
    }
}

/// Abstraction over the lightwalletd operations needed by [`send_payment`].
///
/// The trait has two methods: `latest_height` (for the sync-lag check) and
/// `broadcast_tx` (to submit the signed transaction).  A real implementation
/// is [`crate::client::LightwalletdClient`]; a mock can be used in tests.
///
/// **Why a trait?**  Without this abstraction, `payment.rs` tests would require
/// a live lightwalletd process, making them network-dependent and CI-hostile.
/// The `MockClient` in the test module replaces the gRPC transport entirely,
/// keeping tests deterministic and fast.  Do not remove the trait to simplify
/// the code — that would eliminate the ability to test the payment logic in CI.
///
/// The `#[allow(async_fn_in_trait)]` is appropriate for an internal trait used
/// only within this crate.  RPITIT stabilisation in 1.75 makes this sound; the
/// lint is conservative for public traits where dyn usage matters.
///
/// The `+ Send` bound is required because `send_payment` is async and the
/// future must be sendable across thread boundaries.
#[allow(async_fn_in_trait)]
pub trait WalletClient: Send {
    /// Return the height of the chain tip as reported by the server.
    async fn latest_height(&mut self) -> anyhow::Result<u64>;

    /// Broadcast a raw signed transaction.  Returns the txid on success.
    async fn broadcast_tx(&mut self, raw_tx: &[u8]) -> Result<String, BroadcastError>;
}

impl WalletClient for crate::client::LightwalletdClient {
    async fn latest_height(&mut self) -> anyhow::Result<u64> {
        crate::client::LightwalletdClient::latest_height(self).await
    }

    async fn broadcast_tx(&mut self, raw_tx: &[u8]) -> Result<String, BroadcastError> {
        crate::client::LightwalletdClient::broadcast_tx(self, raw_tx).await
    }
}

/// Build and broadcast a shielded Sapling payment.
///
/// # Steps
///
/// 1. Check the wallet's sync lag against the chain tip.
/// 2. Fetch spendable notes from the local DB.
/// 3. Derive the next change address diversifier.
/// 4. Encode the session UUID into a ZIP-302 memo.
/// 5. Build the signed transaction (note selection is internal to the builder).
/// 6. Broadcast via lightwalletd.
/// 7. Best-effort: mark spent notes, insert tx record.
///
/// # Security
///
/// - `to_address` is never logged.  Log output contains only the amount,
///   session ID, and txid — all of which are safe to emit.
/// - `sk` bytes are never logged.
///
/// # Post-broadcast best-effort
///
/// Step 8 is best-effort: if the DB operations fail after a successful
/// broadcast, the error is logged at `warn` level and the txid is still
/// returned.  **The scanner does not automatically reconcile this failure.**
/// `scanner.rs` tracks note commitments only — it has no nullifier-detection
/// logic.  Notes that fail `mark_notes_spent` remain "unspent" in the DB and
/// will be re-selected on the next send, producing a double-spend rejection
/// at the node.  Recovery requires a full wallet rescan from seed.
/// (Long-term fix: add nullifier scanning to `scanner.rs`.)
/// Production callers must always pass `Some(&loaded_params)` — `None` is
/// reserved for unit tests that exercise code paths before the proving step
/// (e.g. sync-lag guard, empty-notes check).  Passing `None` when proofs are
/// needed causes `SendPaymentError::Build(ParamsNotLoaded)`.
#[allow(clippy::too_many_arguments)]
pub async fn send_payment<C: WalletClient>(
    sk: &SaplingExtendedSpendingKey,
    to_address: &str,
    amount_zatoshi: u64,
    session_id: Uuid,
    store: &WalletStore,
    client: &mut C,
    params: Option<&(SpendParameters, OutputParameters)>,
    network: ZcashNetwork,
) -> Result<String, SendPaymentError> {
    // Step 1: Sync-lag check.
    // scan_tip is also the anchor height for Sapling witnesses (witnesses in
    // spendable_notes() are all valid at the scan_tip).
    //
    // TOCTOU: chain_tip is fetched here; spendable_notes is fetched below.
    // The real chain tip can advance between these two awaits.  The
    // MAX_SYNC_LAG buffer absorbs 1-2 new blocks during the window.  See the
    // MAX_SYNC_LAG constant in sync_guard.rs for the full race analysis.
    // Do not restructure these two fetches into a single await without
    // re-reading that comment.
    let scan_tip = store.scan_tip().await.map_err(SendPaymentError::Db)?;
    let chain_tip = client
        .latest_height()
        .await
        .map_err(SendPaymentError::Connect)?;
    check_lag(scan_tip, chain_tip, MAX_SYNC_LAG).map_err(SendPaymentError::SyncLag)?;

    // Step 2: Fetch spendable notes.
    let all_notes = store
        .spendable_notes(PAYMENT_ACCOUNT)
        .await
        .map_err(SendPaymentError::Db)?;
    if all_notes.is_empty() {
        return Err(SendPaymentError::Build(TxBuildError::NoSpendableNotes));
    }

    // Step 3: Derive change address diversifier.
    let change_di = store
        .next_diversifier(PAYMENT_ACCOUNT)
        .await
        .map_err(SendPaymentError::Db)?;

    // Step 4: Encode the session UUID into a ZIP-302 memo.
    let memo = session_id_to_memo(session_id);

    info!(
        amount_zatoshi,
        session_id = %session_id,
        "payment initiated"
    );

    // Step 5: Build the signed transaction.
    // build_shielded_tx handles note selection internally and returns the selected
    // note IDs alongside the raw tx bytes.  Using these IDs (rather than a separate
    // pre-selection pass) guarantees that mark_notes_spent marks exactly the notes
    // that were actually spent in the built transaction.
    // anchor_height = scan_tip: witnesses in spendable_notes() are valid at scan_tip,
    // not at the individual note's block_height (which is when the note was received).
    let (tx_bytes, selected_ids) = build_shielded_tx(
        sk,
        to_address,
        amount_zatoshi,
        &memo,
        &all_notes,
        params,
        network,
        scan_tip,
        change_di,
    )
    .map_err(SendPaymentError::Build)?;

    // Step 6: Broadcast.
    let txid = client
        .broadcast_tx(&tx_bytes)
        .await
        .map_err(SendPaymentError::Broadcast)?;

    info!(txid = %txid, amount_zatoshi, session_id = %session_id, "payment broadcast");

    // Step 7: Best-effort post-broadcast DB updates.

    // Mark selected notes as spent in one transaction.
    if let Err(e) = store.mark_notes_spent(&selected_ids, &txid).await {
        warn!(txid = %txid, error = %e, "failed to mark notes spent after broadcast — notes remain unspent in DB; next send will re-select them and be rejected as double-spend; recovery requires wallet rescan from seed");
    }

    // Insert the outgoing tx record.
    // i64::try_from: block heights and unix timestamps fit in i64 for any real
    // chain or system clock.  The as-cast is avoided per project convention
    // (DESIGN-sqlite-amount-cast): silent truncation must never reach SQLite.
    let bh = i64::try_from(scan_tip).map_err(|_| {
        SendPaymentError::Db(anyhow::anyhow!(
            "scan_tip {scan_tip} overflows i64 — this is a bug; block heights fit in u32"
        ))
    })?;
    let now_secs = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX); // Unix timestamps won't overflow i64 until year 292 billion.
                          // NOTE: block_height is the scan_tip at broadcast time, not the actual
                          // confirmation height.  The scanner uses INSERT OR IGNORE on txid, so it
                          // will not overwrite this with the confirmed height when the tx is mined.
                          // This means block_height for outgoing txs is approximate (off by ~1-3
                          // blocks).  When the transaction watcher (nie-hov) lands it must either
                          // (a) use UPDATE to correct the height after confirmation, or
                          // (b) add a separate confirmed_height column and leave this as broadcast_height.
    let tx_record = TxRecord {
        txid: txid.clone(),
        block_height: bh,
        direction: TxDirection::Outgoing,
        amount_zatoshi,
        memo: Some(memo.to_vec()),
        peer_pub_id: None,
        created_at: now_secs,
    };
    if let Err(e) = store.insert_tx(&tx_record).await {
        warn!(txid = %txid, error = %e, "failed to insert tx record after broadcast");
    }

    Ok(txid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::SaplingExtendedSpendingKey;
    use crate::params::SaplingParamPaths;
    use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
    use sapling::{note::Rseed, value::NoteValue};
    use std::path::PathBuf;
    use tempfile::NamedTempFile;
    use zcash_primitives::merkle_tree::write_incremental_witness;
    use zcash_protocol::consensus::NetworkType;

    // ---- test infrastructure ----

    async fn make_store() -> (WalletStore, NamedTempFile) {
        let tf = NamedTempFile::new().unwrap();
        let store = WalletStore::new(tf.path()).await.unwrap();
        (store, tf)
    }

    /// Attempt to load Sapling spend/output params from the standard location.
    ///
    /// Returns `None` if the files are not present — the calling test should
    /// early-return (not panic) to skip gracefully in environments without params.
    fn try_load_params() -> Option<(
        sapling::circuit::SpendParameters,
        sapling::circuit::OutputParameters,
    )> {
        let params_dir = std::env::var("ZCASH_PARAMS")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".zcash-params")))
            .ok()?;
        let paths = SaplingParamPaths {
            spend: params_dir.join("sapling-spend.params"),
            output: params_dir.join("sapling-output.params"),
        };
        crate::tx_builder::load_sapling_params(&paths).ok()
    }

    /// Build a SpendableNote containing a real Sapling note commitment.
    ///
    /// The note is addressed to `sk.default_address()` so `sk` can authorize
    /// the spend proof.  A 2-leaf tree ([note_cmu, dummy_leaf]) gives a defined
    /// Merkle path.
    fn real_note(
        sk: &SaplingExtendedSpendingKey,
        value_zatoshi: u64,
        note_id: i64,
        block_height: u64,
        rseed_byte: u8,
    ) -> crate::db::SpendableNote {
        let (_, addr) = sk.default_address();
        let addr_bytes = addr.to_bytes();
        let rseed_bytes = [rseed_byte; 32];
        let rseed = Rseed::AfterZip212(rseed_bytes);
        let note = sapling::Note::from_parts(addr, NoteValue::from_raw(value_zatoshi), rseed);
        let note_node = sapling::Node::from_cmu(&note.cmu());

        let mut tree = CommitmentTree::<sapling::Node, 32>::empty();
        tree.append(note_node).expect("append note cmu");
        let mut witness = IncrementalWitness::from_tree(tree).expect("non-empty tree");
        let dummy = Option::from(sapling::Node::from_bytes([0x42; 32])).expect("valid dummy");
        witness.append(dummy).expect("append dummy sibling");

        let mut wb = Vec::new();
        write_incremental_witness(&witness, &mut wb).expect("serialize witness");

        crate::db::SpendableNote {
            note_id,
            value_zatoshi,
            note_diversifier: addr_bytes[..11].to_vec(),
            note_pk_d: addr_bytes[11..].to_vec(),
            note_rseed: rseed_bytes.to_vec(),
            rseed_after_zip212: true,
            block_height,
            witness_data: wb,
        }
    }

    /// The testnet UA string for the test key (Sapling-only receiver).
    fn testnet_sapling_ua() -> String {
        use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let (_, addr) = sk.default_address();
        let bytes: [u8; 43] = addr.to_bytes();
        let ua = UnifiedAddress::try_from_items(vec![Receiver::Sapling(bytes)])
            .expect("Sapling-only UA must be valid");
        ua.encode(&NetworkType::Test)
    }

    /// Anchor height for tests: past NU5 activation on testnet (1_842_420)
    /// so the builder emits a v5 transaction.
    const HAPPY_ANCHOR_HEIGHT: u64 = 2_000_001;

    // ---- MockClient ----

    struct MockClient {
        chain_tip: u64,
        broadcast_result: Result<String, BroadcastError>,
    }

    impl WalletClient for MockClient {
        async fn latest_height(&mut self) -> anyhow::Result<u64> {
            Ok(self.chain_tip)
        }

        async fn broadcast_tx(&mut self, _raw_tx: &[u8]) -> Result<String, BroadcastError> {
            self.broadcast_result.clone()
        }
    }

    // BroadcastError doesn't implement Clone, so manually clone the mock result.
    impl Clone for MockClient {
        fn clone(&self) -> Self {
            // Only used in tests; clone by reconstructing.
            panic!("MockClient is not meant to be cloned");
        }
    }

    // Helper: clone BroadcastError for the mock's broadcast_result.
    fn broadcast_ok(txid: &str) -> Result<String, BroadcastError> {
        Ok(txid.to_owned())
    }
    fn broadcast_err() -> Result<String, BroadcastError> {
        Err(BroadcastError::BroadcastFailed {
            code: -1,
            message: "insufficient fee".to_owned(),
        })
    }

    // ---- Tests ----

    /// SyncLag error propagates as SendPaymentError::SyncLag.
    ///
    /// Oracle: check_lag(100, 200, 10) would fail; a MockClient that returns
    /// chain_tip=200 with scan_tip=100 in DB guarantees SyncLag.
    /// params=None: the sync-lag check fires before params are needed.
    #[tokio::test]
    async fn sync_lag_propagates() {
        let (store, _tf) = make_store().await;
        // scan_tip defaults to 0; chain_tip = MAX_SYNC_LAG + 1 triggers the guard.
        store.set_scan_tip(100).await.unwrap();
        let mut client = MockClient {
            chain_tip: 200,
            broadcast_result: broadcast_ok("a".repeat(64).as_str()),
        };
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let result = send_payment(
            &sk,
            &testnet_sapling_ua(),
            10_000,
            Uuid::new_v4(),
            &store,
            &mut client,
            None, // params not needed — error fires at sync-lag check
            ZcashNetwork::Testnet,
        )
        .await;
        assert!(
            matches!(result, Err(SendPaymentError::SyncLag(_))),
            "expected SyncLag, got: {result:?}"
        );
    }

    /// latest_height() network failure propagates as SendPaymentError::Connect.
    ///
    /// Oracle: a client that returns Err from latest_height simulates a
    /// lightwalletd network failure (unreachable, TLS error, timeout).
    /// Verified by matching the Connect variant — not Db or SyncLag.
    #[tokio::test]
    async fn latest_height_network_failure_propagates_as_connect() {
        struct NetworkDownClient;
        impl WalletClient for NetworkDownClient {
            async fn latest_height(&mut self) -> anyhow::Result<u64> {
                Err(anyhow::anyhow!("connection refused"))
            }
            async fn broadcast_tx(&mut self, _raw_tx: &[u8]) -> Result<String, BroadcastError> {
                unreachable!("broadcast not reached when latest_height fails")
            }
        }

        let (store, _tf) = make_store().await;
        store.set_scan_tip(HAPPY_ANCHOR_HEIGHT).await.unwrap();
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let result = send_payment(
            &sk,
            &testnet_sapling_ua(),
            10_000,
            Uuid::new_v4(),
            &store,
            &mut NetworkDownClient,
            None,
            ZcashNetwork::Testnet,
        )
        .await;
        assert!(
            matches!(result, Err(SendPaymentError::Connect(_))),
            "latest_height network failure must produce Connect, got: {result:?}"
        );
    }

    /// Build error (NoSpendableNotes) propagates as SendPaymentError::Build.
    ///
    /// Oracle: an empty store returns no notes; build_shielded_tx returns
    /// NoSpendableNotes.  No params needed — the empty check fires first.
    /// params=None: the note-selection check fires before params are needed.
    #[tokio::test]
    async fn no_spendable_notes_propagates_as_build_error() {
        let (store, _tf) = make_store().await;
        store.set_scan_tip(HAPPY_ANCHOR_HEIGHT).await.unwrap();
        let mut client = MockClient {
            chain_tip: HAPPY_ANCHOR_HEIGHT,
            broadcast_result: broadcast_ok("a".repeat(64).as_str()),
        };
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let result = send_payment(
            &sk,
            &testnet_sapling_ua(),
            10_000,
            Uuid::new_v4(),
            &store,
            &mut client,
            None, // params not needed — error fires at empty-notes check
            ZcashNetwork::Testnet,
        )
        .await;
        assert!(
            matches!(
                result,
                Err(SendPaymentError::Build(TxBuildError::NoSpendableNotes))
            ),
            "expected Build(NoSpendableNotes), got: {result:?}"
        );
    }

    /// Happy path: note in DB + params available → Ok(txid), note marked spent,
    /// TxRecord inserted.
    #[tokio::test]
    async fn happy_path_note_marked_spent_and_tx_recorded() {
        let Some(params) = try_load_params() else {
            // Sapling params not available in this environment; skip.
            return;
        };

        let (store, _tf) = make_store().await;
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);

        // Insert a real note with valid witness bytes into the DB.
        let note = real_note(&sk, 1_000_000, 1, 1_000_000, 0xab);
        let note_id = store
            .insert_spendable_note(
                note.value_zatoshi,
                note.block_height,
                &note.note_diversifier,
                &note.note_pk_d,
                &note.note_rseed,
                note.rseed_after_zip212,
                &note.witness_data,
            )
            .await
            .unwrap();
        store.set_scan_tip(HAPPY_ANCHOR_HEIGHT).await.unwrap();

        let expected_txid = "a".repeat(64);
        let mut client = MockClient {
            chain_tip: HAPPY_ANCHOR_HEIGHT,
            broadcast_result: broadcast_ok(&expected_txid),
        };

        let result = send_payment(
            &sk,
            &testnet_sapling_ua(),
            20_000,
            Uuid::new_v4(),
            &store,
            &mut client,
            Some(&params),
            ZcashNetwork::Testnet,
        )
        .await;

        let txid = result.expect("happy path must succeed");
        assert_eq!(txid, expected_txid, "returned txid must match mock");

        // Note must be marked spent.
        let unspent = store.unspent_notes().await.unwrap();
        assert!(
            !unspent.iter().any(|(id, _)| *id == note_id),
            "spent note must not appear in unspent_notes"
        );

        // TxRecord must be inserted.
        let txs = store.recent_txs(10).await.unwrap();
        assert!(
            txs.iter().any(|r| r.txid == expected_txid),
            "TxRecord must be inserted after successful broadcast"
        );
        let record = txs.iter().find(|r| r.txid == expected_txid).unwrap();
        assert_eq!(record.direction, TxDirection::Outgoing);
        assert_eq!(record.amount_zatoshi, 20_000);
    }

    /// Broadcast failure propagates as SendPaymentError::Broadcast.
    ///
    /// Notes must NOT be marked spent when broadcast fails.
    #[tokio::test]
    async fn broadcast_failure_notes_not_marked_spent() {
        let Some(params) = try_load_params() else {
            return;
        };

        let (store, _tf) = make_store().await;
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);

        let note = real_note(&sk, 1_000_000, 1, 1_000_000, 0xab);
        let note_id = store
            .insert_spendable_note(
                note.value_zatoshi,
                note.block_height,
                &note.note_diversifier,
                &note.note_pk_d,
                &note.note_rseed,
                note.rseed_after_zip212,
                &note.witness_data,
            )
            .await
            .unwrap();
        store.set_scan_tip(HAPPY_ANCHOR_HEIGHT).await.unwrap();

        let mut client = MockClient {
            chain_tip: HAPPY_ANCHOR_HEIGHT,
            broadcast_result: broadcast_err(),
        };

        let result = send_payment(
            &sk,
            &testnet_sapling_ua(),
            20_000,
            Uuid::new_v4(),
            &store,
            &mut client,
            Some(&params),
            ZcashNetwork::Testnet,
        )
        .await;

        assert!(
            matches!(result, Err(SendPaymentError::Broadcast(_))),
            "expected Broadcast error, got: {result:?}"
        );

        // Note must still be unspent (broadcast failed before DB update).
        let unspent = store.unspent_notes().await.unwrap();
        assert!(
            unspent.iter().any(|(id, _)| *id == note_id),
            "note must remain unspent when broadcast fails"
        );
    }
}
