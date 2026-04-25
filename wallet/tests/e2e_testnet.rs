//! Testnet end-to-end payment test (nie-3no).
//!
//! Tests connectivity, wallet initialisation, and address generation against the
//! Zcash testnet lightwalletd.  A full send-and-receive payment test is scaffolded
//! but requires two scanner improvements before it can run:
//!
//! - **nie-gw8k**: Sapling IVK note decryption + plaintext storage in the scanner.
//!   Without this, Alice's wallet never has spendable notes even after scanning.
//! - **nie-7766**: Incremental Sapling commitment tree and Merkle witness tracking.
//!   Without this, `spendable_notes()` has no witnesses and refuses every note.
//!
//! Once those issues are closed, the payment test runs end-to-end by providing a
//! pre-populated wallet database in the `ALICE_PRELOADED_DB` env var.
//!
//! # Required environment variables (all tests)
//!
//! ```text
//! TESTNET_ENABLED=1   — opt-in guard; all tests are skipped if absent
//! ```
//!
//! # Additional env vars for the payment test
//!
//! ```text
//! ALICE_MNEMONIC="word ..."   — 24-word BIP-39 mnemonic of a funded testnet wallet
//! ALICE_BIRTHDAY=2800000      — block height at which Alice's wallet was created
//! ALICE_PRELOADED_DB=/path    — path to SQLite DB with spendable notes + witnesses
//!                               (produced by the IVK scanner once nie-gw8k and
//!                                nie-7766 are implemented)
//! ```
//!
//! # Optional overrides
//!
//! ```text
//! TESTNET_ENDPOINT=https://...   — overrides the default lightwalletd URL
//! ZCASH_PARAMS=/path             — path to Sapling parameter files directory
//!                                  (default: ~/.zcash-params)
//! ```
//!
//! # Running the tests
//!
//! ```sh
//! # Connectivity + address generation only:
//! TESTNET_ENABLED=1 cargo test --test e2e_testnet -- --ignored --nocapture
//!
//! # Full payment (once nie-gw8k and nie-7766 are closed):
//! TESTNET_ENABLED=1 \
//!   ALICE_MNEMONIC="abandon ability able ..." \
//!   ALICE_BIRTHDAY=2800000 \
//!   ALICE_PRELOADED_DB=/tmp/alice-funded.db \
//!   ZCASH_PARAMS=$HOME/.zcash-params \
//!   cargo test --test e2e_testnet -- --ignored --nocapture
//! ```

use std::time::Duration;
use tempfile::TempDir;

use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
use zcash_protocol::consensus::NetworkType;

use nie_core::wallet::restore_wallet;
use nie_wallet::{
    address::{SaplingExtendedSpendingKey, ZcashNetwork},
    client::{LightwalletdClient, DEFAULT_TESTNET_ENDPOINT},
    db::WalletStore,
    params::{ensure_params, HttpFetcher, SaplingParamPaths},
    payment::send_payment,
    scanner::{CompactBlockScanner, NullDecryptor, SaplingIvkDecryptor},
    tx_builder::load_sapling_params,
};
use uuid::Uuid;

/// Amount used in the payment test.
const PAYMENT_AMOUNT_ZATOSHI: u64 = 100_000; // 0.001 ZEC

/// Hard time limit for the `send_payment` call only.
const PAYMENT_TIMEOUT_SECS: u64 = 600; // 10 minutes

/// Time budget for the mine-wait polling loop (runs after send_payment returns).
///
/// Zcash testnet targets 75-second blocks but can slow to one block per 10 minutes
/// during low-hashrate periods.  600 s gives the tx at least one full slow cycle.
const MINE_WAIT_SECS: u64 = 600; // 10 minutes

/// Poll interval for the mine-wait loop.
const MINE_POLL_SECS: u64 = 10; // seconds

/// Time budget for Bob's block scan after the tx is mined.
const BOB_SCAN_SECS: u64 = 120; // 2 minutes

/// Return `true` if the testnet suite is opted in via the env var.
fn testnet_enabled() -> bool {
    std::env::var("TESTNET_ENABLED").as_deref() == Ok("1")
}

/// Resolve the lightwalletd endpoint: TESTNET_ENDPOINT env var or the hardcoded default.
fn testnet_endpoint() -> String {
    std::env::var("TESTNET_ENDPOINT").unwrap_or_else(|_| DEFAULT_TESTNET_ENDPOINT.to_string())
}

/// Encode a spending key's default Sapling address as a testnet Unified Address.
///
/// Uses a Sapling-only UA (no Orchard receiver) so the string is accepted by
/// `send_payment`'s `parse_sapling_address` on the testnet network.
fn sapling_address_as_testnet_ua(sk: &SaplingExtendedSpendingKey) -> String {
    let (_, addr) = sk.default_address();
    let sapling_bytes: [u8; 43] = addr.to_bytes();
    let ua = UnifiedAddress::try_from_items(vec![Receiver::Sapling(sapling_bytes)])
        .expect("Sapling-only UA must be valid for a well-formed payment address");
    ua.encode(&NetworkType::Test)
}

/// Resolve the Sapling parameter file directory.
///
/// Uses the `ZCASH_PARAMS` env var if set; falls back to `~/.zcash-params`
/// (the canonical location used by `nie wallet init`).
fn params_dir() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("ZCASH_PARAMS") {
        return std::path::PathBuf::from(p);
    }
    // $HOME is set on all unix-like systems; error if missing rather than silently
    // using a wrong path.
    let home = std::env::var("HOME").expect("$HOME must be set to locate ~/.zcash-params");
    std::path::PathBuf::from(home).join(".zcash-params")
}

// ---- Test 1: lightwalletd connectivity ----------------------------------------

/// Connect to the Zcash testnet lightwalletd and verify the chain tip is non-zero.
///
/// This test verifies:
/// - TLS handshake with the lightwalletd endpoint succeeds.
/// - `latest_height()` returns a block number above Sapling activation height.
///
/// Sapling activated on testnet at block 280 000.  Any healthy testnet node
/// reports a chain tip well above that; a tip of 0 indicates a connectivity failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn testnet_lightwalletd_connectivity() {
    if !testnet_enabled() {
        eprintln!("TESTNET_ENABLED not set — skipping testnet connectivity test");
        return;
    }

    let endpoint = testnet_endpoint();
    eprintln!("connecting to {endpoint}…");

    let mut client = LightwalletdClient::connect(&endpoint)
        .await
        .expect("lightwalletd connect must succeed");

    let height = client
        .latest_height()
        .await
        .expect("latest_height must succeed");

    // Sapling activated at testnet block 280 000.
    assert!(
        height > 280_000,
        "chain tip {height} is below Sapling activation height — node may be out of sync"
    );

    eprintln!("PASS: testnet chain tip = {height}");
}

// ---- Test 2: wallet initialisation and address derivation ----------------------

/// Generate two wallets (alice, bob) and derive their testnet Sapling addresses.
///
/// Fully offline — no network access required.  Verifies:
/// - `WalletStore::new` creates a fresh database with the expected schema.
/// - `SaplingExtendedSpendingKey::from_seed` derives a key without panicking.
/// - The Sapling-only UA is a valid testnet bech32m string starting with "u1".
/// - Distinct seeds produce distinct addresses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn testnet_wallet_address_generation() {
    if !testnet_enabled() {
        eprintln!("TESTNET_ENABLED not set — skipping address generation test");
        return;
    }

    // Alice: deterministic seed for reproducibility.
    let alice_dir = TempDir::new().expect("create alice temp dir");
    let alice_store = WalletStore::new(&alice_dir.path().join("wallet.db"))
        .await
        .expect("create alice WalletStore");
    alice_store
        .ensure_account(0)
        .await
        .expect("alice ensure_account");

    let alice_sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
    let alice_addr = sapling_address_as_testnet_ua(&alice_sk);

    assert!(
        !alice_addr.is_empty(),
        "alice address must be a non-empty string"
    );
    assert!(
        alice_addr.starts_with("u1"),
        "testnet Unified Address must start with 'u1', got: {alice_addr}"
    );

    eprintln!("alice testnet address: {alice_addr}");

    // Bob: separate deterministic seed.
    let bob_dir = TempDir::new().expect("create bob temp dir");
    let bob_store = WalletStore::new(&bob_dir.path().join("wallet.db"))
        .await
        .expect("create bob WalletStore");
    bob_store
        .ensure_account(0)
        .await
        .expect("bob ensure_account");

    let bob_sk = SaplingExtendedSpendingKey::from_seed(&[1u8; 64], ZcashNetwork::Testnet, 0);
    let bob_addr = sapling_address_as_testnet_ua(&bob_sk);

    assert_ne!(
        alice_addr, bob_addr,
        "distinct seeds must produce distinct addresses"
    );
    assert!(
        bob_addr.starts_with("u1"),
        "bob testnet Unified Address must start with 'u1', got: {bob_addr}"
    );

    eprintln!("bob  testnet address: {bob_addr}");
    eprintln!("PASS: wallet initialisation and address generation");

    // Drop stores explicitly to release DB file handles before TempDir cleanup.
    drop(alice_store);
    drop(bob_store);
}

// ---- Test 3: scanning advances the chain tip -----------------------------------

/// Scan the 5 most recent testnet blocks and verify the scan tip advances.
///
/// Uses `NullDecryptor` (the current scanner default), so no notes are discovered.
/// Verifies the scan-tip bookkeeping: after scanning N blocks the stored tip equals
/// the chain tip at the start of the scan.
///
/// Requires `TESTNET_ENABLED=1` and a network connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn testnet_scan_advances_tip() {
    if !testnet_enabled() {
        eprintln!("TESTNET_ENABLED not set — skipping scan tip test");
        return;
    }

    let endpoint = testnet_endpoint();
    let mut client = LightwalletdClient::connect(&endpoint)
        .await
        .expect("connect to lightwalletd");

    let tip = client.latest_height().await.expect("get chain tip");

    // Scan only the 5 most recent blocks to keep the test fast.
    let scan_from = tip.saturating_sub(4);

    let dir = TempDir::new().expect("create temp dir");
    let store = WalletStore::new(&dir.path().join("wallet.db"))
        .await
        .expect("create WalletStore");
    store.ensure_account(0).await.expect("ensure_account");
    store
        .set_scan_tip(scan_from.saturating_sub(1))
        .await
        .expect("set birthday");

    let mut scanner = CompactBlockScanner::new(client, store.clone(), Box::new(NullDecryptor));
    let blocks_scanned =
        tokio::time::timeout(Duration::from_secs(BOB_SCAN_SECS), scanner.scan_to_tip())
            .await
            .expect("scan_to_tip must complete within 2 minutes")
            .expect("scan_to_tip must succeed");

    assert!(
        blocks_scanned >= 5,
        "expected at least 5 blocks scanned, got {blocks_scanned}"
    );

    let new_tip = store.scan_tip().await.expect("read scan tip after scan");
    assert!(
        new_tip >= tip,
        "scan tip {new_tip} must be >= chain tip at scan start {tip}"
    );

    drop(store);
    eprintln!("PASS: scanned {blocks_scanned} blocks, new tip = {new_tip}");
}

// ---- Test 4: full end-to-end payment ----------

/// Send 0.001 ZEC (testnet) from Alice to Bob and verify a valid txid is returned.
///
/// # Double-gate opt-in
///
/// The test is tagged `#[ignore]` so plain `cargo test` skips it.  A second
/// guard (`TESTNET_ENABLED=1`) prevents a silent no-op when a test harness
/// passes `--include-ignored` without the env var: the test returns early and
/// the harness reports **PASS** rather than skipped, which would incorrectly
/// signal that the payment path was validated.  Both gates must be cleared
/// to actually run the test.
///
/// # Running the payment test
///
/// To populate `ALICE_PRELOADED_DB`:
///
/// 1. Run `nie wallet restore --no-passphrase` with `ALICE_MNEMONIC` on testnet.
/// 2. Fund Alice's address from https://faucet.zecpages.com — wait for 1 confirmation.
/// 3. Run `nie chat` for a few minutes to let the scanner pick up the faucet note.
/// 4. Find the `wallet.db` in Alice's data dir (default: `~/.local/share/nie/wallet.db`).
/// 5. Set `ALICE_PRELOADED_DB=<path>` and rerun.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn testnet_shielded_payment_end_to_end() {
    if !testnet_enabled() {
        eprintln!("TESTNET_ENABLED not set — skipping testnet payment test");
        return;
    }

    let alice_db_path = match std::env::var("ALICE_PRELOADED_DB") {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "ALICE_PRELOADED_DB not set — skipping payment test.\n\
                 This test requires a pre-populated wallet DB (see blockers nie-gw8k, nie-7766)."
            );
            return;
        }
    };

    let alice_mnemonic = std::env::var("ALICE_MNEMONIC")
        .expect("ALICE_MNEMONIC must be set when ALICE_PRELOADED_DB is set");
    let alice_birthday: u64 = std::env::var("ALICE_BIRTHDAY")
        .expect("ALICE_BIRTHDAY must be set when ALICE_PRELOADED_DB is set")
        .parse()
        .expect("ALICE_BIRTHDAY must be a non-negative integer block height");

    let endpoint = testnet_endpoint();
    let network = ZcashNetwork::Testnet;

    // --- Alice wallet (pre-populated) ---
    let alice_dir = TempDir::new().expect("create alice temp dir");
    let alice_db_dest = alice_dir.path().join("wallet.db");
    std::fs::copy(&alice_db_path, &alice_db_dest).expect("copy ALICE_PRELOADED_DB to temp dir");

    let alice_store = WalletStore::new(&alice_db_dest)
        .await
        .expect("open alice WalletStore");

    let (_master, alice_seed) =
        restore_wallet(&alice_mnemonic).expect("restore alice wallet from mnemonic");
    let alice_sk = SaplingExtendedSpendingKey::from_seed(&alice_seed, network, 0);

    let alice_scan_tip = alice_store.scan_tip().await.expect("alice scan_tip");
    assert!(
        alice_scan_tip >= alice_birthday,
        "alice scan tip {alice_scan_tip} is below birthday {alice_birthday} — \
         re-scan the preloaded DB from birthday"
    );

    let alice_balance = alice_store
        .balance_with_confirmations(1)
        .await
        .expect("alice balance");
    assert!(
        alice_balance.total_zatoshi() >= PAYMENT_AMOUNT_ZATOSHI + 10_000,
        "alice balance {} zatoshi is insufficient for {} zatoshi + 10 000 fee.\n\
         Fund via https://faucet.zecpages.com then resync.",
        alice_balance.total_zatoshi(),
        PAYMENT_AMOUNT_ZATOSHI
    );
    eprintln!(
        "alice balance: {} confirmed + {} pending zatoshi",
        alice_balance.confirmed_zatoshi, alice_balance.pending_zatoshi
    );

    // --- Bob wallet (fresh, generated during the test) ---
    let bob_dir = TempDir::new().expect("create bob temp dir");
    let bob_store = WalletStore::new(&bob_dir.path().join("wallet.db"))
        .await
        .expect("create bob WalletStore");
    bob_store
        .ensure_account(0)
        .await
        .expect("bob ensure_account");

    let (_bob_words, _bob_master, bob_seed) =
        nie_core::wallet::generate_wallet().expect("generate bob wallet");
    let bob_sk = SaplingExtendedSpendingKey::from_seed(&bob_seed, network, 0);
    let bob_addr = sapling_address_as_testnet_ua(&bob_sk);
    eprintln!("bob receive address: {bob_addr}");

    // --- Sapling proving parameters ---
    let params: SaplingParamPaths = ensure_params(&params_dir(), &HttpFetcher).expect(
        "Sapling params must be present in $ZCASH_PARAMS or ~/.zcash-params; \
             run `nie wallet init` or set ZCASH_PARAMS",
    );
    let loaded_params = load_sapling_params(&params).expect("load Sapling params");

    // --- lightwalletd client ---
    let mut lwd_client = LightwalletdClient::connect(&endpoint)
        .await
        .expect("connect to lightwalletd");

    // --- Send payment (hard timeout) ---
    let session_id = Uuid::new_v4();
    eprintln!(
        "sending {} zatoshi to bob (session {session_id})…",
        PAYMENT_AMOUNT_ZATOSHI
    );

    let txid = tokio::time::timeout(
        Duration::from_secs(PAYMENT_TIMEOUT_SECS),
        send_payment(
            &alice_sk,
            &bob_addr,
            PAYMENT_AMOUNT_ZATOSHI,
            session_id,
            &alice_store,
            &mut lwd_client,
            Some(&loaded_params),
            network,
        ),
    )
    .await
    .expect("payment must complete within 10 minutes")
    .expect("send_payment must succeed");

    // --- Assertions ---
    assert_eq!(txid.len(), 64, "txid must be 64 hex chars, got {txid:?}");
    assert!(
        txid.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "txid must be lowercase hex, got {txid:?}"
    );

    // --- Receive-side verification: wait for mining, scan Bob's wallet, assert funds arrived ---

    // Step 1: record broadcast height (reuse the already-connected client).
    let broadcast_height = lwd_client
        .latest_height()
        .await
        .expect("latest_height after broadcast");

    // Step 2: wait for the chain to advance (a new block appears), timeout 10 minutes.
    // This is a timing heuristic — it waits until scanning would be productive.
    // It does NOT prove the tx was included in the new block; that proof is in Step 4.
    // MINE_WAIT_SECS and BOB_SCAN_SECS apply after send_payment returns;
    // they are independent of PAYMENT_TIMEOUT_SECS, not nested within it.
    let mine_deadline = Duration::from_secs(MINE_WAIT_SECS);
    tokio::time::timeout(mine_deadline, async {
        loop {
            tokio::time::sleep(Duration::from_secs(MINE_POLL_SECS)).await;
            match lwd_client.latest_height().await {
                Ok(h) if h > broadcast_height => break,
                Ok(_) => continue,
                Err(e) => {
                    eprintln!("WARN: latest_height error during mine-wait: {e}");
                    // retry on transient errors
                }
            }
        }
    })
    .await
    .expect("tx must be mined within 10 minutes");

    // Step 3: scan Bob's wallet for the incoming note.
    // Bob's IVK is derived from his DFVK (not directly from the spending key).
    // The IVK bytes are key material; they must not be logged.
    let bob_ivk_bytes = bob_sk.to_dfvk().ivk_bytes();
    let bob_decryptor = SaplingIvkDecryptor::new(&bob_ivk_bytes)
        .expect("Bob IVK must be a valid jubjub::Fr scalar");

    // Set Bob's scan tip to the block before broadcast so the scanner starts
    // from exactly the right height rather than re-scanning from genesis.
    bob_store
        .set_scan_tip(broadcast_height.saturating_sub(1))
        .await
        .expect("set bob scan tip before scanning");

    // Reuse lwd_client — mine-wait is done so the connection is idle.
    // Avoids an extra TLS handshake for the scan phase.
    let mut bob_scanner =
        CompactBlockScanner::new(lwd_client, bob_store.clone(), Box::new(bob_decryptor));
    // load_state() reads the Sapling commitment tree from the DB into memory.
    // scan_to_tip() requires it; skipping it would start from an empty tree
    // and produce invalid Merkle witnesses.
    bob_scanner
        .load_state()
        .await
        .expect("bob scanner load_state");
    tokio::time::timeout(
        Duration::from_secs(BOB_SCAN_SECS),
        bob_scanner.scan_to_tip(),
    )
    .await
    .expect("Bob scan must complete within 2 minutes")
    .expect("bob scan_to_tip");

    // Step 4: assert Bob received the expected amount.
    let bob_balance = bob_store
        .balance_with_confirmations(1)
        .await
        .expect("bob balance");
    assert!(
        bob_balance.total_zatoshi() >= PAYMENT_AMOUNT_ZATOSHI,
        "Bob must have received at least {} zatoshi, got confirmed={} pending={}",
        PAYMENT_AMOUNT_ZATOSHI,
        bob_balance.confirmed_zatoshi,
        bob_balance.pending_zatoshi,
    );
    // spendable_notes() requires plaintext columns non-null (IVK decryption) AND
    // a Merkle witness (nie-7766) — it is the single assertion that proves both.
    let bob_spendable = bob_store
        .spendable_notes(0)
        .await
        .expect("bob spendable_notes");
    assert!(
        !bob_spendable.is_empty(),
        "Bob must have at least one spendable note (proves IVK decryption + witness tracking)"
    );
    assert!(
        bob_spendable
            .iter()
            .any(|n| n.value_zatoshi == PAYMENT_AMOUNT_ZATOSHI),
        "Bob must have a spendable note of exactly {} zatoshi",
        PAYMENT_AMOUNT_ZATOSHI,
    );
    eprintln!(
        "RECEIVE OK: Bob balance = {} zatoshi",
        bob_balance.total_zatoshi()
    );
    // --- End receive-side verification ---

    drop(alice_store);
    drop(bob_store);

    eprintln!("PASS: txid = {txid}, alice_scan_tip = {alice_scan_tip}");
}
