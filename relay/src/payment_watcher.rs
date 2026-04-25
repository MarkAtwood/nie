//! Payment watcher background task (nie-hvw.5).
//!
//! Polls lightwalletd for new compact blocks, trial-decrypts each Sapling
//! output using the merchant DFVK's external IVK, and on a confirmed payment
//! activates the subscription in the DB and notifies the client if online.
//!
//! ## Confirmation depth
//!
//! The watcher scans blocks only up to `tip - CONFIRMATION_DEPTH`.  A payment
//! is acted on only after it has 10 confirmations, reducing the risk of acting
//! on a reorged payment.  This is not a complete reorg defense but provides
//! basic protection for subscription payments.
//!
//! ## Error handling
//!
//! Connection failures log a warning and back off for 60 seconds.  Individual
//! block or output decryption errors log a warning and continue scanning.
//! The watcher never crashes; it runs until the process exits.

use std::time::Duration;

use nie_core::protocol::{rpc_methods, JsonRpcNotification, SubscriptionActiveParams};
use nie_relay::state::AppState;
use nie_relay::store::InvoiceRow;
use nie_wallet::client::{CompactBlock, LightwalletdClient};
use nie_wallet::scanner::{NoteDecryptor, SaplingIvkDecryptor};
use sapling::PaymentAddress;
use tracing::{info, warn};
use zcash_address::{ToAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

/// How many block confirmations a payment must have before activation.
const CONFIRMATION_DEPTH: u64 = 10;

/// How many blocks to scan on the first run (catch recent payments made before
/// the relay started or after a restart).
const INITIAL_LOOKBACK: u64 = 100;

/// How often to poll lightwalletd when caught up to the confirmation frontier.
const POLL_INTERVAL_SECS: u64 = 30;

/// How long to sleep after a connection failure before retrying.
const RECONNECT_DELAY_SECS: u64 = 60;

/// Spawn the payment watcher as a background Tokio task.
///
/// Returns a `JoinHandle` — callers may drop it; the task keeps running.
/// Abort it explicitly to stop.
///
/// Only call this when `state.merchant().is_some()`.  Panics if called when
/// no merchant wallet is configured (programming error, not operator error).
pub fn spawn_payment_watcher(
    state: AppState,
    lightwalletd_url: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_watcher_loop(state, lightwalletd_url).await;
    })
}

/// Main watcher loop.  Runs forever; errors are logged and retried.
async fn run_watcher_loop(state: AppState, lightwalletd_url: String) {
    let merchant = state
        .merchant()
        .expect("spawn_payment_watcher called without merchant wallet");

    // Build the IVK decryptor from the merchant DFVK.
    // ivk_bytes() returns key material — do not log it.
    let ivk_bytes = merchant.dfvk.ivk_bytes();
    let decryptor = match SaplingIvkDecryptor::new(&ivk_bytes) {
        Some(d) => d,
        None => {
            warn!("payment_watcher: merchant IVK bytes are not a valid jubjub scalar; watcher cannot start");
            return;
        }
    };

    // Map ZcashNetwork to NetworkType for bech32 address encoding.
    let network_type = match merchant.network {
        nie_wallet::address::ZcashNetwork::Mainnet => NetworkType::Main,
        nie_wallet::address::ZcashNetwork::Testnet => NetworkType::Test,
    };

    // `last_scanned_height` tracks the highest block we have fully processed.
    // On first run it defaults to `tip - INITIAL_LOOKBACK`; on restart it is
    // loaded from the DB so payments confirmed between restarts are not missed.
    let persisted_tip = match state.inner.store.get_payment_scan_tip().await {
        Ok(h) => h,
        Err(e) => {
            warn!("payment_watcher: failed to load persisted scan tip ({e}); defaulting to tip-based lookback");
            None
        }
    };
    // 0 signals "not yet initialized"; the inner loop will set it from the
    // live chain tip when first called.  A persisted value of 0 is treated
    // the same way to avoid scanning from genesis after a DB wipe.
    let mut last_scanned_height: u64 = persisted_tip.unwrap_or(0);
    let mut blocks_since_purge: u64 = 0;

    loop {
        // Connect (or reconnect) to lightwalletd.
        let mut client = match LightwalletdClient::connect(&lightwalletd_url).await {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "payment_watcher: cannot connect to lightwalletd at {}: {}",
                    lightwalletd_url, e
                );
                tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)).await;
                continue;
            }
        };

        // Inner scan loop — runs until the connection fails.
        loop {
            let tip = match client.latest_height().await {
                Ok(h) => h,
                Err(e) => {
                    warn!("payment_watcher: get_latest_block failed: {e}");
                    // Break inner loop to reconnect.
                    break;
                }
            };

            // On first run, start INITIAL_LOOKBACK blocks behind the tip.
            if last_scanned_height == 0 {
                last_scanned_height = tip.saturating_sub(INITIAL_LOOKBACK);
            }

            // Scan only up to `tip - CONFIRMATION_DEPTH` to require confirmations.
            let scan_end = match tip.checked_sub(CONFIRMATION_DEPTH) {
                Some(h) => h,
                None => {
                    // Chain tip is below the confirmation depth (very short chain).
                    tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
                    continue;
                }
            };

            if last_scanned_height >= scan_end {
                // Already at the confirmation frontier; wait for new blocks.
                tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
                continue;
            }

            let scan_start = last_scanned_height + 1;

            // Fetch compact blocks from lightwalletd.
            let mut stream = match client.get_block_range(scan_start, scan_end).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "payment_watcher: get_block_range({scan_start}..={scan_end}) failed: {e}"
                    );
                    break; // Reconnect.
                }
            };

            // Process each block.
            loop {
                let block = match stream.message().await {
                    Ok(Some(b)) => b,
                    Ok(None) => break, // Stream exhausted normally.
                    Err(e) => {
                        warn!("payment_watcher: block stream error: {e}");
                        break;
                    }
                };

                if block.height == 0 {
                    warn!("payment_watcher: received CompactBlock with height=0; skipping to avoid scan-height reset");
                    continue;
                }

                scan_block(&block, &decryptor, network_type, &state).await;

                last_scanned_height = block.height;
                if let Err(e) = state.inner.store.set_payment_scan_tip(last_scanned_height).await {
                    warn!("payment_watcher: failed to persist scan tip {last_scanned_height}: {e}");
                }
                blocks_since_purge += 1;

                // Purge expired invoices every 100 blocks to keep the table clean.
                if blocks_since_purge >= 100 {
                    blocks_since_purge = 0;
                    match state.inner.store.purge_expired_invoices().await {
                        Ok(n) if n > 0 => info!("payment_watcher: purged {n} expired invoices"),
                        Ok(_) => {}
                        Err(e) => warn!("payment_watcher: purge_expired_invoices failed: {e}"),
                    }
                }
            }
        }

        // Connection broke or stream error — sleep before reconnecting.
        tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)).await;
    }
}

/// Process one compact block: trial-decrypt every Sapling output.
///
/// On a successful decryption and matching invoice, activates the subscription.
/// Errors at the output level are logged and skipped; the block scan continues.
async fn scan_block(
    block: &CompactBlock,
    decryptor: &SaplingIvkDecryptor,
    network_type: NetworkType,
    state: &AppState,
) {
    for tx in &block.vtx {
        for (idx, output) in tx.outputs.iter().enumerate() {
            // try_decrypt_sapling returns None for outputs not belonging to this wallet.
            let note = match decryptor.try_decrypt_sapling(
                block.height,
                block.time,
                &tx.hash,
                idx,
                output,
            ) {
                Some(n) => n,
                None => continue,
            };

            // Reconstruct the PaymentAddress from the decrypted note fields.
            // note_diversifier is 11 bytes; note_pk_d is 32 bytes.
            let address_str = match reconstruct_address(&note, network_type) {
                Some(a) => a,
                None => {
                    warn!(
                        height = block.height,
                        output_index = idx,
                        "payment_watcher: decrypted note has invalid/missing address fields; skipping"
                    );
                    continue;
                }
            };

            // Look up the invoice for this payment address.
            let invoice = match state.inner.store.get_invoice_by_address(&address_str).await {
                Ok(Some(inv)) => inv,
                Ok(None) => continue, // No active invoice for this address.
                Err(e) => {
                    warn!("payment_watcher: get_invoice_by_address failed: {e}");
                    continue;
                }
            };

            // Warn if the invoice has already expired — payment arrived late but
            // we still activate rather than silently drop the confirmed payment.
            {
                use chrono::Utc;
                if let Ok(exp) = chrono::NaiveDateTime::parse_from_str(
                    &invoice.expires_at,
                    "%Y-%m-%d %H:%M:%S",
                ) {
                    if exp.and_utc() < Utc::now() {
                        tracing::warn!(
                            invoice_id = invoice.invoice_id,
                            address = address_str,
                            "payment_watcher: activating payment for expired invoice"
                        );
                    }
                }
            }

            // Check that the received amount meets the invoice minimum.
            let value_zatoshi = note.value_zatoshi;
            if value_zatoshi < invoice.amount_zatoshi {
                warn!(
                    height = block.height,
                    address = address_str,
                    received = value_zatoshi,
                    required = invoice.amount_zatoshi,
                    "payment_watcher: underpayment; ignoring"
                );
                continue;
            }

            info!(
                height = block.height,
                pub_id = invoice.pub_id,
                address = address_str,
                "payment_watcher: confirmed payment — activating subscription"
            );

            if let Err(e) = activate_subscription(state, &invoice).await {
                warn!(
                    pub_id = invoice.pub_id,
                    "payment_watcher: activate_subscription failed: {e}"
                );
            }
        }
    }
}

/// Attempt to reconstruct the Sapling `PaymentAddress` from the decrypted note
/// fields and encode it as a bech32 string.
///
/// Returns `None` if the note is missing the diversifier or pk_d fields, or if
/// the bytes do not form a valid Sapling payment address.
fn reconstruct_address(note: &nie_wallet::db::Note, network_type: NetworkType) -> Option<String> {
    let diversifier_bytes: &[u8] = note.note_diversifier.as_deref()?;
    let pk_d_bytes: &[u8] = note.note_pk_d.as_deref()?;

    let diversifier_arr: [u8; 11] = diversifier_bytes.try_into().ok()?;
    let pk_d_arr: [u8; 32] = pk_d_bytes.try_into().ok()?;

    // Concatenate [d(11) || pk_d(32)] = 43 bytes, then parse via PaymentAddress::from_bytes.
    // This is the same layout as PaymentAddress::to_bytes() in sapling-crypto.
    let mut addr_bytes = [0u8; 43];
    addr_bytes[..11].copy_from_slice(&diversifier_arr);
    addr_bytes[11..].copy_from_slice(&pk_d_arr);

    let addr = PaymentAddress::from_bytes(&addr_bytes)?;

    // ZcashAddress::from_sapling requires the ToAddress trait in scope.
    let bech32 = ZcashAddress::from_sapling(network_type, addr.to_bytes()).encode();
    Some(bech32)
}

/// Activate a subscription: write to DB, delete invoice, notify client.
async fn activate_subscription(state: &AppState, invoice: &InvoiceRow) -> anyhow::Result<()> {
    // Use the invoice's own expires_at (set at creation time and shown to the user)
    // rather than recomputing from the current runtime subscription_days.
    // If the operator changes SUBSCRIPTION_DAYS after the invoice was created,
    // the subscriber still gets the duration they were promised.
    let parsed_expires_at = chrono::NaiveDateTime::parse_from_str(&invoice.expires_at, "%Y-%m-%d %H:%M:%S")
        .map_err(|e| anyhow::anyhow!("invoice expires_at parse error ({:?}): {e}", invoice.expires_at))?
        .and_utc();
    // If the invoice expired before the confirmed payment arrived, grant a
    // fresh subscription from now using the duration originally promised in the
    // invoice (stored as subscription_days at creation time), falling back to the
    // current operator setting only for pre-migration invoices that lack it.
    let fallback_days = invoice
        .subscription_days
        .unwrap_or(state.inner.subscription_days);
    let expires_at = parsed_expires_at.max(
        chrono::Utc::now() + chrono::Duration::days(fallback_days as i64),
    );

    // 1. Write subscription and delete invoice atomically so a crash between
    //    the two operations cannot trigger a double-activation or silent loss.
    state
        .inner
        .store
        .activate_subscription_atomic(&invoice.pub_id, expires_at, &invoice.invoice_id)
        .await?;

    // 3. Notify the client if online.
    let expires_str = expires_at.format("%Y-%m-%d %H:%M:%S").to_string();
    let notification = JsonRpcNotification::new(
        rpc_methods::SUBSCRIPTION_ACTIVE,
        SubscriptionActiveParams {
            expires: expires_str,
        },
    )
    // serde_json::to_value on a derived Serialize cannot fail
    .unwrap();
    // serde_json::to_string on a derived Serialize cannot fail
    let json = serde_json::to_string(&notification).unwrap();
    let delivered = state.deliver_live(&invoice.pub_id, json).await;
    if delivered {
        info!(
            pub_id = invoice.pub_id,
            "payment_watcher: subscription_active notification delivered"
        );
    }

    Ok(())
}
