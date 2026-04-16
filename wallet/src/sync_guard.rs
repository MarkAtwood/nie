//! Sync-lag guard: refuse to send if the wallet is too far behind the chain tip.
//!
//! Sending with a stale scan risks spending notes that were already spent in
//! unscanned blocks, producing a double-spend that the node will reject.
//!
//! # Usage
//!
//! Call [`check_lag`] with the local scan tip and remote chain tip before
//! building a transaction.  Returns [`SyncLagError`] if the gap exceeds
//! [`MAX_SYNC_LAG`] blocks.

/// Maximum tolerated difference between the chain tip and the local scan tip.
///
/// 10 blocks ≈ 12.5 minutes on mainnet (75-second block time).  Beyond this
/// gap the wallet's UTXO view may be stale enough to select already-spent
/// notes, which would cause a double-spend rejection at broadcast time.
/// 10 is a conservative default that accommodates brief network interruptions
/// without blocking the user unnecessarily.
///
/// # TOCTOU note — do not lower this value without understanding the race
///
/// `send_payment` fetches `chain_tip` (one await) then calls `check_lag`, then
/// fetches `spendable_notes` (a second await).  The real chain tip can advance
/// between these two awaits.  On mainnet the block time is ~75 seconds, so
/// the window is short; on testnet blocks arrive much faster.
///
/// The 10-block buffer absorbs this race: even if 1–2 new blocks arrive
/// between the two awaits, the check remains valid.  Lowering `MAX_SYNC_LAG`
/// below ~3 would make the guard flaky on testnet and correct only on paper.
/// Do not tighten this without also making the check re-verify after fetching
/// notes, or rearchitecting to hold `chain_tip` and `spendable_notes` under
/// the same async snapshot.
pub const MAX_SYNC_LAG: u64 = 10;

/// Error returned when the wallet's scan is too far behind the chain tip.
#[derive(Debug)]
pub struct SyncLagError {
    pub scan_tip: u64,
    pub chain_tip: u64,
}

impl SyncLagError {
    /// Number of blocks the local scan lags behind the chain tip.
    ///
    /// Saturating: returns 0 when scan is ahead of or equal to the chain tip
    /// (post-reorg condition — not an error, but the field is kept consistent).
    pub fn lag(&self) -> u64 {
        self.chain_tip.saturating_sub(self.scan_tip)
    }
}

impl std::fmt::Display for SyncLagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "wallet is {} blocks behind chain tip \
             (scan_tip={}, chain_tip={}) — run sync first",
            self.lag(),
            self.scan_tip,
            self.chain_tip
        )
    }
}

impl std::error::Error for SyncLagError {}

/// Check whether the wallet's scan is current enough to safely send.
///
/// Returns `Ok(())` if the gap between `local_tip` and `chain_tip` is within
/// [`MAX_SYNC_LAG`] blocks (or if the chain tip is not ahead of the scan tip,
/// as can happen after a chain reorg).
///
/// Returns `Err(SyncLagError)` if:
/// - `local_tip == 0` — wallet has never been scanned.
/// - `chain_tip > local_tip + max_lag_blocks` — lag exceeds the threshold.
pub fn check_lag(local_tip: u64, chain_tip: u64, max_lag_blocks: u64) -> Result<(), SyncLagError> {
    // A wallet that has never synced must not send — it has no UTXO knowledge.
    if local_tip == 0 {
        return Err(SyncLagError {
            scan_tip: 0,
            chain_tip,
        });
    }

    // Saturating subtraction: if chain_tip <= local_tip (reorg or fresh sync),
    // lag is 0 and the check passes.
    if chain_tip.saturating_sub(local_tip) > max_lag_blocks {
        return Err(SyncLagError {
            scan_tip: local_tip,
            chain_tip,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// scan_tip=100, chain_tip=105, max=10 → Ok (within tolerance).
    ///
    /// Oracle: 105 - 100 = 5 ≤ 10.
    #[test]
    fn within_lag_limit_returns_ok() {
        check_lag(100, 105, MAX_SYNC_LAG).expect("5 blocks behind must be Ok");
    }

    /// scan_tip=100, chain_tip=111, max=10 → Err (lag = 11 > 10).
    ///
    /// Oracle: 111 - 100 = 11 > 10; error fields must match the inputs.
    #[test]
    fn exceeding_lag_limit_returns_err() {
        let err = check_lag(100, 111, MAX_SYNC_LAG).unwrap_err();
        assert_eq!(err.scan_tip, 100);
        assert_eq!(err.chain_tip, 111);
        assert_eq!(err.lag(), 11);
    }

    /// scan_tip=0 → Err regardless of chain_tip (never-synced wallet).
    ///
    /// Oracle: a wallet with scan_tip=0 has no UTXO knowledge and must not send.
    #[test]
    fn never_synced_wallet_returns_err() {
        let err = check_lag(0, 1, MAX_SYNC_LAG).unwrap_err();
        assert_eq!(err.scan_tip, 0);
        assert_eq!(err.chain_tip, 1);
    }

    /// scan_tip=200, chain_tip=198 (chain reorg) → Ok (lag = 0).
    ///
    /// Oracle: saturating_sub(198, 200) = 0 ≤ 10; reorg case must not block.
    #[test]
    fn reorg_scan_ahead_of_chain_returns_ok() {
        check_lag(200, 198, MAX_SYNC_LAG).expect("scan ahead of chain must be Ok");
    }

    /// scan_tip == chain_tip → Ok (fully synced).
    #[test]
    fn fully_synced_returns_ok() {
        check_lag(500, 500, MAX_SYNC_LAG).expect("fully synced must be Ok");
    }

    /// Error Display contains "sync" and the lag count.
    ///
    /// Oracle: the Display implementation must produce an actionable message
    /// per the issue spec: "wallet is N blocks behind … run sync first".
    #[test]
    fn error_display_contains_sync_and_lag() {
        let err = check_lag(100, 115, MAX_SYNC_LAG).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("sync"), "Display must mention sync: {s}");
        assert!(s.contains("15"), "Display must contain lag count 15: {s}");
    }

    /// scan_tip=100, chain_tip=110, max=10 → Ok (exactly at limit).
    ///
    /// Oracle: 110 - 100 = 10 == max; the bound is inclusive so this is Ok.
    #[test]
    fn exactly_at_limit_returns_ok() {
        check_lag(100, 110, MAX_SYNC_LAG).expect("exactly at lag limit must be Ok");
    }
}
