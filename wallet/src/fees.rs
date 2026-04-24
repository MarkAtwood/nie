//! ZIP-317 conventional transaction fee calculation and note (coin) selection (nie-duj, nie-zz8).
//!
//! ZIP-317 defines the conventional fee as:
//!   fee = 5000 * max(2, logical_actions)
//!   logical_actions = max(n_transparent_inputs, n_transparent_outputs)
//!                   + max(n_sapling_spends, n_sapling_outputs)
//!                   + n_orchard_actions
//!
//! Reference: https://zips.z.cash/zip-0317 §2 "Specification".
//! The Sapling contribution is max(spends, outputs), not the sum — ZIP-317
//! rationale §"Rationale" explains that the sum would discriminate against
//! Orchard, which internally pads inputs and outputs to equal counts.
//!
//! For the payment use case in nie (one payer → one payee, shielded Sapling):
//!   logical_actions = max(1, 1) = 1  (one spend + one output)
//!   fee = 5000 * max(2, 1) = 10_000 zatoshi  (grace floor applies)
//!
//! The formula is exported so the UI can display the estimated fee before the
//! user confirms the payment.  The actual fee used when building the
//! transaction (nie-e4x) must match this estimate.

use crate::db::Note;

/// ZIP-317 conventional fee constant: 5000 zatoshi per logical action.
pub const MARGINAL_FEE: u64 = 5_000;

/// ZIP-317 minimum number of logical actions used in the fee formula.
///
/// A transaction with fewer actions is costed as if it had this many, to
/// prevent spam via zero-action transactions.
pub const GRACE_ACTIONS: u64 = 2;

/// Compute the ZIP-317 conventional fee for a transaction.
///
/// `logical_actions` is the number of ZIP-317 logical actions in the
/// transaction.  For a typical shielded payment (one Sapling spend, one
/// Sapling output), `sapling_logical_actions(1, 1) = 1`; the minimum fee
/// of 10 000 zatoshi is enforced by the `GRACE_ACTIONS = 2` floor in this
/// function, not by the logical action count itself.
///
/// The formula is: `MARGINAL_FEE * max(GRACE_ACTIONS, logical_actions)`.
///
/// # Examples
///
/// ```
/// use nie_wallet::fees::zip317_fee;
/// // Typical shielded payment: max(1 spend, 1 output) = 1 logical action;
/// // fee = 10_000 because the grace floor of 2 applies.
/// assert_eq!(zip317_fee(1), 10_000);
/// // High-fan-out: 10 outputs → 10 logical actions.
/// assert_eq!(zip317_fee(10), 50_000);
/// ```
pub fn zip317_fee(logical_actions: u64) -> u64 {
    MARGINAL_FEE * logical_actions.max(GRACE_ACTIONS)
}

/// Compute ZIP-317 logical actions for a standard shielded Sapling payment.
///
/// `n_inputs` = number of Sapling notes being spent.
/// `n_outputs` = number of Sapling outputs (recipient + optional change).
///
/// Per ZIP-317 §2: `contribution_Sapling = max(nSpendsSapling, nOutputsSapling)`.
/// A `(1 input, 2 outputs)` transaction (pay + change) has `max(1, 2) = 2` logical
/// actions, not 3 — this is why Sapling transactions are not penalised relative to
/// Orchard, which also uses a max rather than a sum.
pub fn sapling_logical_actions(n_inputs: u64, n_outputs: u64) -> u64 {
    // ZIP-317 §2: contribution_Sapling = max(nSpendsSapling, nOutputsSapling).
    // Do NOT change to n_inputs + n_outputs — that was an earlier rejected proposal.
    n_inputs.max(n_outputs)
}

// ---- Note (coin) selection (nie-zz8) ----

/// Coin selection error returned by [`select_notes`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CoinSelectError {
    /// The available notes do not cover `target + fee`.
    ///
    /// `have` is the total value of all available notes; `need` is the total
    /// needed (target + fee); `shortfall` is `need - have`.
    #[error(
        "insufficient funds: need {need} zatoshi, have {have} zatoshi (shortfall {shortfall})"
    )]
    InsufficientFunds {
        need: u64,
        have: u64,
        shortfall: u64,
    },

    /// `target + fee` overflows u64 — the caller passed an invalid combination.
    #[error("amount overflow: target {target} + fee {fee} overflows u64")]
    AmountOverflow { target: u64, fee: u64 },
}

/// Select the minimum set of notes needed to fund a payment of `target_zatoshi`
/// plus `fee` zatoshi.
///
/// Selection strategy: FIFO — notes are ordered by ascending `block_height`
/// (oldest first) and accumulated until the total covers `target + fee`.
/// This minimises the incremental witness depth for the oldest notes and is
/// the approach used by most Zcash light-client wallets.
///
/// # Errors
///
/// - [`CoinSelectError::AmountOverflow`] if `target + fee > u64::MAX`.
/// - [`CoinSelectError::InsufficientFunds`] if the sum of all available notes
///   is less than `target + fee`.  The error carries the exact shortfall.
///
/// # Panics
///
/// Never panics — an empty `available` slice is handled as `InsufficientFunds`.
///
/// # Invariant
///
/// On `Ok`, the sum of `value_zatoshi` across the returned notes is guaranteed
/// to be `>= target + fee` (asserted before returning).
pub fn select_notes(
    available: &[Note],
    target_zatoshi: u64,
    fee: u64,
) -> Result<Vec<Note>, CoinSelectError> {
    let total_needed = target_zatoshi
        .checked_add(fee)
        .ok_or(CoinSelectError::AmountOverflow {
            target: target_zatoshi,
            fee,
        })?;

    // Sort oldest-first (lowest block_height) — FIFO minimises witness depth.
    let mut candidates: Vec<&Note> = available.iter().collect();
    candidates.sort_by_key(|n| n.block_height);

    let mut selected: Vec<Note> = Vec::new();
    let mut sum: u64 = 0;

    for note in candidates {
        selected.push(note.clone());
        // checked_add: real Zcash supply cap is ~21M ZEC = ~2.1e15 zatoshi, far
        // below u64::MAX, so overflow is unreachable with real inputs.  Using
        // checked_add rather than saturating_add makes overflow an explicit Err
        // instead of a silent wrong result that could fool the InsufficientFunds
        // check below (a saturated sum would compare >= total_needed and return
        // a falsely-truncated selection).
        sum = sum
            .checked_add(note.value_zatoshi)
            .ok_or(CoinSelectError::AmountOverflow {
                target: sum,
                fee: note.value_zatoshi,
            })?;
        if sum >= total_needed {
            break;
        }
    }

    if sum < total_needed {
        let have = available.iter().map(|n| n.value_zatoshi).sum::<u64>();
        return Err(CoinSelectError::InsufficientFunds {
            need: total_needed,
            have,
            shortfall: total_needed - have,
        });
    }

    // Invariant: sum of selected notes covers the required amount.
    debug_assert!(
        selected.iter().map(|n| n.value_zatoshi).sum::<u64>() >= total_needed,
        "select_notes invariant violated: selected sum < total_needed"
    );

    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ZIP-317 fee tests ----
    // Test vectors derived directly from the ZIP-317 specification:
    // https://zips.z.cash/zip-0317
    // fee = 5000 * max(2, logical_actions)

    #[test]
    fn grace_window_applies_below_threshold() {
        // Transactions with fewer than GRACE_ACTIONS logical actions still pay
        // the minimum fee = MARGINAL_FEE * GRACE_ACTIONS.
        assert_eq!(zip317_fee(0), 10_000);
        assert_eq!(zip317_fee(1), 10_000);
        assert_eq!(zip317_fee(2), 10_000); // exactly at threshold
    }

    #[test]
    fn fee_scales_linearly_above_threshold() {
        // Above GRACE_ACTIONS, fee = MARGINAL_FEE * logical_actions.
        assert_eq!(zip317_fee(3), 15_000);
        assert_eq!(zip317_fee(4), 20_000);
        assert_eq!(zip317_fee(10), 50_000);
        assert_eq!(zip317_fee(100), 500_000);
    }

    #[test]
    fn typical_shielded_payment_fee() {
        // Standard 1-in 1-out shielded payment: max(1,1)=1 logical action.
        // Fee = 5000 * max(2, 1) = 10_000 zatoshi (grace floor covers the gap).
        let actions = sapling_logical_actions(1, 1);
        assert_eq!(actions, 1);
        assert_eq!(zip317_fee(actions), 10_000);
    }

    #[test]
    fn payment_with_change_fee() {
        // 1 input, 2 outputs (recipient + change): max(1,2)=2 logical actions.
        // Fee = 5000 * max(2, 2) = 10_000 zatoshi — same as a 1-in 1-out payment.
        // (With the old sum formula this was incorrectly 15_000.)
        let actions = sapling_logical_actions(1, 2);
        assert_eq!(actions, 2);
        assert_eq!(zip317_fee(actions), 10_000);
    }

    #[test]
    fn sapling_logical_actions_is_symmetric() {
        // max(n, m) == max(m, n) — more spends than outputs costs the same as the reverse.
        assert_eq!(sapling_logical_actions(3, 1), sapling_logical_actions(1, 3));
        assert_eq!(sapling_logical_actions(3, 1), 3);
    }

    #[test]
    fn marginal_fee_and_grace_actions_match_spec() {
        // ZIP-317 §5: "The conventional fee ... 5000 zatoshi ... grace actions = 2"
        assert_eq!(MARGINAL_FEE, 5_000);
        assert_eq!(GRACE_ACTIONS, 2);
    }

    // ---- select_notes tests (nie-zz8) ----

    fn make_note(block_height: u64, value_zatoshi: u64, output_index: i64) -> Note {
        Note {
            txid: format!("{:0>64}", output_index),
            output_index,
            value_zatoshi,
            memo: None,
            block_height,
            created_at: 0,
            note_diversifier: None,
            note_pk_d: None,
            note_rseed: None,
            rseed_after_zip212: None,
        }
    }

    /// Empty note list → InsufficientFunds (not a panic).
    ///
    /// Oracle: no notes → have = 0; need = 1; shortfall = 1.
    #[test]
    fn select_notes_empty_is_insufficient() {
        let err = select_notes(&[], 1, 0).unwrap_err();
        assert_eq!(
            err,
            CoinSelectError::InsufficientFunds {
                need: 1,
                have: 0,
                shortfall: 1
            }
        );
    }

    /// Exact amount (sum == target + fee) succeeds and returns the note.
    ///
    /// Oracle: one note at exactly the required total; selection must succeed.
    #[test]
    fn select_notes_exact_amount_succeeds() {
        let note = make_note(100, 10_000, 0);
        let selected = select_notes(&[note.clone()], 9_990, 10).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value_zatoshi, 10_000);
    }

    /// sum < target + fee → InsufficientFunds with correct shortfall.
    ///
    /// Oracle: shortfall computed by hand: need = 20_000, have = 15_000,
    /// shortfall = 5_000.
    #[test]
    fn select_notes_insufficient_funds_correct_shortfall() {
        let notes = vec![make_note(100, 10_000, 0), make_note(200, 5_000, 1)];
        let err = select_notes(&notes, 19_990, 10).unwrap_err();
        assert_eq!(
            err,
            CoinSelectError::InsufficientFunds {
                need: 20_000,
                have: 15_000,
                shortfall: 5_000,
            }
        );
    }

    /// FIFO: oldest notes (lowest block_height) are selected first.
    ///
    /// Oracle: two notes; only one is needed to cover the target; the one
    /// at lower block_height must be chosen.  Verified by comparing txid,
    /// not value (both have the same value to isolate the ordering logic).
    #[test]
    fn select_notes_prefers_oldest_first() {
        // older note at height 50; newer at height 200 — same value.
        let older = make_note(50, 10_000, 0);
        let newer = make_note(200, 10_000, 1);
        // Pass newer first to ensure sort is not relying on input order.
        let selected = select_notes(&[newer.clone(), older.clone()], 1, 0).unwrap();
        assert_eq!(selected.len(), 1, "only one note is needed");
        assert_eq!(
            selected[0].txid, older.txid,
            "oldest note (lowest block_height) must be preferred"
        );
    }

    /// Returns the minimum number of notes needed (stops as soon as sum >= need).
    ///
    /// Oracle: three notes whose prefix sum covers the target with two notes;
    /// the third must not be included.
    #[test]
    fn select_notes_stops_at_minimum() {
        let notes = vec![
            make_note(10, 6_000, 0),
            make_note(20, 5_000, 1),
            make_note(30, 9_000, 2),
        ];
        // Need 10_000; oldest two sum to 11_000 → covers it.
        let selected = select_notes(&notes, 9_990, 10).unwrap();
        assert_eq!(selected.len(), 2, "must stop as soon as sum >= need");
        let sum: u64 = selected.iter().map(|n| n.value_zatoshi).sum();
        assert!(sum >= 10_000);
    }

    /// target + fee overflow returns AmountOverflow, not a panic.
    ///
    /// Oracle: u64::MAX + 1 overflows; the function must return Err, not panic.
    #[test]
    fn select_notes_fee_overflow_returns_err() {
        let note = make_note(1, u64::MAX, 0);
        let err = select_notes(&[note], u64::MAX, 1).unwrap_err();
        assert!(matches!(err, CoinSelectError::AmountOverflow { .. }));
    }

    /// fee matches ZIP-317 formula for varying input/output counts.
    ///
    /// Oracle: formula constants from ZIP-317 spec; expected values computed
    /// by hand, not from zip317_fee() itself (independent derivation).
    #[test]
    fn select_notes_fee_matches_zip317_for_1_in_1_out() {
        // ZIP-317: 1 spend, 1 output → sapling_logical_actions = max(1,1) = 1
        // fee = MARGINAL_FEE * max(GRACE_ACTIONS, 1) = 5000 * 2 = 10_000
        let computed_fee = zip317_fee(sapling_logical_actions(1, 1));
        assert_eq!(computed_fee, 10_000, "fee constant must match ZIP-317 §2");

        let note = make_note(100, 20_000, 0);
        let selected = select_notes(&[note], 10_000, computed_fee).unwrap();
        assert_eq!(selected.len(), 1);
    }

    // ---- Property tests (proptest) ----

    proptest::proptest! {
        /// For any note set where total >= target + fee, select_notes succeeds
        /// and the returned selection covers the requirement.
        ///
        /// Oracle: the sum invariant is checked inside select_notes (debug_assert)
        /// and re-checked here independently by summing the returned notes.
        #[test]
        fn prop_select_notes_succeeds_when_total_covers_need(
            // Generate 1–20 notes with values 1–1_000_000 zatoshi each.
            values in proptest::collection::vec(1u64..=1_000_000u64, 1..=20),
            target in 0u64..=500_000u64,
            fee in 0u64..=10_000u64,
        ) {
            let total: u64 = values.iter().sum();
            let Some(need) = target.checked_add(fee) else { return Ok(()); };

            let notes: Vec<Note> = values
                .iter()
                .enumerate()
                .map(|(i, &v)| make_note(i as u64, v, i as i64))
                .collect();

            if total >= need {
                let selected = select_notes(&notes, target, fee)
                    .expect("must succeed when total >= need");
                let selected_sum: u64 = selected.iter().map(|n| n.value_zatoshi).sum();
                proptest::prop_assert!(
                    selected_sum >= need,
                    "selected sum {selected_sum} < need {need}"
                );
            } else {
                proptest::prop_assert!(select_notes(&notes, target, fee).is_err());
            }
        }
    }
}
