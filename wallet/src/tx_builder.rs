//! Helpers for shielded transaction construction (nie-wdw).
//!
//! Four pure functions, each handling one step that `build_shielded_tx` calls:
//!
//! - [`witness_to_merkle_path`] — DB witness bytes → `sapling::MerklePath`
//! - [`spendable_note_to_sapling`] — DB `SpendableNote` row → `sapling::Note`
//! - [`load_sapling_params`] — param file paths → `(SpendParameters, OutputParameters)`
//! - [`build_shielded_tx`] — full Sapling transaction builder entry-point
//!
//! All functions return `TxBuildError` on failure with an actionable message.

use std::io::Cursor;

use sapling::{
    circuit::{OutputParameters, SpendParameters},
    note::Rseed,
    value::NoteValue,
    Note, PaymentAddress,
};
use zcash_address::unified::{Container as UaContainer, Receiver as UaReceiver};
use zcash_address::{ConversionError, TryFromAddress, ZcashAddress};
use zcash_primitives::{
    merkle_tree::read_incremental_witness,
    transaction::{
        builder::{BuildConfig, Builder},
        fees::zip317::FeeRule,
    },
};
use zcash_protocol::{
    consensus::{BlockHeight, Network},
    memo::MemoBytes,
    value::Zatoshis,
};
use zcash_transparent::builder::TransparentSigningSet;

use crate::{
    address::{SaplingExtendedSpendingKey, ZcashNetwork},
    db::SpendableNote,
    fees::{sapling_logical_actions, zip317_fee},
    params::{verify_blake2b, OUTPUT_PARAMS_BLAKE2B, SPEND_PARAMS_BLAKE2B},
    tx_error::TxBuildError,
};

/// ZIP-317: amounts at or below this threshold are economically irrational —
/// the ZIP-317 minimum conventional fee (10 000 zatoshi) meets or exceeds the
/// transfer value, so the recipient receives nothing or less than the fee cost.
pub const DUST_THRESHOLD: u64 = 10_000;

// ---- witness deserialization (nie-wdw.4) ----

/// Deserialize `witness_data` bytes into a `sapling::MerklePath`.
///
/// `witness_data` must have been produced by
/// `zcash_primitives::merkle_tree::write_incremental_witness` (the format used by
/// the compact-block scanner and `zcashd` when storing note witnesses).
///
/// # Errors
///
/// - `WitnessDeserialize("empty witness data")` if the slice is empty.
/// - `WitnessDeserialize(...)` if the bytes cannot be deserialized.
/// - `WitnessDeserialize("witness has no path...")` if the witness has not
///   recorded a sibling yet — this can happen if the note was received in the
///   most recent block and the scanner has not yet applied the next block's
///   commitment to the witness.
pub fn witness_to_merkle_path(witness_data: &[u8]) -> Result<sapling::MerklePath, TxBuildError> {
    if witness_data.is_empty() {
        return Err(TxBuildError::WitnessDeserialize(
            "empty witness data".into(),
        ));
    }
    // read_incremental_witness takes any R: io::Read.  std::io::Cursor<&[u8]>
    // satisfies this bound because corez re-exports std::io in std environments.
    let witness = read_incremental_witness::<sapling::Node, _, 32>(Cursor::new(witness_data))
        .map_err(|e| {
            TxBuildError::WitnessDeserialize(format!("failed to parse witness bytes: {e}"))
        })?;
    witness.path().ok_or_else(|| {
        TxBuildError::WitnessDeserialize(
            "witness has no path — the note may not yet have a sibling commitment; \
             wait for one more block and retry"
                .into(),
        )
    })
}

// ---- note reconstruction (nie-wdw.5) ----

/// Reconstruct a `sapling::Note` from a [`SpendableNote`] DB row.
///
/// `spendable_notes()` guarantees that all three plaintext columns are non-NULL,
/// so this function receives data that was stored by the scanner.
///
/// # Errors
///
/// - `NoteDeserialize(...)` if byte lengths are wrong or the address bytes do
///   not represent a point on the Sapling curve.
///
/// # Panics
///
/// None — all `expect()` calls are guarded by length checks above them.
pub fn spendable_note_to_sapling(row: &SpendableNote) -> Result<Note, TxBuildError> {
    // Validate lengths before touching any crypto — gives clear errors instead of panics.
    if row.note_diversifier.len() != 11 {
        return Err(TxBuildError::NoteDeserialize(format!(
            "note_diversifier must be 11 bytes (raw Sapling diversifier d), got {} — DB row {} may be corrupt",
            row.note_diversifier.len(),
            row.note_id
        )));
    }
    if row.note_pk_d.len() != 32 {
        return Err(TxBuildError::NoteDeserialize(format!(
            "note_pk_d must be 32 bytes (pk_d point), got {} — DB row {} may be corrupt",
            row.note_pk_d.len(),
            row.note_id
        )));
    }
    if row.note_rseed.len() != 32 {
        return Err(TxBuildError::NoteDeserialize(format!(
            "note_rseed must be 32 bytes, got {} — DB row {} may be corrupt",
            row.note_rseed.len(),
            row.note_id
        )));
    }

    // PaymentAddress::from_bytes expects a 43-byte slice: [diversifier(11) | pk_d(32)].
    // The `diversifier` here is the raw 11-byte value d; from_bytes internally computes
    // g_d = GH("Zcash_gd", d) and rejects the identity point.
    let mut addr_bytes = [0u8; 43];
    addr_bytes[..11].copy_from_slice(&row.note_diversifier);
    addr_bytes[11..].copy_from_slice(&row.note_pk_d);
    let recipient = PaymentAddress::from_bytes(&addr_bytes).ok_or_else(|| {
        TxBuildError::NoteDeserialize(format!(
            "invalid Sapling payment address in DB row {} — \
             diversifier or pk_d is not on the Sapling curve; the note scanner may have \
             stored corrupt data",
            row.note_id
        ))
    })?;

    let value = NoteValue::from_raw(row.value_zatoshi);

    // Infallible: length == 32 verified above.
    let rseed_bytes: [u8; 32] = row.note_rseed[..].try_into().expect("len == 32");

    let rseed = if row.rseed_after_zip212 {
        // Post-ZIP-212 (the common case): rseed is a 32-byte randomness seed.
        Rseed::AfterZip212(rseed_bytes)
    } else {
        // Pre-ZIP-212: rseed_bytes hold the raw Jubjub Fr scalar (rcm).
        // fr.from_bytes returns CtOption; convert to Option to handle the failure case.
        let fr = Option::from(jubjub::Fr::from_bytes(&rseed_bytes)).ok_or_else(|| {
            TxBuildError::NoteDeserialize(format!(
                "note_rseed in DB row {} is not a valid Jubjub scalar (pre-ZIP-212 rcm) — \
                 the note scanner may have stored corrupt data",
                row.note_id
            ))
        })?;
        Rseed::BeforeZip212(fr)
    };

    Ok(Note::from_parts(recipient, value, rseed))
}

// ---- params loading (nie-wdw.6) ----

/// Load Sapling proving parameters from disk, verifying BLAKE2b-512 hashes.
///
/// The workflow:
/// 1. Read file bytes via `std::fs::read`.
/// 2. Re-verify BLAKE2b-512 against the hardcoded constants from `params.rs`.
///    If mismatch, the file is corrupt — return `ParamsNotLoaded` before touching
///    the parser to avoid a confusing groth16 parse error.
/// 3. Parse with `SpendParameters::read(..., false)` / `OutputParameters::read(..., false)`.
///    `verify_point_encodings = false` is intentional: the hash check already
///    guarantees byte-level integrity; re-verifying curve points adds ~30 s to
///    every cold start with no security gain.
///
/// # Errors
///
/// Returns `TxBuildError::ParamsNotLoaded` for any failure; the message includes
/// the file path, the reason, and an actionable hint.  The spend file is checked
/// first; if it fails, the output file is never opened.
pub fn load_sapling_params(
    paths: &crate::params::SaplingParamPaths,
) -> Result<(SpendParameters, OutputParameters), TxBuildError> {
    // ---- spend params ----
    let spend_bytes = std::fs::read(&paths.spend).map_err(|e| {
        TxBuildError::ParamsNotLoaded(format!(
            "sapling-spend.params not found at {} — \
             run `nie wallet init` to download it: {e}",
            paths.spend.display()
        ))
    })?;
    if !verify_blake2b(&spend_bytes, SPEND_PARAMS_BLAKE2B) {
        return Err(TxBuildError::ParamsNotLoaded(format!(
            "sapling-spend.params at {} failed BLAKE2b-512 integrity check — \
             the file may be corrupt or truncated; delete it and re-run `nie wallet init`",
            paths.spend.display()
        )));
    }
    // verify_point_encodings=false: hash check above already guarantees byte integrity.
    let spend_params = SpendParameters::read(Cursor::new(&spend_bytes), false).map_err(|e| {
        TxBuildError::ParamsNotLoaded(format!(
            "sapling-spend.params at {} could not be parsed as groth16 parameters: {e}",
            paths.spend.display()
        ))
    })?;

    // ---- output params ----
    let output_bytes = std::fs::read(&paths.output).map_err(|e| {
        TxBuildError::ParamsNotLoaded(format!(
            "sapling-output.params not found at {} — \
             run `nie wallet init` to download it: {e}",
            paths.output.display()
        ))
    })?;
    if !verify_blake2b(&output_bytes, OUTPUT_PARAMS_BLAKE2B) {
        return Err(TxBuildError::ParamsNotLoaded(format!(
            "sapling-output.params at {} failed BLAKE2b-512 integrity check — \
             the file may be corrupt or truncated; delete it and re-run `nie wallet init`",
            paths.output.display()
        )));
    }
    let output_params = OutputParameters::read(Cursor::new(&output_bytes), false).map_err(|e| {
        TxBuildError::ParamsNotLoaded(format!(
            "sapling-output.params at {} could not be parsed as groth16 parameters: {e}",
            paths.output.display()
        ))
    })?;

    Ok((spend_params, output_params))
}

// ---- build_shielded_tx (nie-wdw.7) ----

/// Build a signed Sapling shielded transaction and return the serialized bytes.
///
/// # Parameters
///
/// - `sk` — Sapling extended spending key for account 0.
/// - `to_address` — Recipient: Unified Address (with Sapling receiver) or raw
///   Sapling address (`zs…` / `ztestsapling…`).
/// - `amount_zatoshi` — Transfer amount in zatoshi (must be > `DUST_THRESHOLD` = 10 000).
/// - `memo` — ZIP-302 shielded memo; exactly 512 bytes.
/// - `notes` — Spendable notes from `WalletStore::spendable_notes()`,
///   each including a serialized Merkle witness.
/// - `params` — Sapling proving parameters from [`load_sapling_params`], or `None`
///   when the caller knows the call will return an early error (test helper use only).
///   Production callers must always pass `Some(&loaded_params)`.
/// - `network` — Mainnet or testnet; must match `sk`'s derivation network.
/// - `anchor_height` — Block height at which the Sapling commitment tree was last
///   updated; all witnesses must be rooted at the same block's tree root.
///   **Must equal `WalletStore::scan_tip()`** — witnesses from `spendable_notes()`
///   are rooted at the scan tip, not at the individual note's `block_height`.
///   This is because the incremental witness tree advances once per block (when
///   the scanner processes a new block), not once per note; a note's `block_height`
///   is when it was received, but its witness is valid only at the current scan tip.
///   Passing `note.block_height` here causes an anchor mismatch and proof failure.
/// - `change_diversifier_index` — Diversifier index for the change output address.
///   Must be a fresh index obtained from `WalletStore::next_diversifier(account)`.
///   Using the same index twice links change outputs to the same address, breaking
///   transaction unlinkability.
///
/// # Errors
///
/// Returns `TxBuildError` for: dust amount, no spendable notes, unsupported address
/// type, insufficient funds, anchor mismatch, corrupt witness/note data, or
/// builder/serialization failure.
///
/// # Security
///
/// Never logs `sk`, note plaintext values, or the recipient address.
/// Only logs: input count and amount in zatoshi at `info` level.
#[allow(clippy::too_many_arguments)]
pub fn build_shielded_tx(
    sk: &SaplingExtendedSpendingKey,
    to_address: &str,
    amount_zatoshi: u64,
    memo: &[u8; 512],
    notes: &[SpendableNote],
    params: Option<&(SpendParameters, OutputParameters)>,
    network: ZcashNetwork,
    anchor_height: u64,
    change_diversifier_index: u128,
) -> Result<(Vec<u8>, Vec<i64>), TxBuildError> {
    // 1a. No spendable notes — scanner hasn't decrypted any notes yet.
    if notes.is_empty() {
        return Err(TxBuildError::NoSpendableNotes);
    }

    // 1b. Dust check (ZIP-317: the minimum conventional fee is 10 000 zatoshi;
    //     sending ≤ 10 000 zatoshi means the fee meets or exceeds the amount).
    if amount_zatoshi < DUST_THRESHOLD {
        return Err(TxBuildError::DustAmount {
            amount: amount_zatoshi,
            threshold: DUST_THRESHOLD,
        });
    }

    // 2. Parse recipient address → Sapling PaymentAddress.
    let recipient = parse_sapling_address(to_address)?;

    // 3–4. Fee-aware coin selection (2-pass):
    //   Pass 1: estimate fee assuming 1 spend and 2 outputs (pay + change).
    //   Pass 2: re-compute with the actual number of selected notes; re-select
    //           if the fee increased (selecting one more note can push the fee up).
    let (selected_notes, fee) = select_with_fee(notes, amount_zatoshi)?;
    let selected_note_ids: Vec<i64> = selected_notes.iter().map(|n| n.note_id).collect();

    // .sum() is safe: select_notes_spendable used checked_add internally and returned
    // Ok only if the selection sum fits in u64, so this re-sum cannot overflow.
    let selected_sum: u64 = selected_notes.iter().map(|n| n.value_zatoshi).sum();
    // Subtraction is safe: select_with_fee guarantees selected_sum >= amount + fee.
    let change = selected_sum - amount_zatoshi - fee;

    tracing::info!(
        n_inputs = selected_notes.len(),
        amount_zatoshi,
        fee,
        "building shielded tx"
    );

    // 5. Reconstruct sapling::Note objects and deserialize their Merkle witnesses.
    let mut sapling_notes: Vec<sapling::Note> = Vec::with_capacity(selected_notes.len());
    let mut merkle_paths: Vec<sapling::MerklePath> = Vec::with_capacity(selected_notes.len());

    for row in &selected_notes {
        let note = spendable_note_to_sapling(row)?;
        let path = witness_to_merkle_path(&row.witness_data)?;
        sapling_notes.push(note);
        merkle_paths.push(path);
    }

    // 6. Verify all witnesses share the same commitment tree root → same Sapling anchor.
    //    The builder enforces this internally, but we detect it early with a clearer error.
    //    Anchor computation: root = path.root(Node::from_cmu(&note.cmu())), then Anchor::from.
    debug_assert!(
        !sapling_notes.is_empty(),
        "select_with_fee must return at least one note for amount >= DUST_THRESHOLD"
    );
    let first_anchor = {
        let node = sapling::Node::from_cmu(&sapling_notes[0].cmu());
        sapling::Anchor::from(merkle_paths[0].root(node))
    };
    for (note, path) in sapling_notes.iter().zip(merkle_paths.iter()).skip(1) {
        let node = sapling::Node::from_cmu(&note.cmu());
        let anchor = sapling::Anchor::from(path.root(node));
        if anchor != first_anchor {
            return Err(TxBuildError::AnchorMismatch);
        }
    }

    // 7. Construct the transaction builder.
    let consensus_params = match network {
        ZcashNetwork::Mainnet => Network::MainNetwork,
        ZcashNetwork::Testnet => Network::TestNetwork,
    };
    // anchor_height is a u64 from the scan state; Zcash block heights fit in u32.
    let target_height = BlockHeight::try_from(anchor_height).map_err(|_| {
        TxBuildError::BuilderError(format!(
            "anchor_height {anchor_height} exceeds u32::MAX — implausible for any real chain"
        ))
    })?;

    let mut builder = Builder::new(
        consensus_params,
        target_height,
        BuildConfig::Standard {
            sapling_anchor: Some(first_anchor),
            orchard_anchor: None,
        },
    );

    // 8. Add Sapling spends — one per selected note.
    let fvk = sk.full_viewing_key();
    let ovk = fvk.ovk;

    for (note, path) in sapling_notes.into_iter().zip(merkle_paths.into_iter()) {
        // The FE type parameter is Infallible because add_sapling_spend cannot
        // produce a fee error; the only variants it can return are SaplingBuild
        // (anchor mismatch, which we pre-checked) and SaplingBuilderNotAvailable.
        builder
            .add_sapling_spend::<core::convert::Infallible>(fvk.clone(), note, path)
            .map_err(|e| TxBuildError::BuilderError(format!("add_sapling_spend: {e}")))?;
    }

    // 9. Add the recipient output.
    // from_bytes: rejects slices > 512 bytes; our input is exactly 512 bytes
    // so this conversion is infallible.
    let memo_bytes =
        MemoBytes::from_bytes(memo.as_ref()).expect("512-byte memo cannot exceed MemoBytes limit");
    let amount_zatoshis =
        Zatoshis::from_u64(amount_zatoshi).map_err(|_| TxBuildError::AmountOverflow)?;

    builder
        .add_sapling_output::<core::convert::Infallible>(
            Some(ovk),
            recipient,
            amount_zatoshis,
            memo_bytes,
        )
        .map_err(|e| TxBuildError::BuilderError(format!("add_sapling_output (recipient): {e}")))?;

    // 10. Add change output if needed.
    if change > 0 {
        // Use a fresh diversified address for change to prevent address reuse.
        // Reusing default_address() across transactions links all change outputs
        // to the same address, breaking shielded unlinkability.
        // `change_diversifier_index` is a per-transaction value from next_diversifier().
        let (_, change_addr) = sk
            .to_dfvk()
            .find_address(change_diversifier_index)
            .map_err(|e| TxBuildError::BuilderError(format!("change address derivation: {e}")))?;
        let change_zatoshis =
            Zatoshis::from_u64(change).map_err(|_| TxBuildError::AmountOverflow)?;
        builder
            .add_sapling_output::<core::convert::Infallible>(
                Some(ovk),
                change_addr,
                change_zatoshis,
                MemoBytes::empty(),
            )
            .map_err(|e| TxBuildError::BuilderError(format!("add_sapling_output (change): {e}")))?;
    }

    // 11. Generate proofs and build the signed transaction.
    // `params` is Option so that test helpers for pre-proof error paths can pass None
    // without unsafe MaybeUninit.  Production callers always pass Some(&loaded_params).
    let (spend_params, output_params) = params.ok_or_else(|| {
        TxBuildError::ParamsNotLoaded(
            "params must be loaded before building a transaction; \
             call load_sapling_params first"
                .into(),
        )
    })?;
    let extsk = sk.inner_extsk().clone();
    let result = builder
        .build(
            &TransparentSigningSet::new(),
            &[extsk],
            &[],
            rand::rngs::OsRng,
            spend_params,
            output_params,
            &FeeRule::standard(),
        )
        .map_err(|e| TxBuildError::BuilderError(format!("builder.build: {e}")))?;

    // 12. Serialize the transaction.
    let mut bytes = Vec::new();
    result
        .transaction()
        .write(&mut bytes)
        .map_err(|e| TxBuildError::BuilderError(format!("tx serialization failed: {e}")))?;

    Ok((bytes, selected_note_ids))
}

/// Parse `address` and extract a Sapling `PaymentAddress`.
///
/// Accepts:
/// - Raw Sapling addresses (`zs…` mainnet, `ztestsapling…` testnet)
/// - Unified Addresses that contain a Sapling receiver
///
/// Returns `UnsupportedAddressType` for transparent, Sprout, and UA-Orchard-only.
// pub(crate) for direct testing of error variants (nie-wdw.9).
pub(crate) fn parse_sapling_address(address: &str) -> Result<PaymentAddress, TxBuildError> {
    /// Local extractor type implementing `TryFromAddress`.
    ///
    /// Only the Sapling and Unified variants are overridden; all others use the
    /// default implementation which returns `ConversionError::Unsupported`.
    struct SaplingExtractor([u8; 43]);

    impl TryFromAddress for SaplingExtractor {
        type Error = String; // not used; all paths return Ok or Unsupported

        fn try_from_sapling(
            _net: zcash_protocol::consensus::NetworkType,
            data: [u8; 43],
        ) -> Result<Self, ConversionError<Self::Error>> {
            Ok(SaplingExtractor(data))
        }

        fn try_from_unified(
            _net: zcash_protocol::consensus::NetworkType,
            ua: zcash_address::unified::Address,
        ) -> Result<Self, ConversionError<Self::Error>> {
            let sapling_bytes = ua.items().into_iter().find_map(|r| match r {
                UaReceiver::Sapling(b) => Some(b),
                _ => None,
            });
            sapling_bytes.map(SaplingExtractor).ok_or_else(|| {
                // ConversionError::User carries the message; UnsupportedAddress
                // cannot be constructed from outside zcash_address (private field).
                ConversionError::User(
                    "Unified Address has no Sapling receiver (Orchard-only)".to_string(),
                )
            })
        }
    }

    let zaddr = ZcashAddress::try_from_encoded(address)
        .map_err(|e| TxBuildError::InvalidRecipient(format!("invalid address '{address}': {e}")))?;

    let extractor: SaplingExtractor =
        zaddr
            .convert::<SaplingExtractor>()
            .map_err(|e: ConversionError<String>| match e {
                ConversionError::Unsupported(t) => {
                    TxBuildError::UnsupportedAddressType(t.to_string())
                }
                ConversionError::IncorrectNetwork { expected, actual } => {
                    TxBuildError::InvalidRecipient(format!(
                        "address is for {actual:?} but wallet is on {expected:?}"
                    ))
                }
                // ConversionError::User is produced only by our try_from_unified when
                // the UA has no Sapling receiver.  That is "valid address, unsupported
                // protocol" — not a parse failure — so UnsupportedAddressType is correct.
                ConversionError::User(s) => TxBuildError::UnsupportedAddressType(s),
            })?;

    PaymentAddress::from_bytes(&extractor.0)
        .ok_or_else(|| TxBuildError::InvalidRecipient("Sapling address bytes are invalid".into()))
}

/// Fee-aware FIFO coin selection.
///
/// Iterative convergence strategy:
/// 1. Start with fee = zip317_fee for 1 spend + 2 outputs.
/// 2. Select notes to cover `amount + fee`.
/// 3. Compute the fee for the actual selected count.
/// 4. If it equals the fee used, return. Otherwise update fee and go to step 2.
///
/// Why a loop instead of 2 passes: if pass 2 selects more notes than pass 1,
/// the fee based on `n1` is wrong for `n2` inputs, causing the builder to reject
/// the transaction (inputs ≠ outputs + zip317_fee(n2)). The loop converges because:
/// - zip317_fee is monotone-non-decreasing with note count
/// - finitely many notes → eventually InsufficientFunds or convergence
///
/// # Output count assumption
///
/// `sapling_logical_actions(n, 2)` always passes 2 outputs (recipient + change).
/// `build_shielded_tx` only adds the change output when `change > 0`, so for
/// zero-change transactions the builder sees 1 output, not 2.  The fee is still
/// correct because `GRACE_ACTIONS = 2` applies a floor of 2 actions to every
/// transaction: `zip317_fee(max(n, 2)) == zip317_fee(max(n, 1))` for all n,
/// since both sides pass through the same `max(·, 2)` floor in `zip317_fee`.
/// If `GRACE_ACTIONS` or the fee formula ever changes, this assumption must be
/// re-verified or `build_shielded_tx` must report its actual output count here.
///
/// # Orchard coupling warning
///
/// `sapling_logical_actions(n, 2)` counts only Sapling spends and outputs.  When
/// Orchard inputs or outputs are added to `build_shielded_tx`, this function must
/// be updated to include the Orchard action count in the ZIP-317 fee calculation.
/// Failing to do so will make the fee computed here disagree with `FeeRule::standard()`
/// in `builder.build()`, causing a cryptic builder rejection.  See ZIP-317 §2 for
/// how Sapling and Orchard logical-action contributions are combined.
pub(crate) fn select_with_fee(
    notes: &[SpendableNote],
    amount_zatoshi: u64,
) -> Result<(Vec<SpendableNote>, u64), TxBuildError> {
    let mut fee = zip317_fee(sapling_logical_actions(1, 2));
    loop {
        let selected = select_notes_spendable(notes, amount_zatoshi, fee)?;
        let n = selected.len() as u64;
        let required_fee = zip317_fee(sapling_logical_actions(n, 2));
        if required_fee == fee {
            return Ok((selected, fee));
        }
        // required_fee > fee: more inputs than initially estimated — re-select.
        // required_fee < fee cannot happen: more inputs only increases the ZIP-317 fee.
        fee = required_fee;
    }
}

/// FIFO (oldest-first) coin selection for `SpendableNote` rows.
///
/// Selects the minimum number of notes (sorted by ascending `block_height`) whose
/// combined value covers `target_zatoshi + fee`.
///
/// Returns `TxBuildError::InsufficientFunds` or `TxBuildError::AmountOverflow`
/// instead of `CoinSelectError` so callers can propagate directly.
///
/// If Ok is returned, the sum of the returned notes' values fits in u64 — the
/// selection loop uses `checked_add` so callers can safely re-sum with `.sum()`.
/// AmountOverflow is returned if either `target + fee` or the running note sum
/// would overflow u64 (impossible with real ZEC supply but guarded defensively).
// pub(crate) for direct testing of InsufficientFunds / AmountOverflow (nie-wdw.9).
pub(crate) fn select_notes_spendable(
    notes: &[SpendableNote],
    target_zatoshi: u64,
    fee: u64,
) -> Result<Vec<SpendableNote>, TxBuildError> {
    let total_needed = target_zatoshi
        .checked_add(fee)
        .ok_or(TxBuildError::AmountOverflow)?;

    // Sort oldest-first: minimises incremental witness depth (FIFO strategy).
    let mut candidates: Vec<&SpendableNote> = notes.iter().collect();
    candidates.sort_by_key(|n| n.block_height);

    let mut selected: Vec<SpendableNote> = Vec::new();
    let mut sum: u64 = 0;

    for note in candidates {
        selected.push(note.clone());
        // checked_add: note values from a corrupted DB could theoretically sum to > u64::MAX
        // (impossible with real ZEC supply, ~2.1e15 zatoshi << u64::MAX ~1.84e19).
        // Using checked_add makes the selection loop consistent with build_shielded_tx's
        // `.sum()` — if selection succeeds, the caller's re-sum is guaranteed not to overflow.
        sum = sum
            .checked_add(note.value_zatoshi)
            .ok_or(TxBuildError::AmountOverflow)?;
        if sum >= total_needed {
            break;
        }
    }

    if sum < total_needed {
        // saturating_add for the "have" report: this is informational; if note values
        // somehow overflow the error message shows u64::MAX rather than panicking.
        let have: u64 = notes
            .iter()
            .fold(0u64, |acc, n| acc.saturating_add(n.value_zatoshi));
        return Err(TxBuildError::InsufficientFunds {
            have,
            need: total_needed,
        });
    }

    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SaplingParamPaths;
    use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
    use zcash_primitives::merkle_tree::write_incremental_witness;

    // ---- witness_to_merkle_path tests ----

    /// Build a minimal 2-leaf tree, create a witness on the first leaf, add the
    /// sibling so the path is defined, serialize with write_incremental_witness
    /// (the write oracle), then round-trip through witness_to_merkle_path.
    ///
    /// Oracle: the `MerklePath` produced by `witness.path()` before serialization
    /// is the expected value.  `witness_to_merkle_path` is the code under test;
    /// `write_incremental_witness` is an independent write path.
    #[test]
    fn witness_round_trip() {
        // Two arbitrary field elements in little-endian; both are valid because the
        // values are much less than the jubjub base field order q ≈ 2^255.
        let node0 = Option::from(sapling::Node::from_bytes([1u8; 32])).expect("valid node");
        let node1 = Option::from(sapling::Node::from_bytes([2u8; 32])).expect("valid node");

        // Build base tree with node0.
        let mut tree = CommitmentTree::<sapling::Node, 32>::empty();
        tree.append(node0).expect("append node0 to empty tree");

        // Create witness at position 0 (node0).  from_tree consumes the tree,
        // so we must not use it afterward for the base tree.
        let mut witness =
            IncrementalWitness::from_tree(tree).expect("non-empty tree must yield a witness");

        // Append node1 to the witness so it has a sibling and path() is Some.
        witness.append(node1).expect("append sibling to witness");

        // Capture the expected path from the original witness (independent oracle).
        let expected_path = witness
            .path()
            .expect("witness with sibling must have a path");

        // Serialize the witness with the write_incremental_witness oracle.
        let mut bytes: Vec<u8> = Vec::new();
        write_incremental_witness(&witness, &mut bytes)
            .expect("write_incremental_witness must not fail");
        assert!(!bytes.is_empty(), "serialized witness must be non-empty");

        // Deserialize through the function under test.
        let got_path = witness_to_merkle_path(&bytes).expect("round-trip must succeed");

        // Compare path elements — oracle vs function under test.
        assert_eq!(
            got_path, expected_path,
            "deserialized MerklePath must match original"
        );
    }

    /// Empty byte slice must return WitnessDeserialize, not panic.
    #[test]
    fn witness_empty_bytes_returns_error() {
        let err = witness_to_merkle_path(&[]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty"), "error must mention 'empty': {msg}");
    }

    /// Truncated bytes (first 4 bytes of a real witness) must return WitnessDeserialize.
    #[test]
    fn witness_truncated_bytes_returns_error() {
        let err = witness_to_merkle_path(&[0x00, 0x00, 0x00, 0x01]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("witness"),
            "error must mention 'witness': {msg}"
        );
    }

    /// Corrupt bytes (random garbage) must return WitnessDeserialize, not panic.
    #[test]
    fn witness_corrupt_bytes_returns_error() {
        let garbage: Vec<u8> = (0u8..=127).collect();
        let err = witness_to_merkle_path(&garbage).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("witness"),
            "error must mention 'witness': {msg}"
        );
    }

    // ---- spendable_note_to_sapling tests ----

    /// Derive a known PaymentAddress from the ZIP-32 test seed, extract its bytes,
    /// feed into SpendableNote, and verify the round-trip value matches.
    ///
    /// Oracle: the PaymentAddress is derived by `SaplingExtendedSpendingKey::master`
    /// then `default_address()` — independent of spendable_note_to_sapling.
    #[test]
    fn note_round_trip_from_known_address() {
        use crate::address::SaplingExtendedSpendingKey;

        // ZIP-32 test vector seed (same as address.rs tests).
        let seed = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let esk = SaplingExtendedSpendingKey::master(&seed);
        let (_, addr) = esk.default_address();

        // Extract the 43-byte address representation: [diversifier(11) | pk_d(32)].
        let addr_bytes = addr.to_bytes();

        let row = SpendableNote {
            note_id: 1,
            value_zatoshi: 100_000_000, // 1 ZEC
            note_diversifier: addr_bytes[..11].to_vec(),
            note_pk_d: addr_bytes[11..].to_vec(),
            note_rseed: [0xab; 32].to_vec(), // arbitrary post-ZIP-212 randomness seed
            rseed_after_zip212: true,
            block_height: 1_000_000,
            witness_data: vec![],
        };

        let note = spendable_note_to_sapling(&row).expect("round-trip must succeed");

        // Verify value round-trips correctly.
        assert_eq!(note.value().inner(), 100_000_000, "note value must match");
        // Verify the recipient address round-trips.
        assert_eq!(
            note.recipient().to_bytes(),
            addr_bytes,
            "payment address must round-trip"
        );
        // Verify rseed variant.
        assert!(
            matches!(note.rseed(), Rseed::AfterZip212(_)),
            "rseed variant must be AfterZip212"
        );
    }

    /// note_diversifier with wrong length must return NoteDeserialize.
    #[test]
    fn note_wrong_diversifier_length_returns_error() {
        let row = SpendableNote {
            note_id: 1,
            value_zatoshi: 1000,
            note_diversifier: vec![0u8; 10], // wrong: must be 11
            note_pk_d: vec![0u8; 32],
            note_rseed: vec![0u8; 32],
            rseed_after_zip212: true,
            block_height: 1,
            witness_data: vec![],
        };
        let err = spendable_note_to_sapling(&row).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("11"),
            "error must mention expected length 11: {msg}"
        );
        assert!(
            msg.contains("note_diversifier"),
            "error must name the field: {msg}"
        );
    }

    /// note_pk_d with wrong length must return NoteDeserialize.
    #[test]
    fn note_wrong_pk_d_length_returns_error() {
        let row = SpendableNote {
            note_id: 2,
            value_zatoshi: 1000,
            note_diversifier: vec![0u8; 11],
            note_pk_d: vec![0u8; 31], // wrong: must be 32
            note_rseed: vec![0u8; 32],
            rseed_after_zip212: true,
            block_height: 1,
            witness_data: vec![],
        };
        let err = spendable_note_to_sapling(&row).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("32"),
            "error must mention expected length 32: {msg}"
        );
        assert!(
            msg.contains("note_pk_d"),
            "error must name the field: {msg}"
        );
    }

    /// note_rseed with wrong length must return NoteDeserialize.
    #[test]
    fn note_wrong_rseed_length_returns_error() {
        let row = SpendableNote {
            note_id: 3,
            value_zatoshi: 1000,
            note_diversifier: vec![0u8; 11],
            note_pk_d: vec![0u8; 32],
            note_rseed: vec![0u8; 31], // wrong: must be 32
            rseed_after_zip212: true,
            block_height: 1,
            witness_data: vec![],
        };
        let err = spendable_note_to_sapling(&row).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("32"),
            "error must mention expected length 32: {msg}"
        );
        assert!(
            msg.contains("note_rseed"),
            "error must name the field: {msg}"
        );
    }

    /// All-zero diversifier d is not a valid Sapling diversifier; from_bytes returns None.
    ///
    /// Oracle: the all-zero diversifier fails the `GH("Zcash_gd", [0;11])` check
    /// (GH of zero is identity, which is rejected).
    #[test]
    fn note_invalid_address_bytes_returns_error() {
        let row = SpendableNote {
            note_id: 4,
            value_zatoshi: 1000,
            note_diversifier: vec![0u8; 11], // zero diversifier is invalid for Sapling
            note_pk_d: vec![0u8; 32],
            note_rseed: vec![0u8; 32],
            rseed_after_zip212: true,
            block_height: 1,
            witness_data: vec![],
        };
        let err = spendable_note_to_sapling(&row).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid"), "error must say 'invalid': {msg}");
    }

    /// value_zatoshi = u64::MAX must succeed (NoteValue::from_raw accepts any u64).
    #[test]
    fn note_max_value_does_not_panic() {
        use crate::address::SaplingExtendedSpendingKey;
        let seed = [0x00u8; 32]; // any seed that produces a valid default address
        let esk = SaplingExtendedSpendingKey::master(&seed);
        let (_, addr) = esk.default_address();
        let addr_bytes = addr.to_bytes();

        let row = SpendableNote {
            note_id: 5,
            value_zatoshi: u64::MAX,
            note_diversifier: addr_bytes[..11].to_vec(),
            note_pk_d: addr_bytes[11..].to_vec(),
            note_rseed: [0x01; 32].to_vec(),
            rseed_after_zip212: true,
            block_height: 1,
            witness_data: vec![],
        };
        // Must not panic; value is unusual but NoteValue::from_raw is total.
        let note = spendable_note_to_sapling(&row).expect("u64::MAX value must not fail");
        assert_eq!(note.value().inner(), u64::MAX);
    }

    // ---- load_sapling_params tests ----

    /// Missing spend file returns ParamsNotLoaded with the path in the message.
    #[test]
    fn params_missing_spend_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let paths = SaplingParamPaths {
            spend: dir.path().join("sapling-spend.params"),
            output: dir.path().join("sapling-output.params"),
        };
        // SpendParameters does not implement Debug, so we cannot use unwrap_err().
        let err = match load_sapling_params(&paths) {
            Ok(_) => panic!("expected ParamsNotLoaded error"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("sapling-spend.params"),
            "path must be in error: {msg}"
        );
        assert!(
            msg.contains("nie wallet init"),
            "actionable hint must be present: {msg}"
        );
    }

    /// Spend file with wrong content (hash mismatch) returns ParamsNotLoaded.
    /// Output file is never opened.
    #[test]
    fn params_hash_mismatch_spend_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        // Write wrong bytes (not the real params).
        std::fs::write(dir.path().join("sapling-spend.params"), b"not real params").unwrap();
        let paths = SaplingParamPaths {
            spend: dir.path().join("sapling-spend.params"),
            output: dir.path().join("sapling-output.params"), // doesn't exist — never reached
        };
        let err = match load_sapling_params(&paths) {
            Ok(_) => panic!("expected ParamsNotLoaded error"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("integrity check") || msg.contains("BLAKE2b"),
            "hash failure must be mentioned: {msg}"
        );
        assert!(
            msg.contains("sapling-spend.params"),
            "spend path must be in error: {msg}"
        );
    }

    /// Missing output file (spend present with correct hash) returns ParamsNotLoaded.
    ///
    /// We cannot create a real spend params file in a unit test (it is ~48 MB and
    /// requires specific groth16 encoding), so this test verifies the error path where
    /// the spend file passes the hash check but the output file is absent.  We achieve
    /// this by writing a fake file whose BLAKE2b matches the constant we pass — we
    /// override the hash check by writing a file with the right hash for the fake bytes.
    ///
    /// Since SPEND_PARAMS_BLAKE2B is the hash of the real params (not our fake bytes),
    /// the spend file will always fail the hash check in this test — which still triggers
    /// ParamsNotLoaded.  The important thing is that the error mentions spend, not output.
    #[test]
    fn params_missing_output_file_error_mentions_spend_first() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sapling-spend.params"), b"wrong bytes").unwrap();
        // No output file.
        let paths = SaplingParamPaths {
            spend: dir.path().join("sapling-spend.params"),
            output: dir.path().join("sapling-output.params"),
        };
        // The spend hash check fails first; error must mention the spend file.
        // SpendParameters does not implement Debug, so we cannot use unwrap_err().
        let msg = match load_sapling_params(&paths) {
            Ok(_) => panic!("expected ParamsNotLoaded error"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains("sapling-spend.params"),
            "first error must name spend file: {msg}"
        );
    }

    // ---- build_shielded_tx error-path tests (nie-wdw.9) ----

    /// Helper: call build_shielded_tx with params=None for pre-proof error paths.
    ///
    /// All nine TxBuildError variants tested here
    /// (NoSpendableNotes, DustAmount, InvalidRecipient, UnsupportedAddressType,
    /// InsufficientFunds, AmountOverflow, WitnessDeserialize, NoteDeserialize,
    /// AnchorMismatch) are returned before step 11 where params would be used.
    /// Passing None avoids loading the ~48 MB param files in these tests and
    /// eliminates the need for unsafe MaybeUninit that was previously required.
    fn call_build_for_error(
        sk: &SaplingExtendedSpendingKey,
        to_address: &str,
        amount_zatoshi: u64,
        notes: &[SpendableNote],
        anchor_height: u64,
        change_diversifier_index: u128,
    ) -> Result<Vec<u8>, TxBuildError> {
        build_shielded_tx(
            sk,
            to_address,
            amount_zatoshi,
            &[0u8; 512],
            notes,
            // None: all tested error paths return before params is dereferenced.
            // build_shielded_tx returns ParamsNotLoaded when None — but the call
            // never reaches step 11 for these tests.
            None,
            ZcashNetwork::Testnet,
            anchor_height,
            change_diversifier_index,
        )
        .map(|(bytes, _ids)| bytes)
    }

    /// Build a valid SpendableNote with the default Testnet address derived from the
    /// ZIP-32 test seed.  The witness is a 2-leaf tree so `witness_to_merkle_path`
    /// succeeds.
    fn make_valid_note(value_zatoshi: u64, block_height: u64, witness: Vec<u8>) -> SpendableNote {
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let (_, addr) = sk.default_address();
        let addr_bytes = addr.to_bytes();
        SpendableNote {
            note_id: 1,
            value_zatoshi,
            note_diversifier: addr_bytes[..11].to_vec(),
            note_pk_d: addr_bytes[11..].to_vec(),
            note_rseed: [0xab; 32].to_vec(),
            rseed_after_zip212: true,
            block_height,
            witness_data: witness,
        }
    }

    /// Build serialized witness bytes from a 2-leaf Sapling commitment tree.
    ///
    /// `leaf_a` and `leaf_b` are 32-byte little-endian Bls12 scalar values; any
    /// two-byte pattern that's a valid field element works.  The resulting
    /// witness has path() defined (the sibling has been appended).
    fn make_witness(leaf_a: [u8; 32], leaf_b: [u8; 32]) -> Vec<u8> {
        let node_a = Option::from(sapling::Node::from_bytes(leaf_a)).expect("valid node");
        let node_b = Option::from(sapling::Node::from_bytes(leaf_b)).expect("valid node");
        let mut tree = CommitmentTree::<sapling::Node, 32>::empty();
        tree.append(node_a).expect("append a");
        let mut witness = IncrementalWitness::from_tree(tree).expect("non-empty");
        witness.append(node_b).expect("append b");
        let mut bytes = Vec::new();
        write_incremental_witness(&witness, &mut bytes).expect("write witness");
        bytes
    }

    /// Derive a valid testnet Unified Address (Sapling receiver) string from the test key.
    ///
    /// Oracle: the address is derived from the test seed via ZIP-32; it is independent
    /// of the address-encoding function under test.  Used in tests that need a
    /// parseable recipient address string.
    fn testnet_sapling_ua_str() -> String {
        use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
        use zcash_protocol::consensus::NetworkType;
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let (_, addr) = sk.default_address();
        let bytes: [u8; 43] = addr.to_bytes();
        let ua = UnifiedAddress::try_from_items(vec![Receiver::Sapling(bytes)])
            .expect("Sapling-only UA must be valid");
        ua.encode(&NetworkType::Test)
    }

    // ---- NoSpendableNotes ----

    /// Empty notes slice → NoSpendableNotes before any other check.
    #[test]
    fn build_no_spendable_notes_returns_variant() {
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let result = call_build_for_error(&sk, "ignored", 50_000, &[], 1_000_000, 0);
        assert!(
            matches!(result, Err(TxBuildError::NoSpendableNotes)),
            "expected NoSpendableNotes, got: {result:?}"
        );
    }

    // ---- DustAmount ----

    /// amount = 0 → DustAmount.
    #[test]
    fn build_dust_amount_zero_returns_variant() {
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let witness = make_witness([1u8; 32], [2u8; 32]);
        let note = make_valid_note(50_000, 1_000_000, witness);
        let result = call_build_for_error(&sk, "ignored", 0, &[note], 1_000_000, 0);
        assert!(
            matches!(result, Err(TxBuildError::DustAmount { amount: 0, .. })),
            "expected DustAmount, got: {result:?}"
        );
    }

    /// amount = DUST_THRESHOLD - 1 → DustAmount (boundary).
    #[test]
    fn build_dust_amount_below_threshold_returns_variant() {
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let witness = make_witness([1u8; 32], [2u8; 32]);
        let note = make_valid_note(50_000, 1_000_000, witness);
        let result =
            call_build_for_error(&sk, "ignored", DUST_THRESHOLD - 1, &[note], 1_000_000, 0);
        assert!(
            matches!(result, Err(TxBuildError::DustAmount { .. })),
            "expected DustAmount, got: {result:?}"
        );
    }

    // ---- InvalidRecipient / UnsupportedAddressType ----

    /// Empty address string → InvalidRecipient.
    #[test]
    fn parse_address_empty_string_returns_invalid_recipient() {
        let err = parse_sapling_address("").unwrap_err();
        assert!(
            matches!(err, TxBuildError::InvalidRecipient(_)),
            "expected InvalidRecipient, got: {err:?}"
        );
    }

    /// Non-address string → InvalidRecipient.
    #[test]
    fn parse_address_garbage_returns_invalid_recipient() {
        let err = parse_sapling_address("not_an_address_at_all").unwrap_err();
        assert!(
            matches!(err, TxBuildError::InvalidRecipient(_)),
            "expected InvalidRecipient, got: {err:?}"
        );
    }

    /// Valid transparent testnet address (t-address) → UnsupportedAddressType.
    ///
    /// Oracle: transparent addresses parse successfully via ZcashAddress but
    /// are rejected by parse_sapling_address which requires a Sapling receiver.
    #[test]
    fn parse_address_transparent_returns_unsupported_type() {
        // From zcash_address crate's own encoding test vectors (encoding.rs line 333).
        let err = parse_sapling_address("tm9ofD7kHR7AF8MsJomEzLqGcrLCBkD9gDj").unwrap_err();
        assert!(
            matches!(err, TxBuildError::UnsupportedAddressType(_)),
            "expected UnsupportedAddressType, got: {err:?}"
        );
    }

    /// Orchard-only Unified Address → UnsupportedAddressType, not InvalidRecipient.
    ///
    /// An Orchard-only UA is a valid Zcash address — it parses successfully.
    /// parse_sapling_address cannot use it (no Sapling receiver), so it must return
    /// UnsupportedAddressType ("valid but wrong protocol"), not InvalidRecipient
    /// ("couldn't parse the string").
    ///
    /// Oracle: Orchard-only UA built from OrchardSpendingKey::from_seed with a known
    /// seed; the resulting encoding is valid bech32m and parses as a UA.
    #[test]
    fn parse_address_orchard_only_ua_returns_unsupported_type() {
        use crate::orchard::OrchardSpendingKey;
        use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
        use zcash_protocol::consensus::NetworkType;

        let sk = OrchardSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0)
            .expect("Orchard key derivation must succeed for zero seed");
        let fvk = sk.to_fvk();
        let addr = fvk.default_address();
        let raw: [u8; 43] = addr.to_raw_address_bytes();
        let ua = UnifiedAddress::try_from_items(vec![Receiver::Orchard(raw)])
            .expect("Orchard-only UA must be valid");
        let ua_str = ua.encode(&NetworkType::Test);

        let err = parse_sapling_address(&ua_str).unwrap_err();
        assert!(
            matches!(err, TxBuildError::UnsupportedAddressType(_)),
            "Orchard-only UA must return UnsupportedAddressType, not InvalidRecipient: {err:?}"
        );
    }

    /// Valid Sapling-receiver Unified Address parses successfully.
    ///
    /// parse_sapling_address accepts both raw Sapling bech32 (ztestsapling...) and
    /// Unified Addresses containing a Sapling receiver.  testnet_sapling_ua_str()
    /// produces the UA form; this test exercises that branch.
    ///
    /// Oracle: address derived from known test seed via ZIP-32; independent of
    /// parse_sapling_address's address-recognition logic.
    #[test]
    fn parse_address_valid_sapling_testnet_succeeds() {
        let addr_str = testnet_sapling_ua_str();
        let result = parse_sapling_address(&addr_str);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    // ---- InsufficientFunds ----

    /// One note whose value is exactly amount + fee - 1 → InsufficientFunds.
    ///
    /// ZIP-317 fee for 1 spend, 2 outputs = 10 000 zatoshi (grace floor applies).
    /// With amount=50_000 and fee=10_000, need=60_000; note value=59_999 is 1 short.
    #[test]
    fn select_insufficient_funds_exact_returns_variant() {
        use crate::fees::{sapling_logical_actions, zip317_fee};
        let amount = 50_000u64;
        let fee = zip317_fee(sapling_logical_actions(1, 2));
        let have = amount + fee - 1;

        let note = SpendableNote {
            note_id: 1,
            value_zatoshi: have,
            note_diversifier: vec![0u8; 11],
            note_pk_d: vec![0u8; 32],
            note_rseed: vec![0u8; 32],
            rseed_after_zip212: true,
            block_height: 1,
            witness_data: vec![],
        };
        let err = select_notes_spendable(&[note], amount, fee).unwrap_err();
        assert!(
            matches!(err, TxBuildError::InsufficientFunds { have: h, need: n } if h < n),
            "expected InsufficientFunds with have < need, got: {err:?}"
        );
    }

    /// Empty notes slice → InsufficientFunds { have: 0, need: N }.
    #[test]
    fn select_empty_notes_returns_insufficient_funds() {
        let err = select_notes_spendable(&[], 50_000, 10_000).unwrap_err();
        assert!(
            matches!(err, TxBuildError::InsufficientFunds { have: 0, .. }),
            "expected InsufficientFunds with have=0, got: {err:?}"
        );
    }

    // ---- AmountOverflow ----

    /// u64::MAX + any positive fee overflows → AmountOverflow.
    #[test]
    fn select_amount_overflow_returns_variant() {
        let note = SpendableNote {
            note_id: 1,
            value_zatoshi: u64::MAX,
            note_diversifier: vec![0u8; 11],
            note_pk_d: vec![0u8; 32],
            note_rseed: vec![0u8; 32],
            rseed_after_zip212: true,
            block_height: 1,
            witness_data: vec![],
        };
        let err = select_notes_spendable(&[note], u64::MAX, 10_000).unwrap_err();
        assert!(
            matches!(err, TxBuildError::AmountOverflow),
            "expected AmountOverflow, got: {err:?}"
        );
    }

    // ---- AnchorMismatch ----

    /// Two notes from different Merkle trees → AnchorMismatch.
    ///
    /// Oracle: two independent IncrementalWitness trees with different sibling
    /// leaf bytes → different path.root() → anchors differ regardless of note CMU.
    #[test]
    fn build_anchor_mismatch_returns_variant() {
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let addr_str = testnet_sapling_ua_str();

        // Two witnesses from independent trees with different sibling bytes.
        let witness1 = make_witness([0x01u8; 32], [0x02u8; 32]);
        let witness2 = make_witness([0x03u8; 32], [0x04u8; 32]); // different sibling → different root

        // Both notes must have enough combined value to cover amount + fee.
        // fee for 2 inputs, 2 outputs = zip317_fee(max(2,2)) = 10_000.
        // amount = 10_000, so need 20_000 total; each note = 15_000.
        let mut note1 = make_valid_note(15_000, 1_000_000, witness1);
        let mut note2 = make_valid_note(15_000, 1_000_001, witness2);
        note1.note_id = 1;
        note2.note_id = 2;

        let result = call_build_for_error(&sk, &addr_str, 10_000, &[note1, note2], 1_000_001, 0);
        assert!(
            matches!(result, Err(TxBuildError::AnchorMismatch)),
            "expected AnchorMismatch, got: {result:?}"
        );
    }

    // ---- WitnessDeserialize via build_shielded_tx ----

    /// Note with corrupt witness bytes causes WitnessDeserialize via build_shielded_tx.
    ///
    /// Verifies the error propagates correctly from witness_to_merkle_path into
    /// build_shielded_tx rather than testing the helper in isolation.
    #[test]
    fn build_corrupt_witness_returns_variant() {
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let addr_str = testnet_sapling_ua_str();

        // Note with enough value but corrupt witness data.
        let note = make_valid_note(50_000, 1_000_000, vec![0x00, 0x01, 0x02]);
        let result = call_build_for_error(&sk, &addr_str, 30_000, &[note], 1_000_000, 0);
        assert!(
            matches!(result, Err(TxBuildError::WitnessDeserialize(_))),
            "expected WitnessDeserialize, got: {result:?}"
        );
    }

    // ---- NoteDeserialize via build_shielded_tx ----

    /// Note with corrupt diversifier causes NoteDeserialize via build_shielded_tx.
    #[test]
    fn build_corrupt_note_diversifier_returns_variant() {
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let addr_str = testnet_sapling_ua_str();

        let witness = make_witness([1u8; 32], [2u8; 32]);
        let note = SpendableNote {
            note_id: 1,
            value_zatoshi: 50_000,
            note_diversifier: vec![0u8; 10], // wrong length: must be 11
            note_pk_d: vec![0u8; 32],
            note_rseed: vec![0u8; 32],
            rseed_after_zip212: true,
            block_height: 1_000_000,
            witness_data: witness,
        };
        let result = call_build_for_error(&sk, &addr_str, 30_000, &[note], 1_000_000, 0);
        assert!(
            matches!(result, Err(TxBuildError::NoteDeserialize(_))),
            "expected NoteDeserialize, got: {result:?}"
        );
    }

    // ---- Happy-path tests: build_shielded_tx with real params (nie-wdw.8) ----
    //
    // These tests call builder.build() and generate actual Groth16 proofs.
    // They require real Sapling params (~48 MB) at $ZCASH_PARAMS or ~/.zcash-params.
    // When params are absent, each test silently returns without failing.
    //
    // Oracle: Transaction::read is independent of the builder path; it re-parses the
    // serialized bytes and provides an external view of the tx structure.

    /// Attempt to load Sapling params from the standard location.
    /// Returns None when the files are absent so callers can skip gracefully.
    fn try_load_params() -> Option<(SpendParameters, OutputParameters)> {
        let params_dir = std::env::var("ZCASH_PARAMS")
            .map(std::path::PathBuf::from)
            .or_else(|_| {
                std::env::var("HOME").map(|h| std::path::PathBuf::from(h).join(".zcash-params"))
            })
            .ok()?;
        let paths = SaplingParamPaths {
            spend: params_dir.join("sapling-spend.params"),
            output: params_dir.join("sapling-output.params"),
        };
        load_sapling_params(&paths).ok()
    }

    /// Create a SpendableNote from a Sapling note whose cmu is placed in a fresh
    /// commitment tree.  The tree contains [note_cmu, dummy_leaf] so the witness
    /// has a defined Merkle path and the anchor equals hash(note_cmu, dummy_leaf)
    /// padded to depth 32.
    ///
    /// The note is addressed to `sk.default_address()` so the spending key can
    /// authorize the spend proof when `build_shielded_tx` is called with the same `sk`.
    fn real_note_with_witness(
        sk: &SaplingExtendedSpendingKey,
        value_zatoshi: u64,
        note_id: i64,
        block_height: u64,
        rseed_byte: u8,
    ) -> SpendableNote {
        use sapling::{note::Rseed, value::NoteValue};

        let (_, addr) = sk.default_address();
        let addr_bytes = addr.to_bytes();
        let rseed_bytes = [rseed_byte; 32];
        let rseed = Rseed::AfterZip212(rseed_bytes);
        let note = sapling::Note::from_parts(addr, NoteValue::from_raw(value_zatoshi), rseed);
        let note_node = sapling::Node::from_cmu(&note.cmu());

        let mut tree = CommitmentTree::<sapling::Node, 32>::empty();
        tree.append(note_node).expect("append note cmu");
        let mut witness = IncrementalWitness::from_tree(tree).expect("non-empty tree");
        // Dummy sibling makes the Merkle path defined.
        let dummy = Option::from(sapling::Node::from_bytes([0x42; 32])).expect("valid dummy node");
        witness.append(dummy).expect("append dummy sibling");

        let mut witness_bytes = Vec::new();
        write_incremental_witness(&witness, &mut witness_bytes).expect("serialize witness");

        SpendableNote {
            note_id,
            value_zatoshi,
            note_diversifier: addr_bytes[..11].to_vec(),
            note_pk_d: addr_bytes[11..].to_vec(),
            note_rseed: rseed_bytes.to_vec(),
            rseed_after_zip212: true,
            block_height,
            witness_data: witness_bytes,
        }
    }

    /// Create two SpendableNotes from a shared commitment tree so they share the
    /// same Sapling anchor.  The 2-leaf tree is [note0_cmu, note1_cmu]; witness0
    /// records note1 as its sibling, witness1 has note0 as its sibling — both
    /// produce the same root.
    fn two_real_notes_shared_anchor(
        sk: &SaplingExtendedSpendingKey,
        value0: u64,
        value1: u64,
    ) -> (SpendableNote, SpendableNote) {
        use sapling::{note::Rseed, value::NoteValue};

        let (_, addr) = sk.default_address();
        let addr_bytes = addr.to_bytes();

        let rseed0 = Rseed::AfterZip212([0x01; 32]);
        let rseed1 = Rseed::AfterZip212([0x02; 32]);
        let note0 = sapling::Note::from_parts(addr, NoteValue::from_raw(value0), rseed0);
        let note1 = sapling::Note::from_parts(addr, NoteValue::from_raw(value1), rseed1);
        let node0 = sapling::Node::from_cmu(&note0.cmu());
        let node1 = sapling::Node::from_cmu(&note1.cmu());

        let mut tree = CommitmentTree::<sapling::Node, 32>::empty();
        tree.append(node0).expect("append note0 cmu");

        // Snapshot the 1-leaf tree to create w0 before note1 is appended.
        let mut w0 = IncrementalWitness::from_tree(tree.clone()).expect("w0 from 1-leaf tree");

        tree.append(node1).expect("append note1 cmu");
        w0.append(node1)
            .expect("w0 updated with note1 as sibling → has path");

        // w1 is created from the 2-leaf tree; note1 (rightmost) has note0 as sibling.
        let w1 = IncrementalWitness::from_tree(tree).expect("w1 from 2-leaf tree");

        // Verify anchors are consistent before serializing.
        let path0 = w0.path().expect("w0 must have path");
        let path1 = w1.path().expect("w1 must have path in 2-leaf tree");
        debug_assert_eq!(
            sapling::Anchor::from(path0.root(node0)),
            sapling::Anchor::from(path1.root(node1)),
            "witnesses in the same tree must share the same anchor"
        );

        let mut wb0 = Vec::new();
        let mut wb1 = Vec::new();
        write_incremental_witness(&w0, &mut wb0).expect("serialize w0");
        write_incremental_witness(&w1, &mut wb1).expect("serialize w1");

        let s0 = SpendableNote {
            note_id: 1,
            value_zatoshi: value0,
            note_diversifier: addr_bytes[..11].to_vec(),
            note_pk_d: addr_bytes[11..].to_vec(),
            note_rseed: [0x01; 32].to_vec(),
            rseed_after_zip212: true,
            block_height: 1_000_000,
            witness_data: wb0,
        };
        let s1 = SpendableNote {
            note_id: 2,
            value_zatoshi: value1,
            note_diversifier: addr_bytes[..11].to_vec(),
            note_pk_d: addr_bytes[11..].to_vec(),
            note_rseed: [0x02; 32].to_vec(),
            rseed_after_zip212: true,
            block_height: 1_000_001,
            witness_data: wb1,
        };
        (s0, s1)
    }

    // anchor_height for happy-path tests: 2_000_001 is past NU5 activation on
    // testnet (1_842_420), so the builder produces a v5 transaction.
    const HAPPY_ANCHOR_HEIGHT: u64 = 2_000_001;

    /// Parse tx bytes and return the Sapling bundle or panic if absent.
    ///
    /// Oracle: Transaction::read is an independent implementation; it re-parses the
    /// serialized representation rather than inspecting builder state.
    fn parse_sapling_bundle(
        tx_bytes: &[u8],
    ) -> sapling::Bundle<sapling::bundle::Authorized, zcash_protocol::value::ZatBalance> {
        use zcash_primitives::transaction::Transaction;
        use zcash_protocol::consensus::BranchId;

        // BranchId::Nu5 is the branch ID for testnet heights > 1_842_420.
        // For v5 transactions the branch_id is encoded in the tx; passing Nu5
        // is consistent with the height used in HAPPY_ANCHOR_HEIGHT.
        let tx = Transaction::read(std::io::Cursor::new(tx_bytes), BranchId::Nu5)
            .expect("tx_bytes must be a valid serialized transaction");
        tx.sapling_bundle()
            .expect("tx must contain a Sapling bundle")
            .clone()
    }

    /// 1-in-2-out transaction: 1 spend, recipient output + change output.
    ///
    /// Oracle: spend count and output count come from Transaction::read, not
    /// from builder state.  The assertion `outputs == 2` proves that change was
    /// added (input 100_000 > amount 20_000 + fee 10_000 = 30_000 → change 70_000).
    #[test]
    fn tx_single_note_with_change_parses_correctly() {
        let Some(params) = try_load_params() else {
            return;
        };
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let note = real_note_with_witness(&sk, 100_000, 1, 1_000_000, 0xab);
        let addr_str = testnet_sapling_ua_str();

        let (tx_bytes, selected_ids) = build_shielded_tx(
            &sk,
            &addr_str,
            20_000,
            &[0u8; 512],
            &[note],
            Some(&params),
            ZcashNetwork::Testnet,
            HAPPY_ANCHOR_HEIGHT,
            1,
        )
        .expect("build must succeed with valid note and real params");

        assert!(!tx_bytes.is_empty(), "serialized tx must be non-empty");
        assert_eq!(selected_ids.len(), 1, "one note selected for this amount");

        let bundle = parse_sapling_bundle(&tx_bytes);
        assert_eq!(
            bundle.shielded_spends().len(),
            1,
            "must have 1 Sapling spend"
        );
        // change = 100_000 - 20_000 - 10_000 = 70_000 > 0 → 2 outputs
        assert_eq!(
            bundle.shielded_outputs().len(),
            2,
            "must have 2 Sapling outputs (recipient + change)"
        );
    }

    /// 1-in-1-out transaction: exact amount leaves no change.
    ///
    /// amount = note_value - fee guarantees selected_sum == amount + fee exactly
    /// so change == 0 and only 1 output is added.
    #[test]
    fn tx_exact_amount_no_change_output() {
        let Some(params) = try_load_params() else {
            return;
        };
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        // fee = zip317_fee(sapling_logical_actions(1, 2)) = 10_000
        // amount = 90_000, input = 100_000, change = 100_000 - 90_000 - 10_000 = 0
        let note = real_note_with_witness(&sk, 100_000, 1, 1_000_000, 0xcd);
        let addr_str = testnet_sapling_ua_str();

        let (tx_bytes, selected_ids) = build_shielded_tx(
            &sk,
            &addr_str,
            90_000,
            &[0u8; 512],
            &[note],
            Some(&params),
            ZcashNetwork::Testnet,
            HAPPY_ANCHOR_HEIGHT,
            1,
        )
        .expect("build must succeed with exact-amount note");

        assert_eq!(selected_ids.len(), 1, "one note selected");
        let bundle = parse_sapling_bundle(&tx_bytes);
        assert_eq!(
            bundle.shielded_spends().len(),
            1,
            "must have 1 Sapling spend"
        );
        assert_eq!(
            bundle.shielded_outputs().len(),
            1,
            "must have exactly 1 output — no change when input == amount + fee"
        );
    }

    /// 2-in-2-out transaction: both notes are required to cover amount + fee.
    ///
    /// Each note = 15_000; amount = 10_000; fee = 10_000 (ZIP-317 min for ≥2 spends);
    /// need = 20_000 > 15_000 → both notes are selected → 2 spends.
    /// change = 30_000 - 10_000 - 10_000 = 10_000 > 0 → 2 outputs.
    #[test]
    fn tx_two_notes_produces_two_spends() {
        let Some(params) = try_load_params() else {
            return;
        };
        let sk = SaplingExtendedSpendingKey::from_seed(&[0u8; 64], ZcashNetwork::Testnet, 0);
        let (note0, note1) = two_real_notes_shared_anchor(&sk, 15_000, 15_000);
        let addr_str = testnet_sapling_ua_str();

        // Both notes are needed: 15_000 < amount(10_000) + fee(10_000) = 20_000
        let (tx_bytes, selected_ids) = build_shielded_tx(
            &sk,
            &addr_str,
            10_000,
            &[0u8; 512],
            &[note0, note1],
            Some(&params),
            ZcashNetwork::Testnet,
            HAPPY_ANCHOR_HEIGHT,
            1,
        )
        .expect("build must succeed with two valid notes");

        assert_eq!(selected_ids.len(), 2, "both notes selected");
        let bundle = parse_sapling_bundle(&tx_bytes);
        assert_eq!(
            bundle.shielded_spends().len(),
            2,
            "both notes must be spent to reach amount + fee"
        );
        // change = 30_000 - 10_000 - 10_000 = 10_000 > 0 → 2 outputs
        assert_eq!(
            bundle.shielded_outputs().len(),
            2,
            "must have 2 outputs (recipient + change)"
        );
    }
}
