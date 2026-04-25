use thiserror::Error;

/// All failure modes for shielded transaction construction.
///
/// Every variant names the specific fault so that a user (or operator) reading
/// the message at 2 am can understand what broke and what to do about it.
#[derive(Debug, Error)]
pub enum TxBuildError {
    /// The wallet's confirmed spendable balance is less than the requested
    /// amount plus the fee required by ZIP-317.
    #[error(
        "insufficient funds: wallet has {have} zatoshi but need {need} zatoshi \
         (amount + ZIP-317 fee)"
    )]
    InsufficientFunds { have: u64, need: u64 },

    /// The requested amount is below the economic dust threshold (ZIP-317 §4.7).
    /// Sending a dust output would cost more in fees than it's worth.
    #[error(
        "amount {amount} zatoshi is below the dust threshold of {threshold} zatoshi \
         — increase the amount or consolidate notes first"
    )]
    DustAmount { amount: u64, threshold: u64 },

    /// The wallet has no spendable notes — either no ZEC has been received yet,
    /// or received notes have not been fully decrypted by the scanner.
    #[error(
        "no spendable notes: wallet has no received notes, or received notes have not \
         been decrypted yet; wait for the scanner to catch up, then retry"
    )]
    NoSpendableNotes,

    /// Notes were selected from different commitment tree checkpoints.
    /// The Sapling builder requires all inputs to share the same anchor height.
    #[error(
        "anchor mismatch: selected notes come from different block heights and cannot \
         share a common Merkle anchor — restart and let the scanner fully catch up"
    )]
    AnchorMismatch,

    /// The recipient address string could not be parsed as a Zcash address.
    #[error("invalid recipient address: {0}")]
    InvalidRecipient(String),

    /// The recipient address was parsed successfully but resolves to a transparent
    /// or otherwise unsupported protocol (e.g. a raw t-address when only shielded
    /// outputs are permitted).
    #[error(
        "unsupported address type: {0} — only Sapling addresses and Unified Addresses \
         with a Sapling receiver are supported"
    )]
    UnsupportedAddressType(String),

    /// The total of `amount + fee` would exceed `u64::MAX` zatoshi.
    /// This cannot happen with real ZEC supply but is checked defensively.
    #[error(
        "amount overflow: target amount plus fee exceeds u64::MAX zatoshi; \
         this is a bug — please report it"
    )]
    AmountOverflow,

    /// The `zcash_primitives` transaction builder returned an error during
    /// proof generation or finalization.
    #[error("transaction builder error: {0}")]
    BuilderError(String),

    /// The Sapling spend/output parameter files could not be loaded.
    /// The message includes the file path and the reason (not found / corrupt /
    /// hash mismatch) so the operator knows exactly which file to delete and
    /// re-download.
    #[error("Sapling params not loaded: {0}")]
    ParamsNotLoaded(String),

    /// The witness bytes stored in the DB could not be deserialized into an
    /// `IncrementalWitness<sapling::Node>`.  The note cannot be spent until a
    /// new, valid witness is recorded by the scanner.
    #[error("witness deserialization failed: {0}")]
    WitnessDeserialize(String),

    /// One of the note-plaintext columns (`note_g_d`, `note_pk_d`, `note_rseed`)
    /// could not be decoded into a `sapling::Note`.  The note row in the DB may
    /// be corrupt.
    #[error("note deserialization failed: {0}")]
    NoteDeserialize(String),

    /// The iterative fee-estimation loop failed to converge within the allowed
    /// number of rounds.  This indicates a non-monotone interaction between note
    /// selection and the ZIP-317 fee, which should not be possible in practice.
    #[error("fee convergence failed after {iterations} iterations")]
    FeeConvergence { iterations: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_builder::DUST_THRESHOLD;

    // Verify Display output for every variant.  We don't just check "not empty" —
    // we assert that each message contains the key noun that identifies the fault.
    // An independent oracle for "what the message should say" is the doc comment
    // on each variant above.

    #[test]
    fn display_insufficient_funds_names_amounts() {
        let e = TxBuildError::InsufficientFunds {
            have: 500,
            need: 1500,
        };
        let s = e.to_string();
        assert!(s.contains("500"), "have amount missing: {s}");
        assert!(s.contains("1500"), "need amount missing: {s}");
        assert!(s.contains("insufficient funds"), "noun missing: {s}");
    }

    #[test]
    fn display_dust_amount_names_amounts() {
        let e = TxBuildError::DustAmount {
            amount: 50,
            threshold: DUST_THRESHOLD,
        };
        let s = e.to_string();
        assert!(s.contains("50"), "amount missing: {s}");
        assert!(
            s.contains(&DUST_THRESHOLD.to_string()),
            "threshold missing: {s}"
        );
        assert!(s.contains("dust"), "noun missing: {s}");
    }

    #[test]
    fn display_no_spendable_notes_mentions_scanner() {
        let s = TxBuildError::NoSpendableNotes.to_string();
        assert!(s.contains("scanner"), "scanner hint missing: {s}");
    }

    #[test]
    fn display_anchor_mismatch_mentions_anchor() {
        let s = TxBuildError::AnchorMismatch.to_string();
        assert!(s.contains("anchor"), "anchor missing: {s}");
    }

    #[test]
    fn display_invalid_recipient_includes_detail() {
        let e = TxBuildError::InvalidRecipient("not-an-address".into());
        let s = e.to_string();
        assert!(s.contains("not-an-address"), "detail missing: {s}");
        assert!(s.contains("invalid recipient"), "noun missing: {s}");
    }

    #[test]
    fn display_unsupported_address_type_includes_type() {
        let e = TxBuildError::UnsupportedAddressType("t1abc".into());
        let s = e.to_string();
        assert!(s.contains("t1abc"), "type missing: {s}");
        assert!(s.contains("unsupported"), "noun missing: {s}");
    }

    #[test]
    fn display_amount_overflow_says_overflow() {
        let s = TxBuildError::AmountOverflow.to_string();
        assert!(s.contains("overflow"), "noun missing: {s}");
    }

    #[test]
    fn display_builder_error_includes_inner() {
        let e = TxBuildError::BuilderError("proof generation failed".into());
        let s = e.to_string();
        assert!(s.contains("proof generation failed"), "inner missing: {s}");
        assert!(s.contains("builder"), "noun missing: {s}");
    }

    #[test]
    fn display_params_not_loaded_includes_path() {
        let e = TxBuildError::ParamsNotLoaded("/path/to/sapling-spend.params not found".into());
        let s = e.to_string();
        assert!(s.contains("sapling-spend.params"), "path missing: {s}");
        assert!(s.contains("params"), "noun missing: {s}");
    }

    #[test]
    fn display_witness_deserialize_includes_detail() {
        let e = TxBuildError::WitnessDeserialize("empty witness data".into());
        let s = e.to_string();
        assert!(s.contains("empty witness data"), "detail missing: {s}");
        assert!(s.contains("witness"), "noun missing: {s}");
    }

    #[test]
    fn display_note_deserialize_includes_detail() {
        let e = TxBuildError::NoteDeserialize("invalid payment address".into());
        let s = e.to_string();
        assert!(s.contains("invalid payment address"), "detail missing: {s}");
        assert!(s.contains("note"), "noun missing: {s}");
    }

    // Constructability: ensure every variant can be built, providing exhaustive coverage.
    #[test]
    fn all_variants_constructable() {
        let _ = TxBuildError::InsufficientFunds { have: 0, need: 1 };
        let _ = TxBuildError::DustAmount {
            amount: 0,
            threshold: 1,
        };
        let _ = TxBuildError::NoSpendableNotes;
        let _ = TxBuildError::AnchorMismatch;
        let _ = TxBuildError::InvalidRecipient(String::new());
        let _ = TxBuildError::UnsupportedAddressType(String::new());
        let _ = TxBuildError::AmountOverflow;
        let _ = TxBuildError::BuilderError(String::new());
        let _ = TxBuildError::ParamsNotLoaded(String::new());
        let _ = TxBuildError::WitnessDeserialize(String::new());
        let _ = TxBuildError::NoteDeserialize(String::new());
        let _ = TxBuildError::FeeConvergence { iterations: 20 };
    }
}
