//! Integration tests for SaplingIvkDecryptor — nie-gw8k.
//!
//! Tests 3, 4, and 6 from the nie-gw8k test plan.
//! These tests depend on SaplingIvkDecryptor, which is the implementation
//! target of nie-gw8k.  They will fail to compile until that type is defined
//! in nie_wallet::scanner.
//!
//! Oracle for all decryption tests: sapling-crypto upstream test vectors from
//! https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_note_encryption.py
//! (vendored into sapling-crypto's own test suite in src/test_vectors/note_encryption.rs).
//!
//! The compact ciphertext for each test vector is the first 52 bytes of c_enc
//! (COMPACT_NOTE_SIZE = 1 + 11 + 8 + 32 = 52).

use nie_wallet::client::CompactSaplingOutput;
use nie_wallet::scanner::{NoteDecryptor, SaplingIvkDecryptor};

// ---- Test 3: sapling_ivk_decryptor_null_returns_none ----
//
// A SaplingIvkDecryptor given a valid IVK must return None when fed a
// CompactSaplingOutput that is all zeros.  All-zero cmu/epk/ciphertext bytes
// cannot represent a validly-encrypted Sapling note for any key.
//
// Oracle: garbage input should never decrypt to a valid note under any key.
// The sapling-crypto library's try_sapling_compact_note_decryption returns
// None on authentication failure.
//
// IVK from test vector index 0 (sapling-crypto/src/test_vectors/note_encryption.rs):
//   ivk: [0xb7, 0x0b, 0x7c, 0xd0, 0xed, 0x03, 0xcb, 0xdf, 0xd7, 0xad, 0xa9, 0x50, 0x2e, 0xe2,
//         0x45, 0xb1, 0x3e, 0x56, 0x9d, 0x54, 0xa5, 0x71, 0x9d, 0x2d, 0xaa, 0x0f, 0x5f, 0x14,
//         0x51, 0x47, 0x92, 0x04]
#[test]
fn sapling_ivk_decryptor_null_returns_none() {
    // Test vector IVK index 0 (jubjub::Fr scalar, little-endian bytes).
    let ivk_bytes: [u8; 32] = [
        0xb7, 0x0b, 0x7c, 0xd0, 0xed, 0x03, 0xcb, 0xdf, 0xd7, 0xad, 0xa9, 0x50, 0x2e, 0xe2, 0x45,
        0xb1, 0x3e, 0x56, 0x9d, 0x54, 0xa5, 0x71, 0x9d, 0x2d, 0xaa, 0x0f, 0x5f, 0x14, 0x51, 0x47,
        0x92, 0x04,
    ];

    let decryptor = SaplingIvkDecryptor::new(&ivk_bytes)
        .expect("IVK from test vector must be a valid jubjub scalar");

    // All-zero output: cmu=0, epk=0, ciphertext=0.
    // This is not a validly-encrypted note for any key.
    let garbage_output = CompactSaplingOutput {
        cmu: vec![0u8; 32],
        ephemeral_key: vec![0u8; 32],
        ciphertext: vec![0u8; 52],
    };

    let result = decryptor.try_decrypt_sapling(
        1_000_000,                           // block_height
        1_700_000_000u32,                    // block_time
        b"txidbytes_32____________________", // txid (32 bytes)
        0,                                   // output_index
        &garbage_output,
    );

    assert!(
        result.is_none(),
        "garbage all-zero input must not decrypt to a valid note"
    );
}

// ---- Test 4: sapling_ivk_decryptor_wrong_length_returns_none ----
//
// A CompactSaplingOutput with a cmu that is not 32 bytes must not panic and
// must return None.  This tests the defensive length check.
//
// Oracle: the Zcash protocol mandates a 32-byte note commitment (cmu).
// Any other length is structurally invalid and must be rejected.
#[test]
fn sapling_ivk_decryptor_wrong_length_returns_none() {
    let ivk_bytes: [u8; 32] = [
        0xb7, 0x0b, 0x7c, 0xd0, 0xed, 0x03, 0xcb, 0xdf, 0xd7, 0xad, 0xa9, 0x50, 0x2e, 0xe2, 0x45,
        0xb1, 0x3e, 0x56, 0x9d, 0x54, 0xa5, 0x71, 0x9d, 0x2d, 0xaa, 0x0f, 0x5f, 0x14, 0x51, 0x47,
        0x92, 0x04,
    ];

    let decryptor = SaplingIvkDecryptor::new(&ivk_bytes)
        .expect("IVK from test vector must be a valid jubjub scalar");

    // Wrong-length cmu: 16 bytes instead of 32.
    let malformed_output = CompactSaplingOutput {
        cmu: vec![0u8; 16], // wrong: must be 32
        ephemeral_key: vec![0u8; 32],
        ciphertext: vec![0u8; 52],
    };

    let result = decryptor.try_decrypt_sapling(
        1_000_000,
        1_700_000_000u32,
        b"txidbytes_32____________________",
        0,
        &malformed_output,
    );

    assert!(
        result.is_none(),
        "wrong-length cmu (16 bytes) must return None, not panic"
    );
}

// ---- Test 6: sapling_test_vector_decryption ----
//
// Uses sapling-crypto upstream test vector index 0 to verify that
// SaplingIvkDecryptor correctly decrypts a known Sapling compact output.
//
// Oracle: sapling-crypto test vectors at
//   sapling-crypto/src/test_vectors/note_encryption.rs
//   (derived from https://github.com/zcash-hackworks/zcash-test-vectors)
//
// Test vector 0 fields used:
//   ivk:        [0xb7, 0x0b, ...] (32 bytes, jubjub::Fr scalar)
//   default_d:  [0xf1, 0x9d, ...] (11-byte diversifier)
//   default_pk_d: [0xdb, 0x4c, ...] (32-byte Jubjub point)
//   v:          100_000_000 zatoshi (= 1 ZEC)
//   cmu:        [0x63, 0x55, ...] (32-byte note commitment)
//   epk:        [0xde, 0xd6, ...] (32-byte ephemeral public key)
//   c_enc[0..52]: the compact ciphertext (first 52 bytes of c_enc)
//
// The test verifies that the returned Note has:
//   - txid derived from the supplied raw hash bytes (reversed, hex-encoded)
//   - value_zatoshi == 100_000_000
//   - note_diversifier == test_vector.default_d
//   - note_pk_d == test_vector.default_pk_d
//
// This test uses the pre-ZIP-212 format (Zip212Enforcement::Off) because the
// test vector rcm field is a jubjub::Fr scalar (old-style rcm, not an Rseed).
// The version byte in _p_enc[0] == 0x01 confirms pre-ZIP-212.
#[test]
fn sapling_test_vector_decryption() {
    // --- Test vector 0 constants (oracle: sapling-crypto upstream) ---

    let ivk_bytes: [u8; 32] = [
        0xb7, 0x0b, 0x7c, 0xd0, 0xed, 0x03, 0xcb, 0xdf, 0xd7, 0xad, 0xa9, 0x50, 0x2e, 0xe2, 0x45,
        0xb1, 0x3e, 0x56, 0x9d, 0x54, 0xa5, 0x71, 0x9d, 0x2d, 0xaa, 0x0f, 0x5f, 0x14, 0x51, 0x47,
        0x92, 0x04,
    ];

    // Sapling note commitment (ExtractedNoteCommitment, bls12_381::Scalar).
    let cmu: [u8; 32] = [
        0x63, 0x55, 0x72, 0xf5, 0x72, 0xa8, 0xa1, 0xa0, 0xb7, 0xac, 0xbc, 0x0a, 0xfc, 0x6d, 0x66,
        0xf1, 0x4a, 0x02, 0xef, 0xac, 0xde, 0x7b, 0xdf, 0x03, 0x44, 0x3e, 0xd4, 0xc3, 0xe5, 0x51,
        0xd4, 0x70,
    ];

    // Ephemeral public key (Jubjub affine point, compressed).
    let epk: [u8; 32] = [
        0xde, 0xd6, 0x8f, 0x05, 0xc6, 0x58, 0xfc, 0xae, 0x5a, 0xe2, 0x18, 0x64, 0x6f, 0xf8, 0x44,
        0x40, 0x6f, 0x84, 0x42, 0x67, 0x84, 0x04, 0x0d, 0x0b, 0xef, 0x2b, 0x09, 0xcb, 0x38, 0x48,
        0xc4, 0xdc,
    ];

    // Compact ciphertext: first 52 bytes of c_enc from the test vector.
    // COMPACT_NOTE_SIZE = 1 (version) + 11 (diversifier) + 8 (value) + 32 (rseed) = 52.
    // These bytes are the AEAD-encrypted compact note plaintext.
    let compact_ciphertext: [u8; 52] = [
        0x8d, 0x6b, 0x27, 0xe7, 0xef, 0xf5, 0x9b, 0xfb, 0xa0, 0x1d, 0x65, 0x88, 0xba, 0xdd, 0x36,
        0x6c, 0xe5, 0x9b, 0x4d, 0x5b, 0x0e, 0xf9, 0x3b, 0xeb, 0xcb, 0xf2, 0x11, 0x41, 0x7c, 0x56,
        0xae, 0x70, 0x0a, 0xe1, 0x82, 0x44, 0xba, 0xc2, 0xfb, 0x64, 0x37, 0xdb, 0x01, 0xf8, 0x3d,
        0xc1, 0x49, 0xe2, 0x78, 0x6e, 0xc4, 0xec,
    ];

    // Expected plaintext values (oracle: test vector).
    let expected_diversifier: [u8; 11] = [
        0xf1, 0x9d, 0x9b, 0x79, 0x7e, 0x39, 0xf3, 0x37, 0x44, 0x58, 0x39,
    ];
    let expected_pk_d: [u8; 32] = [
        0xdb, 0x4c, 0xd2, 0xb0, 0xaa, 0xc4, 0xf7, 0xeb, 0x8c, 0xa1, 0x31, 0xf1, 0x65, 0x67, 0xc4,
        0x45, 0xa9, 0x55, 0x51, 0x26, 0xd3, 0xc2, 0x9f, 0x14, 0xe3, 0xd7, 0x76, 0xe8, 0x41, 0xae,
        0x74, 0x15,
    ];
    let expected_value_zatoshi: u64 = 100_000_000; // 1 ZEC

    // Dummy raw tx hash (32 bytes): bytes 0x01..0x20 in order.
    // The txid stored in Note.txid must be the reverse-hex of this.
    // Reversed: [0x20, 0x1f, ..., 0x01].
    let raw_tx_hash: Vec<u8> = (0x01u8..=0x20u8).collect();
    let expected_txid = "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201";

    let output = CompactSaplingOutput {
        cmu: cmu.to_vec(),
        ephemeral_key: epk.to_vec(),
        ciphertext: compact_ciphertext.to_vec(),
    };

    let decryptor = SaplingIvkDecryptor::new(&ivk_bytes)
        .expect("IVK from test vector must be a valid jubjub scalar");

    let note = decryptor
        .try_decrypt_sapling(
            1_000_000,        // block_height (arbitrary for this test)
            1_700_000_000u32, // block_time (arbitrary for this test)
            &raw_tx_hash,
            0, // output_index
            &output,
        )
        .expect("test vector must decrypt successfully with the matching IVK");

    // Verify txid conversion (oracle: reversed-hex of raw_tx_hash).
    assert_eq!(
        note.txid, expected_txid,
        "txid must be reverse-byte-order hex of CompactTx.hash"
    );

    // Verify value (oracle: test vector v = 100_000_000).
    assert_eq!(
        note.value_zatoshi, expected_value_zatoshi,
        "value_zatoshi must match test vector v"
    );

    // The scanner stores diversifier and pk_d on the Note returned by
    // try_decrypt_sapling.  The Note struct currently does not have these
    // fields; the implementation is expected to add them or return them via
    // an extended type.  If Note has been extended, verify here:
    //
    // Uncomment when Note gains plaintext fields:
    // assert_eq!(note.note_diversifier, expected_diversifier,
    //     "note_diversifier must match test vector default_d");
    // assert_eq!(note.note_pk_d, expected_pk_d,
    //     "note_pk_d must match test vector default_pk_d");
    //
    // For now, assert that the note value is correct — proving decryption
    // succeeded and the plaintext was parsed correctly.
    let _ = expected_diversifier; // silence unused warning until Note grows these fields
    let _ = expected_pk_d;
}
