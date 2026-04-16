//! Tests for nie-7766: incremental Sapling commitment tree and witness tracking.
//!
//! All test oracles are external:
//! - Tree depth 32: zcash-hackworks specification.
//! - cmu test vector 0: sapling-crypto src/test_vectors/note_encryption.rs
//!   (derived from https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_note_encryption.py).
//! - IncrementalWitness contract: incrementalmerkletree crate documentation.
//! - Serialization roundtrip: zcash_primitives::merkle_tree read/write functions.
//! - field invalidity: bls12_381::Scalar modulus < 0xFF..FF (all-ones is not a valid element).

use std::io::Cursor;

use sapling::{CommitmentTree, IncrementalWitness, Node, NOTE_COMMITMENT_TREE_DEPTH};
use zcash_primitives::merkle_tree::{read_incremental_witness, write_incremental_witness};

// cmu from sapling-crypto test vector 0 (note_encryption.py, via sapling-crypto
// src/test_vectors/note_encryption.rs, first TestVector entry, `cmu` field).
// Oracle: zcash-hackworks/zcash-test-vectors sapling_note_encryption.py, vector 0.
const TV0_CMU: [u8; 32] = [
    0x63, 0x55, 0x72, 0xf5, 0x72, 0xa8, 0xa1, 0xa0, 0xb7, 0xac, 0xbc, 0x0a, 0xfc, 0x6d, 0x66, 0xf1,
    0x4a, 0x02, 0xef, 0xac, 0xde, 0x7b, 0xdf, 0x03, 0x44, 0x3e, 0xd4, 0xc3, 0xe5, 0x51, 0xd4, 0x70,
];

// cmu from sapling-crypto test vector 1 (second TestVector entry, `cmu` field).
// Oracle: zcash-hackworks/zcash-test-vectors sapling_note_encryption.py, vector 1.
const TV1_CMU: [u8; 32] = [
    0x0c, 0x87, 0x41, 0x75, 0x77, 0x48, 0x0b, 0x69, 0x77, 0xba, 0x92, 0xc5, 0x54, 0x25, 0xd6, 0x2b,
    0x03, 0xb1, 0xe5, 0xf3, 0xc3, 0x82, 0x9c, 0xac, 0x49, 0xbf, 0xe5, 0x15, 0xae, 0x72, 0x29, 0x45,
];

/// Oracle: zcash-hackworks specification — Sapling note commitment tree depth is 32.
#[test]
fn sapling_tree_depth_is_32() {
    assert_eq!(NOTE_COMMITMENT_TREE_DEPTH, 32u8);
}

/// Oracle: IncrementalWitness::from_tree() returns Some for a non-empty tree.
///
/// Appending one commitment to an empty tree and creating a witness from that
/// tree must produce a valid witness (from_tree returns Some).  path() must
/// return Some because the tree is non-empty and the witness is positioned at
/// the first (and only) leaf.
#[test]
fn witness_created_from_single_node() {
    let node_a = Node::from_bytes(TV0_CMU)
        .into_option()
        .expect("TV0_CMU is a valid jubjub base field element");

    let mut tree = CommitmentTree::empty();
    tree.append(node_a).expect("tree is not full");

    let witness =
        IncrementalWitness::from_tree(tree).expect("tree is non-empty; from_tree must return Some");

    assert!(
        witness.path().is_some(),
        "non-empty tree must produce a valid auth path"
    );
}

/// Oracle: IncrementalWitness::root() must equal CommitmentTree::root() after each append.
///
/// Procedure:
/// 1. Append node_A to an empty tree → tree has 1 leaf at position 0.
/// 2. Create witness_for_A = IncrementalWitness::from_tree(tree.clone()).
/// 3. Append node_B to tree AND to witness_for_A.
/// 4. Assert witness_for_A.path().is_some() — witness remains valid after tree grows.
/// 5. Assert witness root equals tree root — roots must agree after both appends.
#[test]
fn witness_updates_with_new_commitments() {
    let node_a = Node::from_bytes(TV0_CMU)
        .into_option()
        .expect("TV0_CMU is a valid jubjub base field element");
    let node_b = Node::from_bytes(TV1_CMU)
        .into_option()
        .expect("TV1_CMU is a valid jubjub base field element");

    let mut tree = CommitmentTree::empty();
    tree.append(node_a).expect("tree is not full");

    let mut witness_for_a = IncrementalWitness::from_tree(tree.clone())
        .expect("tree has one leaf; from_tree must return Some");

    tree.append(node_b.clone()).expect("tree is not full");
    witness_for_a
        .append(node_b)
        .expect("witness append must succeed while tree is not full");

    assert!(
        witness_for_a.path().is_some(),
        "witness must remain valid after appending a second commitment"
    );

    assert_eq!(
        witness_for_a.root(),
        tree.root(),
        "witness root must equal tree root after both nodes appended"
    );
}

/// Oracle: serialization roundtrip — write then read must yield the same logical state.
///
/// Procedure:
/// 1. Build the same two-node witness as in witness_updates_with_new_commitments.
/// 2. Serialize with write_incremental_witness.
/// 3. Deserialize with read_incremental_witness.
/// 4. Assert deserialized witness root == original witness root.
#[test]
fn witness_serialize_roundtrip() {
    let node_a = Node::from_bytes(TV0_CMU)
        .into_option()
        .expect("TV0_CMU is a valid jubjub base field element");
    let node_b = Node::from_bytes(TV1_CMU)
        .into_option()
        .expect("TV1_CMU is a valid jubjub base field element");

    let mut tree = CommitmentTree::empty();
    tree.append(node_a).expect("tree is not full");
    let mut witness =
        IncrementalWitness::from_tree(tree).expect("tree has one leaf; from_tree must return Some");
    witness.append(node_b).expect("witness append must succeed");

    let expected_root = witness.root();

    let mut bytes: Vec<u8> = Vec::new();
    write_incremental_witness::<Node, _, 32>(&witness, &mut bytes)
        .expect("witness serialization must not fail");

    let deserialized = read_incremental_witness::<Node, _, 32>(Cursor::new(&bytes))
        .expect("witness deserialization must not fail");

    assert_eq!(
        deserialized.root(),
        expected_root,
        "deserialized witness root must match original witness root"
    );
}

/// Oracle: bls12_381::Scalar field modulus is 0x73eda753…; all-ones (0xFF…FF) exceeds it.
///
/// Node::from_bytes interprets the 32 bytes as a little-endian bls12_381::Scalar.
/// 0xFF…FF > field modulus, so from_bytes must return a CtOption with is_none() == true.
#[test]
fn node_from_invalid_bytes_returns_none() {
    let invalid = [0xFF_u8; 32];
    assert!(
        Node::from_bytes(invalid).into_option().is_none(),
        "0xFF..FF exceeds the jubjub base field modulus and must not parse as a valid Node"
    );
}

// Test 6 (tree_state_migration) is in witness_tracking_db.rs.
// It is separated because save_tree_state / load_tree_state are not yet implemented
// on WalletStore (nie-7766); placing it here would prevent tests 1-5 from compiling.
