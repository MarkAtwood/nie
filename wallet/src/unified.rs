//! ZIP-316 Unified Address assembly and encoding (nie-adl).
//!
//! Combines Sapling and Orchard payment address bytes into a ZIP-316 Unified
//! Address string, and parses UA strings back to receivers.
//!
//! # Format
//!
//! A Unified Address is bech32m-encoded with the F4Jumble transform applied.
//! HRP is `"u"` on mainnet and `"utest"` on testnet.  The wire encoding packs
//! receivers in ascending typecode order (P2PKH=0, P2SH=1, Sapling=2, Orchard=3).
//!
//! # Safety invariant
//!
//! This module accepts and returns **raw address bytes** (43 bytes each for
//! Sapling and Orchard), not keys.  Key material never enters this module.

use anyhow::Result;
use zcash_address::unified::{Address as UnifiedAddress, Container, Encoding, Receiver};
use zcash_protocol::consensus::NetworkType;

use crate::address::{SaplingDiversifiableFvk, ZcashNetwork};
use crate::orchard::OrchardFullViewingKey;

impl ZcashNetwork {
    /// Map to the `zcash_address::Network` enum.
    pub(crate) fn to_zcash_network(self) -> NetworkType {
        match self {
            ZcashNetwork::Mainnet => NetworkType::Main,
            ZcashNetwork::Testnet => NetworkType::Test,
        }
    }
}

/// Encode a Unified Address from Sapling (43 bytes) and Orchard (43 bytes) receivers.
///
/// Both receivers are required.  Returns `Err` if the encoding fails (e.g. if
/// both receivers are identical, which would indicate a bug in key derivation).
///
/// The returned string uses HRP `"u"` (mainnet) or `"utest"` (testnet).
pub fn encode_unified_address(
    sapling_raw: &[u8; 43],
    orchard_raw: &[u8; 43],
    network: ZcashNetwork,
) -> Result<String> {
    let receivers = vec![
        Receiver::Sapling(*sapling_raw),
        Receiver::Orchard(*orchard_raw),
    ];
    let ua = UnifiedAddress::try_from_items(receivers)
        .map_err(|e| anyhow::anyhow!("failed to build UnifiedAddress: {e:?}"))?;
    Ok(ua.encode(&network.to_zcash_network()))
}

/// Decode a Unified Address string into its receivers.
///
/// Returns `Err` for malformed input or if the string is not a Unified Address.
/// The `Network` return value identifies the network the address was encoded for.
pub fn decode_unified_address(s: &str) -> Result<(NetworkType, UnifiedAddress)> {
    UnifiedAddress::decode(s).map_err(|e| anyhow::anyhow!("failed to decode UA: {e:?}"))
}

/// Extract the Sapling receiver bytes (43 bytes) from a Unified Address, if present.
pub fn sapling_receiver(ua: &UnifiedAddress) -> Option<[u8; 43]> {
    ua.items().into_iter().find_map(|r| match r {
        Receiver::Sapling(b) => Some(b),
        _ => None,
    })
}

/// Extract the Orchard receiver bytes (43 bytes) from a Unified Address, if present.
pub fn orchard_receiver(ua: &UnifiedAddress) -> Option<[u8; 43]> {
    ua.items().into_iter().find_map(|r| match r {
        Receiver::Orchard(b) => Some(b),
        _ => None,
    })
}

/// Generate a diversified Unified Address starting at `start_index`.
///
/// Searches forward from `start_index` for a valid Sapling diversifier (not all 11-byte
/// combinations are valid Sapling receivers), bounded to 256 attempts per ZIP-32.
/// The same found diversifier index is used for both the Sapling and Orchard receivers.
///
/// Returns `Ok((found_index, ua_string))` where `found_index` is the actual diversifier
/// index used as a `u128` (which may be ≥ `start_index` after skipping invalid Sapling
/// diversifiers).  Callers that need monotonically distinct addresses must start their
/// next call from `found_index + 1` to avoid reusing the same found index.
///
/// Returns `Err` if no valid Sapling diversifier is found within the bound (extremely
/// unlikely in practice; indicates adversarially constructed keys or out-of-range input).
pub fn diversified_address(
    sapling: &SaplingDiversifiableFvk,
    orchard: &OrchardFullViewingKey,
    start_index: u128,
    network: ZcashNetwork,
) -> Result<(u128, String)> {
    let (di, sapling_addr) = sapling.find_address(start_index)?;
    let orchard_addr = orchard.address_at_index(di);
    let sapling_bytes = sapling_addr.to_bytes();
    let orchard_bytes = orchard_addr.to_raw_address_bytes();
    let ua = encode_unified_address(&sapling_bytes, &orchard_bytes, network)?;
    Ok((u128::from(di), ua))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ZIP-316 test vector 7 (Sapling + Orchard only, account 2, diversifier 0).
    ///
    /// Source: zcash-hackworks/zcash-test-vectors unified_address.py, vector index 7.
    /// Oracle: the Python test-vector generator is independent of zcash_address and
    /// serves as the external reference for encode/decode correctness.
    ///
    /// root_seed = [0x00..0x1f], account = 2, diversifier_index = 0.
    const TV7_SAPLING: [u8; 43] = [
        0x88, 0x53, 0x3c, 0x39, 0x8a, 0x49, 0xc2, 0x51, 0x3d, 0xc8, 0x51, 0x62, 0xbf, 0x22, 0x0a,
        0xba, 0xf4, 0x7d, 0xc9, 0x83, 0xf1, 0x4e, 0x90, 0x8d, 0xda, 0xaa, 0x73, 0x22, 0xdb, 0xa1,
        0x65, 0x31, 0xbc, 0x62, 0xef, 0xe7, 0x50, 0xfe, 0x57, 0x5c, 0x8d, 0x14, 0x9b,
    ];
    const TV7_ORCHARD: [u8; 43] = [
        0x95, 0x3f, 0x3c, 0x78, 0xd1, 0x03, 0xc3, 0x2b, 0x60, 0x55, 0x92, 0x99, 0x46, 0x2e, 0xbb,
        0x27, 0x34, 0x89, 0x64, 0xb8, 0x92, 0xac, 0xad, 0x10, 0x48, 0x2f, 0xe5, 0x02, 0xc9, 0x9f,
        0x0d, 0x52, 0x49, 0x59, 0xba, 0x7b, 0xe4, 0xf1, 0x88, 0xe3, 0xa2, 0x71, 0x38,
    ];
    const TV7_UA: &str = "u1ay3aawlldjrmxqnjf5medr5ma6p3acnet464ht8lmwplq5cd3ugytcmlf96rrmtgwldc75x94qn4n8pgen36y8tywlq6yjk7lkf3fa8wzjrav8z2xpxqnrnmjxh8tmz6jhfh425t7f3vy6p4pd3zmqayq49efl2c4xydc0gszg660q9p";

    /// Encoding known Sapling + Orchard receivers produces the expected UA string.
    ///
    /// Oracle: TV7_UA is from the zcash-hackworks test-vector generator.
    #[test]
    fn encode_known_receivers_matches_test_vector() {
        let ua = encode_unified_address(&TV7_SAPLING, &TV7_ORCHARD, ZcashNetwork::Mainnet)
            .expect("encode must succeed for valid receivers");
        assert_eq!(ua, TV7_UA, "encoded UA must match ZIP-316 test vector 7");
    }

    /// Round-trip: encode → decode → re-encode is stable.
    ///
    /// Oracle: the encoded string is the reference; if the round-trip produces
    /// a different string the encoding is non-deterministic (a bug).
    #[test]
    fn roundtrip_encode_decode_encode_is_stable() {
        let first_encoded =
            encode_unified_address(&TV7_SAPLING, &TV7_ORCHARD, ZcashNetwork::Mainnet)
                .expect("first encode must succeed");
        let (net, decoded) = decode_unified_address(&first_encoded).expect("decode must succeed");
        let second_encoded = decoded.encode(&net);
        assert_eq!(
            first_encoded, second_encoded,
            "re-encoding a decoded UA must produce the same string"
        );
    }

    /// Decoding the test-vector string yields the expected receivers.
    ///
    /// Oracle: receiver bytes are the same as TV7_SAPLING and TV7_ORCHARD from
    /// the test-vector generator.
    #[test]
    fn decode_test_vector_yields_correct_receivers() {
        let (net, ua) = decode_unified_address(TV7_UA).expect("decode must succeed for valid UA");
        assert_eq!(net, NetworkType::Main, "test vector 7 is on mainnet");
        let sapling = sapling_receiver(&ua).expect("sapling receiver must be present");
        let orchard = orchard_receiver(&ua).expect("orchard receiver must be present");
        assert_eq!(
            sapling, TV7_SAPLING,
            "sapling receiver must match test vector"
        );
        assert_eq!(
            orchard, TV7_ORCHARD,
            "orchard receiver must match test vector"
        );
    }

    /// Building a UA with zero receivers returns Err, not panic.
    ///
    /// Oracle: a UA with no receivers is invalid by ZIP-316 definition; the
    /// library must reject it rather than producing garbage output.
    #[test]
    fn empty_receivers_returns_err() {
        let result = UnifiedAddress::try_from_items(vec![]);
        assert!(result.is_err(), "empty receiver list must return Err");
    }

    /// Decoding a malformed string returns Err.
    ///
    /// Oracle: any non-bech32m, non-UA string must be rejected with an error.
    #[test]
    fn decode_invalid_string_returns_err() {
        let result = decode_unified_address("not_a_valid_ua_string");
        assert!(result.is_err(), "invalid UA string must return Err");
    }

    // ---- diversified_address tests ----

    use crate::address::SaplingExtendedSpendingKey;
    use crate::orchard::OrchardSpendingKey;

    /// Helper: derive Sapling DFVK and Orchard FVK from a shared seed (account 0, mainnet).
    fn test_fvks(
        seed: &[u8; 64],
    ) -> (
        crate::address::SaplingDiversifiableFvk,
        crate::orchard::OrchardFullViewingKey,
    ) {
        let sapling_sk = SaplingExtendedSpendingKey::from_seed(seed, ZcashNetwork::Mainnet, 0);
        let orchard_sk = OrchardSpendingKey::from_seed(seed, ZcashNetwork::Mainnet, 0).unwrap();
        (sapling_sk.to_dfvk(), orchard_sk.to_fvk())
    }

    /// 1000 consecutive distinct addresses via chained diversifier calls.
    ///
    /// Each call uses the found_di + 1 as the next start_index, so consecutive
    /// calls never collide even when Sapling skips invalid diversifiers (~50% are
    /// invalid, so raw index iteration 0..999 does not produce 1000 distinct results).
    ///
    /// Oracle: ZIP-32 guarantees that distinct found diversifier indices produce
    /// distinct payment addresses; any collision would indicate a derivation bug.
    #[test]
    fn diversified_address_1000_chained_are_distinct() {
        let seed = [0u8; 64];
        let (sapling, orchard) = test_fvks(&seed);

        let mut addrs = Vec::with_capacity(1000);
        let mut next_start: u128 = 0;
        for _ in 0..1000 {
            let (found_di, ua) =
                diversified_address(&sapling, &orchard, next_start, ZcashNetwork::Mainnet)
                    .expect("diversified_address must succeed for valid indices");
            addrs.push(ua);
            next_start = found_di + 1;
        }

        let mut sorted = addrs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            addrs.len(),
            "all 1000 chained diversified addresses must be distinct"
        );
    }

    /// diversified_address(0) produces the same UA as manually assembling receivers
    /// from the found DI.
    ///
    /// Oracle: both paths use the same found DI; if they disagree the bounded-search
    /// or assembly logic is wrong.
    #[test]
    fn diversified_address_index_zero_matches_manual_assembly() {
        let seed = [0u8; 64];
        let (sapling, orchard) = test_fvks(&seed);

        let (found_di, via_diversified) =
            diversified_address(&sapling, &orchard, 0, ZcashNetwork::Mainnet)
                .expect("diversified_address(0) must succeed");

        // Manually assemble from the same found_di so both paths are comparable.
        // find_address returns the DiversifierIndex we need for orchard.address_at_index.
        let (di, sapling_addr) = sapling
            .find_address(found_di)
            .expect("find_address(found_di) must succeed");
        let orchard_addr = orchard.address_at_index(di);
        let via_manual = encode_unified_address(
            &sapling_addr.to_bytes(),
            &orchard_addr.to_raw_address_bytes(),
            ZcashNetwork::Mainnet,
        )
        .expect("manual encode must succeed");

        assert_eq!(
            via_diversified, via_manual,
            "diversified_address must match manually assembled UA using the same found DI"
        );
    }

    /// diversified_address uses the Sapling-found DI for the Orchard receiver, not start_index.
    ///
    /// This test finds a start where Sapling skips at least one invalid diversifier
    /// (`found_di > start`), then decodes the resulting UA and confirms the Orchard receiver
    /// bytes match `orchard.address_at_index(found_di)`.
    ///
    /// Oracle: `orchard.address_at_index(found_di_index)` is an independent call
    /// into the Orchard key schedule.  If `diversified_address` incorrectly used `start`
    /// for Orchard instead of `found_di`, the extracted receiver bytes would differ from
    /// `expected_bytes` and the assertion would fail.
    #[test]
    fn diversified_address_orchard_uses_found_di_not_start() {
        let seed = [0u8; 64];
        let (sapling, orchard) = test_fvks(&seed);

        // Find the first start where Sapling skips (found_di > start).
        // Store the UA from the same call to avoid a redundant re-derivation.
        let mut skipping_start = None;
        for i in 0u128..10_000 {
            let (found, ua) =
                diversified_address(&sapling, &orchard, i, ZcashNetwork::Mainnet).unwrap();
            if found > i {
                skipping_start = Some((i, found, ua));
                break;
            }
        }
        let (start, found_di, ua_str) =
            skipping_start.expect("must find a skipping start_index within 10 000 attempts");
        assert!(
            found_di > start,
            "test setup: Sapling must skip at least one diversifier"
        );

        // Get the Orchard receiver bytes from the UA produced by diversified_address.
        let (_, decoded_ua) = decode_unified_address(&ua_str).unwrap();
        let orchard_bytes =
            orchard_receiver(&decoded_ua).expect("Orchard receiver must be present in UA");

        // Oracle: call find_address(found_di) to recover the DiversifierIndex, then
        // derive the expected Orchard bytes independently.
        let (found_di_index, _) = sapling
            .find_address(found_di)
            .expect("find_address(found_di) must succeed");
        let expected_bytes = orchard
            .address_at_index(found_di_index)
            .to_raw_address_bytes();

        assert_eq!(
            orchard_bytes, expected_bytes,
            "Orchard receiver must use the Sapling-found DI ({found_di}), not start ({start})"
        );
    }

    /// diversified_address returns Err (not panic) when the start_index is out of the
    /// 88-bit Sapling diversifier index space.
    ///
    /// Oracle: u128::MAX cannot fit in a DiversifierIndex (88-bit space); find_address
    /// must return Err rather than panic.
    #[test]
    fn diversified_address_exhausted_search_returns_err() {
        let seed = [0u8; 64];
        let (sapling, orchard) = test_fvks(&seed);

        let result = diversified_address(&sapling, &orchard, u128::MAX, ZcashNetwork::Mainnet);
        assert!(
            result.is_err(),
            "diversified_address with out-of-range start_index must return Err"
        );
    }
}
