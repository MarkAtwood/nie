//! ZIP-302 shielded memo encoding for nie payment sessions.
//!
//! The 512-byte Sapling/Orchard memo field is populated with the payment
//! session UUID so the payee can match an incoming transaction to the session
//! that requested it, even if app state is lost.
//!
//! # Format (ZIP-302 §3.2.1 — UTF-8 text memo)
//!
//! ```text
//! bytes[0..36]   — UUID in hyphenated lowercase ASCII
//!                  e.g. "550e8400-e29b-41d4-a716-446655440000"
//! bytes[36..512] — 0x00 padding
//! ```
//!
//! The first byte is always an ASCII hex digit (`0x30`–`0x39` for `'0'`–`'9'`
//! or `0x61`–`0x66` for `'a'`–`'f'`), well below the `0xF4` threshold that
//! ZIP-302 uses to distinguish a UTF-8 text memo from a raw-byte memo.

use uuid::Uuid;

/// Encode a payment session UUID into a 512-byte ZIP-302 text memo.
///
/// The UUID is written as its 36-byte hyphenated ASCII string at the start of
/// the buffer; the remainder is zero-padded.  The function is infallible.
pub fn session_id_to_memo(session_id: Uuid) -> [u8; 512] {
    let mut memo = [0u8; 512];
    let s = session_id.hyphenated().to_string();
    // Uuid::hyphenated() is always exactly 36 bytes of ASCII — no truncation possible.
    debug_assert_eq!(s.len(), 36, "UUID hyphenated string must be 36 bytes");
    memo[..36].copy_from_slice(s.as_bytes());
    // ZIP-302: first byte must be ≤ 0xF4 for a UTF-8 text memo.
    // All ASCII hex digits (0x30-0x39, 0x61-0x66) are well below 0xF4.
    debug_assert!(
        memo[0] <= 0xF4,
        "ZIP-302 text memo first byte must be ≤ 0xF4"
    );
    memo
}

/// Decode a session UUID from a 512-byte ZIP-302 memo, if present.
///
/// Returns `None` if the first 36 bytes do not parse as a hyphenated UUID.
/// Never panics on any 512-byte input.
pub fn memo_to_session_id(memo: &[u8; 512]) -> Option<Uuid> {
    let candidate = memo.get(..36)?;
    let s = std::str::from_utf8(candidate).ok()?;
    Uuid::parse_str(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    const KNOWN_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

    /// Roundtrip: encode then decode returns the original UUID.
    ///
    /// Oracle: Uuid::parse_str is the authoritative parser; if the encoded
    /// bytes are valid hyphenated UUID ASCII, it must recover the original value.
    #[test]
    fn roundtrip_returns_original_uuid() {
        let id = Uuid::parse_str(KNOWN_UUID).unwrap();
        let memo = session_id_to_memo(id);
        let recovered = memo_to_session_id(&memo).expect("roundtrip must succeed");
        assert_eq!(recovered, id, "decoded UUID must match original");
    }

    /// bytes[0..36] must match the hyphenated ASCII representation.
    ///
    /// Oracle: the UUID spec defines the hyphenated form; Uuid::hyphenated()
    /// produces it; the bytes match the ASCII for the known test vector.
    #[test]
    fn bytes_0_to_36_are_uuid_string() {
        let id = Uuid::parse_str(KNOWN_UUID).unwrap();
        let memo = session_id_to_memo(id);
        assert_eq!(&memo[..36], KNOWN_UUID.as_bytes());
    }

    /// bytes[36..512] must all be 0x00 (ZIP-302 zero-padding).
    #[test]
    fn bytes_36_to_512_are_zero() {
        let id = Uuid::new_v4();
        let memo = session_id_to_memo(id);
        assert!(
            memo[36..].iter().all(|&b| b == 0),
            "padding bytes must be 0x00"
        );
    }

    /// First byte of the memo must be ≤ 0xF4 (ZIP-302 UTF-8 text marker).
    ///
    /// Oracle: ZIP-302 §3.2.1 — a memo with first byte ≤ 0xF4 is a UTF-8 text memo.
    /// UUID hyphenated strings always start with a hex digit (0-9, a-f) whose
    /// ASCII value is well below 0xF4.
    #[test]
    fn first_byte_satisfies_zip302_text_marker() {
        // Test several UUIDs to cover different leading hex digits.
        for seed in 0u8..=15 {
            let bytes = [seed << 4 | seed; 16];
            let id = Uuid::from_bytes(bytes);
            let memo = session_id_to_memo(id);
            assert!(
                memo[0] <= 0xF4,
                "first byte 0x{:02x} must be ≤ 0xF4 (seed {seed})",
                memo[0]
            );
        }
    }

    /// All-zero memo is not a valid UUID — must return None.
    #[test]
    fn all_zero_memo_returns_none() {
        assert!(memo_to_session_id(&[0u8; 512]).is_none());
    }

    /// The ZIP-302 empty-memo sentinel (first byte 0xF6) must return None.
    #[test]
    fn empty_memo_sentinel_returns_none() {
        let mut memo = [0u8; 512];
        memo[0] = 0xF6;
        assert!(memo_to_session_id(&memo).is_none());
    }

    /// memo_to_session_id must never panic on arbitrary inputs.
    ///
    /// Oracle: the function must be total over all [u8; 512] inputs.
    /// 1000 pseudo-random inputs are enough to exercise non-ASCII and
    /// partial-UUID patterns.
    #[test]
    fn never_panics_on_arbitrary_inputs() {
        // Simple LCG for deterministic pseudo-random bytes — no dependency on rand.
        let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
        let mut buf = [0u8; 512];
        for _ in 0..1000 {
            for b in buf.iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (state >> 33) as u8;
            }
            // Must not panic — return value irrelevant.
            let _ = memo_to_session_id(&buf);
        }
    }
}
