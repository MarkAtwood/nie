use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

pub const TOKEN_VERSION: u8 = 0x01;
pub const OP_ENROLLMENT: u8 = 0x01;
pub const MIN_DIFFICULTY: u8 = 20;
pub const MAX_DIFFICULTY: u8 = 30;
/// Nominal staleness window in seconds.  The actual enforced window is
/// `ts_floor ± 10 minute-floors`, where `ts_floor = unix_time / 60`.
/// Due to floor rounding on both sides the effective window is up to
/// 10 × 60 + 59 = 659 seconds, not exactly 600.  The constant names the
/// intent; the check in `verify_token` is the authoritative definition.
pub const STALENESS_WINDOW_SECS: u64 = 600;

#[derive(Debug, PartialEq, Eq)]
pub enum PowError {
    /// Token string is not valid base64url or wrong length.
    InvalidFormat,
    /// Token version byte is not 0x01.
    InvalidVersion,
    /// Token op_type is not 0x01.
    InvalidOpType,
    /// Difficulty is below minimum or above maximum (20–30).
    InvalidDifficulty,
    /// ts_floor is outside the ±600s staleness window.
    Stale,
    /// PoW hash does not have sufficient leading zeros, or h16 mismatch.
    InvalidHash,
}

/// Count the number of leading zero bits in a 32-byte hash output.
///
/// Returns 255 as a sentinel if all bytes are zero (256 leading zero bits cannot
/// fit in a u8; this is safe because the maximum enforced difficulty is 30).
fn leading_zero_bits(hash: &[u8; 32]) -> u8 {
    let mut count: u8 = 0;
    for &b in hash.iter() {
        if b == 0 {
            // Would add 8, but guard against wrapping on the final byte.
            count = count.saturating_add(8);
        } else {
            count = count.saturating_add(b.leading_zeros() as u8);
            return count;
        }
    }
    // All 32 bytes were zero — 256 leading bits, return 255 as sentinel.
    255
}

/// Build the 111-byte hash input for PoW computation.
fn build_hash_input(
    ver: u8,
    op_type: u8,
    ts_floor: u32,
    diff: u8,
    pub_key_bytes: &[u8; 32],
    server_salt: &[u8; 32],
    nonce: u64,
) -> [u8; 111] {
    let mut input = [0u8; 111];
    let mut pos = 0;

    input[pos] = ver;
    pos += 1;

    input[pos] = op_type;
    pos += 1;

    input[pos..pos + 4].copy_from_slice(&ts_floor.to_be_bytes());
    pos += 4;

    input[pos] = diff;
    pos += 1;

    // Hex-encode each pub_key byte as two lowercase ASCII characters.
    // Total: 32 bytes × 2 chars = 64 bytes.
    // Use a const lookup table to avoid heap allocations in the mining hot path.
    const HEX: &[u8] = b"0123456789abcdef";
    for &byte in pub_key_bytes.iter() {
        input[pos] = HEX[(byte >> 4) as usize];
        input[pos + 1] = HEX[(byte & 0x0f) as usize];
        pos += 2;
    }

    input[pos..pos + 32].copy_from_slice(server_salt);
    pos += 32;

    input[pos..pos + 8].copy_from_slice(&nonce.to_be_bytes());
    // pos += 8; // final field, no need to advance

    debug_assert_eq!(pos + 8, 111);

    input
}

/// Compute double-SHA256 of the hash input.
pub fn compute_hash(
    ver: u8,
    op_type: u8,
    ts_floor: u32,
    diff: u8,
    pub_key_bytes: &[u8; 32],
    server_salt: &[u8; 32],
    nonce: u64,
) -> [u8; 32] {
    let input = build_hash_input(
        ver,
        op_type,
        ts_floor,
        diff,
        pub_key_bytes,
        server_salt,
        nonce,
    );
    let first = Sha256::digest(input);
    let second = Sha256::digest(first);
    second.into()
}

/// Encode a 31-byte token to base64url (no padding).
pub fn encode_token(bytes: &[u8; 31]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a base64url string to a 31-byte token.
/// Returns Err if length != 31 after decode.
pub fn decode_token(s: &str) -> Result<[u8; 31], PowError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| PowError::InvalidFormat)?;
    if decoded.len() != 31 {
        return Err(PowError::InvalidFormat);
    }
    let mut out = [0u8; 31];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Verify a PoW token string.
///
/// Returns `Ok(h16)` on success (caller must add h16 to replay set).
/// The caller is responsible for replay checking — this function does NOT access the replay set.
///
/// # Arguments
/// - `token_b64url`: base64url-encoded 31-byte token
/// - `pub_key_bytes`: 32-byte Ed25519 verifying key (the key being authenticated)
/// - `server_salt`: 32-byte relay salt
/// - `now_unix_secs`: current Unix timestamp in seconds
/// - `min_diff`: minimum acceptable difficulty (default 20)
pub fn verify_token(
    token_b64url: &str,
    pub_key_bytes: &[u8; 32],
    server_salt: &[u8; 32],
    now_unix_secs: u64,
    min_diff: u8,
) -> Result<[u8; 16], PowError> {
    let bytes = decode_token(token_b64url)?;

    // Parse token fields.
    let ver = bytes[0];
    let op_type = bytes[1];
    let ts_floor = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    let diff = bytes[6];
    let nonce = u64::from_be_bytes([
        bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
    ]);
    let h16: [u8; 16] = bytes[15..31].try_into().expect("slice is exactly 16 bytes");

    if ver != TOKEN_VERSION {
        return Err(PowError::InvalidVersion);
    }
    if op_type != OP_ENROLLMENT {
        return Err(PowError::InvalidOpType);
    }
    if diff < min_diff || diff > MAX_DIFFICULTY {
        return Err(PowError::InvalidDifficulty);
    }

    // Staleness check: compare ts_floor (minutes) against now / 60.
    let now_floor = now_unix_secs / 60;
    if now_floor.abs_diff(ts_floor as u64) > 10 {
        return Err(PowError::Stale);
    }

    // Recompute hash and verify.
    let hash = compute_hash(
        ver,
        op_type,
        ts_floor,
        diff,
        pub_key_bytes,
        server_salt,
        nonce,
    );

    if leading_zero_bits(&hash) < diff {
        return Err(PowError::InvalidHash);
    }

    let expected_h16: [u8; 16] = hash[..16].try_into().expect("slice is exactly 16 bytes");
    if h16 != expected_h16 {
        return Err(PowError::InvalidHash);
    }

    Ok(h16)
}

/// Mine a PoW token.
///
/// Iterates nonces starting from 0 until finding one where
/// double-SHA256 of the hash input has >= diff leading zero bits.
///
/// Returns the base64url-encoded 31-byte token string.
///
/// # Arguments
/// - `pub_key_bytes`: 32-byte Ed25519 verifying key
/// - `server_salt`: 32-byte relay salt
/// - `diff`: required leading zero bits
/// - `ts_floor`: Unix timestamp / 60 (caller computes this)
pub fn mine_token(
    pub_key_bytes: &[u8; 32],
    server_salt: &[u8; 32],
    diff: u8,
    ts_floor: u32,
) -> String {
    for nonce in 0u64.. {
        let hash = compute_hash(
            TOKEN_VERSION,
            OP_ENROLLMENT,
            ts_floor,
            diff,
            pub_key_bytes,
            server_salt,
            nonce,
        );
        if leading_zero_bits(&hash) >= diff {
            let mut token = [0u8; 31];
            token[0] = TOKEN_VERSION;
            token[1] = OP_ENROLLMENT;
            token[2..6].copy_from_slice(&ts_floor.to_be_bytes());
            token[6] = diff;
            token[7..15].copy_from_slice(&nonce.to_be_bytes());
            token[15..31].copy_from_slice(&hash[..16]);
            return encode_token(&token);
        }
    }
    unreachable!("nonce space exhausted before finding PoW solution")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Oracle: manually computed leading zero bits
    #[test]
    fn leading_zero_bits_known_values() {
        assert_eq!(leading_zero_bits(&[0u8; 32]), 255u8);
        assert_eq!(
            leading_zero_bits(&{
                let mut a = [0u8; 32];
                a[0] = 0x80;
                a
            }),
            0u8
        );
        assert_eq!(
            leading_zero_bits(&{
                let mut a = [0u8; 32];
                a[0] = 0x40;
                a
            }),
            1u8
        );
        assert_eq!(
            leading_zero_bits(&{
                let mut a = [0u8; 32];
                a[0] = 0x7F;
                a
            }),
            1u8
        );
        assert_eq!(
            leading_zero_bits(&{
                let mut a = [0u8; 32];
                a[0] = 0x0F;
                a
            }),
            4u8
        );
        assert_eq!(
            leading_zero_bits(&{
                let mut a = [0u8; 32];
                a[0] = 0x00;
                a[1] = 0xFF;
                a
            }),
            8u8
        );
    }

    // Oracle: decode must invert encode
    #[test]
    fn token_roundtrip() {
        let mut bytes = [0u8; 31];
        bytes[0] = 0x01;
        bytes[1] = 0x01;
        bytes[2..6].copy_from_slice(&42u32.to_be_bytes());
        bytes[6] = 20;
        bytes[7..15].copy_from_slice(&12345u64.to_be_bytes());
        bytes[15..31].copy_from_slice(&[0xAB; 16]);
        let encoded = encode_token(&bytes);
        let decoded = decode_token(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }

    // Oracle: wrong difficulty < min_diff
    #[test]
    fn verify_rejects_low_difficulty() {
        let pub_key = [0u8; 32];
        let salt = [0u8; 32];
        let now = 1_714_002_048u64;
        let ts_floor = (now / 60) as u32;
        let raw_token = mine_token(&pub_key, &salt, 5, ts_floor);
        assert_eq!(
            verify_token(&raw_token, &pub_key, &salt, now, 20),
            Err(PowError::InvalidDifficulty),
        );
    }

    // Oracle: token mined with diff=1 must pass verify_token with min_diff=1
    #[test]
    fn mine_and_verify_roundtrip() {
        let pub_key = [1u8; 32];
        let salt = [2u8; 32];
        let now = 1_714_002_048u64;
        let ts_floor = (now / 60) as u32;
        let token_str = mine_token(&pub_key, &salt, 1, ts_floor);
        let result = verify_token(&token_str, &pub_key, &salt, now, 1);
        assert!(result.is_ok(), "mined token must verify: {result:?}");
    }

    // Oracle: stale ts_floor
    #[test]
    fn verify_rejects_stale() {
        let pub_key = [0u8; 32];
        let salt = [0u8; 32];
        let now = 1_714_002_048u64;
        let stale_ts = (now / 60 - 11) as u32;
        let token_str = mine_token(&pub_key, &salt, 1, stale_ts);
        assert_eq!(
            verify_token(&token_str, &pub_key, &salt, now, 1),
            Err(PowError::Stale),
        );
    }

    // Oracle: corrupted h16
    #[test]
    fn verify_rejects_bad_h16() {
        let pub_key = [0u8; 32];
        let salt = [0u8; 32];
        let now = 1_714_002_048u64;
        let ts_floor = (now / 60) as u32;
        let token_str = mine_token(&pub_key, &salt, 1, ts_floor);
        let mut bytes = decode_token(&token_str).unwrap();
        bytes[15] ^= 0xFF;
        let corrupted = encode_token(&bytes);
        assert_eq!(
            verify_token(&corrupted, &pub_key, &salt, now, 1),
            Err(PowError::InvalidHash),
        );
    }

    // Oracle: wrong pub_key
    #[test]
    fn verify_rejects_wrong_pubkey() {
        let pub_key = [0u8; 32];
        let wrong_key = [1u8; 32];
        let salt = [0u8; 32];
        let now = 1_714_002_048u64;
        let ts_floor = (now / 60) as u32;
        let token_str = mine_token(&pub_key, &salt, 1, ts_floor);
        assert_eq!(
            verify_token(&token_str, &wrong_key, &salt, now, 1),
            Err(PowError::InvalidHash),
        );
    }
}
