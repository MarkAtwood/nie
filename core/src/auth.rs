use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::Verifier;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::identity::{decode_pub_key, hash_key, Identity, PubId};

/// Maximum age of a challenge nonce before it is considered stale, in seconds.
pub const CHALLENGE_TTL_SECS: u64 = 300;

/// Generate a 32-byte challenge nonce (base64-encoded).
///
/// Bytes 0–3 are the current Unix timestamp in seconds as a big-endian u32,
/// truncated to 32 bits (sufficient until year 2106).  Bytes 4–31 are
/// cryptographically random.  The relay calls `nonce_is_fresh` after receiving
/// the client's authenticate response to reject stale or replayed challenges;
/// clients sign the nonce as raw UTF-8 bytes as usual.
///
/// The timestamp is embedded in the nonce rather than sent as a separate field
/// to avoid any wire-protocol change: `ChallengeParams.nonce` remains a single
/// opaque base64 string.
///
/// Returns `Err` if the system clock is set before the Unix epoch.
pub fn new_challenge() -> Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock error: {e}"))?
        .as_secs() as u32;
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&now.to_be_bytes());
    OsRng.fill_bytes(&mut bytes[4..]);
    Ok(B64.encode(bytes))
}

/// Server: check that a nonce was issued within the last `CHALLENGE_TTL_SECS`.
///
/// Decodes the nonce, reads the big-endian u32 timestamp from bytes 0–3, and
/// compares it against the current Unix time.  Returns `Ok(())` if fresh,
/// `Err` if the nonce is malformed, expired, or from the future (> TTL ahead).
///
/// Call this **before** `verify_challenge` so stale nonces are rejected without
/// performing an Ed25519 signature verification.
pub fn nonce_is_fresh(nonce: &str) -> Result<()> {
    let bytes = B64.decode(nonce)?;
    if bytes.len() < 4 {
        return Err(anyhow::anyhow!("nonce too short"));
    }
    let ts = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Reject nonces older than TTL or more than TTL seconds in the future
    // (the latter catches clock-skew attacks where a pre-mined nonce carries
    // a future timestamp to extend its validity window).
    let age = now.saturating_sub(ts);
    let skew = ts.saturating_sub(now);
    if age > CHALLENGE_TTL_SECS || skew > CHALLENGE_TTL_SECS {
        return Err(anyhow::anyhow!(
            "challenge nonce is stale or from the future"
        ));
    }
    Ok(())
}

/// Client: sign the challenge nonce.
///
/// Returns `(pub_key_b64, signature_b64)` — the actual Ed25519 verifying key
/// bytes (base64) and the signature. The key bytes are sent so the relay can
/// verify the signature and then hash them to derive the caller's PubId.
pub fn sign_challenge(identity: &Identity, nonce: &str) -> (String, String) {
    let sig = identity.sign(nonce.as_bytes());
    let sig_b64 = B64.encode(sig.to_bytes());
    (identity.pub_key_b64(), sig_b64)
}

/// Server: verify the client's signature over the nonce.
///
/// Decodes `pub_key_b64` into a verifying key, checks the signature, then
/// derives and returns the authenticated PubId = hex(SHA-256(key_bytes)).
pub fn verify_challenge(pub_key_b64: &str, nonce: &str, signature_b64: &str) -> Result<PubId> {
    let key = decode_pub_key(pub_key_b64)?;

    let sig_bytes = B64.decode(signature_b64)?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature wrong length"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    key.verify(nonce.as_bytes(), &sig)?;

    Ok(PubId(hash_key(key.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn roundtrip() {
        let id = Identity::generate();
        let nonce = new_challenge().unwrap();
        let (pub_key_b64, sig_b64) = sign_challenge(&id, &nonce);
        let verified = verify_challenge(&pub_key_b64, &nonce, &sig_b64).unwrap();
        assert_eq!(verified, id.pub_id());
    }

    #[test]
    fn wrong_nonce_rejected() {
        let id = Identity::generate();
        let nonce = new_challenge().unwrap();
        let (pub_key_b64, sig_b64) = sign_challenge(&id, &nonce);
        assert!(verify_challenge(&pub_key_b64, "different_nonce", &sig_b64).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let nonce = new_challenge().unwrap();
        let (_, sig_b64) = sign_challenge(&id1, &nonce);
        let (pub_key_b64_id2, _) = sign_challenge(&id2, &nonce);
        // id2's key with id1's signature — must be rejected.
        assert!(verify_challenge(&pub_key_b64_id2, &nonce, &sig_b64).is_err());
    }

    /// A freshly generated nonce must pass the freshness check.
    #[test]
    fn fresh_nonce_is_accepted() {
        let nonce = new_challenge().unwrap();
        assert!(
            nonce_is_fresh(&nonce).is_ok(),
            "fresh nonce must be accepted"
        );
    }

    /// A nonce whose embedded timestamp is exactly TTL+1 seconds in the past must
    /// be rejected.  Oracle: craft the timestamp manually, not via new_challenge().
    #[test]
    fn stale_nonce_is_rejected() {
        // Build a nonce with a timestamp that is TTL+1 seconds ago.
        let stale_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(CHALLENGE_TTL_SECS + 1) as u32;
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&stale_ts.to_be_bytes());
        // bytes[4..] left as zeros — random payload doesn't affect freshness check
        let nonce = B64.encode(bytes);
        assert!(
            nonce_is_fresh(&nonce).is_err(),
            "nonce more than TTL seconds old must be rejected"
        );
    }

    /// A nonce whose timestamp is exactly TTL+1 seconds in the *future* must also
    /// be rejected to prevent pre-mining with inflated timestamps.
    #[test]
    fn future_nonce_is_rejected() {
        let future_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_add(CHALLENGE_TTL_SECS + 1) as u32;
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&future_ts.to_be_bytes());
        let nonce = B64.encode(bytes);
        assert!(
            nonce_is_fresh(&nonce).is_err(),
            "nonce more than TTL seconds in the future must be rejected"
        );
    }

    /// A nonce that is not valid base64 must be rejected.
    #[test]
    fn invalid_base64_nonce_rejected() {
        assert!(nonce_is_fresh("not-valid-base64!!!").is_err());
    }

    /// A nonce that is valid base64 but shorter than 4 bytes must be rejected.
    #[test]
    fn short_nonce_rejected() {
        // B64.encode([0u8; 2]) = "AAA=" — 2 decoded bytes, less than 4.
        let nonce = B64.encode([0u8; 2]);
        assert!(nonce_is_fresh(&nonce).is_err());
    }
}
