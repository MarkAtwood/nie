use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::Verifier;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::identity::{decode_pub_key, hash_key, Identity, PubId};

/// Generate a random 32-byte challenge nonce (base64-encoded).
pub fn new_challenge() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
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
        let nonce = new_challenge();
        let (pub_key_b64, sig_b64) = sign_challenge(&id, &nonce);
        let verified = verify_challenge(&pub_key_b64, &nonce, &sig_b64).unwrap();
        assert_eq!(verified, id.pub_id());
    }

    #[test]
    fn wrong_nonce_rejected() {
        let id = Identity::generate();
        let nonce = new_challenge();
        let (pub_key_b64, sig_b64) = sign_challenge(&id, &nonce);
        assert!(verify_challenge(&pub_key_b64, "different_nonce", &sig_b64).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let nonce = new_challenge();
        let (_, sig_b64) = sign_challenge(&id1, &nonce);
        let (pub_key_b64_id2, _) = sign_challenge(&id2, &nonce);
        // id2's key with id1's signature — must be rejected.
        assert!(verify_challenge(&pub_key_b64_id2, &nonce, &sig_b64).is_err());
    }
}
