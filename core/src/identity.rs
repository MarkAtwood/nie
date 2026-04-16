use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A user's complete identity: an Ed25519 signing keypair and an X25519 HPKE keypair.
/// Nothing else. No email, no phone, no name.
///
/// Neither `SigningKey` nor `StaticSecret` implement `Debug`, so this struct
/// intentionally has no `#[derive(Debug)]`.
#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
    /// X25519 static secret for HPKE (sealing/opening). Independent entropy from
    /// `signing_key` — key separation invariant from CLAUDE.md.
    hpke_secret: x25519_dalek::StaticSecret,
}

/// The public half of an identity — safe to share, used as the user's address.
///
/// Encoded as lowercase hex of SHA-256(verifying_key_bytes). This is a
/// one-way hash: the raw verifying key cannot be reconstructed from the PubId.
/// During auth the client must send the actual verifying key bytes separately
/// (see `pub_key_b64()`), and the relay hashes those bytes to produce the PubId.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PubId(pub String);

impl Identity {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        // Generate separate entropy for HPKE key (key separation invariant).
        let hpke_seed: [u8; 32] = rand::random();
        // Astronomically unlikely, but the invariant requires it.
        assert_ne!(
            &hpke_seed,
            signing_key.to_bytes().as_slice(),
            "Ed25519 and HPKE seeds must differ"
        );
        let hpke_secret = x25519_dalek::StaticSecret::from(hpke_seed);
        Self {
            signing_key,
            hpke_secret,
        }
    }

    /// Restore an identity from a 64-byte keyfile blob:
    /// bytes[0..32] = Ed25519 seed, bytes[32..64] = X25519 HPKE seed.
    pub fn from_secret_bytes(bytes: &[u8; 64]) -> Self {
        let ed_seed: [u8; 32] = bytes[0..32].try_into().unwrap(); // infallible: slice is exactly 32
        let hpke_seed_bytes: [u8; 32] = bytes[32..64].try_into().unwrap(); // infallible: slice is exactly 32
        assert_ne!(
            &ed_seed, &hpke_seed_bytes,
            "keyfile corrupt: Ed25519 and HPKE seeds must not be equal"
        );
        let signing_key = SigningKey::from_bytes(&ed_seed);
        let hpke_secret = x25519_dalek::StaticSecret::from(hpke_seed_bytes);
        Self {
            signing_key,
            hpke_secret,
        }
    }

    /// Raw Ed25519 secret key bytes — used as bytes[0..32] of the keyfile.
    /// SECURITY: Never log this value.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Returns the 32-byte X25519 HPKE secret key bytes.
    /// SECURITY: Never log this value. Used only for keyfile storage and unsealing.
    pub fn hpke_secret_bytes(&self) -> [u8; 32] {
        self.hpke_secret.to_bytes()
    }

    /// Returns the 32-byte X25519 HPKE public key bytes.
    /// Safe to publish. Used by peers to seal messages to this user.
    pub fn hpke_pub_key_bytes(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.hpke_secret).to_bytes()
    }

    /// Returns the full 64-byte keyfile content: Ed25519_seed(32) || X25519_seed(32).
    pub fn to_secret_bytes_64(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&self.secret_bytes());
        out[32..64].copy_from_slice(&self.hpke_secret_bytes());
        out
    }

    /// The user's canonical identity: hex(SHA-256(verifying_key_bytes)).
    pub fn pub_id(&self) -> PubId {
        PubId(hash_key(self.signing_key.verifying_key().as_bytes()))
    }

    /// The actual Ed25519 verifying key, base64-encoded for wire transport.
    ///
    /// This is sent during authentication so the relay can verify the signature
    /// and then derive the PubId by hashing. Never expose this as the "address"
    /// — use `pub_id()` for that.
    pub fn pub_key_b64(&self) -> String {
        B64.encode(self.signing_key.verifying_key().as_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }
}

impl PubId {
    /// Truncated display (first 8 chars + ellipsis).
    pub fn short(&self) -> String {
        if self.0.len() > 8 {
            format!("{}…", &self.0[..8])
        } else {
            self.0.clone()
        }
    }
}

impl std::fmt::Display for PubId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short())
    }
}

/// Compute hex(SHA-256(key_bytes)). Used both by `Identity::pub_id()` and
/// by the relay's `verify_challenge()` to derive PubId from a received public key.
pub fn hash_key(key_bytes: &[u8]) -> String {
    let hash: [u8; 32] = Sha256::digest(key_bytes).into();
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a base64 verifying key and return the `VerifyingKey`.
/// Used by `auth::verify_challenge`.
pub fn decode_pub_key(pub_key_b64: &str) -> Result<VerifyingKey> {
    let raw = B64.decode(pub_key_b64)?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("pub key wrong length (expected 32 bytes)"))?;
    Ok(VerifyingKey::from_bytes(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn sign_and_verify() {
        let id = Identity::generate();
        let msg = b"nie test message";
        let sig = id.sign(msg);
        // Verify against the verifying key directly (PubId is a hash, not the key).
        assert!(id.verifying_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn wrong_message_fails() {
        let id = Identity::generate();
        let sig = id.sign(b"correct message");
        assert!(id.verifying_key().verify(b"wrong message", &sig).is_err());
    }

    #[test]
    fn export_and_restore() {
        let id = Identity::generate();
        let bytes = id.to_secret_bytes_64();
        let restored = Identity::from_secret_bytes(&bytes);
        assert_eq!(id.pub_id(), restored.pub_id());
        // HPKE public key must also round-trip.
        assert_eq!(id.hpke_pub_key_bytes(), restored.hpke_pub_key_bytes());
    }

    #[test]
    fn pub_id_is_hash_not_key() {
        let id = Identity::generate();
        let pub_id = id.pub_id();
        let pub_key_b64 = id.pub_key_b64();
        // PubId must not equal the base64 key.
        assert_ne!(pub_id.0, pub_key_b64);
        // PubId must be 64 hex chars (SHA-256 = 32 bytes = 64 hex digits).
        assert_eq!(pub_id.0.len(), 64);
        assert!(pub_id.0.chars().all(|c| c.is_ascii_hexdigit()));
        // Recomputing the hash from the decoded key must match.
        let key = decode_pub_key(&pub_key_b64).unwrap();
        assert_eq!(pub_id, PubId(hash_key(key.as_bytes())));
    }

    #[test]
    fn hpke_keys_are_independent_from_ed25519() {
        let id = Identity::generate();
        // HPKE secret bytes must not equal Ed25519 seed (key separation invariant).
        assert_ne!(id.hpke_secret_bytes(), id.secret_bytes());
        // HPKE public key must be 32 bytes (non-zero in practice).
        let pub_bytes = id.hpke_pub_key_bytes();
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn keyfile_blob_is_64_bytes() {
        let id = Identity::generate();
        let blob = id.to_secret_bytes_64();
        assert_eq!(blob.len(), 64);
        // First 32 bytes are the Ed25519 seed.
        assert_eq!(&blob[0..32], &id.secret_bytes());
        // Second 32 bytes are the HPKE seed.
        assert_eq!(&blob[32..64], &id.hpke_secret_bytes());
    }
}
