use anyhow::{anyhow, Result};
// Use the leading `::` to reference the external `hpke` crate rather than this module.
use ::hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open,
    single_shot_seal, Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

const INFO: &[u8] = b"nie/sealed/v1";

/// Encapped key length for X25519HkdfSha256 (an X25519 public key = 32 bytes).
const ENC_LEN: usize = 32;

/// Minimum sealed length: encapped key (32 B) + AEAD tag (16 B) for an empty plaintext.
const MIN_SEALED_LEN: usize = ENC_LEN + 16;

/// Seal `plaintext` for the recipient identified by `recipient_pub_key_bytes` (32-byte
/// X25519 public key). Returns `enc (32 B) || ciphertext` — opaque to the relay.
pub fn seal_message(recipient_pub_key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let pk_recip = <Kem as KemTrait>::PublicKey::from_bytes(recipient_pub_key_bytes.as_ref())
        .map_err(|e| anyhow!("invalid recipient public key: {e}"))?;

    let mut rng = OsRng;
    let (encapped_key, ciphertext) = single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk_recip,
        INFO,
        plaintext,
        &[],
        &mut rng,
    )
    .map_err(|e| anyhow!("HPKE seal failed: {e}"))?;

    let enc_bytes = encapped_key.to_bytes();
    debug_assert_eq!(enc_bytes.len(), ENC_LEN);

    let mut out = Vec::with_capacity(enc_bytes.len() + ciphertext.len());
    out.extend_from_slice(&enc_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unseal bytes produced by `seal_message`, using the recipient's X25519 secret key.
/// Returns the original plaintext, or `Err` if decryption or parsing fails.
pub fn unseal_message(recipient_secret_bytes: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < MIN_SEALED_LEN {
        return Err(anyhow!(
            "sealed message too short: {} bytes (minimum {})",
            sealed.len(),
            MIN_SEALED_LEN
        ));
    }

    let sk_recip = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_secret_bytes.as_ref())
        .map_err(|e| anyhow!("invalid recipient secret key: {e}"))?;

    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&sealed[..ENC_LEN])
        .map_err(|e| anyhow!("invalid encapped key: {e}"))?;

    let ciphertext = &sealed[ENC_LEN..];

    let plaintext = single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk_recip,
        &encapped_key,
        INFO,
        ciphertext,
        &[],
    )
    .map_err(|e| anyhow!("HPKE open failed: {e}"))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::hpke::{Kem as KemTrait, Serializable};
    use rand::rngs::OsRng;

    fn gen_x25519_keypair() -> ([u8; 32], [u8; 32]) {
        let mut rng = OsRng;
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        let sk_bytes: [u8; 32] = sk.to_bytes().as_slice().try_into().unwrap();
        let pk_bytes: [u8; 32] = pk.to_bytes().as_slice().try_into().unwrap();
        (sk_bytes, pk_bytes)
    }

    #[test]
    fn roundtrip_non_empty() {
        let (sk, pk) = gen_x25519_keypair();
        let plaintext = b"nie encrypted message";
        let sealed = seal_message(&pk, plaintext).expect("seal failed");
        // Verify wire format length: 32 (enc) + len + 16 (tag)
        assert_eq!(sealed.len(), ENC_LEN + plaintext.len() + 16);
        let recovered = unseal_message(&sk, &sealed).expect("unseal failed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        let (sk, pk) = gen_x25519_keypair();
        let sealed = seal_message(&pk, b"").expect("seal failed");
        assert_eq!(sealed.len(), MIN_SEALED_LEN);
        let recovered = unseal_message(&sk, &sealed).expect("unseal failed");
        assert!(recovered.is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let (_sk, pk) = gen_x25519_keypair();
        let (sk2, _pk2) = gen_x25519_keypair();
        let sealed = seal_message(&pk, b"secret").expect("seal failed");
        let result = unseal_message(&sk2, &sealed);
        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    #[test]
    fn too_short_rejected() {
        let (sk, _pk) = gen_x25519_keypair();
        let result = unseal_message(&sk, &[0u8; 47]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("too short"), "expected 'too short' in: {msg}");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (sk, pk) = gen_x25519_keypair();
        let mut sealed = seal_message(&pk, b"tamper test").expect("seal failed");
        // Flip a byte in the ciphertext portion
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        let result = unseal_message(&sk, &sealed);
        assert!(
            result.is_err(),
            "tampered ciphertext must fail verification"
        );
    }

    #[test]
    fn seal_is_not_deterministic() {
        let (_sk, pk) = gen_x25519_keypair();
        let pt = b"same plaintext";
        let s1 = seal_message(&pk, pt).expect("seal 1 failed");
        let s2 = seal_message(&pk, pt).expect("seal 2 failed");
        assert_ne!(s1, s2, "seal must be probabilistic");
    }
}
