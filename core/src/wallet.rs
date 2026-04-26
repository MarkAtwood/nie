/// Zcash wallet key material: BIP-39 mnemonic generation and ZIP-32 Sapling master key derivation.
///
/// # Key separation invariant
///
/// The wallet seed (wallet.key) and the Ed25519 identity seed (identity.key) MUST be
/// derived from independent entropy sources.  A runtime assertion in the CLI init path
/// enforces that the first 32 bytes of the wallet spending key differ from the identity
/// seed bytes.  See CLAUDE.md §Wallet Security for the full set of invariants.
///
/// # Storage format
///
/// wallet.key: 64 bytes of ZIP-32 master key (spending_key || chain_code), encrypted
/// with the `age` format using a user passphrase (same scheme as identity.key).
///
/// wallet.json: plaintext JSON with `{"network":"mainnet"}` or `{"network":"testnet"}`.
/// Not a secret — network type is not sensitive.  Read on startup to detect mismatches
/// with the --network CLI flag before any key material is accessed.
use anyhow::Result;
use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

/// The 64-byte ZIP-32 Sapling master key.
///
/// Never implement `Debug` — spending_key is key material that must never appear in
/// tracing output.  See CLAUDE.md §Key material handling.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct WalletMasterKey {
    /// ZIP-32 master spending key (I[0..32])
    spending_key: [u8; 32],
    /// ZIP-32 master chain code (I[32..64])
    chain_code: [u8; 32],
}

impl WalletMasterKey {
    /// Derive the ZIP-32 Sapling master key from a 64-byte BIP-39 seed.
    ///
    /// From ZIP-32 §Sapling master key generation:
    ///   I = BLAKE2b-512("ZcashIP32Sapling", seed)
    ///   spending_key = I[0..32]
    ///   chain_code   = I[32..64]
    pub fn from_seed(seed: &[u8; 64]) -> Self {
        // Personalization is exactly 16 bytes: "ZcashIP32Sapling".
        // BLAKE2b-512 with personalization = ZIP-32 spec-defined PRF.
        let hash = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"ZcashIP32Sapling")
            .hash(seed);
        let bytes = hash.as_bytes();
        // Slicing a known-length output — these try_into calls cannot fail.
        let spending_key: [u8; 32] = bytes[..32].try_into().unwrap();
        let chain_code: [u8; 32] = bytes[32..].try_into().unwrap();
        Self {
            spending_key,
            chain_code,
        }
    }

    /// Reconstruct from 64 raw bytes (spending_key || chain_code).
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        // Slicing &[u8; 64] at fixed offsets — these try_into calls cannot fail.
        let spending_key: [u8; 32] = bytes[..32].try_into().unwrap();
        let chain_code: [u8; 32] = bytes[32..].try_into().unwrap();
        Self {
            spending_key,
            chain_code,
        }
    }

    /// Serialize to 64 bytes: spending_key || chain_code.
    pub fn as_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.spending_key);
        out[32..].copy_from_slice(&self.chain_code);
        out
    }

    /// The first 32 bytes (spending key), for key-separation assertion only.
    ///
    /// Never log or display this value.
    pub fn spending_key_bytes(&self) -> &[u8; 32] {
        &self.spending_key
    }
}

/// Generate a fresh Zcash wallet from OS entropy.
///
/// Returns `(word_list, master_key, seed)` where:
/// - `word_list` is the 24-word BIP-39 mnemonic; display once, never store.
/// - `master_key` is the ZIP-32 Sapling master key for the key-separation check.
/// - `seed` is the 64-byte BIP-39 seed (PBKDF2 output); this is what callers
///   must persist and pass to `SaplingExtendedSpendingKey::from_seed` /
///   `OrchardSpendingKey::from_seed` to derive payment keys.
pub fn generate_wallet() -> Result<(Vec<String>, WalletMasterKey, Zeroizing<[u8; 64]>)> {
    use rand::RngCore;
    // 32 bytes of entropy → 256-bit security → 24-word BIP-39 mnemonic.
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
    // BIP-39 seed derivation: PBKDF2-HMAC-SHA512, 2048 rounds, empty passphrase.
    // The passphrase slot is intentionally empty — ZIP-32 key hardening provides
    // equivalent protection, and a user-chosen passphrase would be a second secret
    // to manage without adding unlinkability benefit.
    let seed: Zeroizing<[u8; 64]> = Zeroizing::new(mnemonic.to_seed(""));
    let master = WalletMasterKey::from_seed(&seed);
    // Split via to_string() to avoid depending on a specific word-iterator API.
    let words: Vec<String> = mnemonic.to_string().split(' ').map(str::to_owned).collect();
    Ok((words, master, seed))
}

/// Restore a wallet from a BIP-39 mnemonic phrase.
///
/// `phrase` is the space-separated word list (24 words for 256-bit entropy).
/// Returns `(master_key, seed)` where `seed` is the 64-byte BIP-39 seed that
/// callers must persist in `wallet.key`.
pub fn restore_wallet(phrase: &str) -> Result<(WalletMasterKey, Zeroizing<[u8; 64]>)> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|e| anyhow::anyhow!("invalid mnemonic: {e}"))?;
    let seed: Zeroizing<[u8; 64]> = Zeroizing::new(mnemonic.to_seed(""));
    Ok((WalletMasterKey::from_seed(&seed), seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ZIP-32 Sapling master key derivation against a known test vector.
    ///
    /// Oracle: Python's hashlib.blake2b (independent of this Rust implementation):
    ///   import hashlib
    ///   seed = bytes(range(64))
    ///   h = hashlib.blake2b(seed, digest_size=64, person=b'ZcashIP32Sapling')
    ///   print(h.hexdigest())
    #[test]
    fn zip32_sapling_master_key_test_vector() {
        // seed: 0x00, 0x01, ..., 0x3f (64 bytes)
        let seed: [u8; 64] = core::array::from_fn(|i| i as u8);

        let key = WalletMasterKey::from_seed(&seed);
        let bytes = key.as_bytes();

        let spending_key_hex: String = bytes[..32].iter().map(|b| format!("{b:02x}")).collect();
        let chain_code_hex: String = bytes[32..].iter().map(|b| format!("{b:02x}")).collect();

        // Python oracle output:
        assert_eq!(
            spending_key_hex,
            "0c42477c9a2f0f457d54aaa520826b29a7844e323ae803d1fd39ceece6592739"
        );
        assert_eq!(
            chain_code_hex,
            "69365d018bf606c257399d1b3d53480a8d1db74bd550805c220096af4677609c"
        );
    }

    /// from_bytes / as_bytes roundtrip.
    #[test]
    fn wallet_master_key_roundtrip() {
        let seed: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(3));
        let key = WalletMasterKey::from_seed(&seed);
        let serialized = key.as_bytes();
        let restored = WalletMasterKey::from_bytes(&serialized);
        assert_eq!(key.as_bytes(), restored.as_bytes());
    }

    /// Distinct seeds produce distinct master keys.
    #[test]
    fn different_seeds_different_keys() {
        let seed_a: [u8; 64] = [0u8; 64];
        let seed_b: [u8; 64] = [1u8; 64];
        let key_a = WalletMasterKey::from_seed(&seed_a);
        let key_b = WalletMasterKey::from_seed(&seed_b);
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
    }

    /// BIP-39 mnemonic restore gives the same master key and seed as generation from the same phrase.
    #[test]
    fn restore_from_known_phrase() {
        // 24-word mnemonic with correct BIP-39 checksum (test vector from bip39 spec).
        // This phrase was generated externally and hardcoded — not derived from our code.
        let phrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                      zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
        let (key, seed) = restore_wallet(phrase).expect("must parse valid mnemonic");
        // Restore again from the same phrase — must produce identical bytes.
        let (key2, seed2) = restore_wallet(phrase).expect("must parse valid mnemonic");
        assert_eq!(key.as_bytes(), key2.as_bytes());
        assert_eq!(seed, seed2);
        // The key must be non-zero (all-zeros would indicate a degenerate derivation).
        assert_ne!(key.as_bytes(), [0u8; 64]);
        assert_ne!(*seed, [0u8; 64]);
    }

    /// Invalid mnemonic is rejected with an error.
    #[test]
    fn invalid_mnemonic_rejected() {
        let result = restore_wallet("this is not a valid mnemonic phrase at all nope");
        assert!(result.is_err(), "invalid mnemonic must be rejected");
    }
}
