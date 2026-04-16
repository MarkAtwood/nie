//! Orchard ZIP-32 spending key and payment address derivation (nie-1ws).
//!
//! Derives the Orchard spending key at path m/32'/coin_type'/account',
//! the full viewing key (FVK), incoming viewing key (IVK), and payment
//! address from a 64-byte BIP-39 seed.
//!
//! # Key separation
//!
//! This module operates on the 64-byte wallet seed from `WalletMasterKey`, not
//! the Ed25519 identity key.  See CLAUDE.md §Key separation invariant.
//!
//! # No Debug
//!
//! `OrchardSpendingKey` deliberately does not implement `Debug` — it holds
//! spending key material that must never appear in tracing output.
//! See CLAUDE.md §Wallet Security.

use anyhow::Result;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::Address;
use zip32::{AccountId, DiversifierIndex};

/// Zcash network for ZIP-32 coin-type selection.
///
/// Reuse the same type from the `address` module — both Sapling and Orchard
/// use identical coin-type conventions.
pub use crate::address::ZcashNetwork;

/// Orchard ZIP-32 spending key for one account.
///
/// Wraps the account-level spending key at path m/32'/coin_type'/account'.
/// Never implements `Debug` — spending key material must not appear in
/// tracing output.  See CLAUDE.md §Wallet Security.
pub struct OrchardSpendingKey(SpendingKey);

/// Orchard full viewing key.
///
/// Derived from `OrchardSpendingKey`.  Holds (ak, nk, rivk) and is sufficient
/// to derive payment addresses and detect incoming transactions without spending
/// ability.  Derives `Debug` via the upstream type (orchard FVK is public-key
/// material, not secret).
pub struct OrchardFullViewingKey(FullViewingKey);

impl OrchardSpendingKey {
    /// Derive the Orchard account spending key from a BIP-39 seed at the
    /// ZIP-32 path m/32'/coin_type'/account'.
    ///
    /// `seed` is the 64-byte BIP-39 seed (output of `Mnemonic::to_seed`).
    /// `network` selects mainnet (coin type 133) or testnet (coin type 1).
    /// `account` is the account index (0 for the first account).
    pub fn from_seed(seed: &[u8; 64], network: ZcashNetwork, account: u32) -> Result<Self> {
        let account_id = AccountId::try_from(account)
            .map_err(|_| anyhow::anyhow!("account index {account} out of range for AccountId"))?;
        let sk = SpendingKey::from_zip32_seed(seed, network.coin_type(), account_id)
            .map_err(|e| anyhow::anyhow!("Orchard ZIP-32 derivation failed: {e:?}"))?;
        Ok(Self(sk))
    }

    /// Get the raw 32-byte spending key.
    ///
    /// Never log this value.
    pub fn to_bytes(&self) -> &[u8; 32] {
        self.0.to_bytes()
    }

    /// Derive the full viewing key.
    pub fn to_fvk(&self) -> OrchardFullViewingKey {
        OrchardFullViewingKey(FullViewingKey::from(&self.0))
    }

    /// Return the default Orchard payment address (diversifier index 0, external scope).
    pub fn default_address(&self) -> (DiversifierIndex, Address) {
        let fvk = FullViewingKey::from(&self.0);
        let di = DiversifierIndex::from(0u32);
        let addr = fvk.address_at(di, Scope::External);
        (di, addr)
    }
}

impl OrchardFullViewingKey {
    /// Return the payment address at diversifier index `j`, external scope.
    pub fn address_at(&self, j: u32) -> Address {
        self.0
            .address_at(DiversifierIndex::from(j), Scope::External)
    }

    /// Return the payment address at the given diversifier index, external scope.
    pub(crate) fn address_at_index(&self, di: DiversifierIndex) -> Address {
        self.0.address_at(di, Scope::External)
    }

    /// Return the default payment address (diversifier index 0, external scope).
    pub fn default_address(&self) -> Address {
        self.address_at(0)
    }

    /// Serialize the FVK to 96 bytes: [ak(32) || nk(32) || rivk(32)].
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }

    /// Restore an FVK from 96 bytes produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8; 96]) -> Option<Self> {
        FullViewingKey::from_bytes(bytes).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{SaplingExtendedSpendingKey, ZcashNetwork};

    /// Test vectors from zcash-hackworks/zcash-test-vectors (orchard_key_components.py),
    /// vector 0: sk from raw bytes.
    ///
    /// Oracle: the Python test-vector generator at
    ///   https://github.com/zcash-hackworks/zcash-test-vectors
    /// is independent of the orchard crate and serves as an external oracle.
    ///
    /// Note: this vector uses a raw SpendingKey (not ZIP-32 derived) to test
    /// the FVK → address derivation path independently of ZIP-32.
    const TV_SK_BYTES: [u8; 32] = [
        0x5d, 0x7a, 0x8f, 0x73, 0x9a, 0x2d, 0x9e, 0x94, 0x5b, 0x0c, 0xe1, 0x52, 0xa8, 0x04, 0x9e,
        0x29, 0x4c, 0x4d, 0x6e, 0x66, 0xb1, 0x64, 0x93, 0x9d, 0xaf, 0xfa, 0x2e, 0xf6, 0xee, 0x69,
        0x21, 0x48,
    ];

    /// Expected default address (d || pk_d) for TV_SK_BYTES at diversifier index 0.
    const TV_DEFAULT_ADDR: [u8; 43] = [
        // d (11 bytes)
        0x8f, 0xf3, 0x38, 0x69, 0x71, 0xcb, 0x64, 0xb8, 0xe7, 0x78, 0x99,
        // pk_d (32 bytes)
        0x08, 0xdd, 0x8e, 0xbd, 0x7d, 0xe9, 0x2a, 0x68, 0xe5, 0x86, 0xa3, 0x4d, 0xb8, 0xfe, 0xa9,
        0x99, 0xef, 0xd2, 0x01, 0x6f, 0xae, 0x76, 0x75, 0x0a, 0xfa, 0xe7, 0xee, 0x94, 0x16, 0x46,
        0xbc, 0xb9,
    ];

    /// Address derived from the test-vector SpendingKey matches the expected bytes.
    ///
    /// Oracle: TV_DEFAULT_ADDR comes from orchard_key_components.py in
    /// zcash-hackworks/zcash-test-vectors — independent Python implementation.
    #[test]
    fn orchard_address_from_raw_sk_matches_test_vector() {
        use orchard::keys::SpendingKey;

        let sk_ct = SpendingKey::from_bytes(TV_SK_BYTES);
        let sk = sk_ct.unwrap(); // known-valid from test vector
        let fvk = FullViewingKey::from(&sk);
        let addr = fvk.address_at(DiversifierIndex::from(0u32), Scope::External);
        assert_eq!(
            addr.to_raw_address_bytes(),
            TV_DEFAULT_ADDR,
            "Orchard default address must match test-vector oracle"
        );
    }

    /// ZIP-32 derivation produces different keys for mainnet and testnet.
    ///
    /// Oracle: coin_type 133 vs 1 yields a different hardened path; different
    /// paths must produce different spending keys and therefore different addresses.
    #[test]
    fn orchard_zip32_mainnet_testnet_differ() {
        let seed = [0u8; 64];
        let main_sk = OrchardSpendingKey::from_seed(&seed, ZcashNetwork::Mainnet, 0).unwrap();
        let test_sk = OrchardSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 0).unwrap();
        assert_ne!(
            main_sk.to_bytes(),
            test_sk.to_bytes(),
            "mainnet and testnet spending keys must differ"
        );
        let (_, main_addr) = main_sk.default_address();
        let (_, test_addr) = test_sk.default_address();
        assert_ne!(
            main_addr.to_raw_address_bytes(),
            test_addr.to_raw_address_bytes(),
            "mainnet and testnet addresses must differ"
        );
    }

    /// ZIP-32 derivation produces different keys for account 0 and account 1.
    ///
    /// Oracle: different hardened account indices in the ZIP-32 path must yield
    /// independent spending keys and therefore different addresses.
    #[test]
    fn orchard_zip32_different_accounts_differ() {
        let seed = [0u8; 64];
        let acc0 = OrchardSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 0).unwrap();
        let acc1 = OrchardSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 1).unwrap();
        assert_ne!(
            acc0.to_bytes(),
            acc1.to_bytes(),
            "different accounts must yield different spending keys"
        );
    }

    /// Orchard and Sapling addresses differ for the same seed, network, and account.
    ///
    /// Oracle: Orchard and Sapling use independent key schedules (Pallas vs Jubjub
    /// curves); any overlap in the 43-byte address encoding would indicate a bug.
    #[test]
    fn orchard_address_differs_from_sapling_address() {
        let seed = [0u8; 64];
        let orchard_sk = OrchardSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 0).unwrap();
        let sapling_sk = SaplingExtendedSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 0);

        let (_, orchard_addr) = orchard_sk.default_address();
        let (_, sapling_addr) = sapling_sk.default_address();

        assert_ne!(
            orchard_addr.to_raw_address_bytes(),
            sapling_addr.to_bytes(),
            "Orchard and Sapling addresses must be different"
        );
    }

    /// FVK serialization roundtrips correctly.
    ///
    /// Oracle: re-derive the default address from the restored FVK and compare
    /// to the original; a bytes mismatch would indicate broken serialization.
    #[test]
    fn orchard_fvk_roundtrip() {
        let seed = [0u8; 64];
        let sk = OrchardSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 0).unwrap();
        let fvk = sk.to_fvk();
        let bytes = fvk.to_bytes();
        let restored = OrchardFullViewingKey::from_bytes(&bytes)
            .expect("from_bytes must succeed for valid FVK");
        let addr1 = fvk.default_address();
        let addr2 = restored.default_address();
        assert_eq!(
            addr1.to_raw_address_bytes(),
            addr2.to_raw_address_bytes(),
            "FVK roundtrip must produce identical default address"
        );
    }
}
