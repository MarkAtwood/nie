//! Sapling ZIP-32 extended spending key and payment address derivation (nie-fz7).
//!
//! Derives the Sapling account key at path m/32'/coin_type'/account', the
//! diversifiable full viewing key (DFVK), and payment addresses from a 64-byte
//! BIP-39 seed.
//!
//! # Key separation
//!
//! This module operates on the 64-byte wallet seed from `WalletMasterKey`, not the
//! Ed25519 identity key.  See CLAUDE.md §Key separation invariant.
//!
//! # No Debug
//!
//! `SaplingExtendedSpendingKey` and `SaplingDiversifiableFvk` deliberately do not
//! implement `Debug` — they hold spending key and full viewing key material that
//! must never appear in tracing output.  See CLAUDE.md §Wallet Security.

use anyhow::{bail, Result};
use ff::PrimeField;
use sapling::zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey};
pub use sapling::PaymentAddress;
use zcash_address::{ToAddress, ZcashAddress};
use zip32::{ChildIndex, DiversifierIndex, Scope};
use zeroize::Zeroizing;

use crate::db::WalletStore;

/// Zcash network for ZIP-32 coin-type selection.
///
/// Determines the coin type in the ZIP-32 derivation path m/32'/coin_type'/account':
/// mainnet = 133 (SLIP-0044), testnet = 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZcashNetwork {
    Mainnet,
    Testnet,
}

impl ZcashNetwork {
    pub(crate) fn coin_type(self) -> u32 {
        match self {
            ZcashNetwork::Mainnet => 133,
            ZcashNetwork::Testnet => 1,
        }
    }
}

/// Sapling ZIP-32 extended spending key for one account.
///
/// Wraps the account-level spending key at path m/32'/coin_type'/account'.
/// Never implements `Debug` — spending key material must not appear in
/// tracing output.  See CLAUDE.md §Wallet Security.
///
/// The key bytes are stored in a `Zeroizing` wrapper and overwritten on drop.
/// The `ExtendedSpendingKey` is reconstructed from the bytes on each method call.
pub struct SaplingExtendedSpendingKey(Zeroizing<[u8; 169]>);

/// Sapling diversifiable full viewing key (DFVK).
///
/// Derived from `SaplingExtendedSpendingKey`.  Holds (ak, nk, ovk, dk) and
/// is sufficient to derive payment addresses and detect incoming transactions
/// without spending ability.
///
/// Never implements `Debug` — contains key material.
pub struct SaplingDiversifiableFvk(DiversifiableFullViewingKey);

impl SaplingExtendedSpendingKey {
    /// Construct from a raw `ExtendedSpendingKey`, storing its 169-byte serialization.
    fn from_extsk(key: ExtendedSpendingKey) -> Self {
        Self(Zeroizing::new(key.to_bytes()))
    }

    /// Reconstruct the `ExtendedSpendingKey` from the stored bytes.
    ///
    /// The bytes were written by `ExtendedSpendingKey::to_bytes()` in the constructor,
    /// so this is infallible by construction; the `expect()` is unreachable.
    fn extsk(&self) -> ExtendedSpendingKey {
        ExtendedSpendingKey::from_bytes(&*self.0)
            .expect("SaplingExtendedSpendingKey bytes are always valid ExtendedSpendingKey")
    }

    /// Derive the Sapling account spending key from a BIP-39 seed at the
    /// ZIP-32 path m/32'/coin_type'/account'.
    ///
    /// `seed` is the 64-byte BIP-39 seed (output of `Mnemonic::to_seed`).
    /// `network` selects mainnet (coin type 133) or testnet (coin type 1).
    /// `account` is the account index (0 for the first account).
    pub fn from_seed(seed: &[u8; 64], network: ZcashNetwork, account: u32) -> Self {
        let master = ExtendedSpendingKey::master(seed.as_slice());
        let key = ExtendedSpendingKey::from_path(
            &master,
            &[
                ChildIndex::hardened(32),
                ChildIndex::hardened(network.coin_type()),
                ChildIndex::hardened(account),
            ],
        );
        Self::from_extsk(key)
    }

    /// Compute the diversifiable full viewing key (FVK) from this spending key.
    pub fn to_dfvk(&self) -> SaplingDiversifiableFvk {
        SaplingDiversifiableFvk(self.extsk().to_diversifiable_full_viewing_key())
    }

    /// Return the default payment address and the diversifier index at which
    /// it was found.
    ///
    /// "Default" means the first valid diversifier at index 0 or later.
    pub fn default_address(&self) -> (DiversifierIndex, PaymentAddress) {
        self.extsk().default_address()
    }

    /// Returns the Sapling `FullViewingKey` for use with the transaction builder's
    /// `add_sapling_spend`.  This is the non-diversifiable FVK; derive it fresh each
    /// time rather than caching to avoid accidental key material persistence.
    pub(crate) fn full_viewing_key(&self) -> sapling::keys::FullViewingKey {
        self.extsk().to_diversifiable_full_viewing_key().fvk().clone()
    }

    /// Returns the inner [`ExtendedSpendingKey`] for passing to
    /// `builder.build(sapling_extsks: &[ExtendedSpendingKey])`.
    ///
    /// Returns a value (not a reference) because the key is reconstructed from
    /// the stored bytes each time.
    pub(crate) fn inner_extsk(&self) -> ExtendedSpendingKey {
        self.extsk()
    }

    /// Derive the master key directly from arbitrary seed bytes.
    ///
    /// Used only in tests against ZIP-32 test vectors that target the master key,
    /// not the account-level path.  Production code uses [`Self::from_seed`].
    #[cfg(test)]
    pub(crate) fn master(seed: &[u8]) -> Self {
        Self::from_extsk(ExtendedSpendingKey::master(seed))
    }
}

impl SaplingDiversifiableFvk {
    /// Find a valid Sapling payment address at or after `start_index`.
    ///
    /// Searches up to 256 diversifier indices starting at `start_index`.
    /// Returns `Err` if:
    /// - `start_index` is ≥ 2^88 (diversifier space overflow), or
    /// - no valid address exists within 256 indices of `start_index`.
    ///
    /// The 256-attempt bound ensures termination for any key material — valid
    /// diversifiers are approximately 50% dense in the diversifier space, so
    /// needing more than 256 tries is negligibly unlikely for well-formed keys.
    pub fn find_address(&self, start_index: u128) -> Result<(DiversifierIndex, PaymentAddress)> {
        const MAX_SEARCH: u128 = 256;
        const MAX_INDEX: u128 = (1u128 << 88) - 1;

        let j = DiversifierIndex::try_from(start_index)
            .map_err(|_| anyhow::anyhow!("diversifier index {start_index} exceeds 2^88-1"))?;

        let end_index = start_index.saturating_add(MAX_SEARCH).min(MAX_INDEX);

        match self.0.find_address(j) {
            Some((found_j, addr)) => {
                if u128::from(found_j) <= end_index {
                    Ok((found_j, addr))
                } else {
                    bail!("no valid Sapling diversifier within 256 indices of {start_index}")
                }
            }
            None => bail!("no valid Sapling diversifier at or after index {start_index}"),
        }
    }

    /// Return the default payment address (first valid diversifier ≥ 0).
    pub fn default_address(&self) -> (DiversifierIndex, PaymentAddress) {
        self.0.default_address()
    }

    /// Serialize the DFVK to 128 bytes: [ak(32) || nk(32) || ovk(32) || dk(32)].
    pub fn to_bytes(&self) -> [u8; 128] {
        self.0.to_bytes()
    }

    /// Restore a DFVK from 128 bytes produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8; 128]) -> Option<Self> {
        DiversifiableFullViewingKey::from_bytes(bytes).map(Self)
    }

    /// Return the 32-byte little-endian scalar representation of the external-scope
    /// Sapling incoming viewing key (IVK).
    ///
    /// The returned bytes are a canonically-encoded `jubjub::Fr` scalar and can be
    /// passed directly to [`nie_wallet::scanner::SaplingIvkDecryptor::new`] to
    /// construct a trial-decryption key.
    ///
    /// # Key material
    ///
    /// The IVK is key material — do not log, print, or store the return value.
    /// See CLAUDE.md §Wallet Security.
    pub fn ivk_bytes(&self) -> [u8; 32] {
        self.0.to_ivk(Scope::External).0.to_repr()
    }
}

/// Allocate a fresh Sapling payment address for `account`, advancing the DB diversifier
/// counter past the actual index used by `find_address`.
///
/// # Two-step diversifier advance
///
/// `next_diversifier` atomically returns `start` and stores `start + 1`.  However,
/// `find_address` may skip indices (up to 255 of them) before landing on a valid
/// Sapling diversifier at `actual_di ≥ start`.  If `actual_di > start`, the gap
/// `[start + 1 .. actual_di]` is unprotected: a subsequent call to `next_diversifier`
/// would hand out one of those indices, producing an address identical to the already-
/// allocated `actual_di` when `find_address` searches forward.  This violates
/// shielded unlinkability (ZIP-316 §Fresh subaddress per payment).
///
/// The fix: after `find_address`, advance the DB counter to `actual_di + 1` when
/// `actual_di > start`.  `advance_diversifier_to` is monotonic (ignores retrograde
/// writes), so this is safe to call even on the fast path.
///
/// # Return value
///
/// `(actual_di, payment_address, bech32_string)` where `bech32_string` encodes the
/// Sapling address in the standard network-specific format (`zs1…` mainnet,
/// `ztestsapling…` testnet).
pub async fn alloc_fresh_address(
    dfvk: &SaplingDiversifiableFvk,
    store: &WalletStore,
    network: &ZcashNetwork,
    account: u32,
) -> Result<(DiversifierIndex, PaymentAddress, String)> {
    // Step 1: reserve a diversifier slot.  DB counter advances from `start` to
    // `start + 1` atomically.
    let start: u128 = store.next_diversifier(account).await?;

    // Step 2: find the first valid Sapling diversifier at or after `start`.
    // `actual_di` may be > `start` by up to 255 (ZIP-32 bound).
    let (actual_di, addr) = dfvk.find_address(start)?;
    let actual_u128 = u128::from(actual_di);

    // Step 3: close the gap.  If `find_address` skipped indices, the DB counter
    // currently holds `start + 1` while the allocated index is `actual_u128`.
    // Advance the DB to `actual_u128 + 1` so the next call starts after the gap.
    if actual_u128 > start {
        store
            .advance_diversifier_to(account, actual_u128 + 1)
            .await?;
    }

    // Step 4: encode the payment address as a network-appropriate bech32 string.
    let sapling_bytes = addr.to_bytes();
    let bech32 = ZcashAddress::from_sapling(network.to_zcash_network(), sapling_bytes).encode();

    Ok((actual_di, addr, bech32))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors from zcash-hackworks/zcash-test-vectors (sapling_zip32.py),
    /// master key path "m", seed = bytes(range(32)) = [0x00, 0x01, ..., 0x1f].
    ///
    /// Oracle: the Python test-vector generator at
    ///   https://github.com/zcash-hackworks/zcash-test-vectors
    /// is independent of sapling-crypto and serves as the external oracle for
    /// these tests.
    const TV_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    /// d0: first valid diversifier for the master key with TV_SEED (index 0).
    const TV_D0: [u8; 11] = [
        0xd8, 0x62, 0x1b, 0x98, 0x1c, 0xf3, 0x00, 0xe9, 0xd4, 0xcc, 0x89,
    ];

    /// d1: valid diversifier at index 1.
    const TV_D1: [u8; 11] = [
        0x48, 0xea, 0x17, 0xa1, 0x99, 0xc8, 0x4b, 0xd1, 0xba, 0xa5, 0xd4,
    ];

    /// Default address diversifier matches the ZIP-32 test vector d0.
    ///
    /// Oracle: TV_D0 comes from sapling_zip32.py in zcash-hackworks/zcash-test-vectors,
    /// an independent implementation in Python.
    #[test]
    fn default_address_diversifier_matches_test_vector() {
        let esk = SaplingExtendedSpendingKey::master(&TV_SEED);
        let (_di, addr) = esk.default_address();
        assert_eq!(
            addr.diversifier().0,
            TV_D0,
            "default diversifier must match ZIP-32 test vector d0"
        );
    }

    /// find_address starting at index 1 returns d1.
    ///
    /// Oracle: TV_D1 comes from the same test-vector generator.
    #[test]
    fn find_address_at_index_1_returns_d1() {
        let esk = SaplingExtendedSpendingKey::master(&TV_SEED);
        let dfvk = esk.to_dfvk();
        let (di, addr) = dfvk.find_address(1).unwrap();
        assert_eq!(u128::from(di), 1, "valid diversifier must be at index 1");
        assert_eq!(
            addr.diversifier().0,
            TV_D1,
            "diversifier at index 1 must match ZIP-32 test vector d1"
        );
    }

    /// find_address with index ≥ 2^88 returns Err immediately (overflow guard).
    ///
    /// Oracle: the diversifier space is 11 bytes = 2^88 possible indices; anything
    /// at or above 2^88 is out of range by definition.
    #[test]
    fn find_address_overflow_index_returns_err() {
        let esk = SaplingExtendedSpendingKey::master(&TV_SEED);
        let dfvk = esk.to_dfvk();
        let result = dfvk.find_address(1u128 << 88);
        assert!(result.is_err(), "index >= 2^88 must return Err");
    }

    /// DFVK serialization roundtrips correctly.
    ///
    /// Oracle: re-derive the default address from the restored DFVK and compare
    /// to the original; if bytes mismatch the address derivation would differ.
    #[test]
    fn dfvk_roundtrip() {
        let esk = SaplingExtendedSpendingKey::master(&TV_SEED);
        let dfvk = esk.to_dfvk();
        let bytes = dfvk.to_bytes();
        let restored = SaplingDiversifiableFvk::from_bytes(&bytes)
            .expect("from_bytes must succeed for valid DFVK");
        let (_, addr1) = esk.to_dfvk().default_address();
        let (_, addr2) = restored.default_address();
        assert_eq!(
            addr1.to_bytes(),
            addr2.to_bytes(),
            "DFVK roundtrip must produce identical default address"
        );
    }

    /// from_seed correctly derives distinct keys for mainnet and testnet.
    ///
    /// Oracle: coin_type 133 vs 1 yields a different hardened derivation path,
    /// so the resulting default addresses must differ.
    #[test]
    fn from_seed_mainnet_testnet_differ() {
        let seed = [0u8; 64];
        let mainnet = SaplingExtendedSpendingKey::from_seed(&seed, ZcashNetwork::Mainnet, 0);
        let testnet = SaplingExtendedSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 0);
        let (_, addr_main) = mainnet.default_address();
        let (_, addr_test) = testnet.default_address();
        assert_ne!(
            addr_main.to_bytes(),
            addr_test.to_bytes(),
            "mainnet and testnet derivations must produce different addresses"
        );
    }

    /// from_seed account 0 and account 1 produce different addresses.
    ///
    /// Oracle: different hardened account indices in ZIP-32 path must yield
    /// independent keys and therefore different payment addresses.
    #[test]
    fn from_seed_different_accounts_differ() {
        let seed = [0u8; 64];
        let acc0 = SaplingExtendedSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 0);
        let acc1 = SaplingExtendedSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 1);
        let (_, addr0) = acc0.default_address();
        let (_, addr1) = acc1.default_address();
        assert_ne!(
            addr0.to_bytes(),
            addr1.to_bytes(),
            "different account indices must yield different payment addresses"
        );
    }
}
