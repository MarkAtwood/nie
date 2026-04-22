//! nie-monero — Monero wallet primitives for the nie payment bridge.
//!
//! Provides key generation, address derivation, and per-session subaddress
//! derivation for the Monero chain.  Transaction sending and blockchain
//! scanning require a running Monero daemon and are out of scope here.
//!
//! # Key model
//!
//! A Monero wallet is two Ed25519 scalars:
//! - **Spend key** (`b`): authorizes spending outputs
//! - **View key** (`a`): independently random; detects incoming transactions
//!
//! Generating both keys independently (rather than deriving the view key from
//! the spend key via Keccak-256) is cryptographically sound.  The wallet
//! cannot be recovered from a single mnemonic seed, but for nie's use case
//! (generating disposable receive addresses) this is acceptable.

use anyhow::{bail, Result};
use monero::cryptonote::subaddress;
use monero::util::address::Address;
use monero::util::key::{KeyPair, PrivateKey, ViewPair};
use monero::Network;
use nie_core::coin::CoinWallet;
use nie_core::messages::Chain;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Which Monero network to use.
///
/// Stagenet is recommended for integration testing — testnet wallets are
/// harder to fund, but stagenet faucets exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoneroNetwork {
    Mainnet,
    Stagenet,
    Testnet,
}

impl From<MoneroNetwork> for Network {
    fn from(n: MoneroNetwork) -> Network {
        match n {
            MoneroNetwork::Mainnet => Network::Mainnet,
            MoneroNetwork::Stagenet => Network::Stagenet,
            MoneroNetwork::Testnet => Network::Testnet,
        }
    }
}

/// Monero wallet: spend key bytes, view key bytes, primary address, and network.
///
/// # Security
///
/// `spend_key_bytes` and `view_key_bytes` are 32-byte little-endian Ed25519
/// scalars.  Both are sensitive — store them encrypted and never log them.
/// This type intentionally does NOT implement `Debug` to prevent accidental
/// logging of key material.
#[derive(Clone, Serialize, Deserialize)]
pub struct MoneroKeys {
    /// 32-byte spend key scalar (secret — never log).
    pub spend_key_bytes: [u8; 32],
    /// 32-byte view key scalar (secret).
    pub view_key_bytes: [u8; 32],
    /// Primary address for this wallet (public — safe to share).
    pub primary_address: String,
    /// Network these keys belong to.
    pub network: MoneroNetwork,
}

impl MoneroKeys {
    /// Generate a fresh random wallet on `network`.
    ///
    /// Uses the OS CSPRNG.  Both spend and view keys are independently random
    /// scalars, which is cryptographically sound.  Retries internally if the
    /// random bytes happen to be a zero scalar (probability ≈ 2⁻²⁵²).
    pub fn generate(network: MoneroNetwork) -> Self {
        loop {
            let mut spend_bytes = [0u8; 32];
            let mut view_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut spend_bytes);
            rand::thread_rng().fill_bytes(&mut view_bytes);
            if let Ok(keys) = Self::from_key_bytes(spend_bytes, view_bytes, network) {
                return keys;
            }
            // Retry on the astronomically unlikely zero-scalar case.
        }
    }

    /// Build a wallet from raw 32-byte spend and view key scalars.
    ///
    /// Returns `Err` if either byte slice is not a valid reduced Ed25519 scalar.
    pub fn from_key_bytes(
        spend_bytes: [u8; 32],
        view_bytes: [u8; 32],
        network: MoneroNetwork,
    ) -> Result<Self> {
        let spend = PrivateKey::from_slice(&spend_bytes)
            .map_err(|e| anyhow::anyhow!("invalid spend key: {e}"))?;
        let view = PrivateKey::from_slice(&view_bytes)
            .map_err(|e| anyhow::anyhow!("invalid view key: {e}"))?;

        let view_pair = build_view_pair(spend, view);
        let primary = Address::from_viewpair(network.into(), &view_pair);

        Ok(Self {
            spend_key_bytes: spend_bytes,
            view_key_bytes: view_bytes,
            primary_address: primary.to_string(),
            network,
        })
    }

    /// Derive the unique subaddress at `(major, minor)` index.
    ///
    /// Index `(0, 0)` is defined by the Monero protocol as the primary address.
    pub fn subaddress(&self, major: u32, minor: u32) -> Result<String> {
        let view_pair = self.view_pair()?;
        let index = subaddress::Index { major, minor };
        let addr = subaddress::get_subaddress(&view_pair, index, Some(self.network.into()));
        Ok(addr.to_string())
    }

    /// Generate a unique receive address for a nie payment session.
    ///
    /// The session_id UUID maps to a subaddress minor index via its first 4
    /// bytes interpreted as a little-endian u32, masked to 31 bits to stay
    /// well within the valid range.  Major index is always 0.
    ///
    /// Returns the same address for the same session_id (deterministic).
    pub fn address_for_session(&self, session_id: Uuid) -> Result<String> {
        let b = session_id.as_bytes();
        let minor = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) & 0x7FFF_FFFF;
        self.subaddress(0, minor)
    }

    fn view_pair(&self) -> Result<ViewPair> {
        let spend = PrivateKey::from_slice(&self.spend_key_bytes)
            .map_err(|e| anyhow::anyhow!("invalid spend key in MoneroKeys: {e}"))?;
        let view = PrivateKey::from_slice(&self.view_key_bytes)
            .map_err(|e| anyhow::anyhow!("invalid view key in MoneroKeys: {e}"))?;
        Ok(build_view_pair(spend, view))
    }

    /// Reconstruct the full keypair (needed for spending with a Monero daemon).
    pub fn keypair(&self) -> Result<KeyPair> {
        let spend = PrivateKey::from_slice(&self.spend_key_bytes)
            .map_err(|e| anyhow::anyhow!("invalid spend key: {e}"))?;
        let view = PrivateKey::from_slice(&self.view_key_bytes)
            .map_err(|e| anyhow::anyhow!("invalid view key: {e}"))?;
        Ok(KeyPair { view, spend })
    }
}

fn build_view_pair(spend: PrivateKey, view: PrivateKey) -> ViewPair {
    let keypair = KeyPair { view, spend };
    ViewPair::from(&keypair)
}

/// Parse and validate a Monero address string for the given network.
///
/// Returns `Err` if the string is malformed or belongs to a different network.
pub fn parse_address(s: &str, network: MoneroNetwork) -> Result<Address> {
    let addr: Address = s
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid Monero address: {e}"))?;
    let expected: Network = network.into();
    if addr.network != expected {
        bail!("address is for {:?}, expected {:?}", addr.network, expected);
    }
    Ok(addr)
}

/// `CoinWallet` implementation for the Monero chain.
///
/// Uses `MoneroKeys` to derive per-session subaddresses.  Transaction sending
/// requires a running Monero daemon (monerod / monero-wallet-rpc) and is not
/// yet implemented — `send_payment` returns `Err` with a clear message.
pub struct MoneroCoinWallet {
    keys: MoneroKeys,
}

impl MoneroCoinWallet {
    pub fn new(keys: MoneroKeys) -> Self {
        Self { keys }
    }
}

impl CoinWallet for MoneroCoinWallet {
    fn chain(&self) -> Chain {
        Chain::Monero
    }

    fn receive_address(&self, session_id: Uuid) -> Result<String> {
        self.keys.address_for_session(session_id)
    }

    fn send_payment(&self, _amount_atomic: u64, _address: &str) -> Result<()> {
        anyhow::bail!("Monero sending requires a running daemon; not yet implemented")
    }

    fn coin_name(&self) -> &'static str {
        "Monero"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Primary address is 95 characters for Monero mainnet standard addresses.
    ///
    /// Oracle: Monero address specification — a standard address encodes
    /// 1-byte prefix + 32-byte spend pubkey + 32-byte view pubkey + 4-byte
    /// checksum = 69 raw bytes → 95 Monero Base58 characters.
    #[test]
    fn mainnet_primary_address_is_95_chars() {
        let keys = MoneroKeys::generate(MoneroNetwork::Mainnet);
        assert_eq!(
            keys.primary_address.len(),
            95,
            "mainnet primary address must be 95 chars, got {}",
            keys.primary_address.len()
        );
    }

    /// Mainnet standard addresses begin with '4'.
    ///
    /// Oracle: Monero address specification — mainnet prefix byte is 18 (0x12),
    /// which maps to '4' in Monero's Base58 alphabet.
    #[test]
    fn mainnet_primary_address_starts_with_4() {
        let keys = MoneroKeys::generate(MoneroNetwork::Mainnet);
        assert!(
            keys.primary_address.starts_with('4'),
            "mainnet address must start with '4', got: {}",
            &keys.primary_address[..1]
        );
    }

    /// Stagenet standard addresses begin with '5'.
    ///
    /// Oracle: Monero address specification — stagenet prefix byte is 24 (0x18).
    #[test]
    fn stagenet_primary_address_starts_with_5() {
        let keys = MoneroKeys::generate(MoneroNetwork::Stagenet);
        assert!(
            keys.primary_address.starts_with('5'),
            "stagenet address must start with '5', got: {}",
            &keys.primary_address[..1]
        );
    }

    /// Two independently generated wallets have different primary addresses.
    #[test]
    fn generate_produces_unique_wallets() {
        let a = MoneroKeys::generate(MoneroNetwork::Mainnet);
        let b = MoneroKeys::generate(MoneroNetwork::Mainnet);
        assert_ne!(a.primary_address, b.primary_address);
        assert_ne!(a.spend_key_bytes, b.spend_key_bytes);
    }

    /// Subaddress at (0, 0) uses the subaddress address type (prefix '8' on mainnet),
    /// which is distinct from the primary standard address (prefix '4').
    ///
    /// Oracle: monero crate behavior — `get_subaddress` always returns an
    /// `AddressType::SubAddress` even at index (0,0).  The primary address uses
    /// `AddressType::Standard`.  They encode different public keys and differ.
    #[test]
    fn subaddress_zero_zero_differs_from_primary() {
        let keys = MoneroKeys::generate(MoneroNetwork::Mainnet);
        let sub = keys.subaddress(0, 0).unwrap();
        // The subaddress format prefix ('8') differs from standard ('4').
        assert!(
            sub.starts_with('8'),
            "subaddress(0,0) must use subaddress format starting with '8'"
        );
        assert_ne!(sub, keys.primary_address);
    }

    /// Subaddress at (0, 1) differs from (0, 0) and from primary; all are 95 characters.
    ///
    /// Oracle: Monero address specification — both standard and subaddress
    /// addresses encode to 95 Monero Base58 characters (69 raw bytes).
    #[test]
    fn subaddress_nonzero_differs_and_is_95_chars() {
        let keys = MoneroKeys::generate(MoneroNetwork::Mainnet);
        let sub = keys.subaddress(0, 1).unwrap();
        let sub0 = keys.subaddress(0, 0).unwrap();
        assert_ne!(sub, keys.primary_address);
        assert_ne!(sub, sub0);
        assert_eq!(
            sub.len(),
            95,
            "mainnet subaddress must be 95 chars, got {}",
            sub.len()
        );
    }

    /// address_for_session is deterministic: same session_id → same address.
    #[test]
    fn address_for_session_is_deterministic() {
        let keys = MoneroKeys::generate(MoneroNetwork::Mainnet);
        let sid = Uuid::new_v4();
        let a = keys.address_for_session(sid).unwrap();
        let b = keys.address_for_session(sid).unwrap();
        assert_eq!(a, b);
    }

    /// Two different session_ids produce different addresses (with overwhelming probability).
    #[test]
    fn address_for_session_differs_per_session() {
        let keys = MoneroKeys::generate(MoneroNetwork::Mainnet);
        // Use fixed session IDs with distinct first 4 bytes so they map to different minor indices.
        let sid1 = Uuid::from_bytes([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let sid2 = Uuid::from_bytes([0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let a = keys.address_for_session(sid1).unwrap();
        let b = keys.address_for_session(sid2).unwrap();
        assert_ne!(a, b);
    }

    /// from_key_bytes is deterministic: same input → same primary address.
    ///
    /// Oracle: address derivation is a pure function of the key bytes.
    /// Uses scalar 1 (spend) and scalar 2 (view): small little-endian values
    /// that are definitively < l (Ed25519 group order) and pass the monero
    /// crate's canonical-scalar check.
    #[test]
    fn from_key_bytes_is_deterministic() {
        // Scalar 1 in little-endian (the minimum non-zero valid scalar).
        let mut spend = [0u8; 32];
        spend[0] = 1;
        let mut view = [0u8; 32];
        view[0] = 2;
        let k1 = MoneroKeys::from_key_bytes(spend, view, MoneroNetwork::Mainnet).unwrap();
        let k2 = MoneroKeys::from_key_bytes(spend, view, MoneroNetwork::Mainnet).unwrap();
        assert_eq!(k1.primary_address, k2.primary_address);
    }

    /// Known key bytes produce a valid 95-character mainnet address.
    ///
    /// Oracle: scalar 1 and scalar 2 are valid reduced scalars; their
    /// corresponding public keys combine into a well-formed standard address.
    #[test]
    fn known_key_bytes_produce_valid_address() {
        let mut spend = [0u8; 32];
        spend[0] = 1;
        let mut view = [0u8; 32];
        view[0] = 2;
        let keys = MoneroKeys::from_key_bytes(spend, view, MoneroNetwork::Mainnet).unwrap();
        assert_eq!(keys.primary_address.len(), 95);
        assert!(keys.primary_address.starts_with('4'));
    }

    /// MoneroCoinWallet::chain() returns Chain::Monero.
    #[test]
    fn monero_coin_wallet_chain_is_monero() {
        use nie_core::coin::CoinWallet;
        use nie_core::messages::Chain;
        let wallet = MoneroCoinWallet::new(MoneroKeys::generate(MoneroNetwork::Mainnet));
        assert_eq!(wallet.chain(), Chain::Monero);
    }

    /// MoneroCoinWallet::coin_name() returns "Monero".
    #[test]
    fn monero_coin_wallet_name_is_monero() {
        use nie_core::coin::CoinWallet;
        let wallet = MoneroCoinWallet::new(MoneroKeys::generate(MoneroNetwork::Mainnet));
        assert_eq!(wallet.coin_name(), "Monero");
    }

    /// MoneroCoinWallet::receive_address is deterministic for the same session_id.
    #[test]
    fn monero_coin_wallet_receive_address_is_deterministic() {
        use nie_core::coin::CoinWallet;
        let wallet = MoneroCoinWallet::new(MoneroKeys::generate(MoneroNetwork::Mainnet));
        let sid = Uuid::new_v4();
        let a = wallet.receive_address(sid).unwrap();
        let b = wallet.receive_address(sid).unwrap();
        assert_eq!(a, b);
    }

    /// MoneroCoinWallet::send_payment returns Err (daemon not available).
    #[test]
    fn monero_coin_wallet_send_payment_returns_err() {
        use nie_core::coin::CoinWallet;
        let wallet = MoneroCoinWallet::new(MoneroKeys::generate(MoneroNetwork::Mainnet));
        let result = wallet.send_payment(1_000_000_000, "fake_address");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("daemon"));
    }
}
