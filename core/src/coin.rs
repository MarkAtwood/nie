//! Abstract payment coin interface.
//!
//! `CoinWallet` provides a common interface for different payment chains
//! (Zcash, Monero, etc.) so the payment protocol layer stays coin-agnostic.
//!
//! The minimal interface here is intentionally small: receiving an address for
//! a session, and a stub for sending.  Full implementations that integrate with
//! chain-specific daemons/nodes live in their respective crates (`nie-wallet`
//! for Zcash, `nie-monero` for Monero).

use anyhow::Result;
use uuid::Uuid;

use crate::messages::Chain;

/// Abstract interface for a payment coin wallet.
///
/// Implementors provide the chain-specific operations needed for the nie
/// payment protocol.  The protocol itself (session negotiation, PaymentAction
/// message routing) is chain-agnostic; only the address generation and payment
/// submission differ per coin.
pub trait CoinWallet: Send + Sync {
    /// Which chain this wallet operates on.
    fn chain(&self) -> Chain;

    /// Generate a unique receive address for the given payment session.
    ///
    /// The address is derived deterministically from `session_id` so that
    /// repeated calls with the same session return the same address.  This
    /// allows wallets to recognize which session an incoming payment belongs to.
    fn receive_address(&self, session_id: Uuid) -> Result<String>;

    /// Submit a payment of `amount_atomic` atomic units to `address`.
    ///
    /// `amount_atomic` is in the smallest unit for this chain:
    /// - Zcash: zatoshi (1 ZEC = 10^8 zatoshi)
    /// - Monero: piconero (1 XMR = 10^12 piconero)
    ///
    /// Returns `Err` if sending is not supported or fails.  Implementations
    /// without a live daemon connection should return `Err` with a descriptive
    /// message.
    fn send_payment(&self, amount_atomic: u64, address: &str) -> Result<()>;

    /// Human-readable name for the coin (e.g. "Zcash Sapling", "Monero").
    fn coin_name(&self) -> &'static str;
}

/// A no-op wallet stub that always returns errors.
///
/// Useful as a placeholder during integration tests or when a chain is not
/// yet configured.
pub struct UnimplementedWallet {
    chain: Chain,
}

impl UnimplementedWallet {
    pub fn new(chain: Chain) -> Self {
        Self { chain }
    }
}

impl CoinWallet for UnimplementedWallet {
    fn chain(&self) -> Chain {
        self.chain
    }

    fn receive_address(&self, _session_id: Uuid) -> Result<String> {
        anyhow::bail!("wallet not configured for {:?}", self.chain)
    }

    fn send_payment(&self, _amount_atomic: u64, _address: &str) -> Result<()> {
        anyhow::bail!("wallet not configured for {:?}", self.chain)
    }

    fn coin_name(&self) -> &'static str {
        "unimplemented"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Chain;

    #[test]
    fn unimplemented_wallet_chain_returns_correct_chain() {
        let w = UnimplementedWallet::new(Chain::Monero);
        assert_eq!(w.chain(), Chain::Monero);
    }

    #[test]
    fn unimplemented_wallet_receive_address_returns_err() {
        let w = UnimplementedWallet::new(Chain::Zcash);
        let result = w.receive_address(Uuid::new_v4());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("wallet not configured"));
    }

    #[test]
    fn unimplemented_wallet_send_payment_returns_err() {
        let w = UnimplementedWallet::new(Chain::Zcash);
        let result = w.send_payment(1000, "test_address");
        assert!(result.is_err());
    }
}
