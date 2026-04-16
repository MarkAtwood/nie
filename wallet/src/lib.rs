// nie-wallet: Zcash wallet backend for the nie encrypted relay.
//
// This crate holds all Zcash-specific wallet logic that does not belong in
// nie-core (identity/relay) or nie-cli (user interaction).
//
// Phase 2 planned modules:
// - keys    — ZIP-32 HD key derivation (account 0 spending key, FVK, IVK, OVK)
// - address — Sapling/Orchard address generation (fresh subaddress per payment)
// - db      — SQLite schema: notes, witnesses, tx history, payment sessions
// - client  — lightwalletd gRPC compact-block scanner
//
// Key separation invariant:
// The ZIP-32 master key in wallet.key and the Ed25519 identity key in identity.key
// are derived from independent entropy sources.  This crate never imports or reads
// identity.key.  See nie-core::wallet and CLAUDE.md §Wallet Security.

pub mod address;
pub mod client;
pub mod db;
pub mod fees;
pub mod memo;
pub mod orchard;
pub mod params;
pub mod payment;
pub mod scanner;
pub mod sync_guard;
pub mod tx_builder;
pub mod tx_error;
pub mod unified;
