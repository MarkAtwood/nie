# nie (囁) — Project Brief

Encrypted relay service with privacy coin payments. Paid-Slack model plus in-band user-to-user value transfer. Non-custodial by architecture.

## Core Thesis

Users pay a subscription in privacy coins to access an E2E encrypted comm service and can transfer value to each other inside chat. The operator has zero access to message content and zero custody of funds. Both properties are enforced by architecture, not policy.

## Hard Constraints (Non-Negotiable)

1. Server never holds encryption keys
2. Server never holds wallet keys or addresses beyond merchant invoices
3. Server never sees plaintext message content
4. Server never custodies user funds (no escrow, no platform credits, no conversion)
5. No order book, no matching, no exchange functionality
6. Users are public keys, not identities. No email, no phone, no KYC
7. Message payloads are opaque to the relay by construction

These constraints are what keep the operator outside FinCEN money-transmitter classification. Custodial variants are legally radioactive (MSB registration, 47+ state licenses, BSA/AML, millions in compliance). Don't go there.

## Legal Posture

Wyoming LLC as operator. Position:

> We operate an encrypted relay. We sell access. We cannot read messages or access funds because we never possess either. Users conduct peer-to-peer transactions on public blockchains with their own client-side wallets. We have no ability to comply with requests for message content or financial data because we do not possess either.

Provably true by architecture. That is the point.

## Architecture

Three components, one protocol.

```
nie-core    Rust library. Identity, message types, auth, transport, wallet, MLS.
            Builds as rlib (for CLI) and cdylib (for Android FFI).
nie-relay   Server. WebSocket relay, SQLite store, subscription gating.
nie-cli     CLI/TUI client. ratatui eventually.
android/    Flutter app. Thin UI shell over client-core via flutter_rust_bridge.
```

### Server Responsibilities (Exhaustive)

1. Challenge-response auth (prove ownership of a pub key)
2. Route encrypted blobs between authenticated pub keys
3. Queue encrypted blobs for offline recipients (72h TTL, then drop)
4. Track subscription expiry per pub key
5. Generate per-invoice payment addresses, watch chain for confirmation, update subscription state

### Server Explicitly Does NOT

- Store plaintext messages (never has them)
- Store encryption keys or wallet keys
- Know payment amounts between users
- Know who is paying whom (P2P payment negotiation is inside encrypted channels)
- Maintain identity beyond a public key

### Client Responsibilities

- Keypair generation and storage (encrypted local)
- MLS group state and ratcheting
- Message encrypt/decrypt
- Wallet key storage per chain
- Transaction construction and signing (local)
- Transaction broadcast to chain (direct, not through relay)
- Payment negotiation protocol (runs inside encrypted messages)
- Local message history (encrypted SQLite)

## Protocol

### Identity

Ed25519 keypair. Public key (base64-encoded, 44 chars) is the user's sole identifier. Optional self-chosen display handles, not unique, not verified.

### Auth (Challenge-Response)

```
Server -> Client: Challenge { nonce }
Client -> Server: Authenticate { pub_id, nonce, signature }
Server -> Client: AuthOk { subscription_expires } | AuthFailed { reason }
```

### Envelope (Wire Format)

```
Envelope {
  id: Uuid,
  from: PubId,
  to: PubId,         // DM recipient or channel ID
  timestamp: DateTime<Utc>,
  payload: Vec<u8>,  // opaque ciphertext. Relay cannot read.
}
```

Relay sees: sender pubkey, recipient pubkey, blob size, timestamp. That's the entire metadata surface. Padding + cover traffic for metadata resistance is a v2 concern.

### Message Types (Inside Encrypted Payload)

Decrypted client-side only. Relay never sees these deserialized.

- `Chat { text }` — plain text messages
- `Payment { action: Request | Address | Sent | Confirmed }` — P2P payment negotiation
- `Ack { ref_id }` — message acknowledgement

### Payment Flow (User-to-User, In-Band)

All four steps are encrypted messages. Relay cannot distinguish a payment negotiation from a meme exchange.

```
1. Alice -> Bob: PaymentAction::Request { chain, amount }
2. Bob   -> Alice: PaymentAction::Address { chain, address }   // fresh subaddress
3. Alice constructs + signs tx locally, broadcasts to chain network directly
4. Alice -> Bob: PaymentAction::Sent { chain, tx_hash, amount }
5. Bob's client watches chain, detects receipt
6. Bob   -> Alice: PaymentAction::Confirmed { tx_hash }
```

### Subscription Payment

The one place the server legitimately interacts with a blockchain, as a merchant.

```
1. Client: SubscribeRequest { chain }
2. Server generates per-invoice address, replies SubscribeInvoice { chain, address, amount, expires }
3. Client pays from own wallet (or any external wallet)
4. Server's payment watcher confirms the tx
5. Server updates subscription state keyed by pub_id
6. Server: SubscriptionActive { expires }
```

No identity required. Public key + proof of payment = access.

## Tech Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Server | Rust, axum | Memory-safe, fast, well-known |
| E2E crypto | MLS via `openmls` | Audited, forward secrecy, post-compromise security |
| Transport | WebSocket (tokio-tungstenite) | Bidirectional, simple, standard |
| Identity | ed25519-dalek | Small keys, fast verify |
| Server store | SQLite via sqlx | Subscription state + message queue. Postgres later if needed. |
| Zcash wallet | `zcash_client_backend` (Zashi's stack) | Best Rust tooling, Orchard support |
| Monero wallet | `monero-rs` | Light client mode, remote node |
| MobileCoin wallet | `mc-full-service` SDK | Only option, thin ecosystem |
| Subscription payments | BTCPay Server (XMR + ZEC) or custom Rust watchers | Battle-tested for XMR/ZEC |
| Client local store | SQLite + `sqlcipher` or `age` encryption | Encrypted at rest |
| Client crypto/protocol | Rust `nie-core` as rlib + cdylib | One core, multiple frontends |
| Android frontend | Flutter + `flutter_rust_bridge` | Cross-compile Rust, Dart UI shell |
| TUI frontend | ratatui | Fast to build, no framework overhead |

## Build Phases

### Phase 1: Encrypted Relay + CLI Chat (no payments)

Done as scaffold:
- Workspace structure, three crates
- Ed25519 identity (generate, export, restore)
- Challenge-response auth
- WebSocket relay with message routing
- SQLite subscription + message queue tables
- 72h TTL offline queue
- Contact book (`~/.local/share/nie/contacts.json`)
- CLI subcommands: init, whoami, add, contacts, chat, send
- Interactive line-mode chat

Still needed in Phase 1:
- [ ] MLS integration (`openmls`): replace plaintext payloads with encrypted
  - Key package publishing (where? possibly via relay as unauthenticated lookup)
  - Two-party group setup on first contact
  - Ratchet state persistence client-side
- [ ] Slash command parser in chat loop (`/pay`, `/balance`, `/subscribe`, `/export-key`, `/quit`)
- [ ] Encrypted local storage for identity keyfile (currently stored plaintext, needs passphrase)
- [ ] Strict subscription gating in relay (currently permissive for testing)

### Phase 2: Zcash Wallet + P2P Payments

- [ ] Add `zcash_client_backend` + `zcash_client_sqlite` to `nie-core`
- [ ] Ship Sapling + Orchard proving keys (or download on first run)
- [ ] Expose wallet API in core: `balance()`, `new_shielded_address()`, `build_tx()`, `broadcast_tx()`, `watch_for_receipt()`
- [ ] Connect to public lightwalletd (testnet first) with option for self-hosted
- [ ] Implement payment negotiation state machine in `nie-core`
- [ ] CLI commands: `/pay <contact> <amount>`, `/balance`, `/receive`
- [ ] Persistent wallet state (encrypted SQLite via sqlcipher)

### Phase 3: Subscription Payments

- [ ] Payment watcher daemon: poll zcashd RPC or lightwalletd
- [ ] Per-invoice address generation (server-side merchant wallet)
- [ ] Invoice TTL + cleanup
- [ ] Wire `SubscribeRequest` / `SubscribeInvoice` / `SubscriptionActive` in relay
- [ ] Consider: BTCPay Server as alternative (faster path, less custom code)

### Phase 4: Android Client

- [ ] Add `flutter_rust_bridge` bindings to `nie-core`
- [ ] Cross-compile for `aarch64-linux-android` and `armv7-linux-androideabi`
- [ ] Flutter app structure: chat screen, contacts, wallet, settings
- [ ] Key backup UI (passphrase-encrypted export)
- [ ] Background service for message delivery / payment watching
- [ ] Verify protocol parity with CLI (both should interop on same relay)

### Phase 5: Multi-Chain + Polish

- [ ] Monero integration (`monero-rs`, light wallet mode)
- [ ] MobileCoin integration (only if demand materializes; ecosystem is near-zero)
- [ ] TUI upgrade (ratatui) replacing line mode
- [ ] Metadata resistance: envelope padding, delivery delay buckets
- [ ] Group chat (beyond DMs)
- [ ] Federation (probably not — single-operator model is cleaner)

## Design Decisions Already Made

- **Ed25519 over X25519 for identity.** Sign-first, derive X25519 for MLS if needed. Keeps identity stable across key rotations.
- **Opaque envelope payload.** Relay treats it as `Vec<u8>`. Zero changes to relay when MLS drops in.
- **Per-invoice subscription addresses.** Don't reuse addresses. Each subscription renewal gets a fresh one.
- **Offline queue TTL is short (72h).** The relay is not a mailbox. If the recipient is dead for 3 days, the message is gone. Sender can resend.
- **No federation in v1.** Single relay operator. Simpler trust model, simpler protocol.
- **Pub ID display truncation.** First 8 chars + ellipsis for human-readable display. Full key for verification.
- **Payment flow lives inside encrypted messages.** Server is architecturally blind to payment negotiation. This is the key legal property — server cannot be compelled to produce payment records it does not possess.

## Anti-Features (Things We Do Not Build)

- Custody. Ever. Not even 5 seconds of "processing" custody.
- Conversion between coins.
- Fiat on/off-ramp.
- Order books or matching.
- Identity verification, KYC, phone/email tie-ins.
- Server-side search or indexing.
- Plaintext fallback modes.
- "Compliance" hooks (backdoors).
- Group admin controls that require server trust.

## Known Threat Model Notes

- **Relay operator adversarial.** Design assumes relay could be compromised, subpoenaed, or malicious. Architecture prevents relay from reading content or accessing funds regardless of operator intent.
- **Metadata still leaks.** Who-talks-to-whom is visible to the relay. Cover traffic and padding are v2.
- **Endpoint compromise unaddressed.** If an attacker owns the device, they own the keys. Standard mobile security caveats apply.
- **Regulatory reclassification risk.** FinCEN could decide UX facilitation = transmission. Legal theory exists, no enforcement yet.
- **Privacy coin availability.** Delisting trend continues. Zcash has broader listings than Monero; MobileCoin is effectively illiquid.

## Rough Directory Layout

```
nie/
├── Cargo.toml              # workspace root
├── README.md
├── core/
│   ├── Cargo.toml          # rlib + cdylib
│   └── src/
│       ├── lib.rs
│       ├── identity.rs     # Ed25519 keypair, PubId
│       ├── auth.rs         # challenge-response helpers
│       ├── protocol.rs     # RelayMessage enum (wire protocol)
│       ├── messages.rs     # Envelope + ClearMessage + PaymentAction
│       ├── transport.rs    # WebSocket client + handshake
│       ├── mls.rs          # TODO: openmls wrapper
│       ├── wallet.rs       # TODO: zcash_client_backend integration
│       ├── storage.rs      # TODO: encrypted local state
│       └── ffi.rs          # TODO: flutter_rust_bridge bindings
├── relay/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs         # axum bootstrap
│       ├── state.rs        # AppState, client registry
│       ├── store.rs        # SQLite: subscriptions, message queue
│       ├── ws.rs           # WebSocket handler, auth, routing
│       └── payments.rs     # TODO: chain watcher for subscription payments
├── cli/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs         # clap subcommands
│       ├── config.rs       # data dir, contact book
│       ├── commands.rs     # init, whoami, add, chat, send, ...
│       └── tui.rs          # TODO: ratatui interface
└── android/                # TODO: Flutter project, Phase 4
```

## Workspace Cargo.toml (Deps Already Chosen)

```toml
[workspace]
members = ["relay", "core", "cli"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"

[workspace.dependencies]
nie-core = { path = "core" }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow = "1"
thiserror = "2"
ed25519-dalek = { version = "2", features = ["serde", "rand_core"] }
rand = "0.8"
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite"] }
axum = { version = "0.8", features = ["ws"] }
tokio-tungstenite = "0.26"
futures = "0.3"
base64 = "0.22"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4", "serde"] }
```

## Naming

Project: **nie** (from 囁, Chinese "whisper")
CLI binary: `nie`
Server binary: `nie-relay`
Crate names: `nie-core`, `nie-relay`, `nie-cli`

## First Tasks for Claude Code

In priority order:

1. **Verify scaffold builds clean.** `cargo build --workspace`. Fix any dep version conflicts or edition 2024 issues. (Edition 2024 is new; fall back to 2021 if it causes trouble.)
2. **Two-instance interop smoke test.** Run the relay, run two CLI instances on different keyfiles, verify DM flow works end-to-end with plaintext payloads.
3. **Wire up MLS.** Add `openmls` + `openmls_rust_crypto` to core. Design key package publication (likely: store pub key packages in relay's SQLite, fetched via an unauthenticated lookup endpoint). Implement two-party group creation on first contact. Replace plaintext payloads in CLI with MLS ciphertext. Relay code should require zero changes.
4. **Slash command parser.** Extract chat loop into a command dispatcher. Implement `/quit`, `/help`, `/contacts`. Leave `/pay` stub.
5. **Encrypted keyfile storage.** Add passphrase prompt on init, encrypt with `age` or argon2 + xchacha20poly1305. Prompt on every CLI invocation (or add a session-cache flag).
6. **Start on Zcash wallet.** Spike: get `zcash_client_backend` compiling in `nie-core`, connect to public testnet lightwalletd, fetch balance of a generated address. This is the gnarliest dependency; prove it compiles cleanly before building features on top.

## References

- openmls: https://github.com/openmls/openmls
- zcash_client_backend: https://github.com/zcash/librustzcash
- Zashi (reference client): https://electriccoin.co/zashi/
- flutter_rust_bridge: https://github.com/fzyzcjy/flutter_rust_bridge
- ratatui: https://github.com/ratatui/ratatui
- BTCPay Server (alt subscription path): https://btcpayserver.org/
