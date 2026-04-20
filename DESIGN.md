# nie — Architecture and Design Invariants

This document describes the load-bearing design decisions for nie. These are
not style preferences. Changing them changes the system's security properties.

See also: `nie-brief.md` for the project brief; `README.md` for operator and
user documentation.

## Hard Design Invariants

1. Server never holds encryption keys
2. Server never holds wallet keys or addresses beyond merchant invoices
3. Server never sees plaintext message content
4. Server never custodies user funds
5. Users are public keys only — no email, no phone, no KYC
6. Message payloads are opaque `Vec<u8>` to the relay by construction
7. P2P payment negotiation runs inside encrypted messages — relay is blind to it

## Architecture

```
nie/
├── core/       nie-core (rlib): identity, auth, messages, protocol, transport, MLS
├── relay/      nie-relay (bin): axum WebSocket server, SQLite store
├── cli/        nie-cli (bin): clap CLI, rustyline chat, contact book
├── tui/        nie-tui (bin): ratatui terminal UI
├── daemon/     nie-daemon (bin): HTTP API + WebSocket event server
├── bot/        nie-bot (bin): headless scripting client
├── wallet/     nie-wallet (rlib): Zcash Sapling wallet, lightwalletd client
└── wasm/       nie-wasm (cdylib): browser WebAssembly client
```

### nie-core modules

| Module | File | What it does |
|--------|------|--------------|
| Identity | `identity.rs` | Ed25519 keypair; `PubId` = hex(SHA-256(verifying_key)) |
| Auth | `auth.rs` | Challenge nonce generation and signature verification |
| Messages | `messages.rs` | `ClearMessage` (inside encrypted payload), envelope padding |
| Protocol | `protocol.rs` | All JSON-RPC 2.0 method types |
| Transport | `transport.rs` | WebSocket client; auth handshake, channel pair |
| MLS | `mls.rs` | `MlsClient`: group create/join, encrypt, decrypt |
| HPKE | `hpke.rs` | Sealed sender: HPKE encrypt/decrypt for relay-blind sends |

### nie-relay modules

| Module | File | What it does |
|--------|------|--------------|
| Store | `store.rs` | SQLite: subscriptions, offline queue, key packages, groups |
| State | `state.rs` | `AppState`: live client map, connection sequencing |
| WS handler | `ws.rs` | Auth handshake, message routing, queue drain on reconnect |
| Payment watcher | `payment_watcher.rs` | IVK trial-decrypt, subscription activation |
| Main | `main.rs` | axum bootstrap, env var config |

### Wire protocol

JSON-RPC 2.0 over WebSocket.

```
Server → Client: Challenge { nonce }
Client → Server: Authenticate { pub_key_b64, nonce, signature }
Server → Client: AuthOk { subscription_expires } | AuthFailed { reason }

Client → Server: { jsonrpc, id, method: "broadcast", params: { payload: [u8] } }
Server → Client: notification method: "deliver", params: { from, payload: [u8] }
```

The relay forwards `payload` without deserializing it. The abstraction boundary
is `payload: Vec<u8>` — adding MLS encryption required zero relay changes.

### TLS

TLS is terminated at a reverse proxy (Caddy or nginx). The relay binary speaks
plain `ws://` on `127.0.0.1:3210` only.

```
Client (wss://)  ──▶  Caddy (TLS termination)  ──▶  nie-relay (ws:// 127.0.0.1:3210)
```

## Defensive Programming Checklist

Every code change must satisfy the following. These are not style suggestions.

### 1. Key material handling

`Identity` wraps `SigningKey` which is deliberately not `Debug`. Never add
`#[derive(Debug)]` to `Identity` or any struct that directly contains a
`SigningKey`. Never log, print, or include in error strings the output of
`identity.secret_bytes()`, the `SigningKey`, or any derived key bytes.

```rust
// WRONG — leaks key material to tracing output
tracing::debug!("identity loaded: {:?}", identity);

// CORRECT — log only the public side
tracing::debug!("identity loaded: {}", identity.pub_id());
```

Keyfile on disk is raw 32 bytes, no encoding, no header. `load_identity()`
must validate `bytes.len() == 32` before constructing.

```rust
// WRONG
let bytes: [u8; 32] = std::fs::read(keyfile)?.try_into().unwrap();

// CORRECT
let bytes: [u8; 32] = std::fs::read(keyfile)?
    .try_into()
    .map_err(|_| anyhow::anyhow!("keyfile corrupt: expected 32 bytes"))?;
```

### 2. Signature verification discipline

The auth challenge signs the nonce **as raw UTF-8 bytes** (`nonce.as_bytes()`).
Do not encode the nonce before signing or verifying.

```rust
// WRONG
let sig = identity.sign(nonce.as_bytes().to_base64().as_bytes());

// CORRECT
let sig = identity.sign(nonce.as_bytes());
```

`verify_challenge()` returning `Ok(pub_id)` is the **only** path that produces
a trusted `PubId`. Never trust a `PubId` sourced directly from a wire message.

### 3. Envelope payload is opaque — relay must never deserialize it

The relay's `Deliver` path must never call `serde_json::from_slice`,
`String::from_utf8`, `std::str::from_utf8`, or any deserialization function
on `payload`.

```rust
// WRONG
let msg: ClearMessage = serde_json::from_slice(&payload)?;

// CORRECT
state.deliver_live(&to, payload).await;
```

`ClearMessage` deserialization belongs in the client only.

### 4. Sender identity enforcement

The relay must verify `envelope.from == authenticated_pub_id` on every
`Send`. This check is in `relay/src/ws.rs`. Do not remove it, weaken it,
or add a code path that bypasses it.

```rust
// WRONG
Ok(RelayMessage::Send(envelope)) => {
    state.deliver_live(&to, envelope).await;
}

// CORRECT
Ok(RelayMessage::Send(envelope)) => {
    if envelope.from.0 != pub_id.0 {
        warn!("spoofed from field from {pub_id}");
        continue;
    }
    // ... proceed
}
```

### 5. Serde tag discipline

All enums use `#[serde(tag = ...)]`. Adding a new variant without the correct
tag string will compile fine but silently produce undecodable JSON.

| Enum | Tag field | Example |
|------|-----------|---------|
| `ClearMessage` | `"type"` | `{"type":"chat","text":"..."}` |
| `PaymentAction` | `"action"` | `{"action":"request","chain":"zcash","amount":"0.1"}` |
| `Chain` | (unit, `lowercase`) | `"zcash"` \| `"monero"` |

### 6. PubId format and comparison

`PubId` is `hex(SHA-256(verifying_key_bytes))` — 64 lowercase hex chars.
It is a one-way hash; you cannot reconstruct the `VerifyingKey` from it.
`verify_challenge()` is the only trusted path to a `PubId`.

### 7. Uuid serialization

`Envelope.id` is `Uuid`, serialized as a hyphenated lowercase string
(`"550e8400-e29b-41d4-a716-446655440000"`).

```rust
// CORRECT
assert_eq!(ack.message_id, envelope.id.to_string());
```

### 8. Channel / task failure discipline

`mpsc::Sender::send()` returning `Err` means the client disconnected — treat
it as a clean exit, not a relay error. Do not propagate it to other clients.

`write_task.abort()` drops buffered messages to the disconnecting client.
This is intentional. Do not replace it with a graceful drain.

### 9. SQLite datetime invariant

Every value written to `expires_at` or `created_at` must be SQLite-compatible
UTC datetime (`YYYY-MM-DD HH:MM:SS`). Do not store RFC 3339 strings, Unix
timestamps, or `DateTime<Utc>.to_rfc3339()` output.

```sql
-- WRONG: "2026-04-16T12:00:00Z"
-- CORRECT: "2026-04-16 12:00:00"
```

### 10. Drain-then-deliver is not atomic

`store.drain()` deletes messages and returns them in one operation. If delivery
fails after drain, those messages are gone. Do not add retry logic without
designing at-least-once semantics and filing a tracking issue first.

### 11. `unwrap()` policy

`serde_json::to_string(&T)` where `T: Serialize` with derived `Serialize`
cannot fail. Leave these as `unwrap()`. Every other `unwrap()` in production
code requires an explanatory comment.

```rust
// serde_json::to_string on a derived Serialize cannot fail
let json = serde_json::to_string(&msg).unwrap();
```

### 12. Payment and wallet rules

- `PaymentAction::Address` must generate a **fresh subaddress** on every call.
  Never cache or reuse. Reuse breaks address unlinkability.
- Payment negotiation travels as ordinary opaque `Envelope` payloads.
  Do not add payment-specific routing to the relay.
- `store.set_subscription()` is the **only** write path to subscription state.

### 13. MLS insertion point

When MLS changes are needed, only `nie-core` and client code should change.
The relay must not change. The boundary is `payload: Vec<u8>`.

If a planned change requires modifying `relay/src/ws.rs` for encryption
reasons, stop — the design is wrong.

MLS key packages are unauthenticated lookup data; any user may fetch them
without auth.

### 14. Test oracle discipline

Never use the code under test as its own oracle. Acceptable oracles:

| Algorithm | Oracle |
|-----------|--------|
| Ed25519 sign/verify | Sign with key A, verify with A's `PubId` |
| Auth challenge | Verify rejection with wrong nonce and wrong key |
| Envelope routing | Two live instances exchange a known message |
| MLS | openmls test vectors, or interop with another MLS implementation |

Auth tests must include rejection cases.

## Wallet Security

### Key separation

`identity.key` (Ed25519 seed, 32 bytes) and `wallet.key` (BIP-39 seed, 64 bytes)
MUST be derived from independent entropy. Never derive one from the other.

### Key material logging

`WalletMasterKey` does not implement `Debug`. Never add it. Never log
`spending_key`, `chain_code`, IVK, FVK, or OVK. Log only addresses, tx hashes,
and amounts.

### Fresh subaddress per payment

Every `PaymentAction::Address` response MUST generate a new Sapling subaddress.
Never reuse addresses. Reuse links payments and breaks shielded unlinkability.

### Memo field (ZIP-302)

Populate with the `session_id` UUID only. No secrets, no PII.

### wallet.key format

64 bytes: BIP-39 seed (PBKDF2-HMAC-SHA512 of the mnemonic, empty passphrase).
Input to `SaplingExtendedSpendingKey::from_seed` — do NOT pass the ZIP-32
master key; `from_seed` applies BLAKE2b internally. Encrypted with `age` on disk.

### Network guard

A testnet wallet must not be usable on mainnet. `check_network_guard()` in
`commands.rs` enforces this at startup.

## MLS Admin Election Invariant

`online[0]` is the MLS group admin. Maintained by:

1. Relay stamps `UserJoined` with a monotonic `sequence: u64`.
2. Relay sends `DirectoryList.online` sorted ascending by `connection_seq()`.
3. Client inserts `UserJoined` at `partition_point` to maintain ascending order.

Do not sort `online` in place, append on `UserJoined`, remove `sequence`, or
change the relay sort key. A violation causes split-brain admin election and
undecryptable messages.

## MLS KeyPackageReady Ordering

`ws.rs` broadcasts `KeyPackageReady` only **after** `save_key_package()` succeeds.
Do not broadcast before the `await` — a concurrent `GetKeyPackage` could arrive
before the write commits and silently fail to add the new member.

## MLS KP Republication on UserJoined

Existing members republish their key package on every `UserJoined` while
`!mls_active`. This ensures a newly-arrived admin sees fresh `KeyPackageReady`
events. Do not add relay-side KP replay — it would couple the relay to the
add-member protocol.

## `/!` Shell Injection Boundary

`/!` uses `shlex::split` + `Command::new(&argv[0]).args(&argv[1..])`, not
`sh -c`. Shell metacharacters are passed literally. Do not change this to
`sh -c` — `/!` output goes to all room participants.

## Stress Test Two-Barrier Design

`relay/tests/stress.rs` uses two barriers:

1. `start_barrier` — no client sends until all N have `DirectoryList`.
2. `done_barrier` — no client drains until all N have finished sending.

Both are load-bearing. Do not collapse to one or replace with `sleep`.
