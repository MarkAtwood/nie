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

### Wire format breaking changes

`PaymentAction::Request` and `PaymentAction::Sent` carried `amount: String`
(e.g. `"0.1"`) in early builds. This field was renamed to `amount_zatoshi: u64`
(e.g. `10000000`). Old clients that send the string form will be rejected by new
clients (serde returns an error on missing required field `amount_zatoshi`). There
is no negotiation or fallback — the change requires a coordinated upgrade.

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

The relay `AppState` / `Inner` / `MerchantWallet` structs intentionally do **not**
derive `Debug`. `MerchantWallet` holds a `SaplingDiversifiableFvk` (full viewing
key — can see all incoming transactions). Never add `#[derive(Debug)]` to these
structs or any wrapper that transitively contains a viewing key or HPKE secret.
A `tracing::debug!("{:?}", state)` would silently leak the DFVK to the log.

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

## Anti-Spam PoW Enrollment

Before a new public key can authenticate for the first time, the relay requires
a proof-of-work token. This raises the per-account compute cost without any PII
requirement.

### Token format (versioned, stable API)

31 bytes, base64url-encoded:

```
ver u8 | op_type u8 | ts_floor u32 (big-endian) | diff u8 | nonce u64 (big-endian) | h16 [u8; 16]
```

- `ver`: always `0x01` for this version
- `op_type`: `0x01` for enrollment
- `ts_floor`: `unix_ts / 60` (minute granularity)
- `diff`: number of required leading zero bits (minimum 20; relay rejects tokens below floor)
- `h16`: first 16 bytes of `double_sha256(hash_context || nonce_be64)`

### Hash context

```
double_sha256(ver || op_type || ts_floor_be32 || diff || hex_lower(ed25519_pub_bytes) || server_salt_bytes)
```

`server_salt` is a random 32-byte value generated at relay startup and held in
`AppState`. It is not persisted — restart invalidates all pre-mined tokens.

### Invariants

- Minimum difficulty is 20 bits. Relay must reject any token claiming `diff < 20`.
  Do not lower this floor without a security review.
- Staleness window: `abs(now/60 - ts_floor) > 10` is stale and must be rejected.
  A ±600-second window prevents pre-mining while tolerating clock skew.
- Replay prevention: `h16` must be checked against an in-memory set (TTL = 600s)
  before acceptance. Do not skip this check — without it, a valid token can be
  replayed indefinitely within the staleness window.
- Difficulty is stored in `AppState` and is adjustable at runtime without restart.
  Clients must fetch the current difficulty from the challenge before mining.
- The token format is a client-facing protocol API. Changing field widths or
  ordering is a breaking change requiring a version bump in `ver`.

### Error response

Reject with `AuthFailed { reason: "pow_required" | "pow_invalid" | "pow_stale" | "pow_replayed" }`.

## Rate Limiting

Subscribed clients are rate-limited on outgoing broadcasts. The limit applies
per `pub_id` within a rolling window.

### Scope

Rate-limited methods: `broadcast`, `sealed_broadcast`, `group_send`.

Exempt: `whisper`, `sealed_whisper` (addressed 1:1, natural per-hop cost), all
read and auth methods (`get_key_package`, `get_group_info`, `auth`, and similar).

### Parameters

- Default: 120 messages per 60-second window (configurable via `RATE_LIMIT_MSG_PER_MIN`)
- Keyed by `pub_id`: each authenticated identity has its own counter
- Window: rolling 60-second window. `window_start` is recorded on the first message;
  the counter resets when 60 seconds have elapsed since `window_start`
- State: in-process `DashMap<pub_id, (count, window_start)>` in `AppState`
- No persistence — counters reset on relay restart. This is intentional; persistent
  rate state would require careful migration and adds complexity for marginal gain.

### Error code

Exceeded limit returns JSON-RPC error `{ "code": -32020, "message": "RATE_LIMITED" }`.

`-32020` is a stable wire contract. Do not change it — clients are expected
to branch on this code and back off accordingly.

## Legal Transparency

nie's threat model anticipates legal demands. The relay holds minimal data by
design; transparency about what was demanded and what was produced deters
speculative requests.

### What the relay can produce under compulsion

Exactly this, and nothing else (see Hard Design Invariants §1–6):

| Field | Source |
|-------|--------|
| `pub_id` | hex(SHA-256(verifying_key)) — a hash, not the key |
| `first_seen` | timestamp of first successful authentication |
| `subscription_expires` | subscription expiry timestamp |

The relay does not store IP addresses, message content, payment addresses beyond
merchant invoices, or any identifying information beyond the above.

### Transparency log

Published at `GET /transparency` as JSON and rendered HTML. Each entry records:
sequential ID, requesting entity, demand type, date received, status, and a
link to the redacted response. The log is append-only and operator-maintained.

Every received demand must be logged regardless of outcome. Do not suppress
entries for demands that were successfully challenged or refused.

### Operator billing policy

If 18 USC 2706 applies (US-based relay), bill the requesting agency the
statutory research fee before producing any records. Document this policy in
`LEGAL.md`.

## Display Name Canonicalization

This is a security invariant, not optional. User-supplied display names are
visible to all connected clients in `DirectoryList` and group listings. Without
enforcement they are attack surfaces for bidi spoofing (U+202E renders
`groupname` as `emanpuorg`), homoglyph attacks (Cyrillic `е` vs Latin `e`),
and zero-width confusion (invisible bytes make two byte-distinct names appear
identical).

### Enforcement

`canonicalize_display_name` in `relay/src/ws.rs` applies the following steps
**before storage and before broadcast**, in order:

1. **NFC Unicode normalization** — defeats canonical homoglyph variants.
2. **Reject bidirectional control characters with an error** — any of
   U+202A, U+202B, U+202C, U+202D, U+202E, U+2066, U+2067, U+2068, U+2069,
   U+200E, U+200F causes the request to be rejected.
3. **Strip zero-width characters silently** — U+200B, U+200C, U+2060, U+FEFF are
   removed without error. (U+FEFF is the BOM / zero-width no-break space; it can
   appear in copy-pasted text from BOM-emitting applications.)
4. **Trim** leading and trailing whitespace.
5. **Length check** — post-strip length must be 1–32 characters (by Unicode
   scalar count). Empty or over-length results are rejected with an error.

### Scope

Applies to both `SET_NICKNAME` and `GROUP_CREATE`. Does not apply to `payload`
fields — those are opaque encrypted blobs and must not be touched.

## Offline Queue TTL — Known Limitation

The current purge query is:

```sql
DELETE FROM offline_messages WHERE expires_at < ?
```

This performs a full row scan and delete, which is acceptable for SQLite at
current message volumes. At high throughput (millions of queued messages),
partition-based TTL via `DROP TABLE offline_messages_YYYY_MM_DD` would be
O(1) DDL instead of O(n) row scan.

SQLite does not support table partitioning natively. Revisit this if/when the
relay migrates to Postgres and message volume makes the scan measurably slow.
Until then, do not add complexity to the purge path.
