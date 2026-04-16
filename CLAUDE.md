# nie (囁) — Project Instructions

Encrypted relay service with privacy coin payments. Users are public keys.
Messages are opaque blobs. The server is a paid pipe.

## Hard Design Invariants

These are load-bearing architectural properties, not style preferences.
Violating them changes the legal and threat posture of the project.

1. Server never holds encryption keys
2. Server never holds wallet keys or addresses beyond merchant invoices
3. Server never sees plaintext message content
4. Server never custodies user funds
5. Users are public keys only — no email, no phone, no KYC
6. Message payloads are opaque `Vec<u8>` to the relay by construction
7. P2P payment negotiation runs inside encrypted messages — relay is blind to it

**Legal anchor:** Wyoming LLC operator. Position: "We operate an encrypted
relay. We sell access. We cannot read messages or access funds because we
never possess either." Provably true by architecture.

## Build & Test

```bash
# Build everything
cargo build --workspace

# Run tests
cargo test --workspace

# Run relay (default: sqlite:nie-relay.db, port 3210)
cargo run --bin nie-relay

# Override relay config via env
DATABASE_URL=sqlite:test.db LISTEN_ADDR=127.0.0.1:3210 cargo run --bin nie-relay

# CLI quick start
cargo run --bin nie -- init
cargo run --bin nie -- whoami
cargo run --bin nie -- add bob <pubkey>
cargo run --bin nie -- chat bob
# Via Tor (socks5h:// recommended for .onion relay addresses)
cargo run --bin nie -- --proxy socks5h://127.0.0.1:9050 chat

# Two-instance smoke test (separate data dirs)
cargo run --bin nie -- --data-dir /tmp/alice init
cargo run --bin nie -- --data-dir /tmp/bob init
BOB=$(cargo run --bin nie -- --data-dir /tmp/bob whoami)
cargo run --bin nie -- --data-dir /tmp/alice add bob "$BOB"
cargo run --bin nie -- --data-dir /tmp/alice send bob "test"
```

## Quality Gates

Run all of these before committing:

```bash
cargo fmt --all                              # format; commit result if anything changes
cargo clippy --workspace -- -D warnings     # no warnings allowed
cargo test --workspace                      # all tests must pass
wasm-pack build --target web wasm/          # requires: cargo install wasm-pack
```

## Architecture

```
nie/
├── core/       nie-core (rlib): identity, auth, messages, protocol, transport
│               Will also build as cdylib for Android FFI (Phase 4).
├── relay/      nie-relay (bin): axum WebSocket server, SQLite store
└── cli/        nie-cli (bin): clap CLI, contact book, interactive chat
```

### nie-core modules

| Module | File | What it does |
|--------|------|--------------|
| Identity | `identity.rs` | Ed25519 keypair; `PubId` (base64 string) is the user's address |
| Auth | `auth.rs` | Challenge nonce generation and signature verification |
| Messages | `messages.rs` | `Envelope` (wire format) + `ClearMessage` (inside encrypted payload) |
| Protocol | `protocol.rs` | `RelayMessage` — all WebSocket message types |
| Transport | `transport.rs` | WebSocket client; performs auth handshake, returns channel pair |

### nie-relay modules

| Module | File | What it does |
|--------|------|--------------|
| Store | `store.rs` | SQLite: subscriptions + 72 h offline message queue |
| State | `state.rs` | `AppState`: live client map (DashMap), store handle |
| WS handler | `ws.rs` | Auth handshake, message routing, queue drain on reconnect |
| Main | `main.rs` | axum bootstrap; `DATABASE_URL` and `LISTEN_ADDR` env vars |

### nie-cli modules

| Module | File | What it does |
|--------|------|--------------|
| Config | `config.rs` | Data dir (`~/.local/share/nie/`), contact book JSON |
| Commands | `commands.rs` | init, whoami, add\_contact, list\_contacts, chat, send |
| Main | `main.rs` | clap CLI; `--data-dir` and `--keyfile` override flags |

### Wire protocol summary

```
Server → Client: Challenge { nonce }
Client → Server: Authenticate { pub_id, nonce, signature }
Server → Client: AuthOk { subscription_expires } | AuthFailed { reason }

Client → Server: Send(Envelope)
Server → Client: Deliver(Envelope) | SendAck { message_id }

Envelope { id: Uuid, from: PubId, to: String, timestamp, payload: Vec<u8> }
```

The relay forwards `payload` without deserializing it. Relay code requires
zero changes when MLS encryption replaces the current plaintext payloads.

### TLS architecture

TLS is **terminated at a reverse proxy** (Caddy or nginx). The relay binary
only speaks plain `ws://` on `127.0.0.1:3210`. This keeps OpenSSL / rustls
out of the relay process and allows cert renewal without restarting the relay.

```
Client (wss://)  ──▶  Caddy (TLS termination)  ──▶  nie-relay (ws:// 127.0.0.1:3210)
```

**Production** — one line in `deploy/Caddyfile`. Caddy auto-ACME from Let's Encrypt:

```caddy
relay.example.com {
    reverse_proxy 127.0.0.1:3210
}
```

**Local dev** — use mkcert to generate a locally-trusted cert (no `--insecure` flag):

```bash
./deploy/dev/mkcert-setup.sh          # installs mkcert CA + generates certs (once)
caddy run --config deploy/dev/Caddyfile
nie --relay wss://localhost:8443/ws chat bob
```

**Last-resort dev escape hatch** — `--insecure` skips cert verification entirely.
Only for raw self-signed certs without mkcert. Never in production:

```bash
nie --insecure --relay wss://localhost:8443/ws chat bob
```

The `--insecure` flag is hidden from `--help` output. Using it logs a `warn!`
at the start of every connection so it's visible in RUST_LOG=warn output.

## Phase Status

### Phase 1: Encrypted Relay + CLI Chat (plaintext pre-MLS)

Done:
- [x] Workspace structure (edition 2021, resolver 2)
- [x] Ed25519 identity (generate, export, restore)
- [x] Challenge-response auth
- [x] WebSocket relay with message routing
- [x] SQLite offline queue (72 h TTL)
- [x] Contact book
- [x] CLI subcommands: init, whoami, add, contacts, chat, send
- [x] `--data-dir` for multi-instance testing
- [x] Relay verifies `envelope.from == authenticated pub_id`
- [x] Slash command dispatcher (`/quit`, `/help`, `/pay` stub)

Remaining:
- [ ] MLS via `openmls` — replace plaintext payload with ciphertext
  - Key package publication endpoint on relay
  - Two-party group creation on first contact
  - Ratchet state persistence (client-side encrypted SQLite)
- [ ] Encrypted keyfile (passphrase + argon2 + xchacha20-poly1305 or `age`)
- [ ] Strict subscription gating in relay (currently permissive)

### Phase 2: Zcash wallet + P2P payments (not started)
### Phase 3: Subscription payments (not started)
### Phase 4: Android client / flutter_rust_bridge (not started)
### Phase 5: Multi-chain + polish (not started)

## Paranoid Defensive Programming

Every code change must satisfy this checklist. An agent reviewer should
work through it item by item. These are not style suggestions.

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
must validate `bytes.len() == 32` before constructing. A wrong-length read
must produce a descriptive error, not a panic.

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
Do not encode the nonce before signing or verifying — a format mismatch silently
fails verification and looks like a bug in the key code.

```rust
// WRONG — signs a different byte sequence than the verifier expects
let sig = identity.sign(nonce.as_bytes().to_base64().as_bytes());

// CORRECT — matches what verify_challenge() checks
let sig = identity.sign(nonce.as_bytes());
```

`verify_challenge()` returning `Ok(pub_id)` is the **only** path that produces
a trusted `PubId`. Any `PubId` that was not returned by `verify_challenge()` is
unauthenticated. Never trust a `PubId` that came directly from a wire message
without going through verification.

### 3. Envelope payload is opaque — relay must never deserialize it

This is the core architectural invariant. The relay's `Deliver` path must
never call `serde_json::from_slice`, `String::from_utf8`, `std::str::from_utf8`,
or any deserialization function on `envelope.payload`.

```rust
// WRONG — breaks the architecture, violates invariant #3 and #7
let msg: ClearMessage = serde_json::from_slice(&envelope.payload)?;

// CORRECT — forward the opaque bytes unchanged
let deliver = RelayMessage::Deliver(envelope);
state.deliver_live(&to, deliver).await;
```

If you find yourself wanting to inspect the payload in relay code, you are
in the wrong layer. `ClearMessage` deserialization belongs in the client only.

### 4. Sender identity enforcement

The relay must verify `envelope.from.0 == authenticated_pub_id.0` on every
`RelayMessage::Send`. This check is in `relay/src/ws.rs`. Do not remove it,
weaken it, or add a code path that bypasses it.

Without this check, any authenticated user can set `from` to any other user's
PubId and send spoofed messages that recipients have no way to detect.

```rust
// WRONG — removed the check "for simplicity"
Ok(RelayMessage::Send(envelope)) => {
    let to = envelope.to.clone();
    state.deliver_live(&to, RelayMessage::Deliver(envelope)).await;
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
tag string will compile fine but silently produce JSON that no client can parse,
or worse, silently match the wrong variant on deserialization.

| Enum | Tag field | Example serialized |
|------|-----------|--------------------|
| `RelayMessage` | `"type"` | `{"type":"challenge","nonce":"..."}` |
| `ClearMessage` | `"type"` | `{"type":"chat","text":"..."}` |
| `PaymentAction` | `"action"` | `{"action":"request","chain":"zcash","amount":"0.1"}` |
| `Chain` | (unit, `lowercase`) | `"zcash"` \| `"monero"` \| `"mobilecoin"` |

When adding a variant, verify the serialized form manually with a `dbg!` or test:

```rust
// Add this as a test, delete before committing
let msg = RelayMessage::Challenge { nonce: "test".into() };
println!("{}", serde_json::to_string(&msg).unwrap());
// Must produce: {"type":"challenge","nonce":"test"}
```

### 6. PubId format and comparison

`PubId` is **not** the raw public key. It is `hex(SHA-256(verifying_key_bytes))`:
64 lowercase hex characters. See `identity.rs` `hash_key()`.

`PubId` equality is string equality on `.0`. Two PubIds are equal iff
`a.0 == b.0`. The string is always 64 lowercase hex chars — no padding,
no base64 alphabet involved.

**You cannot reconstruct a `VerifyingKey` from a `PubId`** — it is a
one-way hash. The wire auth message carries the raw public key bytes
(base64-encoded) separately. `verify_challenge()` decodes those bytes,
constructs the `VerifyingKey`, then derives the `PubId` by hashing:

```rust
// In auth.rs — the ONLY trusted path to a PubId
pub fn verify_challenge(pub_key_b64: &str, nonce: &str, sig_b64: &str) -> Result<PubId> {
    let key_bytes = B64.decode(pub_key_b64)?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("pub key wrong length"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)?;
    // ... verify signature ...
    Ok(Identity::hash_key(&key)) // PubId = hex(SHA-256(key_bytes))
}
```

A `PubId` that did not come from `verify_challenge()` is unauthenticated.
Never trust a `PubId` sourced directly from a wire message field.

### 7. Uuid serialization

`Envelope.id` is `Uuid`, serialized as a **hyphenated lowercase string**
(`"550e8400-e29b-41d4-a716-446655440000"`) by the `uuid` crate's serde feature.
`SendAck.message_id` is `String` — it holds the result of `envelope.id.to_string()`.

```rust
// WRONG — comparing hex form to hyphenated form
assert_eq!(ack.message_id, format!("{:032x}", envelope.id.as_u128()));

// CORRECT
assert_eq!(ack.message_id, envelope.id.to_string());
```

### 8. Channel / task failure discipline

`mpsc::Sender::send()` returns `Err` when the receiver is dropped. In `ws.rs`
this means the client disconnected — treat it as a clean exit, not a relay error.
Do not propagate it as a `RelayMessage::Error` to other clients.

```rust
// WRONG — sends error to unrelated clients when one disconnects
if client_tx.send(msg).await.is_err() {
    state.deliver_live(&pub_id.0, RelayMessage::Error { ... }).await;
}

// CORRECT — treat channel close as disconnect, clean up silently
if client_tx.send(msg).await.is_err() {
    break; // client is gone
}
```

Spawned tasks that panic do not propagate to the spawner. If you need to
know whether a background task died, keep and `.await` its `JoinHandle`.

`write_task.abort()` in `ws.rs` drops buffered messages to the disconnecting
client. This is intentional. Do not replace it with a graceful drain — a
disconnected client does not need its outbox flushed.

### 9. SQLite datetime invariant

The store uses `datetime('now')` for all comparisons. Every value written
to `expires_at` or `created_at` must be SQLite-compatible UTC datetime
(`YYYY-MM-DD HH:MM:SS`). Do not store:
- RFC 3339 strings with timezone offsets (`2026-04-16T12:00:00+00:00`)
- Unix timestamps (`1713268800`)
- Chrono `DateTime<Utc>` `.to_rfc3339()` output (includes `T` and `Z`)

SQLite's `datetime()` function compares these as strings. A wrong format
produces silently incorrect `expires_at > datetime('now')` comparisons where
valid subscriptions appear expired or expired messages are never purged.

```sql
-- WRONG stored value: "2026-04-16T12:00:00Z" (RFC 3339)
-- CORRECT stored value: "2026-04-16 12:00:00"
-- How to get it: datetime('now', '+3 days') in the INSERT — already done correctly.
```

### 10. Drain-then-deliver is not atomic

`store.drain()` deletes messages from the queue and returns them in one
operation. If delivery fails after drain, those messages are gone — there is
no retry. This is acceptable Phase 1 behavior. Do not "fix" it by adding retry
logic without first thinking through at-least-once semantics and filing a beads
issue. The correct fix is at-least-once delivery with client-side acking.

### 11. `unwrap()` policy

`serde_json::to_string(&T)` where `T: Serialize` with only derived `Serialize`
cannot fail. The `unwrap()` calls in `ws.rs` on relay message serialization are
intentionally unreachable. Do not replace them with `?` (wrong return type) or
`expect("should serialize")` (no improvement). Leave them as `unwrap()`.

`serde_json::from_str::<RelayMessage>()` on **client input** can and does fail.
These are `warn!` + `continue` in the read loop — intentional. A client sending
garbage gets ignored, not disconnected. Do not promote these to errors.

Any new `unwrap()` in a production code path requires a comment:

```rust
// serde_json::to_string on a derived Serialize cannot fail
let json = serde_json::to_string(&msg).unwrap();
```

Undocumented unwraps are bugs waiting for an input that triggers them.

### 12. Payment and wallet rules (Phases 2–3, not yet implemented)

When wiring in:

- `PaymentAction::Address` must generate a **fresh subaddress** on every call.
  Never return a cached address. Reuse breaks payment unlinkability.
- Payment negotiation messages are ordinary `Envelope`s with opaque payloads.
  The relay routes them identically to chat. Do not add payment-specific routing
  — you cannot distinguish them from the relay side, and that is intentional.
- The subscription merchant wallet generates an invoice address, watches the
  chain, and calls `store.set_subscription()`. It must never hold more in-flight
  value than the current invoice. No pooling, no batching, no conversion.
- `store.set_subscription()` is the **only** write path to subscription state.
  Do not update subscription expiry anywhere else.

### 13. MLS insertion point (Phase 1 → Phase 2 transition)

When MLS lands, the only files that should change are in `nie-core` and `nie-cli`.
The relay must not change at all. The abstraction boundary is `Envelope.payload: Vec<u8>`.

```
Before MLS:  ClearMessage → serde_json::to_vec → payload
After MLS:   ClearMessage → MLS encrypt → ciphertext → payload
```

If a planned MLS change requires modifying `relay/src/ws.rs` or `relay/src/store.rs`,
stop and reconsider. The design is wrong if the relay needs to know about encryption.

MLS key packages (published so peers can initiate groups) are **unauthenticated
lookup data** — any user should be able to fetch anyone's key package without auth.
Design the relay endpoint accordingly.

### 14. Test oracle discipline

Acceptable oracles for nie tests:

| Algorithm | Oracle |
|-----------|--------|
| Ed25519 sign/verify | Sign with key A, verify with A's `PubId` — valid roundtrip test |
| Auth challenge | Sign with known key, verify rejection with wrong nonce and wrong key |
| Envelope routing | Two live CLI instances exchange a known message end-to-end |
| MLS (when added) | openmls own test vectors, or interop with another MLS implementation |

**Never acceptable:** encrypt/sign with function X, decrypt/verify with function X,
and assert the output matches the input. That proves the encode/decode roundtrip,
not correctness. Tests that survive only because they use the code under test as
their own oracle will pass even when the implementation is completely wrong.

Auth tests must include rejection cases. A test suite that only verifies the happy
path is half a test suite.

## Wallet Security

These rules apply to all code that touches the Zcash wallet (Phase 2+).
They are not style preferences — violations break privacy or legal posture.

### Key separation invariant

`identity.key` (Ed25519 seed, 32 bytes) and `wallet.key` (ZIP-32 master key,
64 bytes) MUST be derived from independent entropy.  A runtime assertion in
`wallet_init` checks that the wallet spending key differs from the identity seed.
Never derive one from the other.  Compromise of one must not compromise the other.

### Never log wallet key material

`WalletMasterKey` deliberately does not implement `Debug`.  Never add it.
Never log or print `spending_key`, `chain_code`, or any derived key bytes
(incoming viewing key IVK, full viewing key FVK, outgoing viewing key OVK).
Log only public information: addresses, tx hashes, amounts.

```rust
// WRONG — leaks key material to tracing output
tracing::debug!("wallet key: {:?}", master);

// CORRECT — log only public-facing info
tracing::debug!("wallet initialized for network: {network}");
```

### Fresh subaddress per payment

`PaymentAction::Address` responses MUST generate a fresh Sapling subaddress on
every call.  Never reuse addresses.  Address reuse:
- Links multiple payments to the same entity (breaks shielded unlinkability)
- Weakens the "no custody" legal argument (reuse implies tracking)

### Memo field contents (ZIP-302)

The ZIP-302 shielded memo field (512 bytes) is visible to anyone who holds the
incoming viewing key (IVK).  For nie payments, populate the memo with the
`session_id` UUID so the payee can match the tx to a session even if app state
is lost.  Do not put secrets, PII, or user-identifiable data in the memo.

### Network guard

Wallet commands check `wallet.json` network against the `--network` CLI flag.
`check_network_guard()` in `commands.rs` enforces this.  A testnet wallet MUST
NOT be usable on mainnet (different address formats, different chain ID).
On mismatch, display a clear error: "This wallet was created for testnet."

### wallet.key format

- 64 bytes: BIP-39 seed (PBKDF2-HMAC-SHA512 of the 24-word mnemonic with empty passphrase)
- This is the input to `SaplingExtendedSpendingKey::from_seed` and `OrchardSpendingKey::from_seed`.
  Do NOT store or pass the ZIP-32 master key here — `from_seed` applies the BLAKE2b derivation
  internally; passing the already-derived master key would double-derive and produce wrong addresses.
- Encrypted with the `age` format using a user passphrase (same as identity.key)
- Never stored unencrypted on disk, never logged, never sent over the wire

## Security Design Rules

- **Never log key material.** `Identity`, `SigningKey`, raw secret bytes — none of
  these may appear in tracing output. (See item 1 of the checklist above.)
- **Relay verifies sender identity.** `ws.rs` rejects any `Send(envelope)` where
  `envelope.from != authenticated_pub_id`. (See item 4 above.) Do not remove it.
- **No custody paths.** The relay must not hold, escrow, convert, or otherwise
  touch user funds. This is not a policy rule — it is a legal constraint.
- **Opaque payload.** The relay's `Deliver` path must never deserialize
  `Envelope.payload`. (See item 3 above.)
- **Per-invoice addresses.** Each subscription renewal gets a fresh address.
  Address reuse reduces privacy and weakens the "no custody" argument.

## MLS Admin Election Invariant

`online[0]` (the first element of the client's `online: Vec<String>`) is the MLS
group admin — the one who creates the group and issues Commit + Welcome for new members.

This invariant is maintained by three pieces working together:

1. **Relay** stamps every `UserJoined` event with a monotonic `sequence: u64` from
   `AppState::connection_seq()`. Lower sequence = connected earlier this session.
2. **Relay** sends `DirectoryList.online` sorted ascending by `connection_seq()`.
3. **Client** inserts `UserJoined` events into `online` at the position that maintains
   ascending sequence order (`partition_point`), so `online[0]` is always the peer
   with the globally-lowest connection sequence.

**Do not break this invariant.** Specifically:
- Do not sort `online` for display purposes in place — sort a copy.
- Do not append on `UserJoined`; use `partition_point` to insert in order.
- Do not remove the `sequence` field from `UserInfo` or `UserJoined`.
- Do not change the relay to sort `DirectoryList.online` by any other key.

A violation causes all peers to independently elect different admins, which leads
to concurrent MLS group creation and epoch collisions — messages become undecryptable.

## MLS KeyPackageReady Ordering Guarantee

`ws.rs` broadcasts `KeyPackageReady` **only after** `save_key_package()` succeeds.
This creates a happens-before edge: any `GetKeyPackage` sent in response to this
notification is guaranteed to find the stored data.

A contributor might suggest broadcasting immediately (before the `await`) to reduce
latency. **Do not do that.** The async store write completes asynchronously; a
concurrent `GetKeyPackage` could arrive before the write commits, returning `None`
and silently failing to add the new member — no error, no retry, no user feedback.

## MLS KP Republication on UserJoined

When a new admin joins, existing members have already published their key packages and
the relay has them, but the `KeyPackageReady` broadcasts happened before the admin
arrived and were not replayed. The solution: **existing members republish their key
package on every `UserJoined` while `!mls_active`**. When the new admin appears, all
pre-existing members emit a `UserJoined{admin}` event that triggers republication,
generating fresh `KeyPackageReady` events the admin receives and acts on.

A contributor may try to add KP replay on connect (relay replays stored `KeyPackageReady`
events to newly-connected clients). **Do not do that.** The republication approach keeps
the relay stateless about KP delivery; replay logic in the relay would need to track
delivery state per-client, complicating the relay and coupling it to the add-member
protocol.

## `/!` Shell Injection Boundary

`/!` uses `shlex::split` then `Command::new(&argv[0]).args(&argv[1..])` instead of
`sh -c`. This means shell metacharacters (`|`, `;`, `&&`, `$()`, `>`) in the user's
command string are passed **literally** to the program rather than being interpreted.

A contributor may suggest `Command::new("sh").arg("-c").arg(cmd_str)` for full shell
support. **Do not do that.** `/!` sends output to all chat participants; shell injection
(e.g. `/! echo hi; cat ~/.ssh/id_rsa`) would exfiltrate secrets over the room. The
`shlex` path is an explicit injection boundary. If users need pipelines, they should
compose them in a wrapper script and run that.

## Stress Test Two-Barrier Design

`relay/tests/stress.rs` uses two `Barrier`s:

1. **`start_barrier`** — no client sends until all N have received `DirectoryList`.
   Ensures every `Broadcast` reaches exactly N−1 recipients, making the assertion
   `received == sent * (N-1)` exact with no timing dependency.
2. **`done_barrier`** — no client drains until every client has finished sending.
   Prevents the race where a late message arrives at a peer that has already
   closed its drain window.

A contributor may suggest collapsing to one barrier or using a fixed `sleep`.
**Do not do that.** The two-barrier design was added after the first run showed
missing messages from low-jitter clients that sent before all N clients had
connected. Both barriers are load-bearing; removing either reintroduces that
race and makes the assertion flaky under load.

## Agent Interaction Rules

**Fail fast, report up.** If a shell command fails twice with the same error,
stop and report the exact error to the user with context. Do not try variants.
A repeated failure means your model of the problem is wrong.

**Map once, then act.** Use `Glob`/`Grep` to find files before editing.
Do not re-explore the same area once you have a plan.

**Confirm scope for multi-file changes.** Before touching more than three files,
state which files will change and why.

**Comprehensive options when clarifying.** When asking the user to choose between
approaches, list the realistic options explicitly. Open-ended questions waste a
round trip and often produce a misaligned answer.

**Sources of truth for this project:**

| What you need | Where to look |
|---|---|
| Project intent and constraints | `nie-brief.md` |
| Wire protocol types | `core/src/protocol.rs`, `core/src/messages.rs` |
| Identity and signing | `core/src/identity.rs`, `core/src/auth.rs` |
| Relay routing logic | `relay/src/ws.rs` |
| Offline queue | `relay/src/store.rs` |
| CLI commands | `cli/src/commands.rs` |
| Proxy / SOCKS5 transport | `core/src/transport.rs` |
| Open work items | `bd ready` / `bd list` |

## Non-Interactive Shell Commands

Shell commands `cp`, `mv`, `rm` may be aliased to interactive (`-i`) on this
system. Always use force flags to avoid hanging on y/n prompts:

```bash
cp -f src dst           # not: cp src dst
mv -f src dst           # not: mv src dst
rm -f file              # not: rm file
rm -rf dir              # not: rm -r dir
cp -rf src dst          # not: cp -r src dst
ssh -o BatchMode=yes    # fail instead of prompting for password
```

## Task Tracking (Beads)

```bash
bd ready                  # find available work
bd show <id>              # view issue details
bd update <id> --claim    # claim before starting
bd close <id>             # mark complete
```

Run `bd prime` for the full workflow reference and session-close protocol.

## Session Completion

**Mandatory sequence** when ending a session:

```bash
cargo fmt --all && cargo clippy --workspace -- -D warnings && cargo test --workspace
bd close <completed-ids>
git pull --rebase
bd dolt push
git status
```

git commit and git push require explicit user approval — report what is ready and wait.


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
