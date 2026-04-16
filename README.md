# nie (囁)

Encrypted relay chat with privacy coin payments. The server is a paid pipe — it routes opaque blobs between public keys and cannot read messages or touch funds.

## What it is

- **Identity = Ed25519 public key.** No email, no phone, no username registration.
- **Messages = opaque ciphertext.** The relay forwards `Vec<u8>` without deserializing.
- **Payments = peer-to-peer, in-band.** Payment negotiation happens inside encrypted messages; the relay is architecturally blind to it.
- **Subscription = proof of payment, not identity.** A public key plus on-chain confirmation grants access.

Current status: Phase 1 complete — relay, MLS-encrypted CLI chat, offline message queue, rustyline line editing with command history.

## Building

Requires Rust (stable, 2021 edition). No other system dependencies beyond a C compiler (for SQLite).

```bash
cargo build --workspace
```

Binaries land in `target/debug/`: `nie-relay` and `nie`.

## Running the relay

### Quickstart (dev)

```bash
cargo run --bin nie-relay
```

Listens on `0.0.0.0:3210`, creates `nie-relay.db` in the current directory.

### Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:nie-relay.db?mode=rwc` | SQLite path |
| `LISTEN_ADDR` | `0.0.0.0:3210` | Bind address and port |
| `KEEPALIVE_SECS` | `30` | WebSocket ping interval |
| `REQUIRE_SUBSCRIPTION` | `false` | Gate broadcasts on active subscription |

```bash
DATABASE_URL=sqlite:/var/lib/nie/relay.db \
LISTEN_ADDR=127.0.0.1:3210 \
cargo run --bin nie-relay
```

### Production TLS

The relay speaks plain `ws://` only. TLS is terminated at a reverse proxy. With [Caddy](https://caddyserver.com/) (auto-ACME from Let's Encrypt):

```bash
# edit deploy/Caddyfile — replace relay.example.com with your domain
caddy run --config deploy/Caddyfile
```

The relay behind Caddy becomes `wss://relay.example.com/ws`.

## Python client (no install required)

For a quick connection without building Rust, `nie-py.py` is a single-file Python client that uses only the standard library (Python 3.11+).

```bash
# Get the script
curl -O https://raw.githubusercontent.com/MarkAtwood/nie/main/nie-py.py

# Connect to a relay
python3 nie-py.py --relay wss://relay.example.com/ws

# Or run against a local relay
python3 nie-py.py
```

On first run it generates `identity.key` in the current directory (32 random bytes). Keep it — it is your identity. To reuse the same identity on another machine, copy `identity.key` over.

```
Type a message and Enter to send.
/iam <name>   set your display name
/quit         exit
```

---

## Using the Rust client

### First run

```bash
nie init          # generate Ed25519 keypair, store in ~/.local/share/nie/
nie whoami        # print your public ID
```

Data lives in `~/.local/share/nie/` by default. Use `--data-dir` to override.

### Connect and chat

```bash
nie chat                           # connect to ws://localhost:3210/ws
nie --relay wss://relay.example.com/ws chat
```

The chat room is single-channel: everyone connected to the relay is in the same room.

### Chat commands

| Command | Description |
|---|---|
| `/help` | Show available commands |
| `/who` | List connected users |
| `/me <text>` | Send an action message (`* you text`) |
| `/alias <name> <pubid>` | Assign a local display name to a public ID |
| `/cat <path>` | Paste a local file into chat (≤ 4 KB, UTF-8) |
| `/! <shell command>` | Run a shell command and paste output into chat |
| `/clear` | Clear the terminal (Ctrl+L also works) |
| `/quit` | Exit |

Line editing uses [rustyline](https://github.com/kkawakam/rustyline): arrow keys, Ctrl+A/E, up/down for history.

### Multiple identities / two-instance testing

```bash
nie --data-dir /tmp/alice init
nie --data-dir /tmp/bob   init

BOB=$(nie --data-dir /tmp/bob whoami)
nie --data-dir /tmp/alice chat &
nie --data-dir /tmp/bob   chat
```

### TLS options

```bash
nie --relay wss://relay.example.com/ws chat    # verified TLS (production)
nie --insecure --relay wss://localhost:8443/ws chat  # skip cert check (dev only)
```

`--insecure` is hidden from `--help` and logs a warning on every connection. Never use it in production.

### Tor / SOCKS5 proxy

```bash
# Route the relay WebSocket connection through Tor (or any SOCKS5 proxy)
nie --proxy socks5h://127.0.0.1:9050 chat

# socks5h:// is recommended for .onion relay addresses: the proxy resolves DNS
nie --proxy socks5h://127.0.0.1:9050 --relay ws://exampleonionaddr.onion/ws chat
```

The `--proxy` flag also works from `config.toml`:

```toml
proxy = "socks5h://127.0.0.1:9050"
```

Only `socks5://` and `socks5h://` schemes are accepted. IPv6 proxy addresses must be bracket-quoted: `socks5h://[::1]:9050`.

## Security posture

### What the server knows

| Data | Relay sees it? |
|---|---|
| Message content | **No.** Payload is opaque `Vec<u8>` by construction. |
| Sender / recipient public keys | Yes — required for routing. |
| Message size and timestamp | Yes — unavoidable network metadata. |
| Who is talking to whom | Yes — connection metadata. |
| Encryption keys | **No.** Keys never leave the client. |
| Payment amounts or addresses | **No.** Payment negotiation is inside encrypted messages. |
| User's real identity | **No.** A public key is the entire identity. |

### Threat model

**Relay operator adversarial.** The architecture assumes the relay could be compromised, subpoenaed, or malicious. Encryption keys and fund custody never reach the relay regardless of operator intent or legal pressure. The operator's truthful position: *"We operate an encrypted relay. We cannot read messages or access funds because we never possess either."*

**Metadata leaks.** Who-talks-to-whom is visible to the relay. Padding and cover traffic are planned for a later phase.

**Endpoint security.** If an attacker owns the device, they own the keys. Standard device security practices apply.

### Cryptography

| Component | Algorithm |
|---|---|
| Identity | Ed25519 (ed25519-dalek) |
| Auth | Ed25519 challenge-response; `PubId = hex(SHA-256(verifying_key))` |
| E2E encryption | MLS via [openmls](https://github.com/openmls/openmls) — forward secrecy, post-compromise security |
| Key separation | Ed25519 identity key is signing-only; a separate ECDH key in each MLS KeyPackage handles key agreement |

MLS provides forward secrecy and post-compromise security. Each message ratchets the group state forward; compromise of the current epoch does not expose past messages.

### Non-custodial by construction

The relay code contains no wallet logic, no private key storage, and no payment routing. This is not a policy decision — there is no code path that could hold user funds even if the operator wanted one.

## Architecture

```
nie/
├── core/       nie-core (rlib): identity, auth, messages, protocol, transport, MLS
├── relay/      nie-relay (bin): axum WebSocket server, SQLite offline queue
└── cli/        nie-cli (bin): clap CLI, rustyline chat, contact book
```

The relay treats `Envelope.payload` as opaque bytes throughout. When MLS replaced plaintext in Phase 1, the relay required zero changes — the abstraction boundary held.

## Running tests

```bash
cargo test --workspace
```

Includes a 16-client integration stress test (`relay/tests/stress.rs`) that spins up an in-process relay and has each client send random messages at human-typing cadence, then asserts every broadcast reached exactly N−1 recipients.

## Testnet Developer Walkthrough

Phase 2 adds a Zcash Sapling wallet. The default network during Phase 2 development is testnet. No real funds are required.

### Get testnet ZEC (TAZ)

1. Initialize your wallet (testnet is the default):

   ```bash
   nie init
   nie wallet init
   ```

2. Get your Zcash receive address — connect to chat and type `/receive`:

   ```bash
   nie chat
   # In the chat prompt:
   /receive
   # Prints a testnet Sapling address (starts with ztestsapling…)
   ```

3. Go to <https://faucet.zecpages.com>, paste the address, and request TAZ.

4. Wait 1–2 minutes for the transaction to confirm on the testnet chain.

5. Check your balance from the chat prompt:

   ```bash
   /balance
   ```

### Two-instance payment test

Open two terminals. Use separate data directories so Alice and Bob have independent identities and wallets.

**Terminal 1 — Alice:**

```bash
nie --data-dir /tmp/alice init
nie --data-dir /tmp/alice wallet init
nie --data-dir /tmp/alice chat
# In chat: /receive  →  copy Alice's testnet address, fund from faucet
# Note Alice's public ID: /who
```

**Terminal 2 — Bob:**

```bash
nie --data-dir /tmp/bob init
nie --data-dir /tmp/bob wallet init
nie --data-dir /tmp/bob chat
# In chat: /receive  →  copy Bob's testnet address (fund if needed)
# Note Bob's public ID: /who
```

Once both are funded:

```bash
# In Alice's chat session (Terminal 1):
/pay <bob-pubid> 0.001

# In Bob's chat session (Terminal 2):
# Wait for the PaymentAction::Confirmed notification to appear
/balance
```

Payment negotiation travels inside encrypted MLS messages — the relay routes opaque bytes and cannot observe amounts, addresses, or direction.

> **Note:** `--network testnet` is the default during Phase 2 development. Mainnet support is planned for Phase 3 and will require an explicit `--network mainnet` flag.

## License

MIT