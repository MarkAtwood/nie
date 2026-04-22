# nie (囁) — Project Instructions

Encrypted relay service with privacy coin payments. Users are public keys.
Messages are opaque blobs. The server is a paid pipe.

**DESIGN.md is load-bearing.** It contains hard design invariants, the defensive
programming checklist, wallet security rules, and MLS constraints. These are
not style preferences — violating them changes the system's security properties.
Read DESIGN.md before touching relay, wallet, or crypto code.

Agent-specific invariants, crate boundaries, and test oracle rules: see **AGENTS.md**.

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
cargo run --bin nie -- chat
# Via Tor (socks5h:// recommended for .onion relay addresses)
cargo run --bin nie -- --proxy socks5h://127.0.0.1:9050 chat

# Two-instance smoke test (separate data dirs)
cargo run --bin nie -- --data-dir /tmp/alice init
cargo run --bin nie -- --data-dir /tmp/bob init
cargo run --bin nie -- --data-dir /tmp/alice chat &
cargo run --bin nie -- --data-dir /tmp/bob chat
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

## Sources of Truth

| What you need | Where to look |
|---|---|
| Hard design invariants | `DESIGN.md` |
| Project intent | `nie-brief.md` |
| Wire protocol types | `core/src/protocol.rs`, `core/src/messages.rs` |
| Identity and signing | `core/src/identity.rs`, `core/src/auth.rs` |
| Relay routing logic | `relay/src/ws.rs` |
| Offline queue | `relay/src/store.rs` |
| CLI commands | `cli/src/commands.rs` |
| Proxy / SOCKS5 transport | `core/src/transport.rs` |
| Open work items | `bd ready` / `bd list` |

## Phase Status

Phases 1–4 are complete. Current state:

- [x] Phase 1: Encrypted relay + CLI chat (MLS E2E encryption, offline queue)
- [x] Phase 2: Zcash Sapling wallet + P2P payments
- [x] Phase 3: Subscription payments (shielded, on-chain confirmation)
- [x] Phase 4: nie-daemon (HTTP API + WS events), nie-bot (headless scripting),
              nie-wasm (pure-browser WebAssembly client)

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
