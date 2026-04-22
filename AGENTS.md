# Agent Instructions — nie (囁)

See [DESIGN.md](DESIGN.md) for the full defensive programming checklist, wallet
security rules, and MLS constraints. These are load-bearing — do not violate them.

## Before Writing Code

1. Check `bd ready` and claim your issue before touching any file.
2. Read `DESIGN.md` before touching relay, wallet, MLS, or auth code.
3. State which files will change. If more than 3, get explicit approval first.
4. Confirm `cargo build --workspace` passes before starting (baseline must compile).

## Security Invariants

Violating these changes the system's security properties. See DESIGN.md for
the full rules with code examples.

### 1. Relay payload is opaque — never deserialize it

The relay forwards `payload: Vec<u8>` without inspecting it. The relay deliver
path must never call `serde_json::from_slice`, `String::from_utf8`, or any
deserialization function on `payload`. `ClearMessage` deserialization is
client-only.

### 2. Sender identity check is non-negotiable

`relay/src/ws.rs` verifies `envelope.from == authenticated_pub_id` on every
`Send`. Do not remove, weaken, or add a bypass path. This is the relay's
only defense against identity spoofing.

### 3. `verify_challenge()` is the only trusted path to a PubId

Never trust a `PubId` that came directly from a wire message.
`verify_challenge()` returning `Ok(pub_id)` is the only path that produces
a trusted identity.

### 4. Fresh subaddress per payment request

`PaymentAction::Address` must generate a **new** Sapling subaddress on every
call. Caching or reusing an address links payments and breaks shielded
unlinkability.

### 5. Identity key and wallet key are independent

Ed25519 signing key (32-byte seed) and BIP-39 wallet seed (64 bytes) must
come from independent entropy. Never derive one from the other.

### 6. MLS changes stay in nie-core and client code

If a planned change requires modifying `relay/src/ws.rs` for encryption
reasons, stop — the design is wrong. The relay boundary is `payload: Vec<u8>`.
MLS belongs in `core/src/mls.rs` and client code only.

### 7. `/!` must not use `sh -c`

`/!` uses `shlex::split` + `Command::new(&argv[0]).args(&argv[1..])`. Do not
change this to `sh -c`. Shell metacharacters are passed literally by design —
`/!` output reaches all room participants.

## Crate Boundaries

| Crate | What it owns | Must not import |
|-------|-------------|-----------------|
| `nie-relay` | WS server, SQLite, payment watcher | `nie-wallet` types, MLS types |
| `nie-core` | Protocol, identity, auth, MLS, HPKE | platform I/O |
| `nie-wallet` | Zcash Sapling keys, lightwalletd | relay internals |
| `nie-cli` | CLI, contact book | relay internals |
| `nie-daemon` | HTTP API, WS event server | relay internals |
| `nie-wasm` | Browser client | relay internals, nie-wallet |

Cross-boundary violations break the server-knows-nothing property.

## Test Oracle Discipline

Never use the code under test as its own oracle. See DESIGN.md §14 for the
table of acceptable oracles. Always include rejection cases in auth tests.

**Anti-patterns to avoid:**

```rust
// WRONG — encrypt+decrypt with same function proves nothing
let ct = mls_encrypt(key, msg);
assert_eq!(mls_decrypt(key, ct), msg);

// WRONG — only tests happy path, no rejection cases
let result = verify_challenge(&pub_id, &nonce, &sig);
assert!(result.is_ok());
// Must also test: wrong nonce rejected, wrong key rejected
```

## Non-Interactive Shell Commands

`cp`, `mv`, and `rm` may be aliased to `-i` on this system. Always use force
flags to avoid hanging on y/n prompts:

```bash
cp -f src dst           # not: cp src dst
mv -f src dst           # not: mv src dst
rm -f file              # not: rm file
rm -rf dir              # not: rm -r dir
cp -rf src dst          # not: cp -r src dst
ssh -o BatchMode=yes    # fail instead of prompting for password
```

## Session Completion

```bash
cargo fmt --all && cargo clippy --workspace -- -D warnings && cargo test --workspace
bd close <completed-ids>
git pull --rebase && bd dolt push
git status
```

git commit and git push require explicit user approval — stage changes and report.

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

**When ending a work session**, complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **SYNC BEADS DATA**:
   ```bash
   git pull --rebase
   bd dolt push
   git status
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Report to user** - State what is staged/unstaged; ask for approval before committing or pushing
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- git commit and git push require explicit user approval — never run them without asking
- Stage changes and report what is ready; wait for the user to say "commit" or "push"
<!-- END BEADS INTEGRATION -->
