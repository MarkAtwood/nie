# IMPROVEMENTS.md
<!-- Suggested improvements derived from cross-project design review. -->

## 1. Proof-of-Work anti-spam on account registration

Currently nie has no spam protection on account creation. Anyone can connect and register a nickname for free. Add a Hashcash-style PoW on the `authenticate` flow (or a new `enroll` step before first auth).

**Design:**
- Double-SHA256 PoW, 20-bit leading zeros (adjustable)
- Hash context: `ver || op_type || ts_floor || diff || hex(ed25519_pub) || server_salt || nonce_be64`
- Token: binary struct (ver u8, op_type u8, ts_floor u32, diff u8, nonce u64, h16 [u8;16]) = 31 bytes, base64url-encoded
- Staleness window: ±600s from ts_floor * 60
- Replay prevention: store h16 in a short-lived in-memory set (or Redis) with TTL=600s
- Difficulty stored in AppState, adjustable at runtime without restart
- Client mines in a background thread before sending Authenticate

This raises the cost of spinning up bot accounts without adding any PII requirement. The subscription payment (when REQUIRE_SUBSCRIPTION=true) is a weak bot deterrent because small amounts of Zcash can be automated; PoW requires per-account compute that can't be batched as cheaply.

## 2. Per-session message rate limiting

Currently there is no message rate limit within an active subscription period. A subscribed client can broadcast thousands of messages per second.

**Design:**
- Add a `message_counter: DashMap<String, (u32, Instant)>` to AppState keyed by pub_id
- Window: 60 seconds, max 120 broadcasts per window (configurable via env var RATE_LIMIT_MSG_PER_MIN)
- On broadcast: check counter; if exceeded, return JSON-RPC error -32020 RATE_LIMITED
- Counters expire automatically after the window; no persistent storage needed
- Apply to: `broadcast`, `sealed_broadcast`, `group_send` — not to `whisper` (1:1 messages have natural cost)

Simple, in-process, no Redis required for a single-relay deployment.

## 3. Content canonicalization for user-supplied plaintext metadata

nie passes nickname and group name strings through without normalization. These fields are visible to other clients in plaintext (DirectoryList, group_list). They are attack surfaces for:
- RTL override: `groupname` rendered as `emanpuorg` via U+202E RIGHT-TO-LEFT OVERRIDE
- Homoglyph spoofing: `niе` using Cyrillic е (U+0435) indistinguishable from Latin e
- Zero-width characters: invisible characters inserted to create two "identical" nicknames with different bytes

**Status: Implemented.** See `canonicalize_display_name` in `relay/src/ws.rs` and
`§Display Name Canonicalization` in `DESIGN.md`. Applied to `SET_NICKNAME` and
`GROUP_CREATE` handlers. Bidi controls are rejected (not stripped); ZWS chars are
stripped silently.

## 4. Partition-based TTL for offline message queue

Currently offline messages are purged with `DELETE FROM offline_messages WHERE expires_at < ?` — a row-by-row delete that becomes expensive at scale.

**Design:**
- Create daily partitioned tables: `offline_messages_2026_04_21`, etc.
- Purge is `DROP TABLE offline_messages_YYYY_MM_DD` — O(1) DDL, no row scan
- Cron or `pg_cron` (if migrating to Postgres): create tomorrow's partition daily, drop partitions older than 72h

At nie's current message volume this is an optimization rather than a fix. Worth doing if the relay ever handles high message throughput or if the deployment migrates from SQLite to Postgres for concurrency reasons. SQLite does not support table partitioning natively — this improvement is only relevant if/when nie moves to Postgres.
