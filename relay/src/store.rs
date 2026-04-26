use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use tracing::info;

/// Maximum number of groups returned per user by [`Store::list_groups_for_user`].
const MAX_GROUPS_PER_USER: i64 = 256;

/// Maximum number of members returned per group by [`Store::list_group_members`].
const MAX_MEMBERS_PER_GROUP: i64 = 1000;

/// Maximum number of key packages returned per user by [`Store::get_all_key_packages`].
const MAX_KEY_PACKAGES_PER_USER: i64 = 10;

/// Maximum number of users returned by [`Store::all_users`].
const MAX_ALL_USERS: i64 = 10_000;

/// A group registry record.
#[derive(Debug, Clone)]
pub struct GroupRow {
    pub group_id: String,
    pub created_by: String,
    pub name: String,
    /// SQLite-compatible UTC datetime string: `"YYYY-MM-DD HH:MM:SS"`.
    pub created_at: String,
}

/// A pending subscription invoice record.
#[derive(Debug, Clone)]
pub struct InvoiceRow {
    pub invoice_id: String,
    pub pub_id: String,
    pub address: String,
    pub amount_zatoshi: u64,
    /// SQLite-compatible UTC datetime string: `"YYYY-MM-DD HH:MM:SS"`.
    pub expires_at: String,
    /// Subscription duration promised at invoice-creation time (in days).
    /// `None` for pre-migration rows; payment watcher falls back to the
    /// operator setting in that case.
    pub subscription_days: Option<u64>,
}

/// Result of a [`Store::try_set_nickname`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum SetNicknameResult {
    /// Nickname was successfully stored.
    Set,
    /// This user already has a nickname; nicknames are immutable once assigned.
    HasNickname,
    /// Another user already holds this nickname (unique constraint violation).
    NicknameTaken,
}

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn new(db_url: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            // Enable FK enforcement on every connection from the pool.
            // SQLite disables FK checks by default; this makes group_member →
            // groups and group_member → users constraints actually enforced.
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::query("PRAGMA foreign_keys = ON")
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(db_url)
            .await?;

        // Schema migration runner using PRAGMA user_version.
        // user_version 0 means no schema exists yet (or pre-migration baseline).
        // Each migration block checks version < N, applies, then sets version = N.
        // Never modify a migration once shipped — add a new one after it.
        let schema_version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await?;

        // Migration v0 → v1: key_packages gains device_id column + composite PK.
        // If the old single-column-PK table exists, migrate data with device_id='legacy'.
        // Runs inside a transaction so a crash mid-migration leaves the DB untouched.
        if schema_version < 1 {
            let mut tx = pool.begin().await?;
            let kp_exists: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='key_packages'",
            )
            .fetch_one(&mut *tx)
            .await?;
            if kp_exists > 0 {
                sqlx::query(
                    "CREATE TABLE key_packages_v1 (
                        pub_id      TEXT NOT NULL,
                        device_id   TEXT NOT NULL,
                        data        BLOB NOT NULL,
                        updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
                        PRIMARY KEY (pub_id, device_id)
                    )",
                )
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "INSERT INTO key_packages_v1 (pub_id, device_id, data, updated_at) \
                     SELECT pub_id, 'legacy', data, updated_at FROM key_packages",
                )
                .execute(&mut *tx)
                .await?;
                sqlx::query("DROP TABLE key_packages")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("ALTER TABLE key_packages_v1 RENAME TO key_packages")
                    .execute(&mut *tx)
                    .await?;
            }
            // PRAGMA user_version does not accept parameterized binding — the
            // integer literal must be inlined.  This is safe: it is a constant.
            sqlx::query("PRAGMA user_version = 1")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }

        // Migration v1 → v2: add FK constraints to group_members.
        //
        // SQLite does not support ALTER TABLE ADD FOREIGN KEY, so we recreate
        // the table.  The new table enforces:
        //   group_id → groups(group_id) ON DELETE CASCADE
        //   pub_id   → users(pub_id)   ON DELETE CASCADE
        //
        // This migration runs AFTER the base CREATE TABLE IF NOT EXISTS blocks
        // below (by reading schema_version before those blocks run), so it
        // operates on the already-populated table when upgrading.  On a fresh
        // install the table does not yet exist, so the migration re-reads
        // schema_version and only runs if < 2 at that point.
        {
            let sv: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&pool)
                .await?;
            if sv < 2 {
                let mut tx = pool.begin().await?;
                // Ensure the base tables exist first (migration may run before
                // the CREATE TABLE IF NOT EXISTS blocks below on a fresh DB).
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS users (
                        pub_id      TEXT PRIMARY KEY,
                        nickname    TEXT,
                        first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
                        last_seen   TEXT NOT NULL DEFAULT (datetime('now'))
                    )",
                )
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS groups (
                        group_id   TEXT PRIMARY KEY,
                        created_by TEXT NOT NULL,
                        name       TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT (datetime('now'))
                    )",
                )
                .execute(&mut *tx)
                .await?;
                // Recreate group_members with FK constraints.
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS group_members_v2 (
                        group_id  TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
                        pub_id    TEXT NOT NULL REFERENCES users(pub_id)  ON DELETE CASCADE,
                        joined_at TEXT NOT NULL DEFAULT (datetime('now')),
                        PRIMARY KEY (group_id, pub_id)
                    )",
                )
                .execute(&mut *tx)
                .await?;
                let gm_exists: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='group_members'",
                )
                .fetch_one(&mut *tx)
                .await?;
                if gm_exists > 0 {
                    // Only migrate rows whose FKs resolve; orphaned rows are dropped
                    // rather than causing the migration to fail.
                    sqlx::query(
                        "INSERT INTO group_members_v2 \
                         SELECT gm.group_id, gm.pub_id, gm.joined_at \
                         FROM group_members gm \
                         WHERE EXISTS (SELECT 1 FROM groups g WHERE g.group_id = gm.group_id) \
                           AND EXISTS (SELECT 1 FROM users  u WHERE u.pub_id   = gm.pub_id)",
                    )
                    .execute(&mut *tx)
                    .await?;
                    sqlx::query("DROP TABLE group_members")
                        .execute(&mut *tx)
                        .await?;
                }
                sqlx::query("ALTER TABLE group_members_v2 RENAME TO group_members")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("PRAGMA user_version = 2")
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
        }

        // Migration v2 → v3: add relay_kv table for persistent relay state.
        {
            let sv: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&pool)
                .await?;
            if sv < 3 {
                let mut tx = pool.begin().await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS relay_kv (
                        key   TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )",
                )
                .execute(&mut *tx)
                .await?;
                sqlx::query("PRAGMA user_version = 3")
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
        }

        // Migration v3 → v4: add subscription_days column to subscription_invoices.
        //
        // Stores the duration promised at invoice-creation time so that the payment
        // watcher can grant the originally-promised duration even when the operator's
        // SUBSCRIPTION_DAYS setting has changed between invoice creation and payment
        // confirmation (late-payment bug nie-jmmd.2).
        //
        // NULL means "unknown" (pre-migration rows); the payment watcher falls back
        // to the operator setting in that case.
        {
            let sv: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&pool)
                .await?;
            if sv < 4 {
                let mut tx = pool.begin().await?;
                // Only ALTER if the table already exists (upgrade path).
                // Fresh installs create the table with the column via the
                // CREATE TABLE IF NOT EXISTS block below, so the ALTER is skipped.
                let table_exists: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM sqlite_master \
                     WHERE type='table' AND name='subscription_invoices'",
                )
                .fetch_one(&mut *tx)
                .await?;
                if table_exists > 0 {
                    // ALTER TABLE ADD COLUMN is safe in SQLite when the column has no
                    // NOT NULL constraint without a default (NULL is the implicit default).
                    let col_exists: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM pragma_table_info('subscription_invoices') \
                         WHERE name = 'subscription_days'",
                    )
                    .fetch_one(&mut *tx)
                    .await?;
                    if col_exists == 0 {
                        sqlx::query(
                            "ALTER TABLE subscription_invoices \
                             ADD COLUMN subscription_days INTEGER",
                        )
                        .execute(&mut *tx)
                        .await?;
                    }
                }
                sqlx::query("PRAGMA user_version = 4")
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
        }

        // Migration v4 → v5: add UNIQUE index on users(nickname).
        //
        // Prevents two different pub_ids from claiming the same display name.
        // CREATE UNIQUE INDEX IF NOT EXISTS is idempotent; safe on both fresh
        // installs (index does not exist yet) and upgrades.  The users table
        // is guaranteed to exist before this migration block runs because the
        // v1→v2 migration block above creates it with CREATE TABLE IF NOT EXISTS.
        {
            let sv: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&pool)
                .await?;
            if sv < 5 {
                let mut tx = pool.begin().await?;
                sqlx::query(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nickname \
                     ON users(nickname)",
                )
                .execute(&mut *tx)
                .await?;
                sqlx::query("PRAGMA user_version = 5")
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
        }

        // Persistent user directory: every pub_id that has ever authenticated.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                pub_id      TEXT PRIMARY KEY,
                nickname    TEXT,
                first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen   TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&pool)
        .await?;

        // Subscription state for Phase 3 payment gating.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS subscriptions (
                pub_id      TEXT PRIMARY KEY,
                expires_at  TEXT NOT NULL,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&pool)
        .await?;

        // MLS key packages: one row per (pub_id, device_id) pair.
        // device_id is a 64-char lowercase hex string (SHA-256 of KeyPackage bytes).
        // Data is opaque bytes (TLS-serialized MlsMessageOut / serde_json-encoded KeyPackage).
        // The relay never inspects the bytes.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS key_packages (
                pub_id      TEXT NOT NULL,
                device_id   TEXT NOT NULL,
                data        BLOB NOT NULL,
                updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (pub_id, device_id)
            )",
        )
        .execute(&pool)
        .await?;

        // HPKE public keys: one per pub_id, used for sealed-sender encryption.
        // The relay stores and returns opaque bytes; it never performs HPKE operations.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS hpke_keys (
                pub_id      TEXT PRIMARY KEY,
                public_key  BLOB NOT NULL,
                updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&pool)
        .await?;

        // Offline message queue: enqueued for recipients who are not live.
        // Messages expire after 72 hours via datetime() comparison.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS offline_messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                to_pub_id  TEXT NOT NULL,
                payload    TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_offline_messages_to_pub_id \
             ON offline_messages(to_pub_id)",
        )
        .execute(&pool)
        .await?;

        // Subscription invoices: pending payment requests for subscription renewals.
        // invoice_id is caller-supplied (e.g. UUID). address is UNIQUE: one active
        // invoice per Zcash subaddress. expires_at uses YYYY-MM-DD HH:MM:SS UTC.
        // subscription_days stores the duration promised at creation time so late
        // payments honour the originally-quoted duration (nie-jmmd.2).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS subscription_invoices (
                invoice_id        TEXT PRIMARY KEY,
                pub_id            TEXT NOT NULL,
                address           TEXT NOT NULL UNIQUE,
                amount_zatoshi    INTEGER NOT NULL,
                expires_at        TEXT NOT NULL,
                subscription_days INTEGER
            )",
        )
        .execute(&pool)
        .await?;

        // Sapling diversifier index for the merchant wallet (account 0).
        // Stored as decimal TEXT to fit the full 11-byte (2^88) diversifier space
        // without loss.  One row per account; starts at 0 on first use.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS merchant_diversifier (
                account         INTEGER PRIMARY KEY,
                diversifier_idx TEXT NOT NULL DEFAULT '0'
            )",
        )
        .execute(&pool)
        .await?;

        // MLS group registry: one row per group, records creator and display name.
        // group_id is caller-supplied (e.g. UUID or MLS group_id hex).
        // The relay stores and routes; it never interprets group semantics.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS groups (
                group_id   TEXT PRIMARY KEY,
                created_by TEXT NOT NULL,
                name       TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&pool)
        .await?;

        // Group membership: maps (group_id, pub_id) pairs to join timestamps.
        // Composite primary key prevents duplicate membership rows.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS group_members (
                group_id  TEXT NOT NULL,
                pub_id    TEXT NOT NULL,
                joined_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (group_id, pub_id)
            )",
        )
        .execute(&pool)
        .await?;

        info!("store ready");
        Ok(Self { pool })
    }

    // ---- User directory ----

    /// Record (or refresh last_seen for) a user who has just authenticated.
    pub async fn register_user(&self, pub_id: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO users (pub_id) VALUES (?)
             ON CONFLICT(pub_id) DO UPDATE SET last_seen = datetime('now')",
        )
        .bind(pub_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete directory entries not seen within `expiry_days`.
    ///
    /// Returns the number of rows deleted.  A value of 0 means all current
    /// users are within the retention window.
    ///
    /// `expiry_days == 0` is a no-op — callers use 0 to disable expiry.
    pub async fn prune_inactive_users(&self, expiry_days: u64) -> Result<u64> {
        if expiry_days == 0 {
            return Ok(0);
        }
        let mut tx = self.pool.begin().await?;
        let result =
            sqlx::query("DELETE FROM users WHERE last_seen < datetime('now', ? || ' days')")
                .bind(format!("-{expiry_days}"))
                .execute(&mut *tx)
                .await?;
        // Remove group_members rows for users that were just deleted.
        // The v2 migration adds ON DELETE CASCADE, but we delete explicitly here
        // so the cleanup is correct regardless of whether FK enforcement is active.
        sqlx::query("DELETE FROM group_members WHERE pub_id NOT IN (SELECT pub_id FROM users)")
            .execute(&mut *tx)
            .await?;
        // Remove groups that have no remaining members.
        sqlx::query(
            "DELETE FROM groups WHERE NOT EXISTS \
             (SELECT 1 FROM group_members WHERE group_members.group_id = groups.group_id)",
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected())
    }

    /// All known users in order of first appearance, with their nicknames.
    /// Returns at most [`MAX_ALL_USERS`] rows.
    pub async fn all_users(&self) -> Result<Vec<(String, Option<String>)>> {
        let rows: Vec<(String, Option<String>)> =
            sqlx::query_as("SELECT pub_id, nickname FROM users ORDER BY first_seen ASC LIMIT ?1")
                .bind(MAX_ALL_USERS)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows)
    }

    /// Return `true` if `pub_id` is in the users table (i.e., has ever enrolled).
    pub async fn user_exists(&self, pub_id: &str) -> Result<bool> {
        let row: Option<(String,)> = sqlx::query_as("SELECT pub_id FROM users WHERE pub_id = ?")
            .bind(pub_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Attempt to set a nickname for `pub_id`.
    ///
    /// Succeeds only if this user has no nickname yet (nicknames are immutable
    /// once assigned) and no other user already holds this nickname (enforced by
    /// the UNIQUE index on nickname).
    ///
    /// Returns:
    /// - `Ok(SetNicknameResult::Set)` — nickname stored.
    /// - `Ok(SetNicknameResult::HasNickname)` — this user already has a nickname.
    /// - `Ok(SetNicknameResult::NicknameTaken)` — another user holds this nickname.
    pub async fn try_set_nickname(
        &self,
        pub_id: &str,
        nickname: &str,
    ) -> Result<SetNicknameResult> {
        // First check whether this user already has a nickname. We do this as a
        // separate query so we can distinguish the two failure cases: a zero
        // rows_affected result from the UPDATE below is ambiguous (user already
        // has a nickname vs. nickname taken by someone else).
        let existing: Option<String> =
            sqlx::query_scalar("SELECT nickname FROM users WHERE pub_id = ?")
                .bind(pub_id)
                .fetch_optional(&self.pool)
                .await?
                .flatten();
        if existing.is_some() {
            return Ok(SetNicknameResult::HasNickname);
        }

        let result =
            sqlx::query("UPDATE users SET nickname = ? WHERE pub_id = ? AND nickname IS NULL")
                .bind(nickname)
                .bind(pub_id)
                .execute(&self.pool)
                .await;
        match result {
            Ok(_) => Ok(SetNicknameResult::Set),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Ok(SetNicknameResult::NicknameTaken)
            }
            Err(e) => Err(e.into()),
        }
    }

    // ---- MLS key packages ----

    /// Store (or replace) the MLS key package for `(pub_id, device_id)`. Opaque bytes.
    pub async fn save_key_package(&self, pub_id: &str, device_id: &str, data: &[u8]) -> Result<()> {
        sqlx::query(
            "INSERT INTO key_packages (pub_id, device_id, data) VALUES (?1, ?2, ?3)
             ON CONFLICT(pub_id, device_id) DO UPDATE SET data = excluded.data,
                                                          updated_at = datetime('now')",
        )
        .bind(pub_id)
        .bind(device_id)
        .bind(data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Store (or replace) the MLS key package for `(pub_id, device_id)`, enforcing a
    /// per-user row count cap atomically.
    ///
    /// Acquires an exclusive write lock (`BEGIN IMMEDIATE`), counts existing rows for
    /// `pub_id`, and rejects the write if the count is already at or above
    /// `MAX_KEY_PACKAGES_PER_USER`.  The COUNT and INSERT OR REPLACE execute inside
    /// a single transaction to prevent TOCTOU races where two concurrent callers
    /// both read count < cap and both insert.
    ///
    /// Returns `Ok(true)` if the package was stored.
    /// Returns `Ok(false)` if the cap is already reached (caller should send a quota error).
    /// Returns `Err` only on database failures.
    pub async fn save_key_package_capped(
        &self,
        pub_id: &str,
        device_id: &str,
        data: &[u8],
    ) -> Result<bool> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let result: Result<bool> = async {
            // Count packages for *other* devices belonging to this user.
            // An upsert (same device updating its own package) must not be
            // blocked even when the cap is full — it doesn't increase the count.
            // Only reject when other devices have already filled the quota.
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM key_packages WHERE pub_id = ?1 AND device_id != ?2",
            )
            .bind(pub_id)
            .bind(device_id)
            .fetch_one(&mut *conn)
            .await?;
            if count >= MAX_KEY_PACKAGES_PER_USER {
                return Ok(false);
            }
            sqlx::query(
                "INSERT INTO key_packages (pub_id, device_id, data) VALUES (?1, ?2, ?3)
                 ON CONFLICT(pub_id, device_id) DO UPDATE SET data = excluded.data,
                                                              updated_at = datetime('now')",
            )
            .bind(pub_id)
            .bind(device_id)
            .bind(data)
            .execute(&mut *conn)
            .await?;
            Ok(true)
        }
        .await;
        if result.is_ok() {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
        } else {
            sqlx::query("ROLLBACK").execute(&mut *conn).await.ok();
        }
        result
    }

    /// Fetch the stored MLS key package for `(pub_id, device_id)`, or None if not found.
    pub async fn get_key_package(&self, pub_id: &str, device_id: &str) -> Result<Option<Vec<u8>>> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT data FROM key_packages WHERE pub_id = ?1 AND device_id = ?2")
                .bind(pub_id)
                .bind(device_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| r.0))
    }

    /// Fetch all stored MLS key packages for `pub_id`, ordered most-recent first.
    /// Returns one entry per device that has published a key package.
    pub async fn get_all_key_packages(&self, pub_id: &str) -> Result<Vec<Vec<u8>>> {
        let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT data FROM key_packages WHERE pub_id = ?1 ORDER BY updated_at DESC LIMIT ?2",
        )
        .bind(pub_id)
        .bind(MAX_KEY_PACKAGES_PER_USER)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Delete the key package for a specific `(pub_id, device_id)` pair.
    /// No-op if the row does not exist.
    pub async fn delete_device_key_package(&self, pub_id: &str, device_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM key_packages WHERE pub_id = ?1 AND device_id = ?2")
            .bind(pub_id)
            .bind(device_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- HPKE public keys (sealed sender) ----

    /// Store (or replace) the HPKE public key for `pub_id`. Opaque bytes.
    /// The relay never interprets these bytes — it stores and returns them verbatim.
    pub async fn save_hpke_key(&self, pub_id: &str, public_key: &[u8]) -> Result<()> {
        sqlx::query(
            "INSERT INTO hpke_keys (pub_id, public_key) VALUES (?, ?)
             ON CONFLICT(pub_id) DO UPDATE SET public_key = excluded.public_key,
                                               updated_at = datetime('now')",
        )
        .bind(pub_id)
        .bind(public_key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch the stored HPKE public key for `pub_id`, or None if not published.
    pub async fn get_hpke_key(&self, pub_id: &str) -> Result<Option<Vec<u8>>> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT public_key FROM hpke_keys WHERE pub_id = ?")
                .bind(pub_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| r.0))
    }

    // ---- Offline message queue ----

    /// Enqueue a JSON-encoded relay message for a recipient who is not currently live.
    /// The payload is the serialized wire message (already a JSON string).
    /// Expires after 72 hours via SQLite's datetime() function.
    ///
    /// Silently drops the message (returning `Ok`) if the recipient's queue already
    /// holds 1000 messages.  This prevents a flood of whispers from growing the
    /// `offline_messages` table without bound.
    ///
    /// Uses `BEGIN IMMEDIATE` so the read-then-write COUNT + INSERT sequence holds
    /// a write lock from the start, preventing two concurrent callers from both
    /// reading count < 1000 and both inserting, which would bypass the flood cap.
    pub async fn enqueue(&self, to_pub_id: &str, payload_json: &str) -> Result<()> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let result: Result<()> = async {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages WHERE to_pub_id = ?1")
                    .bind(to_pub_id)
                    .fetch_one(&mut *conn)
                    .await?;
            if count >= 1000 {
                tracing::warn!(
                    to_pub_id,
                    "offline queue full (1000 messages), dropping message"
                );
                return Ok(());
            }
            sqlx::query(
                "INSERT INTO offline_messages (to_pub_id, payload, expires_at) \
                 VALUES (?1, ?2, datetime('now', '+72 hours'))",
            )
            .bind(to_pub_id)
            .bind(payload_json)
            .execute(&mut *conn)
            .await?;
            Ok(())
        }
        .await;
        if result.is_ok() {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
        } else {
            sqlx::query("ROLLBACK").execute(&mut *conn).await.ok();
        }
        result
    }

    /// Drain up to 100 queued messages for `pub_id` per call.
    ///
    /// Returns only non-expired messages (expires_at > datetime('now')), ordered
    /// by insertion order (id ASC), with a LIMIT 100 cap to bound memory use.
    /// Deletes the rows that were selected (by id) plus any expired rows, so a
    /// subsequent call fetches the next batch. The select and delete run inside a
    /// single transaction for atomicity.
    ///
    /// When the batch is empty (no non-expired rows remain), only expired rows
    /// are purged — valid rows are never touched.
    ///
    /// Callers must loop until an empty vec is returned to drain all messages.
    pub async fn drain(&self, pub_id: &str) -> Result<Vec<String>> {
        let mut tx = self.pool.begin().await?;
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT id, payload FROM offline_messages \
             WHERE to_pub_id = ?1 AND expires_at > datetime('now') \
             ORDER BY id ASC \
             LIMIT 100",
        )
        .bind(pub_id)
        .fetch_all(&mut *tx)
        .await?;
        if let Some((last_id, _)) = rows.last() {
            // Delete the batch we read, plus any expired rows for this user.
            sqlx::query(
                "DELETE FROM offline_messages \
                 WHERE to_pub_id = ?1 \
                 AND (expires_at <= datetime('now') OR id <= ?2)",
            )
            .bind(pub_id)
            .bind(*last_id)
            .execute(&mut *tx)
            .await?;
        } else {
            // Batch was empty — only purge expired rows; do NOT touch valid ones.
            sqlx::query(
                "DELETE FROM offline_messages \
                 WHERE to_pub_id = ?1 AND expires_at <= datetime('now')",
            )
            .bind(pub_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(rows.into_iter().map(|(_, s)| s).collect())
    }

    // ---- Payment watcher state ----

    /// Read the last height fully scanned by the payment watcher, or `None` if
    /// the watcher has never run on this relay instance.
    pub async fn get_payment_scan_tip(&self) -> Result<Option<u64>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM relay_kv WHERE key = 'payment_watcher_scan_height'")
                .fetch_optional(&self.pool)
                .await?;
        match row {
            None => Ok(None),
            Some((s,)) => {
                let h: u64 = s.parse().map_err(|e| {
                    anyhow::anyhow!("corrupt payment_watcher_scan_height in DB: {e}")
                })?;
                Ok(Some(h))
            }
        }
    }

    /// Persist the last height fully scanned by the payment watcher.
    pub async fn set_payment_scan_tip(&self, height: u64) -> Result<()> {
        sqlx::query(
            "INSERT INTO relay_kv (key, value) VALUES ('payment_watcher_scan_height', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(height.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ---- Subscriptions (Phase 3) ----

    /// Subscription expiry string for `pub_id`, or None if not subscribed.
    pub async fn subscription_expiry(&self, pub_id: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT expires_at FROM subscriptions
             WHERE pub_id = ? AND expires_at > datetime('now')",
        )
        .bind(pub_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.0))
    }

    /// Insert or update a subscription expiry.
    /// Used by the payment watcher (Phase 3).
    ///
    /// `expires_at` must be a `DateTime<Utc>` — formatted internally as
    /// `YYYY-MM-DD HH:MM:SS` so SQLite's `datetime('now')` comparisons
    /// work correctly.  Passing a pre-formatted string is deliberately
    /// not supported to prevent the silent format mismatch described in
    /// CLAUDE.md §9.
    pub async fn set_subscription(&self, pub_id: &str, expires_at: DateTime<Utc>) -> Result<()> {
        // SQLite datetime() compares as strings; the format must match.
        let expires_str = expires_at.format("%Y-%m-%d %H:%M:%S").to_string();
        sqlx::query(
            "INSERT INTO subscriptions (pub_id, expires_at) VALUES (?, ?)
             ON CONFLICT(pub_id) DO UPDATE SET expires_at = excluded.expires_at",
        )
        .bind(pub_id)
        .bind(&expires_str)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ---- Merchant diversifier (Sapling fresh-address tracking) ----

    /// Atomically return-and-advance the diversifier index for `account`.
    ///
    /// Returns the current index (to be used as the diversifier start), then
    /// stores `current + 1`.  The caller must call `advance_diversifier_to` if
    /// `find_address` lands on an index > the returned value.
    ///
    /// Creates the account row on first use (INSERT OR IGNORE + UPDATE pattern
    /// so the row always exists before we read it).
    ///
    /// Uses `BEGIN IMMEDIATE` to serialize concurrent callers; a DEFERRED
    /// transaction would allow two callers to read the same current index before
    /// either advances it, producing duplicate diversifiers.
    pub async fn next_diversifier(&self, account: u32) -> anyhow::Result<u128> {
        const MAX_DIVERSIFIER: u128 = (1u128 << 88) - 1;

        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let result: anyhow::Result<u128> = async {
            // Ensure the row exists.
            sqlx::query(
                "INSERT OR IGNORE INTO merchant_diversifier (account, diversifier_idx) \
                 VALUES (?, '0')",
            )
            .bind(account as i64)
            .execute(&mut *conn)
            .await?;

            let raw: String = sqlx::query_scalar(
                "SELECT diversifier_idx FROM merchant_diversifier WHERE account = ?",
            )
            .bind(account as i64)
            .fetch_one(&mut *conn)
            .await?;

            let current: u128 = raw
                .parse()
                .map_err(|e| anyhow::anyhow!("corrupt diversifier_idx in DB: {e}"))?;

            if current >= MAX_DIVERSIFIER {
                anyhow::bail!("diversifier index overflow for account {account}");
            }

            let next = current + 1;
            sqlx::query("UPDATE merchant_diversifier SET diversifier_idx = ? WHERE account = ?")
                .bind(next.to_string())
                .bind(account as i64)
                .execute(&mut *conn)
                .await?;

            Ok(current)
        }
        .await;

        if result.is_ok() {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
        } else {
            sqlx::query("ROLLBACK").execute(&mut *conn).await.ok();
        }
        result
    }

    /// Advance the diversifier index for `account` to at least `idx`.
    ///
    /// Monotonic: ignored if `idx` ≤ the current stored value.
    pub async fn advance_diversifier_to(&self, account: u32, idx: u128) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;

        // Ensure the row exists.
        sqlx::query(
            "INSERT OR IGNORE INTO merchant_diversifier (account, diversifier_idx) \
             VALUES (?, '0')",
        )
        .bind(account as i64)
        .execute(&mut *tx)
        .await?;

        let raw: String = sqlx::query_scalar(
            "SELECT diversifier_idx FROM merchant_diversifier WHERE account = ?",
        )
        .bind(account as i64)
        .fetch_one(&mut *tx)
        .await?;

        let current: u128 = raw
            .parse()
            .map_err(|e| anyhow::anyhow!("corrupt diversifier_idx in DB: {e}"))?;

        if idx > current {
            sqlx::query("UPDATE merchant_diversifier SET diversifier_idx = ? WHERE account = ?")
                .bind(idx.to_string())
                .bind(account as i64)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    // ---- Subscription invoices (Phase 3) ----

    /// Insert a new invoice. INSERT OR IGNORE — idempotent for retry safety.
    ///
    /// `row.amount_zatoshi` is stored as SQLite INTEGER (i64). An overflow
    /// above `i64::MAX` is rejected with an error rather than silently
    /// truncated.
    pub async fn create_invoice(&self, row: &InvoiceRow) -> Result<()> {
        let amount_i64 = i64::try_from(row.amount_zatoshi).context("amount_zatoshi overflow")?;
        let days_i64: Option<i64> = row
            .subscription_days
            .map(i64::try_from)
            .transpose()
            .context("subscription_days overflow")?;
        sqlx::query(
            "INSERT OR IGNORE INTO subscription_invoices \
             (invoice_id, pub_id, address, amount_zatoshi, expires_at, subscription_days) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&row.invoice_id)
        .bind(&row.pub_id)
        .bind(&row.address)
        .bind(amount_i64)
        .bind(&row.expires_at)
        .bind(days_i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch the most recent unexpired invoice for `pub_id`, or None.
    pub async fn get_pending_invoice(&self, pub_id: &str) -> Result<Option<InvoiceRow>> {
        let row: Option<(String, String, String, i64, String, Option<i64>)> = sqlx::query_as(
            "SELECT invoice_id, pub_id, address, amount_zatoshi, expires_at, subscription_days \
             FROM subscription_invoices \
             WHERE pub_id = ?1 AND expires_at > datetime('now') \
             ORDER BY expires_at DESC \
             LIMIT 1",
        )
        .bind(pub_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(
            |(invoice_id, pub_id, address, amount_zatoshi, expires_at, subscription_days)| {
                Ok(InvoiceRow {
                    invoice_id,
                    pub_id,
                    address,
                    amount_zatoshi: u64::try_from(amount_zatoshi)
                        .context("amount_zatoshi negative in DB")?,
                    expires_at,
                    subscription_days: subscription_days
                        .map(u64::try_from)
                        .transpose()
                        .context("subscription_days negative in DB")?,
                })
            },
        )
        .transpose()
    }

    /// Fetch an invoice by its payment address, or None.
    ///
    /// Does NOT filter on `expires_at`: the payment watcher must be able to
    /// activate a subscription even when a confirmed payment arrives after the
    /// invoice's nominal expiry (Zcash confirmation latency).  The watcher
    /// validates the amount independently; finding an expired-but-unpurged
    /// invoice is strictly better than silently dropping a confirmed payment.
    pub async fn get_invoice_by_address(&self, address: &str) -> Result<Option<InvoiceRow>> {
        let row: Option<(String, String, String, i64, String, Option<i64>)> = sqlx::query_as(
            "SELECT invoice_id, pub_id, address, amount_zatoshi, expires_at, subscription_days \
             FROM subscription_invoices \
             WHERE address = ?1",
        )
        .bind(address)
        .fetch_optional(&self.pool)
        .await?;
        row.map(
            |(invoice_id, pub_id, address, amount_zatoshi, expires_at, subscription_days)| {
                Ok(InvoiceRow {
                    invoice_id,
                    pub_id,
                    address,
                    amount_zatoshi: u64::try_from(amount_zatoshi)
                        .context("amount_zatoshi negative in DB")?,
                    expires_at,
                    subscription_days: subscription_days
                        .map(u64::try_from)
                        .transpose()
                        .context("subscription_days negative in DB")?,
                })
            },
        )
        .transpose()
    }

    /// Delete an invoice by its invoice_id.
    pub async fn delete_invoice(&self, invoice_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM subscription_invoices WHERE invoice_id = ?1")
            .bind(invoice_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Atomically activate a subscription and delete the fulfilled invoice.
    ///
    /// Both writes execute inside a single SQLite transaction so that a crash
    /// between the two operations cannot leave the invoice present (causing a
    /// second activation on the next scan) or absent with no subscription
    /// (causing the payment to be silently lost).
    pub async fn activate_subscription_atomic(
        &self,
        pub_id: &str,
        expires_at: DateTime<Utc>,
        invoice_id: &str,
    ) -> Result<()> {
        let expires_str = expires_at.format("%Y-%m-%d %H:%M:%S").to_string();
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO subscriptions (pub_id, expires_at) VALUES (?, ?)
             ON CONFLICT(pub_id) DO UPDATE SET
                 expires_at = CASE
                     WHEN excluded.expires_at > subscriptions.expires_at
                     THEN excluded.expires_at
                     ELSE subscriptions.expires_at
                 END",
        )
        .bind(pub_id)
        .bind(&expires_str)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM subscription_invoices WHERE invoice_id = ?1")
            .bind(invoice_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Count pending (non-expired) invoices for `pub_id`.
    ///
    /// Used by the SUBSCRIBE_REQUEST handler to cap the number of outstanding
    /// invoices per user, preventing unbounded growth of the subscription_invoices
    /// table from repeated subscription requests (nie-qgag.4).
    pub async fn count_pending_invoices(&self, pub_id: &str) -> Result<u64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM subscription_invoices \
             WHERE pub_id = ?1 AND expires_at > datetime('now')",
        )
        .bind(pub_id)
        .fetch_one(&self.pool)
        .await?;
        u64::try_from(count).context("count_pending_invoices overflow")
    }

    /// Atomically count pending invoices for `pub_id` and, if the count is
    /// below `cap`, create a new invoice — all inside a single `BEGIN IMMEDIATE`
    /// transaction.
    ///
    /// This eliminates the TOCTOU between `count_pending_invoices` and
    /// `create_invoice`: two concurrent `SUBSCRIBE_REQUEST` handlers that both
    /// read count=4 would otherwise both pass the ≥5 check and both insert,
    /// leaving 6 pending invoices.
    ///
    /// Returns `Ok(true)` if the invoice was created.
    /// Returns `Ok(false)` if the count is already ≥ `cap` (caller should rate-limit).
    /// Returns `Err` only on database failures.
    pub async fn count_and_create_invoice(&self, row: &InvoiceRow, cap: u64) -> Result<bool> {
        let amount_i64 = i64::try_from(row.amount_zatoshi).context("amount_zatoshi overflow")?;
        let days_i64: Option<i64> = row
            .subscription_days
            .map(i64::try_from)
            .transpose()
            .context("subscription_days overflow")?;

        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let result: Result<bool> = async {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM subscription_invoices \
                 WHERE pub_id = ?1 AND expires_at > datetime('now')",
            )
            .bind(&row.pub_id)
            .fetch_one(&mut *conn)
            .await?;

            if count as u64 >= cap {
                return Ok(false);
            }

            sqlx::query(
                "INSERT OR IGNORE INTO subscription_invoices \
                 (invoice_id, pub_id, address, amount_zatoshi, expires_at, subscription_days) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&row.invoice_id)
            .bind(&row.pub_id)
            .bind(&row.address)
            .bind(amount_i64)
            .bind(&row.expires_at)
            .bind(days_i64)
            .execute(&mut *conn)
            .await?;

            Ok(true)
        }
        .await;

        if result.is_ok() {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
        } else {
            sqlx::query("ROLLBACK").execute(&mut *conn).await.ok();
        }
        result
    }

    /// Allocate a Sapling diversifier index and create a subscription invoice.
    ///
    /// Uses a two-phase approach to avoid holding the SQLite write lock during
    /// CPU-bound Zcash key derivation:
    ///
    /// **Phase 1 (no lock):** Read the current diversifier index with a plain
    /// SELECT, then call `find_addr` (CPU-bound key derivation) outside any
    /// transaction.
    ///
    /// **Phase 2 (BEGIN IMMEDIATE):** Re-read the diversifier inside the write
    /// transaction. If it has advanced since Phase 1 (concurrent request), bail
    /// with an error — the caller can retry. Otherwise check the invoice cap,
    /// advance the diversifier, and insert the invoice atomically.
    ///
    /// `find_addr` is `FnOnce`: it is called exactly once in Phase 1. If the
    /// Phase 2 re-read detects a concurrent change, the function returns `Err`
    /// (very rare race; the SUBSCRIBE_REQUEST handler propagates this to the
    /// client, which retries).
    ///
    /// Returns:
    /// - `Ok(Some(address))` — diversifier advanced, invoice inserted.
    /// - `Ok(None)` — invoice cap already reached; diversifier NOT advanced.
    /// - `Err` — DB failure or concurrent diversifier change; diversifier NOT advanced.
    pub async fn alloc_diversifier_and_create_invoice(
        &self,
        account: u32,
        row: &InvoiceRow,
        cap: u64,
        find_addr: impl FnOnce(u128) -> anyhow::Result<(u128, String)>,
    ) -> Result<Option<String>> {
        const MAX_DIVERSIFIER: u128 = (1u128 << 88) - 1;

        let amount_i64 = i64::try_from(row.amount_zatoshi).context("amount_zatoshi overflow")?;
        let days_i64: Option<i64> = row
            .subscription_days
            .map(i64::try_from)
            .transpose()
            .context("subscription_days overflow")?;

        let mut conn = self.pool.acquire().await?;

        // Phase 1: read diversifier and run CPU-bound key derivation without
        // holding the write lock.
        sqlx::query(
            "INSERT OR IGNORE INTO merchant_diversifier (account, diversifier_idx) \
             VALUES (?, '0')",
        )
        .bind(account as i64)
        .execute(&mut *conn)
        .await?;

        let raw_start: String = sqlx::query_scalar(
            "SELECT diversifier_idx FROM merchant_diversifier WHERE account = ?",
        )
        .bind(account as i64)
        .fetch_one(&mut *conn)
        .await?;

        let start: u128 = raw_start
            .parse()
            .map_err(|e| anyhow::anyhow!("corrupt diversifier_idx in DB: {e}"))?;

        if start >= MAX_DIVERSIFIER {
            anyhow::bail!("diversifier index overflow for account {account}");
        }

        // CPU-bound: no lock held.
        let (actual, address) = find_addr(start)?;

        // Phase 2: acquire write lock and complete the transaction.
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let result: Result<Option<String>> = async {
            // Re-read diversifier; bail if a concurrent request advanced it.
            let raw_now: String = sqlx::query_scalar(
                "SELECT diversifier_idx FROM merchant_diversifier WHERE account = ?",
            )
            .bind(account as i64)
            .fetch_one(&mut *conn)
            .await?;

            let now: u128 = raw_now
                .parse()
                .map_err(|e| anyhow::anyhow!("corrupt diversifier_idx in DB: {e}"))?;

            if now != start {
                anyhow::bail!(
                    "diversifier for account {account} changed concurrently \
                     (was {start}, now {now}); caller should retry"
                );
            }

            // Check invoice cap.
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM subscription_invoices \
                 WHERE pub_id = ?1 AND expires_at > datetime('now')",
            )
            .bind(&row.pub_id)
            .fetch_one(&mut *conn)
            .await?;

            if count as u64 >= cap {
                return Ok(None);
            }

            // Advance the stored index past the one we just used.
            let next = actual.saturating_add(1);
            sqlx::query("UPDATE merchant_diversifier SET diversifier_idx = ? WHERE account = ?")
                .bind(next.to_string())
                .bind(account as i64)
                .execute(&mut *conn)
                .await?;

            // Insert the invoice row with the allocated address.
            sqlx::query(
                "INSERT OR IGNORE INTO subscription_invoices \
                 (invoice_id, pub_id, address, amount_zatoshi, expires_at, subscription_days) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&row.invoice_id)
            .bind(&row.pub_id)
            .bind(&address)
            .bind(amount_i64)
            .bind(&row.expires_at)
            .bind(days_i64)
            .execute(&mut *conn)
            .await?;

            Ok(Some(address))
        }
        .await;

        if result.is_ok() {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
        } else {
            sqlx::query("ROLLBACK").execute(&mut *conn).await.ok();
        }
        result
    }

    /// Delete all invoices whose `expires_at` is in the past. Returns the
    /// number of rows deleted.
    pub async fn purge_expired_invoices(&self) -> Result<u64> {
        let result =
            sqlx::query("DELETE FROM subscription_invoices WHERE expires_at <= datetime('now')")
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected())
    }

    // ---- Groups ----

    /// Create a group record. Returns a unique-constraint error if `group_id`
    /// already exists — callers must detect duplicate group creation.
    pub async fn create_group(&self, group_id: &str, created_by: &str, name: &str) -> Result<()> {
        sqlx::query("INSERT INTO groups (group_id, created_by, name) VALUES (?1, ?2, ?3)")
            .bind(group_id)
            .bind(created_by)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Fetch the group record for `group_id`, or None if not found.
    pub async fn get_group(&self, group_id: &str) -> Result<Option<GroupRow>> {
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            "SELECT group_id, created_by, name, created_at FROM groups WHERE group_id = ?1",
        )
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(
            row.map(|(group_id, created_by, name, created_at)| GroupRow {
                group_id,
                created_by,
                name,
                created_at,
            }),
        )
    }

    /// All groups that `pub_id` is a member of.
    pub async fn list_groups_for_user(&self, pub_id: &str) -> Result<Vec<GroupRow>> {
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT g.group_id, g.created_by, g.name, g.created_at \
             FROM groups g \
             JOIN group_members m ON g.group_id = m.group_id \
             WHERE m.pub_id = ?1 \
             LIMIT ?2",
        )
        .bind(pub_id)
        .bind(MAX_GROUPS_PER_USER)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(group_id, created_by, name, created_at)| GroupRow {
                group_id,
                created_by,
                name,
                created_at,
            })
            .collect())
    }

    /// Add `pub_id` to `group_id`. INSERT OR IGNORE — idempotent.
    pub async fn add_group_member(&self, group_id: &str, pub_id: &str) -> Result<()> {
        sqlx::query("INSERT OR IGNORE INTO group_members (group_id, pub_id) VALUES (?1, ?2)")
            .bind(group_id)
            .bind(pub_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Atomically check the member count cap and add `pub_id` to `group_id`.
    ///
    /// The COUNT and INSERT run inside a single `BEGIN IMMEDIATE` transaction,
    /// eliminating the TOCTOU where two concurrent GROUP_ADD callers both read
    /// count < cap and then both insert, exceeding the limit.
    ///
    /// Returns `Ok(true)` if the member was added (or was already a member),
    /// `Ok(false)` if the group already has `cap` or more members.
    pub async fn add_group_member_capped(
        &self,
        group_id: &str,
        pub_id: &str,
        cap: u64,
    ) -> Result<bool> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let result: Result<bool> = async {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = ?1")
                    .bind(group_id)
                    .fetch_one(&mut *conn)
                    .await?;
            if count as u64 >= cap {
                return Ok(false);
            }
            sqlx::query("INSERT OR IGNORE INTO group_members (group_id, pub_id) VALUES (?1, ?2)")
                .bind(group_id)
                .bind(pub_id)
                .execute(&mut *conn)
                .await?;
            Ok(true)
        }
        .await;
        if result.is_ok() {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
        } else {
            sqlx::query("ROLLBACK").execute(&mut *conn).await.ok();
        }
        result
    }

    /// Remove `pub_id` from `group_id`. No-op if the membership does not exist.
    pub async fn remove_group_member(&self, group_id: &str, pub_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM group_members WHERE group_id = ?1 AND pub_id = ?2")
            .bind(group_id)
            .bind(pub_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// All member pub_ids for `group_id`.
    pub async fn list_group_members(&self, group_id: &str) -> Result<Vec<String>> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT pub_id FROM group_members WHERE group_id = ?1 LIMIT ?2")
                .bind(group_id)
                .bind(MAX_MEMBERS_PER_GROUP)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    /// Returns `true` if `pub_id` is a member of `group_id`.
    pub async fn is_group_member(&self, group_id: &str, pub_id: &str) -> Result<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM group_members WHERE group_id = ?1 AND pub_id = ?2",
        )
        .bind(group_id)
        .bind(pub_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }

    /// Number of members in `group_id`.
    pub async fn member_count(&self, group_id: &str) -> Result<u64> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = ?1")
                .bind(group_id)
                .fetch_one(&self.pool)
                .await?;
        u64::try_from(count).context("member_count overflow")
    }

    /// Return a map of `group_id → member_count` for all groups that `pub_id`
    /// belongs to, in a single SQL query (avoids N+1 in GROUP_LIST).
    pub async fn member_counts_for_user(
        &self,
        pub_id: &str,
    ) -> Result<std::collections::HashMap<String, u64>> {
        // Aggregate counts for only the groups this user belongs to.
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT gm.group_id, COUNT(*) \
             FROM group_members gm \
             WHERE gm.group_id IN (SELECT group_id FROM group_members WHERE pub_id = ?1) \
             GROUP BY gm.group_id",
        )
        .bind(pub_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(gid, cnt)| {
                u64::try_from(cnt)
                    .context("member_count overflow")
                    .map(|n| (gid, n))
            })
            .collect()
    }

    /// Atomically remove `pub_id` from `group_id`, then delete the group if it
    /// has no remaining members.
    ///
    /// Returns `true` if the group was deleted (member count dropped to 0),
    /// `false` if other members remain.
    ///
    /// All three operations (DELETE member row, COUNT remaining members,
    /// conditional DELETE group) run inside a single SQLite transaction,
    /// eliminating the TOCTOU between a concurrent GROUP_ADD and the final
    /// delete decision.
    pub async fn remove_member_and_maybe_delete_group(
        &self,
        group_id: &str,
        pub_id: &str,
    ) -> Result<bool> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let result: Result<bool> = async {
            sqlx::query("DELETE FROM group_members WHERE group_id = ?1 AND pub_id = ?2")
                .bind(group_id)
                .bind(pub_id)
                .execute(&mut *conn)
                .await?;
            let remaining: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = ?1")
                    .bind(group_id)
                    .fetch_one(&mut *conn)
                    .await?;
            if remaining == 0 {
                sqlx::query("DELETE FROM groups WHERE group_id = ?1")
                    .bind(group_id)
                    .execute(&mut *conn)
                    .await?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        .await;
        if result.is_ok() {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
        } else {
            sqlx::query("ROLLBACK").execute(&mut *conn).await.ok();
        }
        result
    }

    /// Atomically create a group and add its creator as the first member.
    ///
    /// Both the INSERT into `groups` and the INSERT into `group_members` run
    /// inside a single SQLite transaction.  If either fails, the transaction
    /// rolls back and no orphan group row is left behind.
    ///
    /// Idempotent on the group row (INSERT OR IGNORE): if the group already
    /// exists the creator is still added as a member (also idempotent).
    pub async fn create_group_with_creator(
        &self,
        group_id: &str,
        created_by: &str,
        name: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT OR IGNORE INTO groups (group_id, created_by, name) VALUES (?1, ?2, ?3)",
        )
        .bind(group_id)
        .bind(created_by)
        .bind(name)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT OR IGNORE INTO group_members (group_id, pub_id) VALUES (?1, ?2)")
            .bind(group_id)
            .bind(created_by)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Atomically check the per-creator group count cap and create the group.
    ///
    /// The COUNT and INSERT run inside a single `BEGIN IMMEDIATE` transaction,
    /// eliminating the TOCTOU where two concurrent GROUP_CREATE callers both read
    /// count < cap and both insert, exceeding the limit.
    ///
    /// Returns `Ok(true)` if the group was created, `Ok(false)` if `created_by`
    /// already owns `cap` or more groups.
    pub async fn create_group_with_creator_capped(
        &self,
        group_id: &str,
        created_by: &str,
        name: &str,
        cap: u64,
    ) -> Result<bool> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let result: Result<bool> = async {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM groups WHERE created_by = ?1")
                    .bind(created_by)
                    .fetch_one(&mut *conn)
                    .await?;
            if count as u64 >= cap {
                return Ok(false);
            }
            sqlx::query(
                "INSERT OR IGNORE INTO groups (group_id, created_by, name) VALUES (?1, ?2, ?3)",
            )
            .bind(group_id)
            .bind(created_by)
            .bind(name)
            .execute(&mut *conn)
            .await?;
            sqlx::query("INSERT OR IGNORE INTO group_members (group_id, pub_id) VALUES (?1, ?2)")
                .bind(group_id)
                .bind(created_by)
                .execute(&mut *conn)
                .await?;
            Ok(true)
        }
        .await;
        if result.is_ok() {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
        } else {
            sqlx::query("ROLLBACK").execute(&mut *conn).await.ok();
        }
        result
    }

    /// Delete a group and all its membership rows, atomically.
    pub async fn delete_group(&self, group_id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM group_members WHERE group_id = ?1")
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM groups WHERE group_id = ?1")
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    async fn make_store() -> (Store, tempfile::NamedTempFile) {
        let f = tempfile::NamedTempFile::new().unwrap();
        let url = format!("sqlite:{}?mode=rwc", f.path().display());
        let store = Store::new(&url).await.unwrap();
        (store, f)
    }

    // ---- subscription_expiry boundary tests ----

    /// Active subscription (expires 24 h from now) is found.
    #[tokio::test]
    async fn subscription_future_expiry_is_found() {
        let (store, _f) = make_store().await;
        let expires = Utc::now() + Duration::hours(24);
        store.set_subscription("alice", expires).await.unwrap();
        let result = store.subscription_expiry("alice").await.unwrap();
        assert!(
            result.is_some(),
            "subscription expiring in 24h must be found"
        );
    }

    /// Expired subscription (2 s in the past) is not found.
    #[tokio::test]
    async fn subscription_past_expiry_is_not_found() {
        let (store, _f) = make_store().await;
        let expires = Utc::now() - Duration::seconds(2);
        store.set_subscription("bob", expires).await.unwrap();
        let result = store.subscription_expiry("bob").await.unwrap();
        assert!(
            result.is_none(),
            "subscription that expired 2s ago must not be found"
        );
    }

    /// pub_id with no subscription row returns None.
    #[tokio::test]
    async fn no_subscription_returns_none() {
        let (store, _f) = make_store().await;
        let result = store.subscription_expiry("nobody").await.unwrap();
        assert!(result.is_none(), "nonexistent pub_id must return None");
    }

    /// set_subscription stores in YYYY-MM-DD HH:MM:SS format, not RFC 3339.
    ///
    /// Oracle: read the raw stored string directly from SQLite and check its structure
    /// independently of the comparison logic in subscription_expiry().
    ///
    /// This is the invariant from CLAUDE.md §9 — if the format is wrong, the
    /// `expires_at > datetime('now')` comparison silently fails.
    #[tokio::test]
    async fn set_subscription_stores_sqlite_compatible_format() {
        let (store, _f) = make_store().await;
        let expires = Utc::now() + Duration::hours(1);
        store.set_subscription("carol", expires).await.unwrap();

        let row: Option<(String,)> =
            sqlx::query_as("SELECT expires_at FROM subscriptions WHERE pub_id = ?")
                .bind("carol")
                .fetch_optional(&store.pool)
                .await
                .unwrap();

        let raw = row.expect("row must exist after set_subscription").0;

        // Must NOT contain RFC 3339 separators or timezone suffixes.
        assert!(
            !raw.contains('T'),
            "must not be RFC 3339 (T separator), got: {raw}"
        );
        assert!(
            !raw.contains('Z'),
            "must not be RFC 3339 (Z suffix), got: {raw}"
        );
        assert!(
            !raw.contains('+'),
            "must not have timezone offset, got: {raw}"
        );
        // Must be exactly YYYY-MM-DD HH:MM:SS (19 chars, space at position 10).
        assert_eq!(
            raw.len(),
            19,
            "must be 19 chars (YYYY-MM-DD HH:MM:SS), got: {raw}"
        );
        assert_eq!(
            raw.as_bytes()[10],
            b' ',
            "character 10 must be space separator (not 'T'), got: {raw}"
        );
    }

    // ---- offline_messages tests ----

    /// Enqueue one message and drain it back.
    ///
    /// Oracle: the expected string is a hardcoded literal, not produced by any
    /// function under test.
    #[tokio::test]
    async fn test_enqueue_drain_roundtrip() {
        let (store, _f) = make_store().await;
        let payload = r#"{"jsonrpc":"2.0","method":"whisper_deliver","params":{"from":"bob","payload":"aGVsbG8="}}"#;
        store.enqueue("alice", payload).await.unwrap();
        let msgs = store.drain("alice").await.unwrap();
        assert_eq!(
            msgs,
            vec![
                r#"{"jsonrpc":"2.0","method":"whisper_deliver","params":{"from":"bob","payload":"aGVsbG8="}}"#
            ],
            "drained message must equal the enqueued literal"
        );
    }

    /// Multiple messages are returned in insertion order.
    ///
    /// Oracle: the expected ordering is the known insertion sequence, verified
    /// against the ORDER BY id ASC guarantee from the schema, not the drain
    /// implementation itself.
    #[tokio::test]
    async fn test_drain_ordering() {
        let (store, _f) = make_store().await;
        store.enqueue("alice", "msg_1").await.unwrap();
        store.enqueue("alice", "msg_2").await.unwrap();
        let msgs = store.drain("alice").await.unwrap();
        assert_eq!(
            msgs,
            vec!["msg_1", "msg_2"],
            "messages must be in insertion order"
        );
    }

    /// A second drain returns nothing — the first drain cleared the queue.
    #[tokio::test]
    async fn test_drain_clears_queue() {
        let (store, _f) = make_store().await;
        store.enqueue("alice", "hello").await.unwrap();
        let first = store.drain("alice").await.unwrap();
        assert_eq!(
            first.len(),
            1,
            "first drain must return the enqueued message"
        );
        let second = store.drain("alice").await.unwrap();
        assert!(
            second.is_empty(),
            "second drain must return empty vec after queue cleared"
        );
    }

    /// Draining one user's queue does not remove another user's messages.
    #[tokio::test]
    async fn test_drain_other_user_unaffected() {
        let (store, _f) = make_store().await;
        store.enqueue("alice", "for_alice").await.unwrap();
        store.enqueue("bob", "for_bob").await.unwrap();
        let alice_msgs = store.drain("alice").await.unwrap();
        assert_eq!(
            alice_msgs,
            vec!["for_alice"],
            "alice must receive her own message"
        );
        let bob_msgs = store.drain("bob").await.unwrap();
        assert_eq!(
            bob_msgs,
            vec!["for_bob"],
            "bob's message must survive alice's drain"
        );
    }

    /// Demonstrates the exact failure mode when RFC 3339 format is used instead of
    /// the required YYYY-MM-DD HH:MM:SS format (CLAUDE.md §9 invariant).
    ///
    /// SQLite compares datetime strings lexicographically. At position 10, RFC 3339
    /// uses 'T' (0x54) while datetime('now') uses ' ' (0x20). Since 'T' > ' ' in
    /// ASCII, any RFC 3339 datetime on the same calendar day compares as "after"
    /// datetime('now') — meaning an EXPIRED subscription on the same day appears
    /// ACTIVE. This is the silent wrong behavior that set_subscription prevents.
    ///
    /// The test inserts two expired times (1 hour ago) with different formats and
    /// verifies they produce opposite results:
    ///   - Correct format → correctly identified as expired (not found)
    ///   - RFC 3339 format → incorrectly identified as active (found) on same day
    ///
    /// Note: the RFC 3339 half is skipped if the test runs in the 00:00–01:00 UTC
    /// window, because 1-hour-ago falls on the previous calendar day and the day
    /// portion sorts correctly regardless of the separator.
    #[tokio::test]
    async fn wrong_format_rfc3339_breaks_expiry_comparison() {
        let (store, _f) = make_store().await;
        let one_hour_ago = Utc::now() - Duration::hours(1);

        // (a) Correct format: expired subscription must NOT be found.
        let correct_fmt = one_hour_ago.format("%Y-%m-%d %H:%M:%S").to_string();
        sqlx::query("INSERT INTO subscriptions (pub_id, expires_at) VALUES (?, ?)")
            .bind("alice-correct")
            .bind(&correct_fmt)
            .execute(&store.pool)
            .await
            .unwrap();
        let correct_result = store.subscription_expiry("alice-correct").await.unwrap();
        assert!(
            correct_result.is_none(),
            "correct format: expired subscription must not be found, got {correct_result:?}"
        );

        // (b) RFC 3339 format on the same calendar day: same expired time IS
        // incorrectly found as active because 'T' > ' ' in SQLite string comparison.
        // Skip near midnight (00:00–01:00 UTC) where 1-hour-ago is a different day.
        let today = Utc::now().format("%Y-%m-%d").to_string();
        if one_hour_ago.format("%Y-%m-%d").to_string() == today {
            let rfc3339_fmt = one_hour_ago.to_rfc3339();
            sqlx::query("INSERT INTO subscriptions (pub_id, expires_at) VALUES (?, ?)")
                .bind("bob-rfc3339")
                .bind(&rfc3339_fmt)
                .execute(&store.pool)
                .await
                .unwrap();
            let rfc3339_result = store.subscription_expiry("bob-rfc3339").await.unwrap();
            assert!(
                rfc3339_result.is_some(),
                "RFC 3339 bug: expired subscription on same calendar day is incorrectly \
                 found as active. 'T' (0x54) > ' ' (0x20) in SQLite string comparison \
                 makes any same-day RFC 3339 datetime sort after datetime('now'). \
                 If this assertion fails, SQLite's comparison behavior has changed."
            );
        }
    }

    // ---- subscription_invoices CRUD tests ----

    fn future_expires_at() -> String {
        (Utc::now() + Duration::hours(24))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    }

    fn past_expires_at() -> String {
        (Utc::now() - Duration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    }

    /// create_invoice + get_pending_invoice: roundtrip. Fields are checked against
    /// the literals passed in, not against any function output used as oracle.
    #[tokio::test]
    async fn invoice_create_and_get_pending() {
        let (store, _f) = make_store().await;
        let row = InvoiceRow {
            invoice_id: "inv-001".to_string(),
            pub_id: "alice".to_string(),
            address: "zs1abc".to_string(),
            amount_zatoshi: 100_000,
            expires_at: future_expires_at(),
            subscription_days: Some(30),
        };
        store.create_invoice(&row).await.unwrap();

        let got = store.get_pending_invoice("alice").await.unwrap();
        let got = got.expect("must find the just-created invoice");
        assert_eq!(got.invoice_id, "inv-001");
        assert_eq!(got.pub_id, "alice");
        assert_eq!(got.address, "zs1abc");
        assert_eq!(got.amount_zatoshi, 100_000u64);
    }

    /// create_invoice is idempotent: a duplicate insert is silently ignored.
    #[tokio::test]
    async fn invoice_create_idempotent() {
        let (store, _f) = make_store().await;
        let row = InvoiceRow {
            invoice_id: "inv-idem".to_string(),
            pub_id: "carol".to_string(),
            address: "zs1idem".to_string(),
            amount_zatoshi: 50_000,
            expires_at: future_expires_at(),
            subscription_days: Some(30),
        };
        store.create_invoice(&row).await.unwrap();
        // Second insert with same invoice_id must not fail.
        store.create_invoice(&row).await.unwrap();
        let got = store.get_pending_invoice("carol").await.unwrap();
        assert!(
            got.is_some(),
            "invoice must still be present after duplicate insert"
        );
    }

    /// Expired invoice is not returned by get_pending_invoice.
    #[tokio::test]
    async fn invoice_expired_not_returned() {
        let (store, _f) = make_store().await;
        let row = InvoiceRow {
            invoice_id: "inv-exp".to_string(),
            pub_id: "dave".to_string(),
            address: "zs1exp".to_string(),
            amount_zatoshi: 1_000,
            expires_at: past_expires_at(),
            subscription_days: Some(30),
        };
        store.create_invoice(&row).await.unwrap();
        let got = store.get_pending_invoice("dave").await.unwrap();
        assert!(got.is_none(), "expired invoice must not be returned");
    }

    /// get_invoice_by_address finds an invoice by address (active or expired);
    /// unknown address returns None.
    #[tokio::test]
    async fn invoice_get_by_address() {
        let (store, _f) = make_store().await;
        let row = InvoiceRow {
            invoice_id: "inv-addr".to_string(),
            pub_id: "eve".to_string(),
            address: "zs1addr".to_string(),
            amount_zatoshi: 200_000,
            expires_at: future_expires_at(),
            subscription_days: Some(30),
        };
        store.create_invoice(&row).await.unwrap();

        let got = store.get_invoice_by_address("zs1addr").await.unwrap();
        let got = got.expect("must find invoice by address");
        assert_eq!(got.invoice_id, "inv-addr");
        assert_eq!(got.amount_zatoshi, 200_000u64);

        // Unknown address returns None.
        let missing = store.get_invoice_by_address("zs1unknown").await.unwrap();
        assert!(missing.is_none(), "unknown address must return None");
    }

    /// delete_invoice removes the row; subsequent get returns None.
    #[tokio::test]
    async fn invoice_delete() {
        let (store, _f) = make_store().await;
        let row = InvoiceRow {
            invoice_id: "inv-del".to_string(),
            pub_id: "frank".to_string(),
            address: "zs1del".to_string(),
            amount_zatoshi: 9_999,
            expires_at: future_expires_at(),
            subscription_days: Some(30),
        };
        store.create_invoice(&row).await.unwrap();
        store.delete_invoice("inv-del").await.unwrap();
        let got = store.get_pending_invoice("frank").await.unwrap();
        assert!(got.is_none(), "deleted invoice must not be returned");
    }

    /// purge_expired_invoices deletes only expired rows; active rows survive.
    #[tokio::test]
    async fn invoice_purge_expired() {
        let (store, _f) = make_store().await;
        let active = InvoiceRow {
            invoice_id: "inv-active".to_string(),
            pub_id: "grace".to_string(),
            address: "zs1active".to_string(),
            amount_zatoshi: 1_000,
            expires_at: future_expires_at(),
            subscription_days: Some(30),
        };
        let expired = InvoiceRow {
            invoice_id: "inv-old".to_string(),
            pub_id: "grace".to_string(),
            // Different address — UNIQUE constraint.
            address: "zs1old".to_string(),
            amount_zatoshi: 1_000,
            expires_at: past_expires_at(),
            subscription_days: Some(30),
        };
        store.create_invoice(&active).await.unwrap();
        store.create_invoice(&expired).await.unwrap();

        let deleted = store.purge_expired_invoices().await.unwrap();
        assert_eq!(
            deleted, 1,
            "purge must remove exactly the one expired invoice"
        );

        // Active invoice must still be retrievable.
        let got = store.get_invoice_by_address("zs1active").await.unwrap();
        assert!(got.is_some(), "active invoice must survive purge");

        // Expired invoice must be gone.
        let gone = store.get_invoice_by_address("zs1old").await.unwrap();
        assert!(gone.is_none(), "expired invoice must be deleted by purge");
    }

    /// amount_zatoshi overflow: create_invoice must error, not silently truncate.
    ///
    /// Oracle: u64::MAX > i64::MAX; i64::try_from(u64::MAX) is Err, so the method
    /// must propagate that error. We check that the call fails, not inspect the
    /// exact error message.
    #[tokio::test]
    async fn invoice_amount_overflow_is_error() {
        let (store, _f) = make_store().await;
        let row = InvoiceRow {
            invoice_id: "inv-overflow".to_string(),
            pub_id: "heidi".to_string(),
            address: "zs1overflow".to_string(),
            amount_zatoshi: u64::MAX,
            expires_at: future_expires_at(),
            subscription_days: Some(30),
        };
        let result = store.create_invoice(&row).await;
        assert!(
            result.is_err(),
            "u64::MAX must not be silently truncated to i64"
        );
    }

    // ---- group CRUD tests ----

    /// create_group + get_group: roundtrip; fields checked against the literals
    /// passed in, not against any function output used as oracle.
    #[tokio::test]
    async fn group_create_and_get() {
        let (store, _f) = make_store().await;
        store
            .create_group("grp-001", "alice", "test group")
            .await
            .unwrap();

        let got = store.get_group("grp-001").await.unwrap();
        let got = got.expect("must find the just-created group");
        assert_eq!(got.group_id, "grp-001");
        assert_eq!(got.created_by, "alice");
        assert_eq!(got.name, "test group");
        // created_at must be non-empty (relay-generated, not caller-supplied)
        assert!(!got.created_at.is_empty(), "created_at must be set");
    }

    /// get_group on a non-existent group_id returns None.
    #[tokio::test]
    async fn group_get_missing_returns_none() {
        let (store, _f) = make_store().await;
        let got = store.get_group("no-such-group").await.unwrap();
        assert!(got.is_none(), "unknown group_id must return None");
    }

    /// create_group returns an error on duplicate group_id.
    #[tokio::test]
    async fn group_create_duplicate_is_error() {
        let (store, _f) = make_store().await;
        store
            .create_group("grp-dup", "alice", "original name")
            .await
            .unwrap();
        // Second insert with same group_id must fail with a unique-constraint error.
        let result = store.create_group("grp-dup", "bob", "different name").await;
        assert!(
            result.is_err(),
            "duplicate group_id must return an error, not silently ignore"
        );
        // Original row must be unchanged.
        let got = store.get_group("grp-dup").await.unwrap().unwrap();
        assert_eq!(got.created_by, "alice", "original row must be preserved");
        assert_eq!(got.name, "original name");
    }

    /// add_group_member + is_group_member: membership is visible after add.
    #[tokio::test]
    async fn group_add_and_is_member() {
        let (store, _f) = make_store().await;
        store.register_user("bob").await.unwrap();
        store
            .create_group("grp-mem", "alice", "member test")
            .await
            .unwrap();
        store.add_group_member("grp-mem", "bob").await.unwrap();

        let is_member = store.is_group_member("grp-mem", "bob").await.unwrap();
        assert!(is_member, "bob must be a member after add_group_member");

        let not_member = store.is_group_member("grp-mem", "carol").await.unwrap();
        assert!(!not_member, "carol must not be a member");
    }

    /// add_group_member is idempotent: adding the same member twice is not an error.
    #[tokio::test]
    async fn group_add_member_idempotent() {
        let (store, _f) = make_store().await;
        store.register_user("bob").await.unwrap();
        store
            .create_group("grp-idem-mem", "alice", "idempotent member")
            .await
            .unwrap();
        store.add_group_member("grp-idem-mem", "bob").await.unwrap();
        store.add_group_member("grp-idem-mem", "bob").await.unwrap();
        // Member count must still be 1, not 2.
        let count = store.member_count("grp-idem-mem").await.unwrap();
        assert_eq!(count, 1, "duplicate add must not create a second row");
    }

    /// list_group_members returns all added members.
    ///
    /// Oracle: the expected member list is the exact set of literals inserted.
    #[tokio::test]
    async fn group_list_members() {
        let (store, _f) = make_store().await;
        store.register_user("bob").await.unwrap();
        store.register_user("carol").await.unwrap();
        store
            .create_group("grp-list", "alice", "list test")
            .await
            .unwrap();
        store.add_group_member("grp-list", "bob").await.unwrap();
        store.add_group_member("grp-list", "carol").await.unwrap();

        let mut members = store.list_group_members("grp-list").await.unwrap();
        members.sort(); // order is not guaranteed; sort for comparison
        assert_eq!(
            members,
            vec!["bob", "carol"],
            "list_group_members must return all added members"
        );
    }

    /// list_group_members for a group with no members returns an empty vec.
    #[tokio::test]
    async fn group_list_members_empty() {
        let (store, _f) = make_store().await;
        store
            .create_group("grp-empty", "alice", "empty group")
            .await
            .unwrap();
        let members = store.list_group_members("grp-empty").await.unwrap();
        assert!(
            members.is_empty(),
            "newly created group must have no members"
        );
    }

    /// member_count reflects the number of members added.
    #[tokio::test]
    async fn group_member_count() {
        let (store, _f) = make_store().await;
        store.register_user("bob").await.unwrap();
        store.register_user("carol").await.unwrap();
        store
            .create_group("grp-count", "alice", "count test")
            .await
            .unwrap();
        assert_eq!(
            store.member_count("grp-count").await.unwrap(),
            0,
            "new group must have 0 members"
        );
        store.add_group_member("grp-count", "bob").await.unwrap();
        assert_eq!(
            store.member_count("grp-count").await.unwrap(),
            1,
            "after adding bob, count must be 1"
        );
        store.add_group_member("grp-count", "carol").await.unwrap();
        assert_eq!(
            store.member_count("grp-count").await.unwrap(),
            2,
            "after adding carol, count must be 2"
        );
    }

    /// remove_group_member: membership is gone after remove; other members unaffected.
    #[tokio::test]
    async fn group_remove_member() {
        let (store, _f) = make_store().await;
        store.register_user("bob").await.unwrap();
        store.register_user("carol").await.unwrap();
        store
            .create_group("grp-rm", "alice", "remove test")
            .await
            .unwrap();
        store.add_group_member("grp-rm", "bob").await.unwrap();
        store.add_group_member("grp-rm", "carol").await.unwrap();

        store.remove_group_member("grp-rm", "bob").await.unwrap();

        assert!(
            !store.is_group_member("grp-rm", "bob").await.unwrap(),
            "bob must not be a member after removal"
        );
        assert!(
            store.is_group_member("grp-rm", "carol").await.unwrap(),
            "carol must still be a member"
        );
    }

    /// remove_group_member on a non-member is a no-op (not an error).
    #[tokio::test]
    async fn group_remove_nonmember_is_noop() {
        let (store, _f) = make_store().await;
        store
            .create_group("grp-rm-noop", "alice", "noop test")
            .await
            .unwrap();
        // Removing someone who was never added must not fail.
        store
            .remove_group_member("grp-rm-noop", "nobody")
            .await
            .unwrap();
    }

    /// delete_group removes both the group row and all membership rows.
    ///
    /// Oracle: after delete, get_group returns None and list_group_members
    /// returns empty — verified against literals, not against the same
    /// store path used to write them.
    #[tokio::test]
    async fn group_delete_cascades() {
        let (store, _f) = make_store().await;
        store.register_user("bob").await.unwrap();
        store.register_user("carol").await.unwrap();
        store
            .create_group("grp-del", "alice", "delete test")
            .await
            .unwrap();
        store.add_group_member("grp-del", "bob").await.unwrap();
        store.add_group_member("grp-del", "carol").await.unwrap();

        store.delete_group("grp-del").await.unwrap();

        let group = store.get_group("grp-del").await.unwrap();
        assert!(group.is_none(), "group row must be deleted");

        // Verify directly that no orphan membership rows remain.
        let orphan_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = 'grp-del'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(
            orphan_count, 0,
            "delete_group must remove all group_members rows"
        );
    }

    /// list_groups_for_user returns groups the user belongs to, not others.
    #[tokio::test]
    async fn group_list_for_user() {
        let (store, _f) = make_store().await;
        store.register_user("bob").await.unwrap();
        store.register_user("carol").await.unwrap();
        store
            .create_group("grp-a", "alice", "group a")
            .await
            .unwrap();
        store
            .create_group("grp-b", "alice", "group b")
            .await
            .unwrap();
        store
            .create_group("grp-c", "alice", "group c")
            .await
            .unwrap();

        store.add_group_member("grp-a", "bob").await.unwrap();
        store.add_group_member("grp-b", "bob").await.unwrap();
        store.add_group_member("grp-c", "carol").await.unwrap();

        let mut groups = store.list_groups_for_user("bob").await.unwrap();
        groups.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        let ids: Vec<&str> = groups.iter().map(|g| g.group_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["grp-a", "grp-b"],
            "bob must be in grp-a and grp-b only"
        );

        let carol_groups = store.list_groups_for_user("carol").await.unwrap();
        assert_eq!(carol_groups.len(), 1);
        assert_eq!(carol_groups[0].group_id, "grp-c");
    }

    // ---- prune_inactive_users tests ----

    /// Oracle: a user whose last_seen is manually set to 91 days ago is deleted;
    /// a user seen today survives.
    #[tokio::test]
    async fn prune_removes_stale_user_and_keeps_recent() {
        let (store, _f) = make_store().await;

        store.register_user("active").await.unwrap();
        store.register_user("stale").await.unwrap();

        // Wind stale user's last_seen back 91 days via raw SQL.
        sqlx::query(
            "UPDATE users SET last_seen = datetime('now', '-91 days') WHERE pub_id = 'stale'",
        )
        .execute(&store.pool)
        .await
        .unwrap();

        let pruned = store.prune_inactive_users(90).await.unwrap();
        assert_eq!(pruned, 1, "exactly one stale user must be pruned");

        let remaining = store.all_users().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, "active");
    }

    /// Oracle: expiry_days=0 is a no-op — no rows are deleted even with stale users.
    #[tokio::test]
    async fn prune_with_zero_expiry_days_is_noop() {
        let (store, _f) = make_store().await;

        store.register_user("old-user").await.unwrap();
        sqlx::query(
            "UPDATE users SET last_seen = datetime('now', '-999 days') WHERE pub_id = 'old-user'",
        )
        .execute(&store.pool)
        .await
        .unwrap();

        let pruned = store.prune_inactive_users(0).await.unwrap();
        assert_eq!(pruned, 0, "expiry_days=0 must not delete any rows");

        let remaining = store.all_users().await.unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "stale user must survive when expiry is disabled"
        );
    }

    // ---- key_packages per-device tests ----

    /// save + get roundtrip for a specific device.
    ///
    /// Oracle: the expected bytes are the literals passed in, not produced by any
    /// function under test.
    #[tokio::test]
    async fn key_package_save_and_get() {
        let (store, _f) = make_store().await;
        store
            .save_key_package("alice", "device_aaa", b"kp-data-aaa")
            .await
            .unwrap();

        let got = store.get_key_package("alice", "device_aaa").await.unwrap();
        assert_eq!(
            got.as_deref(),
            Some(b"kp-data-aaa" as &[u8]),
            "get_key_package must return the bytes that were saved"
        );
    }

    /// Different devices for the same pub_id are stored independently.
    ///
    /// Oracle: each returned payload matches the literal written for that device.
    #[tokio::test]
    async fn key_package_multiple_devices_independent() {
        let (store, _f) = make_store().await;
        store
            .save_key_package("bob", "dev1", b"kp-bob-dev1")
            .await
            .unwrap();
        store
            .save_key_package("bob", "dev2", b"kp-bob-dev2")
            .await
            .unwrap();

        let dev1 = store.get_key_package("bob", "dev1").await.unwrap();
        let dev2 = store.get_key_package("bob", "dev2").await.unwrap();
        assert_eq!(
            dev1.as_deref(),
            Some(b"kp-bob-dev1" as &[u8]),
            "dev1 must return its own bytes"
        );
        assert_eq!(
            dev2.as_deref(),
            Some(b"kp-bob-dev2" as &[u8]),
            "dev2 must return its own bytes"
        );
    }

    /// get_all_key_packages returns all devices; unknown pub_id returns empty vec.
    ///
    /// Oracle: the expected count and bytes are the literals inserted.
    #[tokio::test]
    async fn key_package_get_all() {
        let (store, _f) = make_store().await;
        store
            .save_key_package("carol", "d1", b"c-d1")
            .await
            .unwrap();
        store
            .save_key_package("carol", "d2", b"c-d2")
            .await
            .unwrap();

        let all = store.get_all_key_packages("carol").await.unwrap();
        assert_eq!(all.len(), 2, "get_all must return both devices");

        let empty = store.get_all_key_packages("nobody").await.unwrap();
        assert!(empty.is_empty(), "unknown pub_id must return empty vec");
    }

    /// delete_device_key_package removes only the named device; sibling survives.
    ///
    /// Oracle: after delete, get_key_package returns None for the deleted device
    /// and Some for the sibling — verified against inserted literals.
    #[tokio::test]
    async fn key_package_delete_device_leaves_sibling() {
        let (store, _f) = make_store().await;
        store
            .save_key_package("dave", "phone", b"kp-phone")
            .await
            .unwrap();
        store
            .save_key_package("dave", "laptop", b"kp-laptop")
            .await
            .unwrap();

        store
            .delete_device_key_package("dave", "phone")
            .await
            .unwrap();

        let phone = store.get_key_package("dave", "phone").await.unwrap();
        assert!(phone.is_none(), "deleted device must not be found");

        let laptop = store.get_key_package("dave", "laptop").await.unwrap();
        assert_eq!(
            laptop.as_deref(),
            Some(b"kp-laptop" as &[u8]),
            "sibling device must survive deletion"
        );
    }

    /// save_key_package is idempotent: second save with same device_id replaces data.
    ///
    /// Oracle: the final returned bytes must match the second literal, not the first.
    #[tokio::test]
    async fn key_package_save_replaces_same_device() {
        let (store, _f) = make_store().await;
        store
            .save_key_package("eve", "devX", b"old-kp")
            .await
            .unwrap();
        store
            .save_key_package("eve", "devX", b"new-kp")
            .await
            .unwrap();

        let got = store.get_key_package("eve", "devX").await.unwrap();
        assert_eq!(
            got.as_deref(),
            Some(b"new-kp" as &[u8]),
            "second save must replace the first"
        );

        let all = store.get_all_key_packages("eve").await.unwrap();
        assert_eq!(all.len(), 1, "upsert must not create a second row");
    }

    /// Migration v0→v1: data written under the old single-column schema survives.
    ///
    /// Simulates the old schema by inserting directly into the table via raw SQL
    /// with the old structure, then opening a fresh Store on the same file to
    /// trigger the migration.  Verifies the migrated row is reachable with
    /// device_id='legacy'.
    ///
    /// Oracle: the raw bytes are the literal written before migration.
    #[tokio::test]
    async fn key_package_v0_to_v1_migration_preserves_data() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let url = format!("sqlite:{}?mode=rwc", f.path().display());

        // Bootstrap a pool directly to build the old schema (no PRAGMA user_version).
        {
            let pool = sqlx::sqlite::SqlitePool::connect(&url).await.unwrap();
            sqlx::query(
                "CREATE TABLE key_packages (
                    pub_id      TEXT PRIMARY KEY,
                    data        BLOB NOT NULL,
                    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
                )",
            )
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query("INSERT INTO key_packages (pub_id, data) VALUES ('frank', ?)")
                .bind(b"frank-kp" as &[u8])
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }

        // Open via Store::new — this triggers the v0→v1 migration.
        let store = Store::new(&url).await.unwrap();

        // The migrated row must be accessible with device_id='legacy'.
        let got = store.get_key_package("frank", "legacy").await.unwrap();
        assert_eq!(
            got.as_deref(),
            Some(b"frank-kp" as &[u8]),
            "v0 data must survive migration with device_id='legacy'"
        );
    }
}
