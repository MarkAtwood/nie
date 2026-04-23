// Methods are used by later beads (JMAP HTTP handlers).
#![allow(dead_code)]

use anyhow::{Context, Result};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use ulid::Ulid;

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn new(db_url: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(db_url)
            .await
            .with_context(|| format!("open JMAP store: {db_url}"))?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<()> {
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&self.pool)
            .await?;

        if version < 1 {
            let mut tx = self.pool.begin().await?;
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS chat_contact (
                    id TEXT NOT NULL PRIMARY KEY,
                    login TEXT NOT NULL,
                    display_name TEXT,
                    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
                    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
                    presence TEXT NOT NULL DEFAULT 'offline',
                    last_active_at TEXT,
                    blocked INTEGER NOT NULL DEFAULT 0
                )",
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "CREATE TABLE IF NOT EXISTS space (
                    id TEXT NOT NULL PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )",
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "CREATE TABLE IF NOT EXISTS chat (
                    id TEXT NOT NULL PRIMARY KEY,
                    kind TEXT NOT NULL,
                    name TEXT,
                    space_id TEXT,
                    contact_id TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    last_message_at TEXT,
                    unread_count INTEGER NOT NULL DEFAULT 0,
                    muted INTEGER NOT NULL DEFAULT 0
                )",
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "CREATE TABLE IF NOT EXISTS message (
                    id TEXT NOT NULL PRIMARY KEY,
                    sender_msg_id TEXT NOT NULL,
                    chat_id TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    body TEXT NOT NULL DEFAULT '',
                    body_type TEXT NOT NULL DEFAULT 'text/plain',
                    sent_at TEXT NOT NULL,
                    received_at TEXT NOT NULL DEFAULT (datetime('now')),
                    delivery_state TEXT NOT NULL DEFAULT 'delivered',
                    deleted_at TEXT,
                    reactions TEXT NOT NULL DEFAULT '{}',
                    edit_history TEXT NOT NULL DEFAULT '[]',
                    reply_to TEXT
                )",
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_message_chat_id ON message(chat_id, received_at)",
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "CREATE TABLE IF NOT EXISTS space_member (
                    space_id TEXT NOT NULL,
                    contact_id TEXT NOT NULL,
                    nick TEXT,
                    joined_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (space_id, contact_id)
                )",
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "CREATE TABLE IF NOT EXISTS state_version (
                    type_name TEXT NOT NULL PRIMARY KEY,
                    seq INTEGER NOT NULL DEFAULT 1
                )",
            )
            .execute(&mut *tx)
            .await?;

            for type_name in &["ChatContact", "Chat", "Message", "Space", "SpaceInvite"] {
                sqlx::query("INSERT OR IGNORE INTO state_version (type_name, seq) VALUES (?, 1)")
                    .bind(type_name)
                    .execute(&mut *tx)
                    .await?;
            }

            sqlx::query("PRAGMA user_version = 1")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        Ok(())
    }

    // ── ChatContact ──────────────────────────────────────────────────────

    pub async fn upsert_chat_contact(&self, pub_id: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO chat_contact (id, login)
             VALUES (?, ?)
             ON CONFLICT(id) DO UPDATE SET last_seen_at = datetime('now')",
        )
        .bind(pub_id)
        .bind(pub_id)
        .execute(&self.pool)
        .await?;
        self.bump_state_seq("ChatContact").await?;
        Ok(())
    }

    pub async fn set_contact_presence(&self, pub_id: &str, presence: &str) -> Result<()> {
        sqlx::query(
            "UPDATE chat_contact SET presence = ?, last_seen_at = datetime('now')
             WHERE id = ?",
        )
        .bind(presence)
        .bind(pub_id)
        .execute(&self.pool)
        .await?;
        self.bump_state_seq("ChatContact").await?;
        Ok(())
    }

    pub async fn set_contact_display_name(&self, pub_id: &str, name: &str) -> Result<()> {
        sqlx::query("UPDATE chat_contact SET display_name = ? WHERE id = ?")
            .bind(name)
            .bind(pub_id)
            .execute(&self.pool)
            .await?;
        self.bump_state_seq("ChatContact").await?;
        Ok(())
    }

    // ── Space ────────────────────────────────────────────────────────────

    pub async fn find_space_by_name(&self, name: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT id FROM space WHERE name = ? LIMIT 1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.0))
    }

    pub async fn create_space(&self, id: &str, name: &str) -> Result<()> {
        sqlx::query("INSERT OR IGNORE INTO space (id, name) VALUES (?, ?)")
            .bind(id)
            .bind(name)
            .execute(&self.pool)
            .await?;
        self.bump_state_seq("Space").await?;
        Ok(())
    }

    // ── Chat ─────────────────────────────────────────────────────────────

    pub async fn find_channel_in_space(&self, space_id: &str) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT id FROM chat WHERE space_id = ? AND kind = 'channel' LIMIT 1")
                .bind(space_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| r.0))
    }

    pub async fn create_channel(&self, id: &str, name: &str, space_id: &str) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO chat (id, kind, name, space_id) VALUES (?, 'channel', ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(space_id)
        .execute(&self.pool)
        .await?;
        self.bump_state_seq("Chat").await?;
        Ok(())
    }

    // ── SpaceMember ──────────────────────────────────────────────────────

    pub async fn upsert_space_member(&self, space_id: &str, contact_id: &str) -> Result<()> {
        sqlx::query("INSERT OR IGNORE INTO space_member (space_id, contact_id) VALUES (?, ?)")
            .bind(space_id)
            .bind(contact_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Message ──────────────────────────────────────────────────────────

    pub async fn insert_message(
        &self,
        chat_id: &str,
        sender_id: &str,
        body: &str,
        sent_at: &str,
    ) -> Result<String> {
        let id = Ulid::new().to_string();
        let sender_msg_id = Ulid::new().to_string();
        sqlx::query(
            "INSERT INTO message (id, sender_msg_id, chat_id, sender_id, body, sent_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&sender_msg_id)
        .bind(chat_id)
        .bind(sender_id)
        .bind(body)
        .bind(sent_at)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE chat SET last_message_at = datetime('now'), unread_count = unread_count + 1
             WHERE id = ?",
        )
        .bind(chat_id)
        .execute(&self.pool)
        .await?;
        self.bump_state_seq("Message").await?;
        Ok(id)
    }

    // ── State tokens ─────────────────────────────────────────────────────

    pub async fn state_token(&self, type_name: &str) -> Result<String> {
        let seq: i64 = sqlx::query_scalar("SELECT seq FROM state_version WHERE type_name = ?")
            .bind(type_name)
            .fetch_optional(&self.pool)
            .await?
            .unwrap_or(1);
        Ok(seq.to_string())
    }

    async fn bump_state_seq(&self, type_name: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO state_version (type_name, seq) VALUES (?, 1)
             ON CONFLICT(type_name) DO UPDATE SET seq = seq + 1",
        )
        .bind(type_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub fn new_id() -> String {
        Ulid::new().to_string()
    }

    #[cfg(test)]
    pub(crate) async fn contact_count(&self) -> Result<i64> {
        Ok(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM chat_contact")
                .fetch_one(&self.pool)
                .await?,
        )
    }

    #[cfg(test)]
    pub(crate) async fn space_member_count(&self, space_id: &str) -> Result<i64> {
        Ok(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM space_member WHERE space_id = ?")
                .bind(space_id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    #[cfg(test)]
    pub(crate) async fn contact_presence(&self, pub_id: &str) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar::<_, String>("SELECT presence FROM chat_contact WHERE id = ?")
                .bind(pub_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }
}
