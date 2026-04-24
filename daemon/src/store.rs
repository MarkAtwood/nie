// Methods are used by later beads (JMAP HTTP handlers).
#![allow(dead_code)]

use anyhow::{Context, Result};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use ulid::Ulid;

// ── Private type alias for complex sqlx tuple ─────────────────────────────────
#[allow(clippy::type_complexity)]
type ChatTuple = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    i64,
    i64,
);

// ── Row types for JMAP method handlers ────────────────────────────────────────

#[derive(Debug)]
pub struct ChatContactRow {
    pub id: String,
    pub login: String,
    pub display_name: Option<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub presence: String,
    pub blocked: bool,
}

#[derive(Debug)]
pub struct ChatRow {
    pub id: String,
    pub kind: String,
    pub name: Option<String>,
    pub space_id: Option<String>,
    pub contact_id: Option<String>,
    pub created_at: String,
    pub last_message_at: Option<String>,
    pub unread_count: i64,
    pub muted: bool,
}

#[derive(Debug)]
pub struct SpaceRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Debug)]
pub struct SpaceMemberRow {
    pub space_id: String,
    pub contact_id: String,
    pub nick: Option<String>,
    pub role: String,
    pub joined_at: String,
}

#[derive(Debug)]
pub struct SpaceInviteRow {
    pub id: String,
    /// User-shareable, server-assigned invite code (distinct from `id`).
    pub code: String,
    pub space_id: String,
    pub created_by: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug)]
pub struct CategoryRow {
    pub id: String,
    pub space_id: String,
    pub name: String,
    pub sort_order: i64,
}

#[derive(Debug, sqlx::FromRow)]
pub struct MessageRow {
    pub id: String,
    pub sender_msg_id: String,
    pub chat_id: String,
    pub sender_id: String,
    pub body: String,
    pub body_type: String,
    pub sent_at: String,
    pub received_at: String,
    pub delivery_state: String,
    pub deleted_at: Option<String>,
    pub deleted_for_all: bool,
    /// JSON object: { "<reactionId>": { "emoji": "...", "sentAt": "...", "senderId": "..." } }
    pub reactions: String,
    /// JSON array of previous body versions: [{ "body": "...", "editedAt": "..." }]
    pub edit_history: String,
    pub reply_to: Option<String>,
    pub thread_root_id: Option<String>,
    pub expires_at: Option<String>,
    pub burn_on_read: bool,
}

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

        if version < 2 {
            let mut tx = self.pool.begin().await?;
            // message: rich-message feature columns (nie-a2l0) and expiry columns (nie-jtsk)
            for stmt in &[
                "ALTER TABLE message ADD COLUMN deleted_for_all INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE message ADD COLUMN thread_root_id TEXT",
                "ALTER TABLE message ADD COLUMN expires_at TEXT",
                "ALTER TABLE message ADD COLUMN burn_on_read INTEGER NOT NULL DEFAULT 0",
                // chat: per-chat expiry policy (nie-jtsk)
                "ALTER TABLE chat ADD COLUMN message_expiry_seconds INTEGER",
            ] {
                sqlx::query(stmt).execute(&mut *tx).await?;
            }
            sqlx::query("PRAGMA user_version = 2")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }

        if version < 3 {
            let mut tx = self.pool.begin().await?;
            // blob: content-addressed storage for RFC 8620 §6 upload/download (nie-cgtz)
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS blob (
                    id TEXT NOT NULL PRIMARY KEY,
                    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
                    size INTEGER NOT NULL,
                    data BLOB NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )",
            )
            .execute(&mut *tx)
            .await?;
            sqlx::query("PRAGMA user_version = 3")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }

        if version < 4 {
            let mut tx = self.pool.begin().await?;
            // space model: roles, invites, categories (nie-7ew5)
            for stmt in &[
                // role on space_member: admin | moderator | member
                "ALTER TABLE space_member ADD COLUMN role TEXT NOT NULL DEFAULT 'member'",
                // category_id on chat: optional grouping within a space
                "ALTER TABLE chat ADD COLUMN category_id TEXT",
            ] {
                sqlx::query(stmt).execute(&mut *tx).await?;
            }
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS space_invite (
                    id TEXT NOT NULL PRIMARY KEY,
                    code TEXT NOT NULL UNIQUE,
                    space_id TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    expires_at TEXT
                )",
            )
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS category (
                    id TEXT NOT NULL PRIMARY KEY,
                    space_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    sort_order INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )",
            )
            .execute(&mut *tx)
            .await?;
            // Register new state token types (idempotent INSERT OR IGNORE)
            for type_name in &["SpaceMember", "Category"] {
                sqlx::query("INSERT OR IGNORE INTO state_version (type_name, seq) VALUES (?, 1)")
                    .bind(type_name)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("PRAGMA user_version = 4")
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

    /// Clear displayName (set to NULL).  Returns Ok(true) if found, Ok(false) if not found.
    pub async fn clear_contact_display_name(&self, pub_id: &str) -> Result<bool> {
        let rows = sqlx::query("UPDATE chat_contact SET display_name = NULL WHERE id = ?")
            .bind(pub_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if rows > 0 {
            self.bump_state_seq("ChatContact").await?;
        }
        Ok(rows > 0)
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

    /// Create a space and add `creator_pub_id` as its first admin member.
    pub async fn create_space_full(
        &self,
        id: &str,
        name: &str,
        description: Option<&str>,
        creator_pub_id: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT OR IGNORE INTO space (id, name, description) VALUES (?, ?, ?)")
            .bind(id)
            .bind(name)
            .bind(description)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT OR IGNORE INTO space_member (space_id, contact_id, role) VALUES (?, ?, 'admin')",
        )
        .bind(id)
        .bind(creator_pub_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.bump_state_seq("Space").await?;
        self.bump_state_seq("SpaceMember").await?;
        Ok(())
    }

    /// Fetch spaces by IDs.  Pass `None` to return all spaces.
    /// Returns `(found_rows, not_found_ids)`.
    pub async fn get_spaces(&self, ids: Option<&[&str]>) -> Result<(Vec<SpaceRow>, Vec<String>)> {
        match ids {
            None => {
                let rows = sqlx::query_as::<_, (String, String, Option<String>, String)>(
                    "SELECT id, name, description, created_at FROM space ORDER BY created_at ASC",
                )
                .fetch_all(&self.pool)
                .await?;
                let spaces = rows
                    .into_iter()
                    .map(|(id, name, description, created_at)| SpaceRow {
                        id,
                        name,
                        description,
                        created_at,
                    })
                    .collect();
                Ok((spaces, vec![]))
            }
            Some(ids) => {
                let mut found = Vec::new();
                let mut not_found = Vec::new();
                for &id in ids {
                    let row = sqlx::query_as::<_, (String, String, Option<String>, String)>(
                        "SELECT id, name, description, created_at FROM space WHERE id = ?",
                    )
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await?;
                    match row {
                        Some((id, name, description, created_at)) => found.push(SpaceRow {
                            id,
                            name,
                            description,
                            created_at,
                        }),
                        None => not_found.push(id.to_string()),
                    }
                }
                Ok((found, not_found))
            }
        }
    }

    /// Return all space IDs ordered by creation time.
    pub async fn query_spaces(&self) -> Result<Vec<String>> {
        Ok(
            sqlx::query_scalar::<_, String>("SELECT id FROM space ORDER BY created_at ASC")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    /// Update space name and/or description.  Returns `true` if found.
    pub async fn update_space_props(
        &self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<bool> {
        if name.is_none() && description.is_none() {
            // Nothing to update; check existence.
            let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM space WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            return Ok(exists.is_some());
        }
        let rows = if let Some(n) = name {
            if let Some(d) = description {
                sqlx::query("UPDATE space SET name = ?, description = ? WHERE id = ?")
                    .bind(n)
                    .bind(d)
                    .bind(id)
                    .execute(&self.pool)
                    .await?
                    .rows_affected()
            } else {
                sqlx::query("UPDATE space SET name = ? WHERE id = ?")
                    .bind(n)
                    .bind(id)
                    .execute(&self.pool)
                    .await?
                    .rows_affected()
            }
        } else if let Some(d) = description {
            sqlx::query("UPDATE space SET description = ? WHERE id = ?")
                .bind(d)
                .bind(id)
                .execute(&self.pool)
                .await?
                .rows_affected()
        } else {
            0
        };
        if rows > 0 {
            self.bump_state_seq("Space").await?;
        }
        Ok(rows > 0)
    }

    /// Permanently delete a space row.  Returns `true` if a row was deleted.
    pub async fn delete_space(&self, id: &str) -> Result<bool> {
        let rows = sqlx::query("DELETE FROM space WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if rows > 0 {
            self.bump_state_seq("Space").await?;
        }
        Ok(rows > 0)
    }

    // ── SpaceMember ──────────────────────────────────────────────────────────

    /// Return all members of a space.
    pub async fn get_space_members(&self, space_id: &str) -> Result<Vec<SpaceMemberRow>> {
        let rows = sqlx::query_as::<_, (String, String, Option<String>, String, String)>(
            "SELECT space_id, contact_id, nick, role, joined_at
             FROM space_member WHERE space_id = ? ORDER BY joined_at ASC",
        )
        .bind(space_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(space_id, contact_id, nick, role, joined_at)| SpaceMemberRow {
                    space_id,
                    contact_id,
                    nick,
                    role,
                    joined_at,
                },
            )
            .collect())
    }

    /// Add or re-add a member with a specific role.
    /// If already a member, updates the role.
    ///
    /// **Precondition**: `role` must be one of `"admin"`, `"moderator"`, or
    /// `"member"`. The store accepts any string — callers are responsible for
    /// validation before calling this function. See `apply_member_patch` in
    /// `jmap.rs` for the canonical validation site.
    pub async fn upsert_space_member_with_role(
        &self,
        space_id: &str,
        contact_id: &str,
        role: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO space_member (space_id, contact_id, role)
             VALUES (?, ?, ?)
             ON CONFLICT(space_id, contact_id) DO UPDATE SET role = excluded.role",
        )
        .bind(space_id)
        .bind(contact_id)
        .bind(role)
        .execute(&self.pool)
        .await?;
        self.bump_state_seq("SpaceMember").await?;
        Ok(())
    }

    /// Update a member's role.  Returns `true` if the member was found.
    pub async fn set_member_role(
        &self,
        space_id: &str,
        contact_id: &str,
        role: &str,
    ) -> Result<bool> {
        let rows =
            sqlx::query("UPDATE space_member SET role = ? WHERE space_id = ? AND contact_id = ?")
                .bind(role)
                .bind(space_id)
                .bind(contact_id)
                .execute(&self.pool)
                .await?
                .rows_affected();
        if rows > 0 {
            self.bump_state_seq("SpaceMember").await?;
        }
        Ok(rows > 0)
    }

    /// Remove a member from a space.  Returns `true` if a row was deleted.
    pub async fn remove_space_member(&self, space_id: &str, contact_id: &str) -> Result<bool> {
        let rows = sqlx::query("DELETE FROM space_member WHERE space_id = ? AND contact_id = ?")
            .bind(space_id)
            .bind(contact_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if rows > 0 {
            self.bump_state_seq("SpaceMember").await?;
        }
        Ok(rows > 0)
    }

    // ── SpaceInvite ───────────────────────────────────────────────────────────

    /// Create a new invite with a server-assigned id and code.
    /// `id` and `code` are generated by the caller (both must be unique).
    pub async fn create_space_invite(
        &self,
        id: &str,
        code: &str,
        space_id: &str,
        created_by: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO space_invite (id, code, space_id, created_by) VALUES (?, ?, ?, ?)",
        )
        .bind(id)
        .bind(code)
        .bind(space_id)
        .bind(created_by)
        .execute(&self.pool)
        .await?;
        self.bump_state_seq("SpaceInvite").await?;
        Ok(())
    }

    /// Fetch invites by IDs.  Pass `None` to return all invites.
    pub async fn get_space_invites(
        &self,
        ids: Option<&[&str]>,
    ) -> Result<(Vec<SpaceInviteRow>, Vec<String>)> {
        match ids {
            None => {
                let rows =
                    sqlx::query_as::<_, (String, String, String, String, String, Option<String>)>(
                        "SELECT id, code, space_id, created_by, created_at, expires_at
                     FROM space_invite ORDER BY created_at ASC",
                    )
                    .fetch_all(&self.pool)
                    .await?;
                Ok((
                    rows.into_iter().map(Self::tuple_to_invite).collect(),
                    vec![],
                ))
            }
            Some(ids) => {
                let mut found = Vec::new();
                let mut not_found = Vec::new();
                for &id in ids {
                    let row = sqlx::query_as::<
                        _,
                        (String, String, String, String, String, Option<String>),
                    >(
                        "SELECT id, code, space_id, created_by, created_at, expires_at
                         FROM space_invite WHERE id = ?",
                    )
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await?;
                    match row {
                        Some(r) => found.push(Self::tuple_to_invite(r)),
                        None => not_found.push(id.to_string()),
                    }
                }
                Ok((found, not_found))
            }
        }
    }

    fn tuple_to_invite(
        (id, code, space_id, created_by, created_at, expires_at): (
            String,
            String,
            String,
            String,
            String,
            Option<String>,
        ),
    ) -> SpaceInviteRow {
        SpaceInviteRow {
            id,
            code,
            space_id,
            created_by,
            created_at,
            expires_at,
        }
    }

    /// Accept an invite by its user-shareable code.
    /// Looks up the invite, adds `user_pub_id` as a member of the space, and
    /// returns the `space_id` on success, or `None` if the code is invalid /
    /// expired.
    pub async fn use_space_invite_code(
        &self,
        code: &str,
        user_pub_id: &str,
    ) -> Result<Option<String>> {
        let row: Option<(String, Option<String>)> =
            sqlx::query_as("SELECT space_id, expires_at FROM space_invite WHERE code = ?")
                .bind(code)
                .fetch_optional(&self.pool)
                .await?;
        let Some((space_id, expires_at)) = row else {
            return Ok(None);
        };
        // Reject expired invites.
        if let Some(exp) = &expires_at {
            let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
            if exp.as_str() < now.as_str() {
                return Ok(None);
            }
        }
        self.upsert_space_member_with_role(&space_id, user_pub_id, "member")
            .await?;
        Ok(Some(space_id))
    }

    // ── Category ──────────────────────────────────────────────────────────────

    /// Return all categories for a space, ordered by sort_order.
    pub async fn get_categories(&self, space_id: &str) -> Result<Vec<CategoryRow>> {
        let rows = sqlx::query_as::<_, (String, String, String, i64)>(
            "SELECT id, space_id, name, sort_order FROM category WHERE space_id = ?
             ORDER BY sort_order ASC",
        )
        .bind(space_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, space_id, name, sort_order)| CategoryRow {
                id,
                space_id,
                name,
                sort_order,
            })
            .collect())
    }

    /// Create a category in a space.
    pub async fn create_category(&self, id: &str, space_id: &str, name: &str) -> Result<()> {
        sqlx::query("INSERT OR IGNORE INTO category (id, space_id, name) VALUES (?, ?, ?)")
            .bind(id)
            .bind(space_id)
            .bind(name)
            .execute(&self.pool)
            .await?;
        self.bump_state_seq("Category").await?;
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
        self.insert_message_ext(chat_id, sender_id, body, sent_at, None, None, None, false)
            .await
    }

    /// Extended insert supporting optional rich-message and expiry fields.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_message_ext(
        &self,
        chat_id: &str,
        sender_id: &str,
        body: &str,
        sent_at: &str,
        reply_to: Option<&str>,
        thread_root_id: Option<&str>,
        expires_at: Option<&str>,
        burn_on_read: bool,
    ) -> Result<String> {
        let id = Ulid::new().to_string();
        let sender_msg_id = Ulid::new().to_string();
        sqlx::query(
            "INSERT INTO message
                (id, sender_msg_id, chat_id, sender_id, body, sent_at,
                 reply_to, thread_root_id, expires_at, burn_on_read)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&sender_msg_id)
        .bind(chat_id)
        .bind(sender_id)
        .bind(body)
        .bind(sent_at)
        .bind(reply_to)
        .bind(thread_root_id)
        .bind(expires_at)
        .bind(if burn_on_read { 1i64 } else { 0i64 })
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

    // ── ChatContact read/query ────────────────────────────────────────────────

    /// Fetch contacts by IDs.  Pass `None` to return all contacts.
    /// Returns `(found_rows, not_found_ids)`.
    pub async fn get_contacts(
        &self,
        ids: Option<&[&str]>,
    ) -> Result<(Vec<ChatContactRow>, Vec<String>)> {
        match ids {
            None => {
                let rows = sqlx::query_as::<
                    _,
                    (String, String, Option<String>, String, String, String, i64),
                >(
                    "SELECT id, login, display_name, first_seen_at, last_seen_at, presence, blocked
                     FROM chat_contact
                     ORDER BY first_seen_at ASC",
                )
                .fetch_all(&self.pool)
                .await?;
                let contacts = rows.into_iter().map(Self::tuple_to_contact).collect();
                Ok((contacts, vec![]))
            }
            Some(ids) => {
                let mut found = Vec::new();
                let mut not_found = Vec::new();
                for &id in ids {
                    let row = sqlx::query_as::<_, (String, String, Option<String>, String, String, String, i64)>(
                        "SELECT id, login, display_name, first_seen_at, last_seen_at, presence, blocked
                         FROM chat_contact WHERE id = ?",
                    )
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await?;
                    match row {
                        Some(r) => found.push(Self::tuple_to_contact(r)),
                        None => not_found.push(id.to_string()),
                    }
                }
                Ok((found, not_found))
            }
        }
    }

    fn tuple_to_contact(
        (id, login, display_name, first_seen_at, last_seen_at, presence, blocked): (
            String,
            String,
            Option<String>,
            String,
            String,
            String,
            i64,
        ),
    ) -> ChatContactRow {
        ChatContactRow {
            id,
            login,
            display_name,
            first_seen_at,
            last_seen_at,
            presence,
            blocked: blocked != 0,
        }
    }

    /// Return all contact IDs matching the optional presence/blocked filters,
    /// ordered by first_seen_at ascending.
    pub async fn query_contacts(
        &self,
        presence: Option<&str>,
        blocked: Option<bool>,
    ) -> Result<Vec<String>> {
        // Build query dynamically based on which filters are present.
        let mut conditions = Vec::new();
        if presence.is_some() {
            conditions.push("presence = ?1");
        }
        if blocked.is_some() {
            conditions.push("blocked = ?2");
        }
        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };
        let sql = format!("SELECT id FROM chat_contact {where_clause} ORDER BY first_seen_at ASC");
        // sqlx doesn't support fully dynamic binding; use raw query with explicit branches.
        let ids: Vec<String> = match (presence, blocked) {
            (None, None) => sqlx::query_scalar(&sql).fetch_all(&self.pool).await?,
            (Some(p), None) => {
                sqlx::query_scalar(&sql)
                    .bind(p)
                    .fetch_all(&self.pool)
                    .await?
            }
            (None, Some(b)) => {
                sqlx::query_scalar(&sql)
                    .bind(i64::from(b))
                    .fetch_all(&self.pool)
                    .await?
            }
            (Some(p), Some(b)) => {
                sqlx::query_scalar(&sql)
                    .bind(p)
                    .bind(i64::from(b))
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(ids)
    }

    /// Update the `blocked` flag on a contact. Returns Ok(true) if found, Ok(false) if not found.
    pub async fn set_contact_blocked(&self, pub_id: &str, blocked: bool) -> Result<bool> {
        let rows = sqlx::query(
            "UPDATE chat_contact SET blocked = ?, last_seen_at = last_seen_at WHERE id = ?",
        )
        .bind(i64::from(blocked))
        .bind(pub_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if rows > 0 {
            self.bump_state_seq("ChatContact").await?;
        }
        Ok(rows > 0)
    }

    // ── Chat read/query ───────────────────────────────────────────────────────

    /// Fetch chats by IDs.  Pass `None` to return all chats.
    /// Returns `(found_rows, not_found_ids)`.
    pub async fn get_chats(&self, ids: Option<&[&str]>) -> Result<(Vec<ChatRow>, Vec<String>)> {
        match ids {
            None => {
                let rows = sqlx::query_as::<_, ChatTuple>(
                    "SELECT id, kind, name, space_id, contact_id, created_at, last_message_at, unread_count, muted
                     FROM chat ORDER BY created_at ASC",
                )
                .fetch_all(&self.pool)
                .await?;
                let chats = rows.into_iter().map(Self::tuple_to_chat).collect();
                Ok((chats, vec![]))
            }
            Some(ids) => {
                let mut found = Vec::new();
                let mut not_found = Vec::new();
                for &id in ids {
                    let row = sqlx::query_as::<_, ChatTuple>(
                        "SELECT id, kind, name, space_id, contact_id, created_at, last_message_at, unread_count, muted
                         FROM chat WHERE id = ?",
                    )
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await?;
                    match row {
                        Some(r) => found.push(Self::tuple_to_chat(r)),
                        None => not_found.push(id.to_string()),
                    }
                }
                Ok((found, not_found))
            }
        }
    }

    fn tuple_to_chat(
        (id, kind, name, space_id, contact_id, created_at, last_message_at, unread_count, muted): ChatTuple,
    ) -> ChatRow {
        ChatRow {
            id,
            kind,
            name,
            space_id,
            contact_id,
            created_at,
            last_message_at,
            unread_count,
            muted: muted != 0,
        }
    }

    // ── Message read/query ────────────────────────────────────────────────────

    /// Fetch messages by IDs.  Returns `(found_rows, not_found_ids)`.
    pub async fn get_messages(&self, ids: &[&str]) -> Result<(Vec<MessageRow>, Vec<String>)> {
        let mut found = Vec::new();
        let mut not_found = Vec::new();
        for &id in ids {
            let row = sqlx::query_as::<_, MessageRow>(
                "SELECT id, sender_msg_id, chat_id, sender_id, body, body_type, sent_at,
                        received_at, delivery_state, deleted_at, deleted_for_all,
                        reactions, edit_history, reply_to, thread_root_id, expires_at, burn_on_read
                 FROM message WHERE id = ?",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
            match row {
                Some(r) => found.push(r),
                None => not_found.push(id.to_string()),
            }
        }
        Ok((found, not_found))
    }

    /// Query messages in a chat, ordered by received_at ascending.
    /// `chat_id` is required (callers must filter by chat).
    /// Returns up to `limit` messages starting at `position` (0-based).
    pub async fn query_messages(
        &self,
        chat_id: &str,
        position: i64,
        limit: i64,
    ) -> Result<Vec<String>> {
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM message WHERE chat_id = ? AND deleted_at IS NULL
             ORDER BY received_at ASC LIMIT ? OFFSET ?",
        )
        .bind(chat_id)
        .bind(limit)
        .bind(position)
        .fetch_all(&self.pool)
        .await?;
        Ok(ids)
    }

    /// Count messages in a chat (for `total` in query responses).
    pub async fn count_messages_in_chat(&self, chat_id: &str) -> Result<i64> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM message WHERE chat_id = ? AND deleted_at IS NULL",
        )
        .bind(chat_id)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Reset unread count for a chat to zero.
    pub async fn mark_chat_read(&self, chat_id: &str) -> Result<()> {
        sqlx::query("UPDATE chat SET unread_count = 0 WHERE id = ?")
            .bind(chat_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Message mutations ─────────────────────────────────────────────────────

    /// Soft-delete a message by setting `deleted_at`.
    /// `for_all`: if true, also sets `deleted_for_all = 1` (visible to peers).
    /// Returns `true` if the message was found, `false` if not found.
    pub async fn soft_delete_message(&self, msg_id: &str, for_all: bool) -> Result<bool> {
        let affected = sqlx::query(
            "UPDATE message SET deleted_at = datetime('now'), deleted_for_all = ? WHERE id = ?",
        )
        .bind(if for_all { 1i64 } else { 0i64 })
        .bind(msg_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if affected > 0 {
            self.bump_state_seq("Message").await?;
        }
        Ok(affected > 0)
    }

    /// Update the `delivery_state` column of a message by its JMAP id.
    /// Returns `true` if the row was found.
    pub async fn update_message_delivery_state(
        &self,
        msg_id: &str,
        delivery_state: &str,
    ) -> Result<bool> {
        let rows = sqlx::query("UPDATE message SET delivery_state = ? WHERE id = ?")
            .bind(delivery_state)
            .bind(msg_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if rows > 0 {
            self.bump_state_seq("Message").await?;
        }
        Ok(rows > 0)
    }

    /// Hard-delete a message row entirely (no tombstone).
    /// Returns `true` if a row was deleted.
    pub async fn hard_delete_message(&self, msg_id: &str) -> Result<bool> {
        let affected = sqlx::query("DELETE FROM message WHERE id = ?")
            .bind(msg_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if affected > 0 {
            self.bump_state_seq("Message").await?;
        }
        Ok(affected > 0)
    }

    /// Add or update a reaction on a message.
    /// `senderId` is always stored as `"self"` for locally-originated reactions.
    /// Returns `true` if the message was found.
    pub async fn set_message_reaction(
        &self,
        msg_id: &str,
        reaction_id: &str,
        emoji: &str,
        sent_at: &str,
    ) -> Result<bool> {
        let existing: Option<String> =
            sqlx::query_scalar("SELECT reactions FROM message WHERE id = ?")
                .bind(msg_id)
                .fetch_optional(&self.pool)
                .await?;
        let Some(json_str) = existing else {
            return Ok(false);
        };
        let mut map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&json_str).unwrap_or_default();
        map.insert(
            reaction_id.to_string(),
            serde_json::json!({ "emoji": emoji, "sentAt": sent_at, "senderId": "self" }),
        );
        let new_json = serde_json::to_string(&map)?;
        sqlx::query("UPDATE message SET reactions = ? WHERE id = ?")
            .bind(&new_json)
            .bind(msg_id)
            .execute(&self.pool)
            .await?;
        self.bump_state_seq("Message").await?;
        Ok(true)
    }

    /// Remove a reaction from a message.
    /// Returns `true` if the message was found (even if the reaction_id wasn't present).
    pub async fn remove_message_reaction(&self, msg_id: &str, reaction_id: &str) -> Result<bool> {
        let existing: Option<String> =
            sqlx::query_scalar("SELECT reactions FROM message WHERE id = ?")
                .bind(msg_id)
                .fetch_optional(&self.pool)
                .await?;
        let Some(json_str) = existing else {
            return Ok(false);
        };
        let mut map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&json_str).unwrap_or_default();
        if map.remove(reaction_id).is_none() {
            return Ok(true); // message found, reaction simply wasn't there
        }
        let new_json = serde_json::to_string(&map)?;
        sqlx::query("UPDATE message SET reactions = ? WHERE id = ?")
            .bind(&new_json)
            .bind(msg_id)
            .execute(&self.pool)
            .await?;
        self.bump_state_seq("Message").await?;
        Ok(true)
    }

    /// Edit a message body.  Saves the previous body to `edit_history`.
    /// Returns `true` if the message was found.
    pub async fn edit_message_body(&self, msg_id: &str, new_body: &str) -> Result<bool> {
        let row: Option<(String, String, String)> =
            sqlx::query_as("SELECT body, sent_at, edit_history FROM message WHERE id = ?")
                .bind(msg_id)
                .fetch_optional(&self.pool)
                .await?;
        let Some((old_body, sent_at, history_json)) = row else {
            return Ok(false);
        };
        let mut history: Vec<serde_json::Value> =
            serde_json::from_str(&history_json).unwrap_or_default();
        history.push(serde_json::json!({
            "body": old_body,
            "sentAt": sent_at,
            "editedAt": chrono::Utc::now().to_rfc3339(),
        }));
        let new_history = serde_json::to_string(&history)?;
        sqlx::query("UPDATE message SET body = ?, edit_history = ? WHERE id = ?")
            .bind(new_body)
            .bind(&new_history)
            .bind(msg_id)
            .execute(&self.pool)
            .await?;
        self.bump_state_seq("Message").await?;
        Ok(true)
    }

    /// Mark a message as read.  If `burn_on_read = 1`, hard-deletes the message
    /// and returns `true`.  Otherwise sets a `read_at` marker and returns `false`.
    /// Returns `Err` if the message is not found.
    pub async fn read_message(&self, msg_id: &str, read_at: &str) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as("SELECT burn_on_read FROM message WHERE id = ?")
            .bind(msg_id)
            .fetch_optional(&self.pool)
            .await?;
        let Some((burn,)) = row else {
            anyhow::bail!("message not found: {msg_id}");
        };
        if burn != 0 {
            self.hard_delete_message(msg_id).await?;
            return Ok(true); // burned
        }
        // No dedicated read_at column; update delivery_state to 'read'.
        sqlx::query("UPDATE message SET delivery_state = 'read' WHERE id = ?")
            .bind(msg_id)
            .execute(&self.pool)
            .await?;
        let _ = read_at; // stored implicitly via delivery_state transition
        self.bump_state_seq("Message").await?;
        Ok(false)
    }

    /// Hard-delete all messages whose `expires_at` is in the past.
    /// Returns the number of rows deleted.
    pub async fn hard_delete_expired_messages(&self) -> Result<u64> {
        let n = sqlx::query(
            "DELETE FROM message WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')",
        )
        .execute(&self.pool)
        .await?
        .rows_affected();
        if n > 0 {
            self.bump_state_seq("Message").await?;
        }
        Ok(n)
    }

    // ── Blob ──────────────────────────────────────────────────────────────────

    /// Store a blob.  The blob ID is the hex-encoded SHA-256 of the content.
    /// Idempotent: if the same ID already exists, returns the existing ID without error.
    pub async fn upsert_blob(&self, blob_id: &str, content_type: &str, data: &[u8]) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO blob (id, content_type, size, data) VALUES (?, ?, ?, ?)",
        )
        .bind(blob_id)
        .bind(content_type)
        .bind(data.len() as i64)
        .bind(data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Retrieve a blob by ID.  Returns `(content_type, data)` or `None` if not found.
    pub async fn get_blob(&self, blob_id: &str) -> Result<Option<(String, Vec<u8>)>> {
        let row: Option<(String, Vec<u8>)> =
            sqlx::query_as("SELECT content_type, data FROM blob WHERE id = ?")
                .bind(blob_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row)
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
