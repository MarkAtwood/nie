// Phase 1: plaintext local message history.
//
// Messages are stored unencrypted in history.db. After MLS is integrated, the
// payload column will store decrypted cleartext (MLS handles confidentiality in
// transit; local-at-rest encryption keyed from the identity key is Phase 2).
//
// Schema is broadcast-only — no "to" field. All messages go to the room.

use std::path::Path;

use anyhow::Result;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

/// Maximum rows retained in history.db. Older rows are pruned on open.
/// Phase 1 plaintext messages are small (~hundreds of bytes each), so
/// 10 000 rows ≈ a few MB at most.
pub const MAX_HISTORY_ROWS: i64 = 10_000;

#[derive(Clone)]
pub struct History {
    pool: SqlitePool,
}

pub struct HistoryEntry {
    pub direction: String,   // "sent" or "received"
    pub from_pub_id: String, // sender's pub_id (our own for sent)
    pub payload: Vec<u8>,    // cleartext bytes; use String::from_utf8_lossy to display
    pub timestamp: i64,      // Unix seconds
}

impl History {
    pub async fn open(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("history.db");
        let url = format!("sqlite:{}?mode=rwc", path.to_string_lossy());
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                direction   TEXT    NOT NULL,
                from_pub_id TEXT    NOT NULL,
                payload     BLOB    NOT NULL,
                timestamp   INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        // Prune the oldest rows so the DB stays bounded. This runs on every open
        // (i.e. once per `nie chat` session) and is fast: the subquery uses the
        // primary-key index, and the DELETE touches only the excess tail.
        // Phase 2 (at-rest encryption) can lower this if encrypted payloads are
        // large; Phase 1 plaintext is small so 10 000 rows is ~a few MB max.
        prune_to(&pool, MAX_HISTORY_ROWS).await?;

        Ok(Self { pool })
    }
}

/// Delete rows beyond `max`, keeping the most-recent ones (by id).
/// Extracted so tests can exercise pruning with a small limit without
/// inserting tens of thousands of rows.
async fn prune_to(pool: &SqlitePool, max: i64) -> Result<()> {
    sqlx::query(
        "DELETE FROM messages WHERE id NOT IN \
         (SELECT id FROM messages ORDER BY id DESC LIMIT ?)",
    )
    .bind(max)
    .execute(pool)
    .await?;
    Ok(())
}

impl History {
    /// Record a message we received from `from_pub_id`.
    pub async fn append_received(&self, from_pub_id: &str, payload: &[u8]) -> Result<()> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        sqlx::query(
            "INSERT INTO messages (direction, from_pub_id, payload, timestamp) VALUES (?, ?, ?, ?)",
        )
        .bind("received")
        .bind(from_pub_id)
        .bind(payload)
        .bind(ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record a message we sent. `our_pub_id` identifies us as the sender.
    pub async fn append_sent(&self, our_pub_id: &str, payload: &[u8]) -> Result<()> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        sqlx::query(
            "INSERT INTO messages (direction, from_pub_id, payload, timestamp) VALUES (?, ?, ?, ?)",
        )
        .bind("sent")
        .bind(our_pub_id)
        .bind(payload)
        .bind(ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Return the most recent `limit` messages in chronological order.
    pub async fn recent(&self, limit: i64) -> Result<Vec<HistoryEntry>> {
        let rows: Vec<(String, String, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT direction, from_pub_id, payload, timestamp
             FROM messages
             ORDER BY id DESC
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        // Reverse so oldest-first for display.
        let entries = rows
            .into_iter()
            .rev()
            .map(
                |(direction, from_pub_id, payload, timestamp)| HistoryEntry {
                    direction,
                    from_pub_id,
                    payload,
                    timestamp,
                },
            )
            .collect();
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn append_and_retrieve() {
        let dir = tempfile::tempdir().expect("temp dir");
        let history = History::open(dir.path()).await.expect("open");

        history
            .append_sent("aabbcc", b"hello world")
            .await
            .expect("append sent");
        history
            .append_received("ddeeff", b"hi there")
            .await
            .expect("append received");

        let entries = history.recent(10).await.expect("recent");
        assert_eq!(entries.len(), 2);

        // Oldest first after reversal.
        assert_eq!(entries[0].direction, "sent");
        assert_eq!(entries[0].from_pub_id, "aabbcc");
        assert_eq!(entries[0].payload, b"hello world");

        assert_eq!(entries[1].direction, "received");
        assert_eq!(entries[1].from_pub_id, "ddeeff");
        assert_eq!(entries[1].payload, b"hi there");
    }

    #[tokio::test]
    async fn binary_payload_roundtrip() {
        // Regression guard: arbitrary bytes (e.g. MLS ciphertext) must survive
        // the BLOB round-trip unchanged. Earlier TEXT schema mangled non-UTF-8
        // sequences via from_utf8_lossy, permanently destroying data.
        let dir = tempfile::tempdir().expect("temp dir");
        let history = History::open(dir.path()).await.expect("open");

        let binary: Vec<u8> = (0u8..=255).collect(); // all 256 byte values
        history
            .append_sent("aabbcc", &binary)
            .await
            .expect("append binary");

        let entries = history.recent(1).await.expect("recent");
        assert_eq!(entries[0].payload, binary);
    }

    #[tokio::test]
    async fn pruning_keeps_newest_rows() {
        // Use prune_to directly with a small limit so the test stays fast.
        // This tests the same SQL path that open() calls with MAX_HISTORY_ROWS.
        let dir = tempfile::tempdir().expect("temp dir");
        let history = History::open(dir.path()).await.expect("open");

        for i in 0..15usize {
            history
                .append_sent("aabbcc", format!("msg {i}").as_bytes())
                .await
                .expect("append");
        }

        // Prune to 10 — should drop the 5 oldest (msg 0..4) and keep msg 5..14.
        prune_to(&history.pool, 10).await.expect("prune");

        let entries = history.recent(20).await.expect("recent");
        assert_eq!(entries.len(), 10, "should have exactly 10 rows after prune");
        assert_eq!(
            entries[0].payload, b"msg 5",
            "oldest survivor should be msg 5"
        );
        assert_eq!(
            entries[9].payload, b"msg 14",
            "newest survivor should be msg 14"
        );
    }

    #[tokio::test]
    async fn limit_respected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let history = History::open(dir.path()).await.expect("open");

        for i in 0..10 {
            history
                .append_sent("aabbcc", format!("msg {i}").as_bytes())
                .await
                .expect("append");
        }

        let entries = history.recent(3).await.expect("recent");
        assert_eq!(entries.len(), 3);
        // Should be the last 3 messages (7, 8, 9) in order.
        assert_eq!(entries[0].payload, b"msg 7");
        assert_eq!(entries[1].payload, b"msg 8");
        assert_eq!(entries[2].payload, b"msg 9");
    }
}
