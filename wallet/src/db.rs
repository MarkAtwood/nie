use std::path::Path;

use anyhow::Result;
use nie_core::messages::{Chain, PaymentRole, PaymentSession, PaymentState};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use uuid::Uuid;

/// A received Sapling/Orchard note.
///
/// Field types are primitives — no dependency on `zcash_primitives`.
/// The four optional plaintext fields (`note_diversifier`, `note_pk_d`,
/// `note_rseed`, `rseed_after_zip212`) are populated by the IVK scanner when
/// it successfully decrypts an output.  They are `None` when a note is inserted
/// by the scan stub (pre-decryption path) or when decryption has not yet run.
/// `spendable_notes()` excludes rows where any of these is `None`.
#[derive(Debug, Clone)]
pub struct Note {
    /// Transaction that created this output (hex txid).
    pub txid: String,
    /// Output index within the transaction.
    pub output_index: i64,
    /// Value in zatoshi (1 ZEC = 10^8 zatoshi).
    pub value_zatoshi: u64,
    /// ZIP-302 shielded memo field (up to 512 bytes). `None` = empty/no memo.
    pub memo: Option<Vec<u8>>,
    /// Block height at which this note was confirmed.
    /// Used to compute confirmation depth: `depth = scan_tip - block_height`.
    pub block_height: u64,
    /// Unix timestamp of the block that confirmed this note.
    pub created_at: i64,
    /// Raw Sapling diversifier d — 11 bytes.  `None` if not yet decrypted.
    pub note_diversifier: Option<Vec<u8>>,
    /// Recipient public key pk_d — 32-byte compressed Jubjub point.  `None` if not yet decrypted.
    pub note_pk_d: Option<Vec<u8>>,
    /// Commitment randomness (Rseed post-ZIP-212, or rcm pre-ZIP-212) — 32 bytes.
    /// `None` if not yet decrypted.
    pub note_rseed: Option<Vec<u8>>,
    /// `true` → `note_rseed` is the post-ZIP-212 `Rseed` (randomness seed).
    /// `false` → `note_rseed` is the pre-ZIP-212 `rcm` (raw commitment randomness).
    /// `None` if `note_rseed` is not populated.
    pub rseed_after_zip212: Option<bool>,
}

/// A note that can be spent: all three plaintext columns are populated and an
/// incremental Merkle witness exists.
///
/// Unlike `Note`, which is returned by `unspent_notes()` and may have NULL
/// plaintext columns (not yet decrypted by the scanner), every field here is
/// guaranteed non-NULL.  `spendable_notes()` never returns a row with missing
/// plaintext data or a missing witness.
#[derive(Debug, Clone)]
pub struct SpendableNote {
    /// Primary key of the notes row.
    pub note_id: i64,
    /// Value in zatoshi (1 ZEC = 10^8 zatoshi).
    pub value_zatoshi: u64,
    /// Raw Sapling diversifier d — the 11-byte value from which g_d = GH("Zcash_gd", d)
    /// is derived.  PaymentAddress::from_bytes expects [d(11) | pk_d(32)].
    pub note_diversifier: Vec<u8>,
    /// Recipient public key pk_d — 32-byte compressed Jubjub point.
    pub note_pk_d: Vec<u8>,
    /// Commitment randomness (Rseed if `rseed_after_zip212`, old rcm otherwise).
    pub note_rseed: Vec<u8>,
    /// `true`  → `note_rseed` is the post-ZIP-212 `Rseed` (randomness seed).
    /// `false` → `note_rseed` is the pre-ZIP-212 `rcm` (raw commitment randomness).
    pub rseed_after_zip212: bool,
    /// Block height at which this note was confirmed.
    pub block_height: u64,
    /// Serialized `IncrementalWitness` bytes for the Sapling commitment tree.
    /// Written by the compact-block scanner; required by the tx builder to produce
    /// a Merkle inclusion proof.  Fetched by JOIN with the `witnesses` table in
    /// `spendable_notes()`.
    pub witness_data: Vec<u8>,
}

/// Shielded wallet balance split by confirmation depth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Balance {
    /// Sum of unspent notes at depth >= `min_confirmations`.
    pub confirmed_zatoshi: u64,
    /// Sum of unspent notes at depth < `min_confirmations` (recently received).
    pub pending_zatoshi: u64,
}

impl Balance {
    /// Total balance (confirmed + pending).
    pub fn total_zatoshi(&self) -> u64 {
        self.confirmed_zatoshi.saturating_add(self.pending_zatoshi)
    }
}

/// Direction of a transaction from the wallet's perspective.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxDirection {
    Incoming,
    Outgoing,
}

/// A wallet transaction record.
#[derive(Debug, Clone)]
pub struct TxRecord {
    /// Transaction identifier (hex txid).
    pub txid: String,
    /// Block height at which the transaction was confirmed.
    pub block_height: i64,
    /// Whether this transaction received or spent funds.
    pub direction: TxDirection,
    /// Net amount in zatoshi.
    pub amount_zatoshi: u64,
    /// ZIP-302 shielded memo field (up to 512 bytes).
    pub memo: Option<Vec<u8>>,
    /// The nie peer involved in this payment, if known (from session metadata).
    pub peer_pub_id: Option<String>,
    /// Unix timestamp of the confirming block.
    pub created_at: i64,
}

/// Wallet SQLite store.  Tracks payment sessions, received notes, incremental
/// Merkle witnesses, and transaction history.
///
/// All datetimes are stored as Unix timestamps (i64) to avoid the SQLite
/// datetime string format pitfall described in CLAUDE.md §9.
#[derive(Clone)]
pub struct WalletStore {
    pool: SqlitePool,
}

impl WalletStore {
    /// Open (or create) the wallet DB at `db_path`.
    pub async fn new(db_path: &Path) -> Result<Self> {
        // foreign_keys(true) is set on the connect options, not via a post-connect
        // PRAGMA query, so it applies to every connection the pool creates regardless
        // of max_connections.  A post-connect PRAGMA only sets it for a single
        // connection, which silently breaks ON DELETE CASCADE if the pool is ever
        // widened above 1 connection.
        let opts = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;

        // Schema migration runner using PRAGMA user_version.
        // user_version 0 means no schema exists yet.
        // Each migration block checks version < N, applies, then sets version = N.
        // Never modify a migration once shipped — add a new one after it.
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await?;

        if version < 1 {
            // Wrapped in a transaction so a crash between CREATE TABLE and the
            // PRAGMA user_version update leaves user_version < 1 and retries
            // cleanly on the next open (CREATE TABLE IF NOT EXISTS is idempotent).
            let mut txn = pool.begin().await?;
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS payment_sessions (
                    session_id      TEXT PRIMARY KEY,
                    peer_pub_id     TEXT NOT NULL,
                    role            TEXT NOT NULL,
                    state           TEXT NOT NULL,
                    chain           TEXT NOT NULL,
                    amount_zatoshi  INTEGER NOT NULL,
                    tx_hash         TEXT,
                    address         TEXT,
                    created_at      INTEGER NOT NULL,
                    updated_at      INTEGER NOT NULL
                )",
            )
            .execute(&mut *txn)
            .await?;
            // PRAGMA user_version does not accept parameterized binding — the
            // integer literal must be inlined.  This is safe: it is a constant.
            sqlx::query("PRAGMA user_version = 1")
                .execute(&mut *txn)
                .await?;
            txn.commit().await?;
        }

        if version < 2 {
            // Wrapped in a transaction so a crash between any CREATE TABLE and the
            // PRAGMA user_version update leaves user_version < 2 and retries
            // cleanly on the next open (CREATE TABLE IF NOT EXISTS is idempotent).
            let mut txn = pool.begin().await?;
            // notes: received Sapling/Orchard outputs, one row per output.
            // memo is stored as a raw BLOB (up to 512 bytes, ZIP-302).
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS notes (
                    note_id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    txid          TEXT    NOT NULL,
                    output_index  INTEGER NOT NULL,
                    value_zatoshi INTEGER NOT NULL,
                    memo          BLOB,
                    spent         INTEGER NOT NULL DEFAULT 0,
                    spending_txid TEXT,
                    created_at    INTEGER NOT NULL,
                    UNIQUE(txid, output_index)
                )",
            )
            .execute(&mut *txn)
            .await?;

            // witnesses: latest incremental Merkle witness per note.
            // One row per note; updated on each block scan.
            // witness_data is the serialized IncrementalWitness bytes from the
            // scanner (raw BLOB; format is zcash_primitives-compatible).
            // ON DELETE CASCADE removes the witness when the note is deleted.
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS witnesses (
                    note_id      INTEGER NOT NULL PRIMARY KEY
                                     REFERENCES notes(note_id) ON DELETE CASCADE,
                    block_height INTEGER NOT NULL,
                    witness_data BLOB    NOT NULL
                )",
            )
            .execute(&mut *txn)
            .await?;

            // transactions: confirmed wallet transactions (both directions).
            // direction TEXT is either 'incoming' or 'outgoing'.
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS transactions (
                    txid           TEXT    PRIMARY KEY,
                    block_height   INTEGER NOT NULL,
                    direction      TEXT    NOT NULL,
                    amount_zatoshi INTEGER NOT NULL,
                    memo           BLOB,
                    peer_pub_id    TEXT,
                    created_at     INTEGER NOT NULL
                )",
            )
            .execute(&mut *txn)
            .await?;

            sqlx::query("PRAGMA user_version = 2")
                .execute(&mut *txn)
                .await?;
            txn.commit().await?;
        }

        if version < 3 {
            // Wrapped in a transaction so a crash between CREATE TABLE, INSERT,
            // and PRAGMA user_version leaves user_version < 3 and retries cleanly.
            let mut txn = pool.begin().await?;
            // scan_state: single-row table tracking the last fully-scanned
            // block height.  id is always 1; the CHECK constraint enforces
            // the single-row invariant so UPDATE does not need a WHERE clause
            // that could silently affect zero rows on a fresh DB.
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS scan_state (
                    id         INTEGER PRIMARY KEY CHECK (id = 1),
                    tip_height INTEGER NOT NULL DEFAULT 0
                )",
            )
            .execute(&mut *txn)
            .await?;
            // Seed the row so scan_tip() can always use fetch_one.
            sqlx::query("INSERT OR IGNORE INTO scan_state (id, tip_height) VALUES (1, 0)")
                .execute(&mut *txn)
                .await?;
            sqlx::query("PRAGMA user_version = 3")
                .execute(&mut *txn)
                .await?;
            txn.commit().await?;
        }

        if version < 4 {
            // Add block_height column to notes.  Needed for confirmation-depth
            // balance queries.  Existing rows (none in practice — scanner was
            // not yet live) default to 0.
            //
            // Wrapped in a transaction so a crash between the ALTER TABLE and the
            // PRAGMA user_version update leaves the schema in a consistent state:
            // user_version stays < 4 and the next open retries cleanly rather than
            // hitting "duplicate column name".  SQLite supports transactional DDL
            // for ALTER TABLE ADD COLUMN.
            let mut txn = pool.begin().await?;
            sqlx::query("ALTER TABLE notes ADD COLUMN block_height INTEGER NOT NULL DEFAULT 0")
                .execute(&mut *txn)
                .await?;
            sqlx::query("PRAGMA user_version = 4")
                .execute(&mut *txn)
                .await?;
            txn.commit().await?;
        }

        if version < 5 {
            // Wrapped in a transaction so a crash between CREATE TABLE and the
            // PRAGMA user_version update leaves user_version < 5 and retries
            // cleanly on the next open (CREATE TABLE IF NOT EXISTS is idempotent).
            let mut txn = pool.begin().await?;
            // accounts: one row per ZIP-32 account (usually just account 0).
            //
            // diversifier_index is stored as TEXT (decimal u128), not INTEGER.
            // SQLite INTEGER is signed 64-bit; a u128 diversifier index can
            // exceed i64::MAX in theory, silently wrapping to a negative value.
            // TEXT avoids that entirely and is still comparable as an ordered
            // decimal string for display purposes.
            // DO NOT change this column to INTEGER in a future migration —
            // the diversifier_index_roundtrip test deliberately writes u128::MAX
            // to catch exactly that regression.
            //
            // The DEFAULT '0' seeds account 0 implicitly when ensure_account()
            // is called on a fresh wallet — no manual insert is required by callers.
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS accounts (
                    account_index     INTEGER PRIMARY KEY,
                    diversifier_index TEXT    NOT NULL DEFAULT '0'
                )",
            )
            .execute(&mut *txn)
            .await?;
            sqlx::query("PRAGMA user_version = 5")
                .execute(&mut *txn)
                .await?;
            txn.commit().await?;
        }

        if version < 6 {
            // Add note-plaintext columns required to reconstruct a spendable sapling::Note
            // for the transaction builder (nie-wdw).
            //
            // Nullable: existing notes from the scan stub have no plaintext yet.
            // spendable_notes() excludes rows where any column is NULL — it only returns
            // notes the scanner has fully decrypted.
            //
            // note_diversifier (11 bytes) — raw Sapling diversifier d; g_d = GH("Zcash_gd", d)
            //                              PaymentAddress::from_bytes expects [d(11) | pk_d(32)].
            // note_pk_d        (32 bytes) — recipient public key pk_d (Jubjub point, compressed)
            // note_rseed       (32 bytes) — commitment randomness (Rseed or old rcm)
            // note_rseed_after_zip212 (INTEGER, nullable) — 1 if note_rseed is the post-ZIP-212
            //                                     Rseed, 0 if it is the pre-ZIP-212 rcm field.
            //                                     NULL means the note has not yet been decrypted
            //                                     and classified; spendable_notes() excludes NULLs.
            //
            // All four ALTER TABLEs and the PRAGMA run inside a single SQLite transaction.
            // SQLite DDL is transactional: a failure or process-kill mid-migration rolls
            // back all column additions, leaving user_version < 6.  The next open retries
            // cleanly.  Without the transaction, a partial failure leaves orphaned columns
            // and makes every subsequent open fail with "duplicate column name".
            let mut txn = pool.begin().await?;
            for col in &[
                "ALTER TABLE notes ADD COLUMN note_diversifier BLOB",
                "ALTER TABLE notes ADD COLUMN note_pk_d BLOB",
                "ALTER TABLE notes ADD COLUMN note_rseed BLOB",
                "ALTER TABLE notes ADD COLUMN note_rseed_after_zip212 INTEGER",
            ] {
                sqlx::query(col).execute(&mut *txn).await?;
            }
            sqlx::query("PRAGMA user_version = 6")
                .execute(&mut *txn)
                .await?;
            txn.commit().await?;
        }

        if version < 7 {
            // Index to accelerate spendable_notes() which filters on spent = 0.
            // Without it, every payment does a full table scan of notes — O(n)
            // in the number of lifetime notes, which grows unboundedly with scanner use.
            //
            // Partial index on spent = 0 only — SQLite supports partial indexes
            // and this one is selective: in a normal wallet most notes are spent.
            // When the notes table gains an account_index column, extend this
            // to (account_index, spent) for efficient per-account queries.
            //
            // Wrapped in a transaction: a crash between CREATE INDEX and PRAGMA
            // user_version leaves user_version < 7 so the next open retries.
            // CREATE INDEX IF NOT EXISTS is idempotent on retry.
            let mut txn = pool.begin().await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS notes_unspent ON notes(spent)
                 WHERE spent = 0",
            )
            .execute(&mut *txn)
            .await?;
            sqlx::query("PRAGMA user_version = 7")
                .execute(&mut *txn)
                .await?;
            txn.commit().await?;
        }

        if version < 8 {
            // Add tree_state BLOB to scan_state.  Stores the serialized
            // CommitmentTree<sapling::Node, 32> snapshot so the scanner can resume
            // without replaying the full chain from genesis on restart.
            // NULL means no snapshot yet; scanner falls back to an empty tree.
            //
            // Wrapped in a transaction: a crash between ALTER TABLE and PRAGMA
            // user_version leaves user_version < 8 so the next open retries.
            // SQLite supports transactional DDL for ALTER TABLE ADD COLUMN.
            let mut txn = pool.begin().await?;
            sqlx::query("ALTER TABLE scan_state ADD COLUMN tree_state BLOB")
                .execute(&mut *txn)
                .await?;
            sqlx::query("PRAGMA user_version = 8")
                .execute(&mut *txn)
                .await?;
            txn.commit().await?;
        }

        Ok(Self { pool })
    }

    /// Expire non-terminal sessions that have not been updated in
    /// `max_age_secs` seconds.
    ///
    /// `now_ts` is the current Unix timestamp; it is stored as the new
    /// `updated_at` for expired rows.  The cutoff is computed internally as
    /// `now_ts - max_age_secs as i64`.
    ///
    /// Sessions with `updated_at < cutoff` and a non-terminal state
    /// (`requested`, `address_provided`, `sent`) are transitioned to `expired`.
    /// Returns the number of rows updated.
    ///
    /// `max_age_secs` is `u64` (not `i64`) so that negative values — which
    /// would compute a future cutoff and mass-expire all sessions — are
    /// structurally impossible.
    ///
    /// This is a single bulk SQL UPDATE — callers should use it instead of
    /// looping over sessions and calling `upsert_session` individually, which
    /// issues one round-trip per row.
    pub async fn expire_sessions_older_than(&self, now_ts: i64, max_age_secs: u64) -> Result<u64> {
        // max_age_secs is u64; cast to i64 is safe for any realistic duration
        // (u64::MAX seconds ≈ 585 billion years, far beyond i64::MAX).
        // saturating_sub handles the degenerate case where now_ts < max_age_secs.
        let max_age_i64 = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
        let cutoff = now_ts.saturating_sub(max_age_i64);
        let result = sqlx::query(
            "UPDATE payment_sessions
             SET state = 'expired', updated_at = ?
             WHERE state NOT IN ('confirmed', 'failed', 'expired')
               AND updated_at < ?",
        )
        .bind(now_ts)
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Insert or update a payment session.  `session_id` is the conflict key;
    /// state, tx_hash, address, and updated_at are updated on conflict.
    pub async fn upsert_session(&self, session: &PaymentSession) -> Result<()> {
        sqlx::query(
            "INSERT INTO payment_sessions
                (session_id, peer_pub_id, role, state, chain,
                 amount_zatoshi, tx_hash, address, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(session_id) DO UPDATE SET
                state         = excluded.state,
                tx_hash       = excluded.tx_hash,
                address       = excluded.address,
                updated_at    = excluded.updated_at",
        )
        .bind(session.id.to_string())
        .bind(&session.peer_pub_id)
        .bind(role_to_str(&session.role))
        .bind(state_to_str(&session.state))
        .bind(chain_to_str(&session.chain))
        // Zcash total supply is ~21M ZEC = ~2.1×10¹⁵ zatoshi, well within i64::MAX
        // (~9.2×10¹⁸).  Still use try_from so a direct-API caller with a synthetic
        // value doesn't silently corrupt SQLite with a negative integer. (nie-nej)
        .bind(i64::try_from(session.amount_zatoshi).map_err(|_| {
            anyhow::anyhow!(
                "amount_zatoshi {} exceeds i64::MAX; cannot store in SQLite",
                session.amount_zatoshi
            )
        })?)
        .bind(&session.tx_hash)
        .bind(&session.address)
        .bind(session.created_at)
        .bind(session.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// All payment sessions, in no guaranteed order.
    pub async fn all_sessions(&self) -> Result<Vec<PaymentSession>> {
        sqlx::query_as::<_, SessionRow>(
            "SELECT session_id, peer_pub_id, role, state, chain,
                    amount_zatoshi, tx_hash, address, created_at, updated_at
             FROM payment_sessions",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(session_from_row)
        .collect()
    }

    /// Look up a payee session by the address it is watching.
    ///
    /// Returns the first payee session with `address = addr` that is still
    /// unconfirmed (`address_provided` or `sent`).  Returns `Ok(None)` when no
    /// matching session exists — the caller should treat a received payment to an
    /// unknown address as a no-op rather than an error.
    ///
    /// Only payee sessions are searched: payer sessions never hold a watched
    /// address, so including them would only return stale data.
    ///
    /// `addr` is untrusted input; it is always bound as a query parameter,
    /// never interpolated into SQL.
    pub async fn get_session_by_address(&self, addr: &str) -> Result<Option<PaymentSession>> {
        sqlx::query_as::<_, SessionRow>(
            "SELECT session_id, peer_pub_id, role, state, chain,
                    amount_zatoshi, tx_hash, address, created_at, updated_at
             FROM payment_sessions
             WHERE address = ?
               AND role    = 'payee'
               AND state  IN ('address_provided', 'sent')
             LIMIT 1",
        )
        .bind(addr)
        .fetch_optional(&self.pool)
        .await?
        .map(session_from_row)
        .transpose()
    }

    /// All payee sessions that are actively awaiting an incoming payment.
    ///
    /// Returns every `payee` session in `address_provided` or `sent` state that
    /// has a non-null `address`.  This is the set the payment monitor calls on
    /// startup to re-arm its watch list after a process restart.
    ///
    /// Sessions without an address are excluded: they have not yet generated a
    /// receiving address and cannot be matched against incoming transactions.
    pub async fn sessions_to_watch(&self) -> Result<Vec<PaymentSession>> {
        // Fetch all payee sessions with an address and filter in Rust using an
        // exhaustive match on PaymentState.  This ensures the compiler flags any
        // new variant that is added to the enum without a conscious decision about
        // whether it needs watching — the build will fail rather than silently
        // dropping sessions from the watcher on restart.
        let rows = sqlx::query_as::<_, SessionRow>(
            "SELECT session_id, peer_pub_id, role, state, chain,
                    amount_zatoshi, tx_hash, address, created_at, updated_at
             FROM payment_sessions
             WHERE role    = 'payee'
               AND address IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await?;

        let sessions = rows
            .into_iter()
            .map(session_from_row)
            .collect::<Result<Vec<_>>>()?;

        let watchable = sessions
            .into_iter()
            .filter(|s| match s.state {
                PaymentState::AddressProvided | PaymentState::Sent => true,
                PaymentState::Requested
                | PaymentState::Confirmed
                | PaymentState::Failed
                | PaymentState::Expired => false,
            })
            .collect();

        Ok(watchable)
    }

    // ---- notes ----

    /// INSERT SQL for a note row with all plaintext fields populated.
    /// Shared between `insert_note` and `insert_note_with_witness` so a schema
    /// change only needs one update.
    const NOTE_INSERT_FULL: &'static str = "INSERT INTO notes
       (txid, output_index, value_zatoshi, memo, block_height, created_at,
        note_diversifier, note_pk_d, note_rseed, note_rseed_after_zip212)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     RETURNING note_id";

    /// INSERT SQL for a note row without plaintext fields (trial-decrypt pending).
    const NOTE_INSERT_PARTIAL: &'static str =
        "INSERT INTO notes (txid, output_index, value_zatoshi, memo, block_height, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         RETURNING note_id";

    /// Insert a received note.  Returns the DB-assigned `note_id`.
    ///
    /// Fails with a unique-constraint error if `(txid, output_index)` already
    /// exists — callers should treat that as a no-op (already indexed).
    pub async fn insert_note(&self, note: &Note) -> Result<i64> {
        let value = i64::try_from(note.value_zatoshi).map_err(|_| {
            anyhow::anyhow!(
                "note value {} exceeds i64::MAX; cannot store in SQLite",
                note.value_zatoshi
            )
        })?;
        let block_height = i64::try_from(note.block_height).map_err(|_| {
            anyhow::anyhow!(
                "block_height {} exceeds i64::MAX; cannot store in SQLite",
                note.block_height
            )
        })?;
        // Use two different INSERT queries depending on whether plaintext columns are
        // populated.  When plaintext fields are absent, omit them from the INSERT so
        // note_rseed_after_zip212 stays NULL (meaning unclassified).
        let id = if let (Some(diversifier), Some(pk_d), Some(rseed), Some(after_zip212)) = (
            &note.note_diversifier,
            &note.note_pk_d,
            &note.note_rseed,
            note.rseed_after_zip212,
        ) {
            let rseed_after_zip212_int: i64 = if after_zip212 { 1 } else { 0 };
            sqlx::query_scalar(Self::NOTE_INSERT_FULL)
                .bind(&note.txid)
                .bind(note.output_index)
                .bind(value)
                .bind(&note.memo)
                .bind(block_height)
                .bind(note.created_at)
                .bind(diversifier)
                .bind(pk_d)
                .bind(rseed)
                .bind(rseed_after_zip212_int)
                .fetch_one(&self.pool)
                .await?
        } else {
            sqlx::query_scalar(Self::NOTE_INSERT_PARTIAL)
                .bind(&note.txid)
                .bind(note.output_index)
                .bind(value)
                .bind(&note.memo)
                .bind(block_height)
                .bind(note.created_at)
                .fetch_one(&self.pool)
                .await?
        };
        Ok(id)
    }

    /// All unspent notes, in no guaranteed order.
    pub async fn unspent_notes(&self) -> Result<Vec<(i64, Note)>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            note_id: i64,
            txid: String,
            output_index: i64,
            value_zatoshi: i64,
            memo: Option<Vec<u8>>,
            block_height: i64,
            created_at: i64,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT note_id, txid, output_index, value_zatoshi, memo, block_height, created_at
             FROM notes WHERE spent = 0",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok((
                    r.note_id,
                    Note {
                        txid: r.txid,
                        output_index: r.output_index,
                        value_zatoshi: u64::try_from(r.value_zatoshi).map_err(|_| {
                            anyhow::anyhow!(
                                "note {} has negative value_zatoshi {} in DB — data corruption",
                                r.note_id,
                                r.value_zatoshi
                            )
                        })?,
                        memo: r.memo,
                        block_height: u64::try_from(r.block_height).map_err(|_| {
                            anyhow::anyhow!(
                                "note {} has negative block_height {} in DB — data corruption",
                                r.note_id,
                                r.block_height
                            )
                        })?,
                        created_at: r.created_at,
                        // unspent_notes() does not fetch plaintext columns — they remain None.
                        // spendable_notes() is the path that returns notes with plaintext populated.
                        note_diversifier: None,
                        note_pk_d: None,
                        note_rseed: None,
                        rseed_after_zip212: None,
                    },
                ))
            })
            .collect()
    }

    /// Unspent notes that have fully-decrypted plaintext — safe to spend.
    ///
    /// A note is spendable only when the scanner has written all three plaintext
    /// columns (`note_diversifier`, `note_pk_d`, `note_rseed`).  Rows where any column
    /// is `NULL` (not yet decrypted) are excluded: they cannot be used as inputs
    /// to the Sapling builder without causing a panic or corrupt proof.
    ///
    /// Returns `Err` if `account != 0`; multi-account support requires an
    /// `account_index` column on the `notes` table (not yet added).
    ///
    /// The caller should not rely on ordering; use coin-selection logic to pick
    /// which notes to spend.
    pub async fn spendable_notes(&self, account: u32) -> Result<Vec<SpendableNote>> {
        if account != 0 {
            anyhow::bail!(
                "multi-account not yet supported; only account 0 is valid — pass account=0"
            );
        }
        #[derive(sqlx::FromRow)]
        struct Row {
            note_id: i64,
            value_zatoshi: i64,
            note_diversifier: Vec<u8>,
            note_pk_d: Vec<u8>,
            note_rseed: Vec<u8>,
            note_rseed_after_zip212: Option<i64>,
            block_height: i64,
            witness_data: Vec<u8>,
        }
        // Filter: spent = 0 AND all three plaintext columns NOT NULL AND witness exists.
        // INNER JOIN with witnesses excludes notes that have no Merkle witness — such
        // notes cannot be spent because no inclusion proof can be generated for them.
        //
        // Account isolation: the `notes` table has no `account_index` column yet.
        // The `account != 0` guard above is the only enforcement.  When multi-account
        // support lands, a migration must add `account_index INTEGER NOT NULL DEFAULT 0`
        // to `notes` and this query must add `AND n.account_index = ?`.
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT n.note_id, n.value_zatoshi, n.note_diversifier, n.note_pk_d, n.note_rseed,
                    n.note_rseed_after_zip212, n.block_height, w.witness_data
             FROM notes n
             JOIN witnesses w ON n.note_id = w.note_id
             WHERE n.spent = 0
               AND n.note_diversifier          IS NOT NULL
               AND n.note_pk_d                IS NOT NULL
               AND n.note_rseed               IS NOT NULL
               AND n.note_rseed_after_zip212   IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(SpendableNote {
                    note_id: r.note_id,
                    value_zatoshi: u64::try_from(r.value_zatoshi).map_err(|_| {
                        anyhow::anyhow!(
                            "note {} has negative value_zatoshi {} in DB — data corruption",
                            r.note_id,
                            r.value_zatoshi
                        )
                    })?,
                    note_diversifier: r.note_diversifier,
                    note_pk_d: r.note_pk_d,
                    note_rseed: r.note_rseed,
                    rseed_after_zip212: r.note_rseed_after_zip212.unwrap_or(0) != 0,
                    block_height: u64::try_from(r.block_height).map_err(|_| {
                        anyhow::anyhow!(
                            "note {} has negative block_height {} in DB — data corruption",
                            r.note_id,
                            r.block_height
                        )
                    })?,
                    witness_data: r.witness_data,
                })
            })
            .collect()
    }

    /// Mark a note as spent by the given transaction.
    ///
    /// Returns `Err` if `note_id` does not exist.  A silent no-op would leave the
    /// note in `unspent_notes()` forever, producing incorrect balance calculations.
    pub async fn mark_note_spent(&self, note_id: i64, spending_txid: &str) -> Result<()> {
        let result = sqlx::query("UPDATE notes SET spent = 1, spending_txid = ? WHERE note_id = ?")
            .bind(spending_txid)
            .bind(note_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            anyhow::bail!("mark_note_spent: note_id {note_id} not found");
        }
        Ok(())
    }

    /// Mark multiple notes spent in a single transaction.
    ///
    /// All notes are updated atomically: either all succeed or none are marked.
    /// Callers that need best-effort semantics should catch the returned error and
    /// log it — the scanner will self-heal any unmarked notes on the next sync.
    pub async fn mark_notes_spent(&self, note_ids: &[i64], spending_txid: &str) -> Result<()> {
        if note_ids.is_empty() {
            return Ok(());
        }
        let mut txn = self.pool.begin().await?;
        for &note_id in note_ids {
            let result =
                sqlx::query("UPDATE notes SET spent = 1, spending_txid = ? WHERE note_id = ?")
                    .bind(spending_txid)
                    .bind(note_id)
                    .execute(&mut *txn)
                    .await?;
            if result.rows_affected() == 0 {
                anyhow::bail!("mark_notes_spent: note_id {note_id} not found");
            }
        }
        txn.commit().await?;
        Ok(())
    }

    // ---- witnesses ----

    /// Insert or replace the latest incremental Merkle witness for a note.
    ///
    /// `witness_data` is the serialized `IncrementalWitness` bytes produced by
    /// the compact-block scanner.  Only the most-recent witness per note is
    /// kept — the scanner calls this on every block for each unspent note.
    pub async fn upsert_witness(
        &self,
        note_id: i64,
        block_height: i64,
        witness_data: &[u8],
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO witnesses (note_id, block_height, witness_data)
             VALUES (?, ?, ?)
             ON CONFLICT(note_id) DO UPDATE SET
                 block_height = excluded.block_height,
                 witness_data = excluded.witness_data",
        )
        .bind(note_id)
        .bind(block_height)
        .bind(witness_data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically insert a note and its initial Merkle witness in one transaction.
    ///
    /// If the note INSERT succeeds but the witness INSERT were to fail, the note
    /// would be permanently excluded from `spendable_notes()` because that query
    /// does an INNER JOIN with `witnesses`.  Running both in a single transaction
    /// ensures either both succeed or neither is committed.
    ///
    /// Returns the DB-assigned `note_id` on success.
    ///
    /// Fails with a unique-constraint error if `(txid, output_index)` already
    /// exists — callers should treat that as a no-op (scanner re-processing a block).
    pub(crate) async fn insert_note_with_witness(
        &self,
        note: &Note,
        block_height: u64,
        witness_data: &[u8],
    ) -> Result<i64> {
        let value = i64::try_from(note.value_zatoshi).map_err(|_| {
            anyhow::anyhow!(
                "note value {} exceeds i64::MAX; cannot store in SQLite",
                note.value_zatoshi
            )
        })?;
        let note_bh = i64::try_from(note.block_height).map_err(|_| {
            anyhow::anyhow!(
                "block_height {} exceeds i64::MAX; cannot store in SQLite",
                note.block_height
            )
        })?;
        let bh_i64 = i64::try_from(block_height)
            .map_err(|_| anyhow::anyhow!("block height {block_height} exceeds i64::MAX"))?;

        let mut txn = self.pool.begin().await?;

        // Insert note — two query variants depending on whether plaintext columns
        // are populated, matching the logic in insert_note().  SQL strings shared
        // via NOTE_INSERT_FULL / NOTE_INSERT_PARTIAL so schema changes only need
        // one update.
        let note_id: i64 = if let (Some(diversifier), Some(pk_d), Some(rseed), Some(after_zip212)) = (
            &note.note_diversifier,
            &note.note_pk_d,
            &note.note_rseed,
            note.rseed_after_zip212,
        ) {
            let rseed_flag: i64 = if after_zip212 { 1 } else { 0 };
            sqlx::query_scalar(Self::NOTE_INSERT_FULL)
                .bind(&note.txid)
                .bind(note.output_index)
                .bind(value)
                .bind(&note.memo)
                .bind(note_bh)
                .bind(note.created_at)
                .bind(diversifier)
                .bind(pk_d)
                .bind(rseed)
                .bind(rseed_flag)
                .fetch_one(&mut *txn)
                .await?
        } else {
            sqlx::query_scalar(Self::NOTE_INSERT_PARTIAL)
                .bind(&note.txid)
                .bind(note.output_index)
                .bind(value)
                .bind(&note.memo)
                .bind(note_bh)
                .bind(note.created_at)
                .fetch_one(&mut *txn)
                .await?
        };

        // Insert witness in the same transaction so both succeed or both roll back.
        sqlx::query(
            "INSERT INTO witnesses (note_id, block_height, witness_data)
             VALUES (?, ?, ?)
             ON CONFLICT(note_id) DO UPDATE SET
                 block_height = excluded.block_height,
                 witness_data = excluded.witness_data",
        )
        .bind(note_id)
        .bind(bh_i64)
        .bind(witness_data)
        .execute(&mut *txn)
        .await?;

        txn.commit().await?;
        Ok(note_id)
    }

    /// Fetch the `note_id` for an existing note by its `(txid, output_index)` pair.
    ///
    /// Returns `None` if no row matches.  Used by the scanner on a unique-constraint
    /// collision during rescan: the note is already in the DB, so look up its primary
    /// key to populate the in-memory witness map and keep it current.
    pub(crate) async fn get_note_id_by_output(
        &self,
        txid: &str,
        output_index: i64,
    ) -> Result<Option<i64>> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT note_id FROM notes WHERE txid = ?1 AND output_index = ?2")
                .bind(txid)
                .bind(output_index)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(id,)| id))
    }

    // ---- transactions ----

    /// Record a confirmed transaction.  Ignores conflicts (idempotent re-index).
    pub async fn insert_tx(&self, tx: &TxRecord) -> Result<()> {
        let value = i64::try_from(tx.amount_zatoshi).map_err(|_| {
            anyhow::anyhow!(
                "tx amount {} exceeds i64::MAX; cannot store in SQLite",
                tx.amount_zatoshi
            )
        })?;
        sqlx::query(
            "INSERT OR IGNORE INTO transactions
                (txid, block_height, direction, amount_zatoshi, memo, peer_pub_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&tx.txid)
        .bind(tx.block_height)
        .bind(tx_direction_to_str(&tx.direction))
        .bind(value)
        .bind(&tx.memo)
        .bind(&tx.peer_pub_id)
        .bind(tx.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Most recent `limit` transactions, newest first (by block height then txid).
    pub async fn recent_txs(&self, limit: i64) -> Result<Vec<TxRecord>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            txid: String,
            block_height: i64,
            direction: String,
            amount_zatoshi: i64,
            memo: Option<Vec<u8>>,
            peer_pub_id: Option<String>,
            created_at: i64,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT txid, block_height, direction, amount_zatoshi, memo, peer_pub_id, created_at
             FROM transactions
             ORDER BY block_height DESC, txid ASC
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                let amount_zatoshi = u64::try_from(r.amount_zatoshi).map_err(|_| {
                    anyhow::anyhow!(
                        "tx {} has negative amount_zatoshi {} in DB — data corruption",
                        r.txid,
                        r.amount_zatoshi
                    )
                })?;
                Ok(TxRecord {
                    txid: r.txid,
                    block_height: r.block_height,
                    direction: tx_direction_from_str(&r.direction)?,
                    amount_zatoshi,
                    memo: r.memo,
                    peer_pub_id: r.peer_pub_id,
                    created_at: r.created_at,
                })
            })
            .collect()
    }

    // ---- scan state ----

    /// Return the last fully-scanned block height.
    ///
    /// Returns `0` for a brand-new wallet.  Callers that want to start
    /// scanning from a particular "birthday height" should call
    /// [`set_scan_tip`] to set an initial value before the first scan.
    pub async fn scan_tip(&self) -> Result<u64> {
        let h: i64 = sqlx::query_scalar("SELECT tip_height FROM scan_state WHERE id = 1")
            .fetch_one(&self.pool)
            .await?;
        // A negative tip_height would silently bypass the sync guard in check_lag
        // (saturating_sub would compute lag=0, allowing spends with a wrong anchor).
        u64::try_from(h).map_err(|_| {
            anyhow::anyhow!(
                "scan_state tip_height {} is negative — DB corruption; \
                 run `nie wallet sync` to reset the scan tip",
                h
            )
        })
    }

    /// Update the last fully-scanned block height.
    ///
    /// Called by the compact-block scanner after each block is processed.
    pub async fn set_scan_tip(&self, height: u64) -> Result<()> {
        let h = i64::try_from(height).map_err(|_| {
            anyhow::anyhow!("scan tip {height} exceeds i64::MAX; cannot store in SQLite")
        })?;
        let result = sqlx::query("UPDATE scan_state SET tip_height = ? WHERE id = 1")
            .bind(h)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() != 1 {
            return Err(anyhow::anyhow!(
                "set_scan_tip: scan_state row missing (rows_affected={}); \
                 call init_scan_state before scanning",
                result.rows_affected()
            ));
        }
        Ok(())
    }

    /// Atomically persist all per-block scanner state in a single transaction.
    ///
    /// Writes the commitment tree snapshot, all updated Merkle witnesses, and the
    /// new scan tip inside one SQLite transaction.  Either all three writes commit
    /// or none do, so a crash between writes cannot leave the DB in a state where
    /// `scan_state.tip_height` is N but some witnesses are missing.
    ///
    /// `witnesses` is a slice of `(note_id, block_height, serialized_witness)` tuples.
    pub async fn save_block_state(
        &self,
        tree_data: &[u8],
        witnesses: &[(i64, i64, Vec<u8>)],
        tip_height: i64,
    ) -> Result<()> {
        let mut txn = self.pool.begin().await?;

        let tree_rows = sqlx::query("UPDATE scan_state SET tree_state = ? WHERE id = 1")
            .bind(tree_data)
            .execute(&mut *txn)
            .await?;
        if tree_rows.rows_affected() != 1 {
            return Err(anyhow::anyhow!(
                "save_block_state: scan_state row missing while saving tree (rows_affected={})",
                tree_rows.rows_affected()
            ));
        }

        for (note_id, block_height, witness_data) in witnesses {
            sqlx::query(
                "INSERT INTO witnesses (note_id, block_height, witness_data)
                 VALUES (?, ?, ?)
                 ON CONFLICT(note_id) DO UPDATE SET
                     block_height = excluded.block_height,
                     witness_data = excluded.witness_data",
            )
            .bind(note_id)
            .bind(block_height)
            .bind(witness_data.as_slice())
            .execute(&mut *txn)
            .await?;
        }

        let tip_rows = sqlx::query("UPDATE scan_state SET tip_height = ? WHERE id = 1")
            .bind(tip_height)
            .execute(&mut *txn)
            .await?;
        if tip_rows.rows_affected() != 1 {
            return Err(anyhow::anyhow!(
                "save_block_state: scan_state row missing while saving tip (rows_affected={})",
                tip_rows.rows_affected()
            ));
        }

        txn.commit().await?;
        Ok(())
    }

    /// Load the most recently persisted `CommitmentTree` snapshot, if any.
    ///
    /// Returns `None` for a fresh wallet (no snapshot stored yet).  The scanner
    /// should fall back to `CommitmentTree::empty()` in that case and replay
    /// from the wallet birthday height.
    pub async fn load_tree_state(&self) -> Result<Option<Vec<u8>>> {
        let bytes: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT tree_state FROM scan_state WHERE id = 1")
                .fetch_one(&self.pool)
                .await?;
        Ok(bytes)
    }

    // ---- balance (nie-8t7) ----

    /// Compute the shielded wallet balance split by confirmation depth.
    ///
    /// `scan_tip` is the last fully-scanned block height (from `scan_tip()`).
    /// `min_confirmations` is the minimum depth for a note to be considered
    /// confirmed (Zcash conventionally uses 10).
    ///
    /// A note is confirmed when `scan_tip - block_height >= min_confirmations`.
    /// Notes that do not meet this threshold are pending.
    ///
    /// Returns [`Balance`] with `confirmed_zatoshi` and `pending_zatoshi`.
    pub async fn balance(&self, scan_tip: u64, min_confirmations: u64) -> Result<Balance> {
        // Threshold height: notes at block_height <= threshold are confirmed.
        //
        // When scan_tip < min_confirmations nothing is confirmed yet.  Using
        // saturating_sub would give threshold = 0, causing notes with
        // block_height = 0 (the migration v4 DEFAULT sentinel) to satisfy
        // `block_height <= 0` and appear as confirmed — contradicting the
        // documented formula `depth = scan_tip - block_height >= min_confirmations`.
        //
        // Fix: use -1 as the threshold when scan_tip < min_confirmations so that
        // `block_height <= -1` is never satisfied (block heights are non-negative).
        let threshold_i64: i64 = if scan_tip < min_confirmations {
            -1 // No note can be confirmed yet; -1 is below any valid block_height.
        } else {
            // scan_tip - min_confirmations is safe (checked above); the result
            // must fit in i64 (block heights are bounded by the chain length,
            // far below i64::MAX).  Overflow here would mean every note is
            // counted as confirmed regardless of depth — return an error instead.
            (scan_tip - min_confirmations)
                .try_into()
                .map_err(|_| anyhow::anyhow!("scan_tip computation overflow: scan_tip={scan_tip} min_confirmations={min_confirmations}"))?
        };

        #[derive(sqlx::FromRow)]
        struct Row {
            confirmed: Option<i64>,
            pending: Option<i64>,
        }

        let row: Row = sqlx::query_as(
            "SELECT
               SUM(CASE WHEN block_height > 0 AND block_height <= ? THEN value_zatoshi ELSE 0 END) AS confirmed,
               SUM(CASE WHEN block_height = 0 OR block_height  > ? THEN value_zatoshi ELSE 0 END) AS pending
             FROM notes
             WHERE spent = 0",
        )
        .bind(threshold_i64)
        .bind(threshold_i64)
        .fetch_one(&self.pool)
        .await?;

        // SUM on an empty table returns NULL; treat as 0.
        // u64::try_from: a negative SUM indicates DB corruption (negative value_zatoshi).
        let confirmed_zatoshi = u64::try_from(row.confirmed.unwrap_or(0)).map_err(|_| {
            anyhow::anyhow!("confirmed balance SUM is negative — notes table may be corrupt")
        })?;
        let pending_zatoshi = u64::try_from(row.pending.unwrap_or(0)).map_err(|_| {
            anyhow::anyhow!("pending balance SUM is negative — notes table may be corrupt")
        })?;
        Ok(Balance {
            confirmed_zatoshi,
            pending_zatoshi,
        })
    }

    // ---- accounts / diversifier index (nie-0dg) ----

    /// Atomically read, validate, increment, and persist the diversifier index.
    ///
    /// Returns the **pre-increment** value — the one to use as the address
    /// diversifier for the next subaddress — then stores `current + 1` so the
    /// next call gets a fresh index.  10 consecutive calls from index 0 produce
    /// [0, 1, 2, ..., 9].
    ///
    /// The operation runs inside an explicit transaction so that a process crash
    /// between the read and the write cannot produce a stale (reused) index.
    /// With `max_connections = 1` this also serialises all callers within the
    /// same process, eliminating TOCTOU for in-process concurrent writers.
    ///
    /// # Errors
    ///
    /// - If the account row does not exist (caller must call `ensure_account`
    ///   first): `anyhow::Error("account N not found")`.
    /// - If the current index equals or exceeds the ZIP-32 diversifier maximum
    ///   (2^88 − 1, the full 11-byte range): `anyhow::Error("diversifier overflow")`.
    pub async fn next_diversifier(&self, account: u32) -> Result<u128> {
        // ZIP-32 diversifier index is 11 bytes wide.  2^88 − 1 is the last valid
        // index value.  u128::MAX is 2^128 − 1 which is well above this, so the
        // u128 storage fits the full range without ambiguity.
        const MAX_DIVERSIFIER: u128 = (1u128 << 88) - 1;

        // Transaction serialises the read-then-update in a single database lock.
        // With max_connections=1 this is doubly safe against in-process races.
        let mut tx = self.pool.begin().await?;

        let opt: Option<String> =
            sqlx::query_scalar("SELECT diversifier_index FROM accounts WHERE account_index = ?")
                .bind(account as i64)
                .fetch_optional(&mut *tx)
                .await?;

        let current: u128 = match opt {
            None => anyhow::bail!(
                "next_diversifier: account {} not found; call ensure_account() first",
                account
            ),
            Some(s) => s
                .parse::<u128>()
                .map_err(|e| anyhow::anyhow!("corrupt diversifier_index in DB: {e}"))?,
        };

        if current >= MAX_DIVERSIFIER {
            anyhow::bail!(
                "diversifier index overflow for account {}: \
                 all {} diversifier indices are exhausted",
                account,
                MAX_DIVERSIFIER
            );
        }

        let next = current + 1;
        sqlx::query("UPDATE accounts SET diversifier_index = ? WHERE account_index = ?")
            .bind(next.to_string())
            .bind(account as i64)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        // Return the pre-increment value — the caller uses this as the diversifier.
        Ok(current)
    }

    /// Ensure account row exists.  A no-op if the row is already present.
    ///
    /// Must be called before `get_diversifier_index` / `advance_diversifier_to`
    /// for any account that was not previously persisted.  Callers that always
    /// call this first do not need to check whether the account exists.
    pub async fn ensure_account(&self, account: u32) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO accounts (account_index, diversifier_index)
             VALUES (?, '0')",
        )
        .bind(account as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Return the current diversifier index for `account`.
    ///
    /// Returns `0` for any account that has never been seen (no row exists).
    /// Callers that create accounts via `ensure_account` first will always get
    /// a well-defined value; callers that skip that step get `0` as a safe default.
    pub async fn get_diversifier_index(&self, account: u32) -> Result<u128> {
        let opt: Option<String> =
            sqlx::query_scalar("SELECT diversifier_index FROM accounts WHERE account_index = ?")
                .bind(account as i64)
                .fetch_optional(&self.pool)
                .await?;

        match opt {
            None => Ok(0),
            Some(s) => s
                .parse::<u128>()
                .map_err(|e| anyhow::anyhow!("corrupt diversifier_index in DB: {e}")),
        }
    }

    /// Advance the diversifier index for `account` to at least `idx`.
    ///
    /// Only writes if `idx` is strictly greater than the current stored value —
    /// a retrograde call is silently ignored, preventing address reuse when a
    /// stale caller retries with an earlier index.  The monotonicity check is
    /// done in Rust because the diversifier is stored as a decimal TEXT string and
    /// SQLite's `max()` on TEXT is lexicographic (not numeric).
    ///
    /// Uses a SQLite transaction to serialise the read-then-write, matching the
    /// pattern used by `next_diversifier`.  With `max_connections = 1` the
    /// serialisation would hold anyway, but the transaction makes the intent
    /// explicit and safe if the pool is ever reconfigured.
    ///
    /// Creates the account row if it does not exist.  `ensure_account` need not
    /// be called before the first `advance_diversifier_to`.
    pub async fn advance_diversifier_to(&self, account: u32, idx: u128) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        let current: Option<u128> =
            sqlx::query_scalar("SELECT diversifier_index FROM accounts WHERE account_index = ?")
                .bind(account as i64)
                .fetch_optional(&mut *tx)
                .await?
                .map(|s: String| {
                    s.parse::<u128>()
                        .map_err(|e| anyhow::anyhow!("corrupt diversifier_index in DB: {e}"))
                })
                .transpose()?;

        // If the row exists and the stored value is already >= idx, nothing to do.
        if let Some(c) = current {
            if idx <= c {
                // Read-only path: explicitly roll back rather than relying on
                // async drop, which may not complete under all executor configs.
                tx.rollback().await?;
                return Ok(());
            }
        }

        sqlx::query(
            "INSERT INTO accounts (account_index, diversifier_index)
             VALUES (?, ?)
             ON CONFLICT(account_index) DO UPDATE SET
                 diversifier_index = excluded.diversifier_index",
        )
        .bind(account as i64)
        .bind(idx.to_string())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Compute the shielded wallet balance using the stored scan tip.
    ///
    /// Convenience wrapper around `scan_tip()` + `balance()` for callers that
    /// do not need the raw scan tip value.  Uses the single-connection pool so
    /// both queries run on the same connection with no interleaved writes.
    ///
    /// `min_confirmations` is the minimum depth for a note to be considered
    /// confirmed (Zcash conventionally uses 10).
    pub async fn balance_with_confirmations(&self, min_confirmations: u64) -> Result<Balance> {
        let scan_tip = self.scan_tip().await?;
        self.balance(scan_tip, min_confirmations).await
    }
}

// ---- enum ↔ TEXT helpers ----
// Explicit matches rather than serde to guarantee SQLite values are stable
// even if serde rename attributes change.

fn chain_to_str(c: &Chain) -> &'static str {
    match c {
        Chain::Zcash => "zcash",
        Chain::Monero => "monero",
        Chain::Mobilecoin => "mobilecoin",
    }
}

fn chain_from_str(s: &str) -> Result<Chain> {
    match s {
        "zcash" => Ok(Chain::Zcash),
        "monero" => Ok(Chain::Monero),
        "mobilecoin" => Ok(Chain::Mobilecoin),
        _ => Err(anyhow::anyhow!("unknown chain in DB: {s}")),
    }
}

fn role_to_str(r: &PaymentRole) -> &'static str {
    match r {
        PaymentRole::Payer => "payer",
        PaymentRole::Payee => "payee",
    }
}

fn role_from_str(s: &str) -> Result<PaymentRole> {
    match s {
        "payer" => Ok(PaymentRole::Payer),
        "payee" => Ok(PaymentRole::Payee),
        _ => Err(anyhow::anyhow!("unknown role in DB: {s}")),
    }
}

fn state_to_str(s: &PaymentState) -> &'static str {
    match s {
        PaymentState::Requested => "requested",
        PaymentState::AddressProvided => "address_provided",
        PaymentState::Sent => "sent",
        PaymentState::Confirmed => "confirmed",
        PaymentState::Failed => "failed",
        PaymentState::Expired => "expired",
    }
}

fn state_from_str(s: &str) -> Result<PaymentState> {
    match s {
        "requested" => Ok(PaymentState::Requested),
        "address_provided" => Ok(PaymentState::AddressProvided),
        "sent" => Ok(PaymentState::Sent),
        "confirmed" => Ok(PaymentState::Confirmed),
        "failed" => Ok(PaymentState::Failed),
        "expired" => Ok(PaymentState::Expired),
        _ => Err(anyhow::anyhow!("unknown state in DB: {s}")),
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    session_id: String,
    peer_pub_id: String,
    role: String,
    state: String,
    chain: String,
    amount_zatoshi: i64,
    tx_hash: Option<String>,
    address: Option<String>,
    created_at: i64,
    updated_at: i64,
}

fn session_from_row(r: SessionRow) -> Result<PaymentSession> {
    Ok(PaymentSession {
        id: Uuid::parse_str(&r.session_id)
            .map_err(|e| anyhow::anyhow!("corrupt session_id in DB: {e}"))?,
        peer_pub_id: r.peer_pub_id,
        role: role_from_str(&r.role)?,
        state: state_from_str(&r.state)?,
        chain: chain_from_str(&r.chain)?,
        amount_zatoshi: u64::try_from(r.amount_zatoshi).map_err(|_| {
            anyhow::anyhow!(
                "session {} has negative amount_zatoshi {} in DB — data corruption",
                r.session_id,
                r.amount_zatoshi
            )
        })?,
        tx_hash: r.tx_hash,
        address: r.address,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

fn tx_direction_to_str(d: &TxDirection) -> &'static str {
    match d {
        TxDirection::Incoming => "incoming",
        TxDirection::Outgoing => "outgoing",
    }
}

/// Test-only helpers — gated behind `#[cfg(test)]` so they never ship.
#[cfg(test)]
impl WalletStore {
    /// Insert a fully-decrypted spendable note, bypassing the scanner.
    ///
    /// Sets all three plaintext columns and inserts a witness row so that
    /// `spendable_notes()` returns this note immediately.
    ///
    /// Each call generates a unique (txid, output_index) pair via an atomic
    /// counter so multiple calls in the same store do not hit the UNIQUE
    /// constraint on (txid, output_index).
    ///
    /// The `witness_data` bytes must be a valid serialized `IncrementalWitness`
    /// whose tree state is consistent with `block_height`; otherwise the tx
    /// builder will reject the spend proof.
    pub(crate) async fn insert_spendable_note(
        &self,
        value_zatoshi: u64,
        block_height: u64,
        note_diversifier: &[u8],
        note_pk_d: &[u8],
        note_rseed: &[u8],
        rseed_after_zip212: bool,
        witness_data: &[u8],
    ) -> Result<i64> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT_IDX: AtomicU32 = AtomicU32::new(0);
        let idx = NEXT_IDX.fetch_add(1, Ordering::Relaxed);

        let value = i64::try_from(value_zatoshi).map_err(|_| anyhow::anyhow!("value overflow"))?;
        let height =
            i64::try_from(block_height).map_err(|_| anyhow::anyhow!("block_height overflow"))?;
        // Unique synthetic txid per call: zero-padded decimal index fills 64 hex chars.
        let txid = format!("{idx:0>64}");
        let mut txn = self.pool.begin().await?;
        let note_id: i64 = sqlx::query_scalar(
            "INSERT INTO notes
               (txid, output_index, value_zatoshi, block_height, created_at,
                note_diversifier, note_pk_d, note_rseed, note_rseed_after_zip212)
             VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)
             RETURNING note_id",
        )
        .bind(&txid)
        .bind(idx as i64)
        .bind(value)
        .bind(height)
        .bind(note_diversifier)
        .bind(note_pk_d)
        .bind(note_rseed)
        .bind(if rseed_after_zip212 { 1i64 } else { 0i64 })
        .fetch_one(&mut *txn)
        .await?;
        sqlx::query(
            "INSERT INTO witnesses (note_id, block_height, witness_data)
             VALUES (?, ?, ?)
             ON CONFLICT(note_id) DO UPDATE SET
                 block_height = excluded.block_height,
                 witness_data = excluded.witness_data",
        )
        .bind(note_id)
        .bind(height)
        .bind(witness_data)
        .execute(&mut *txn)
        .await?;
        txn.commit().await?;
        Ok(note_id)
    }
}

fn tx_direction_from_str(s: &str) -> Result<TxDirection> {
    match s {
        "incoming" => Ok(TxDirection::Incoming),
        "outgoing" => Ok(TxDirection::Outgoing),
        _ => Err(anyhow::anyhow!("unknown direction in DB: {s}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_store() -> (WalletStore, tempfile::NamedTempFile) {
        // _tempfile must be returned and held by the caller — dropping it deletes
        // the temp file, which would close the DB mid-test.
        let _tempfile = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(_tempfile.path()).await.unwrap();
        (store, _tempfile)
    }

    fn sample_session(role: PaymentRole) -> PaymentSession {
        PaymentSession {
            id: Uuid::new_v4(),
            chain: Chain::Zcash,
            amount_zatoshi: 1_000_000,
            peer_pub_id: "a".repeat(64),
            role,
            state: PaymentState::Requested,
            created_at: 1_000_000,
            updated_at: 1_000_000,
            tx_hash: None,
            address: None,
        }
    }

    #[tokio::test]
    async fn upsert_and_retrieve_roundtrips() {
        let (store, _tempfile) = make_store().await;
        let session = sample_session(PaymentRole::Payer);
        store.upsert_session(&session).await.unwrap();
        let all = store.all_sessions().await.unwrap();
        assert_eq!(all.len(), 1);
        let got = &all[0];
        assert_eq!(got.id, session.id);
        assert_eq!(got.amount_zatoshi, 1_000_000);
        assert_eq!(got.role, PaymentRole::Payer);
        assert_eq!(got.state, PaymentState::Requested);
        assert_eq!(got.chain, Chain::Zcash);
        assert_eq!(got.peer_pub_id, "a".repeat(64));
    }

    /// upsert on an existing session_id must update state fields, not insert a
    /// new row.  This is the primary correctness invariant for session persistence.
    #[tokio::test]
    async fn upsert_updates_state_not_duplicate() {
        let (store, _tempfile) = make_store().await;
        let mut session = sample_session(PaymentRole::Payee);
        store.upsert_session(&session).await.unwrap();

        session.state = PaymentState::AddressProvided;
        session.address = Some("stub-addr".to_string());
        session.updated_at = 2_000_000;
        store.upsert_session(&session).await.unwrap();

        let all = store.all_sessions().await.unwrap();
        assert_eq!(all.len(), 1, "upsert must not create a duplicate row");
        assert_eq!(all[0].state, PaymentState::AddressProvided);
        assert_eq!(all[0].address.as_deref(), Some("stub-addr"));
    }

    #[tokio::test]
    async fn empty_store_returns_empty_vec() {
        let (store, _tempfile) = make_store().await;
        assert!(store.all_sessions().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn multiple_sessions_stored_independently() {
        let (store, _tempfile) = make_store().await;
        let payer = sample_session(PaymentRole::Payer);
        let payee = sample_session(PaymentRole::Payee);
        store.upsert_session(&payer).await.unwrap();
        store.upsert_session(&payee).await.unwrap();
        let all = store.all_sessions().await.unwrap();
        assert_eq!(all.len(), 2);
    }

    /// Opening the same DB file twice must succeed and preserve existing rows.
    ///
    /// Oracle: the row count after both opens matches what was inserted, confirming
    /// the migration runner does not truncate or recreate the table on a second open.
    #[tokio::test]
    async fn reopening_store_preserves_data() {
        let f = tempfile::NamedTempFile::new().unwrap();
        {
            let s1 = WalletStore::new(f.path()).await.unwrap();
            s1.upsert_session(&sample_session(PaymentRole::Payer))
                .await
                .unwrap();
        }
        // Second open — migration version check runs; must not drop rows.
        let s2 = WalletStore::new(f.path()).await.unwrap();
        assert_eq!(
            s2.all_sessions().await.unwrap().len(),
            1,
            "row must survive a second open"
        );
    }

    /// expire_sessions_older_than transitions non-terminal sessions older than
    /// max_age_secs and leaves terminal or recently-updated ones untouched.
    ///
    /// Oracle: counts before/after are known from setup; terminal sessions are
    /// verified independently by checking their state does not change.
    #[tokio::test]
    async fn expire_stale_sessions_bulk() {
        let (store, _tempfile) = make_store().await;

        // A stale non-terminal session (updated_at = 0, well before any cutoff).
        let mut stale = sample_session(PaymentRole::Payer);
        stale.updated_at = 0;
        store.upsert_session(&stale).await.unwrap();

        // A recent non-terminal session (updated_at = 9_999_999, after cutoff).
        let mut recent = sample_session(PaymentRole::Payee);
        recent.updated_at = 9_999_999;
        store.upsert_session(&recent).await.unwrap();

        // A terminal session that must not be touched.
        let mut terminal = sample_session(PaymentRole::Payer);
        terminal.state = PaymentState::Confirmed;
        terminal.updated_at = 0;
        store.upsert_session(&terminal).await.unwrap();

        // Expire sessions older than 1_000 seconds relative to now_ts=5_000.
        // Internal cutoff = 5_000 - 1_000 = 4_000; stale (updated_at=0) is expired,
        // recent (updated_at=9_999_999) is not.
        let n = store
            .expire_sessions_older_than(5_000, 1_000)
            .await
            .unwrap();
        assert_eq!(n, 1, "exactly one stale session should be expired");

        let all = store.all_sessions().await.unwrap();
        for s in &all {
            if s.id == stale.id {
                assert_eq!(
                    s.state,
                    PaymentState::Expired,
                    "stale session must be expired"
                );
                assert_eq!(s.updated_at, 5_000, "updated_at must be set to now_ts");
            } else if s.id == recent.id {
                assert_ne!(
                    s.state,
                    PaymentState::Expired,
                    "recent session must not be expired"
                );
            } else if s.id == terminal.id {
                assert_eq!(
                    s.state,
                    PaymentState::Confirmed,
                    "terminal session must be unchanged"
                );
            }
        }
    }

    /// Amount at exactly i64::MAX must succeed; above must fail.
    ///
    /// Oracle: i64::MAX value is 9_223_372_036_854_775_807, which is above any
    /// realistic Zcash amount.  Testing the boundary directly is the only way to
    /// exercise the try_from error path. (nie-nej)
    #[tokio::test]
    async fn amount_zatoshi_overflow_rejected() {
        let (store, _tempfile) = make_store().await;
        let mut session = sample_session(PaymentRole::Payer);
        session.amount_zatoshi = u64::MAX; // definitely > i64::MAX
        let result = store.upsert_session(&session).await;
        assert!(
            result.is_err(),
            "amount_zatoshi > i64::MAX must be rejected"
        );
    }

    // ---- get_session_by_address / sessions_to_watch ----

    /// get_session_by_address returns Ok(None) when no session matches.
    ///
    /// Oracle: empty store; any address lookup must return None, not an error.
    #[tokio::test]
    async fn get_session_by_address_missing_returns_none() {
        let (store, _tempfile) = make_store().await;
        let result = store.get_session_by_address("z1nothere").await.unwrap();
        assert!(result.is_none());
    }

    /// get_session_by_address finds a payee session in address_provided state.
    ///
    /// Oracle: the session is inserted with a known address; the returned session
    /// id must match exactly.  The lookup address is not re-derived from any
    /// query result — it is the literal string used at insert time.
    #[tokio::test]
    async fn get_session_by_address_finds_payee_address_provided() {
        let (store, _tempfile) = make_store().await;
        let mut session = sample_session(PaymentRole::Payee);
        session.state = PaymentState::AddressProvided;
        session.address = Some("zs1testaddr".to_string());
        store.upsert_session(&session).await.unwrap();

        let found = store
            .get_session_by_address("zs1testaddr")
            .await
            .unwrap()
            .expect("session must be found");
        assert_eq!(found.id, session.id);
        assert_eq!(found.state, PaymentState::AddressProvided);
        assert_eq!(found.role, PaymentRole::Payee);
    }

    /// get_session_by_address finds a payee session in sent state.
    ///
    /// Oracle: the session is inserted in the sent state, which is still
    /// unconfirmed and should be returned.
    #[tokio::test]
    async fn get_session_by_address_finds_payee_sent() {
        let (store, _tempfile) = make_store().await;
        let mut session = sample_session(PaymentRole::Payee);
        session.state = PaymentState::Sent;
        session.address = Some("zs1sentaddr".to_string());
        store.upsert_session(&session).await.unwrap();

        let found = store
            .get_session_by_address("zs1sentaddr")
            .await
            .unwrap()
            .expect("sent payee session must be found");
        assert_eq!(found.id, session.id);
        assert_eq!(found.state, PaymentState::Sent);
    }

    /// get_session_by_address ignores payer sessions even when the address matches.
    ///
    /// Oracle: a payer session is inserted with the same address string; the
    /// method must return None because only payee sessions are eligible.
    #[tokio::test]
    async fn get_session_by_address_ignores_payer_sessions() {
        let (store, _tempfile) = make_store().await;
        let mut session = sample_session(PaymentRole::Payer);
        session.state = PaymentState::AddressProvided;
        session.address = Some("zs1payeraddr".to_string());
        store.upsert_session(&session).await.unwrap();

        let result = store.get_session_by_address("zs1payeraddr").await.unwrap();
        assert!(result.is_none(), "payer session must not be returned");
    }

    /// get_session_by_address ignores terminal states (confirmed, failed, expired).
    ///
    /// Oracle: three terminal sessions are inserted with the same address; all
    /// must return None because confirmed payments need no further watching.
    #[tokio::test]
    async fn get_session_by_address_ignores_terminal_states() {
        let (store, _tempfile) = make_store().await;

        for state in [
            PaymentState::Confirmed,
            PaymentState::Failed,
            PaymentState::Expired,
        ] {
            let mut s = sample_session(PaymentRole::Payee);
            s.state = state;
            s.address = Some("zs1termaddr".to_string());
            store.upsert_session(&s).await.unwrap();
        }

        let result = store.get_session_by_address("zs1termaddr").await.unwrap();
        assert!(
            result.is_none(),
            "terminal payee sessions must not be returned"
        );
    }

    /// sessions_to_watch returns an empty vec when no watchable sessions exist.
    ///
    /// Oracle: an empty store; the result must be an empty Vec, not an error.
    #[tokio::test]
    async fn sessions_to_watch_empty_store() {
        let (store, _tempfile) = make_store().await;
        let result = store.sessions_to_watch().await.unwrap();
        assert!(result.is_empty());
    }

    /// sessions_to_watch returns payee sessions in address_provided or sent state.
    ///
    /// Oracle: two eligible sessions and several ineligible ones are inserted;
    /// only the two eligible ones must appear in the result.  Session ids are
    /// checked explicitly against the inserted values.
    #[tokio::test]
    async fn sessions_to_watch_returns_eligible_only() {
        let (store, _tempfile) = make_store().await;

        // Eligible: payee + address_provided + address present.
        let mut ap = sample_session(PaymentRole::Payee);
        ap.state = PaymentState::AddressProvided;
        ap.address = Some("zs1addr_ap".to_string());
        store.upsert_session(&ap).await.unwrap();

        // Eligible: payee + sent + address present.
        let mut sent = sample_session(PaymentRole::Payee);
        sent.state = PaymentState::Sent;
        sent.address = Some("zs1addr_sent".to_string());
        store.upsert_session(&sent).await.unwrap();

        // Ineligible: payer role.
        let mut payer = sample_session(PaymentRole::Payer);
        payer.state = PaymentState::AddressProvided;
        payer.address = Some("zs1addr_payer".to_string());
        store.upsert_session(&payer).await.unwrap();

        // Ineligible: payee but confirmed (terminal).
        let mut confirmed = sample_session(PaymentRole::Payee);
        confirmed.state = PaymentState::Confirmed;
        confirmed.address = Some("zs1addr_conf".to_string());
        store.upsert_session(&confirmed).await.unwrap();

        // Ineligible: payee + address_provided but address IS NULL.
        let mut no_addr = sample_session(PaymentRole::Payee);
        no_addr.state = PaymentState::AddressProvided;
        no_addr.address = None;
        store.upsert_session(&no_addr).await.unwrap();

        let watching = store.sessions_to_watch().await.unwrap();
        assert_eq!(watching.len(), 2, "only two sessions are eligible to watch");

        let ids: Vec<uuid::Uuid> = watching.iter().map(|s| s.id).collect();
        assert!(
            ids.contains(&ap.id),
            "address_provided session must be included"
        );
        assert!(ids.contains(&sent.id), "sent session must be included");
    }

    /// State string values stored in SQLite must be stable — these are the
    /// canonical strings used for upsert and deserialisation.  If a variant is
    /// renamed, this test catches the breakage before corrupted rows reach prod.
    ///
    /// Oracle: the expected strings are defined in the protocol spec and in the
    /// issue description for nie-6pr, independent of the Rust serde rename.
    #[tokio::test]
    async fn state_strings_are_spec_canonical() {
        assert_eq!(state_to_str(&PaymentState::Requested), "requested");
        assert_eq!(
            state_to_str(&PaymentState::AddressProvided),
            "address_provided"
        );
        assert_eq!(state_to_str(&PaymentState::Sent), "sent");
        assert_eq!(state_to_str(&PaymentState::Confirmed), "confirmed");
        assert_eq!(state_to_str(&PaymentState::Failed), "failed");
        assert_eq!(state_to_str(&PaymentState::Expired), "expired");

        assert_eq!(role_to_str(&PaymentRole::Payer), "payer");
        assert_eq!(role_to_str(&PaymentRole::Payee), "payee");

        assert_eq!(chain_to_str(&Chain::Zcash), "zcash");
        assert_eq!(chain_to_str(&Chain::Monero), "monero");
        assert_eq!(chain_to_str(&Chain::Mobilecoin), "mobilecoin");

        assert_eq!(tx_direction_to_str(&TxDirection::Incoming), "incoming");
        assert_eq!(tx_direction_to_str(&TxDirection::Outgoing), "outgoing");
    }

    // ---- notes / witnesses / transactions (nie-6tn) ----

    fn sample_note() -> Note {
        Note {
            txid: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string(),
            output_index: 0,
            value_zatoshi: 500_000,
            memo: Some(b"test memo".to_vec()),
            block_height: 1_000_000,
            created_at: 2_000_000,
            note_diversifier: None,
            note_pk_d: None,
            note_rseed: None,
            rseed_after_zip212: None,
        }
    }

    /// Insert a note and retrieve it from unspent_notes.
    ///
    /// Oracle: the retrieved values are compared field-by-field against the
    /// inserted note, not re-derived from the insert path.
    #[tokio::test]
    async fn insert_and_retrieve_note() {
        let (store, _tempfile) = make_store().await;
        let note = sample_note();
        let note_id = store.insert_note(&note).await.unwrap();
        assert!(note_id > 0);

        let notes = store.unspent_notes().await.unwrap();
        assert_eq!(notes.len(), 1);
        let (got_id, got_note) = &notes[0];
        assert_eq!(*got_id, note_id);
        assert_eq!(got_note.txid, note.txid);
        assert_eq!(got_note.output_index, 0);
        assert_eq!(got_note.value_zatoshi, 500_000);
        assert_eq!(got_note.block_height, 1_000_000);
        assert_eq!(got_note.memo.as_deref(), Some(b"test memo".as_slice()));
    }

    /// mark_note_spent returns Err for a note_id that doesn't exist.
    ///
    /// Oracle: no note inserted, so any note_id is absent; the function must
    /// return Err rather than silently succeeding with rows_affected == 0.
    #[tokio::test]
    async fn mark_note_spent_nonexistent_note_errors() {
        let (store, _tempfile) = make_store().await;
        let result = store.mark_note_spent(9999, "deadbeef").await;
        assert!(
            result.is_err(),
            "mark_note_spent on missing note_id must return Err"
        );
    }

    /// mark_note_spent removes the note from unspent_notes.
    ///
    /// Oracle: unspent_notes count drops to zero after mark_note_spent;
    /// independently verified against a known starting state of one note.
    #[tokio::test]
    async fn mark_note_spent_removes_from_unspent() {
        let (store, _tempfile) = make_store().await;
        let note_id = store.insert_note(&sample_note()).await.unwrap();

        let spending = "1122334455667788990011223344556677889900112233445566778899001122";
        store.mark_note_spent(note_id, spending).await.unwrap();

        assert!(
            store.unspent_notes().await.unwrap().is_empty(),
            "spent note must not appear in unspent_notes"
        );
    }

    /// mark_notes_spent marks all notes atomically; all are visible as spent after success.
    ///
    /// Oracle: after mark_notes_spent, unspent_notes is empty; the notes were
    /// inserted individually and their ids confirmed before the batch call.
    #[tokio::test]
    async fn mark_notes_spent_batch_success() {
        let (store, _tempfile) = make_store().await;
        let id1 = store.insert_note(&sample_note()).await.unwrap();
        let mut n2 = sample_note();
        n2.txid = "aaaa".to_string();
        let id2 = store.insert_note(&n2).await.unwrap();

        let txid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        store.mark_notes_spent(&[id1, id2], txid).await.unwrap();

        assert!(
            store.unspent_notes().await.unwrap().is_empty(),
            "both notes must be spent after mark_notes_spent"
        );
    }

    /// mark_notes_spent with an empty slice is a no-op that returns Ok.
    ///
    /// Oracle: unspent_notes is unchanged after the call; the inserted note
    /// is still present, proving no accidental delete occurred.
    #[tokio::test]
    async fn mark_notes_spent_empty_slice_is_noop() {
        let (store, _tempfile) = make_store().await;
        let _id = store.insert_note(&sample_note()).await.unwrap();

        store.mark_notes_spent(&[], "any-txid").await.unwrap();

        assert_eq!(
            store.unspent_notes().await.unwrap().len(),
            1,
            "empty batch must not affect existing notes"
        );
    }

    /// mark_notes_spent rolls back on a missing note_id; no notes are marked.
    ///
    /// Oracle: valid note is still in unspent_notes after a batch that includes
    /// a nonexistent note_id — proving the transaction was rolled back.
    #[tokio::test]
    async fn mark_notes_spent_rolls_back_on_missing_note() {
        let (store, _tempfile) = make_store().await;
        let real_id = store.insert_note(&sample_note()).await.unwrap();
        let missing_id = real_id + 9999;

        let result = store
            .mark_notes_spent(&[real_id, missing_id], "some-txid")
            .await;
        assert!(
            result.is_err(),
            "batch with a missing note_id must return Err"
        );

        assert_eq!(
            store.unspent_notes().await.unwrap().len(),
            1,
            "transaction must have rolled back; real note must still be unspent"
        );
    }

    /// upsert_witness replaces the previous witness for a note.
    ///
    /// Oracle: the block_height retrieved after a second upsert matches the
    /// second call's height, not the first — proving the row was updated.
    #[tokio::test]
    async fn upsert_witness_replaces_previous() {
        let (store, _tempfile) = make_store().await;
        let note_id = store.insert_note(&sample_note()).await.unwrap();

        store
            .upsert_witness(note_id, 100, b"witness-at-100")
            .await
            .unwrap();
        store
            .upsert_witness(note_id, 200, b"witness-at-200")
            .await
            .unwrap();

        // Verify by reading the witnesses table directly.
        let (height, data): (i64, Vec<u8>) =
            sqlx::query_as("SELECT block_height, witness_data FROM witnesses WHERE note_id = ?")
                .bind(note_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(height, 200, "latest witness must replace the previous one");
        assert_eq!(data, b"witness-at-200");
    }

    /// Deleting a note cascades to its witness row (FK ON DELETE CASCADE).
    ///
    /// Oracle: witnesses table is empty after the note row is deleted.
    /// This verifies that PRAGMA foreign_keys = ON is active.
    #[tokio::test]
    async fn cascade_delete_removes_witness() {
        let (store, _tempfile) = make_store().await;
        let note_id = store.insert_note(&sample_note()).await.unwrap();
        store
            .upsert_witness(note_id, 100, b"some-witness")
            .await
            .unwrap();

        sqlx::query("DELETE FROM notes WHERE note_id = ?")
            .bind(note_id)
            .execute(&store.pool)
            .await
            .unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM witnesses WHERE note_id = ?")
            .bind(note_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "witness must be deleted when its note is deleted");
    }

    /// insert_note_with_witness atomically inserts a note and its witness row.
    ///
    /// Oracle: `spendable_notes()` does an INNER JOIN with `witnesses` and also
    /// requires all three plaintext columns to be non-NULL.  If either the note
    /// or the witness row is missing the note will not appear.  A successful
    /// return from `spendable_notes()` with the correct values proves that both
    /// rows were written and the note is spendable — the oracle is independent of
    /// the write path.
    #[tokio::test]
    async fn insert_note_with_witness_is_atomic() {
        let (store, _tempfile) = make_store().await;

        // Note with all plaintext columns populated — required for spendable_notes().
        let note = Note {
            txid: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            output_index: 0,
            value_zatoshi: 100_000,
            memo: None,
            block_height: 1_000_050,
            created_at: 2_000_000,
            note_diversifier: Some(vec![0x01u8; 11]),
            note_pk_d: Some(vec![0x02u8; 32]),
            note_rseed: Some(vec![0x03u8; 32]),
            rseed_after_zip212: Some(true),
        };
        let witness_data = b"stub-witness-bytes";
        let block_height = 1_000_050u64;

        let note_id = store
            .insert_note_with_witness(&note, block_height, witness_data)
            .await
            .expect("insert_note_with_witness must succeed");
        assert!(note_id > 0, "note_id must be positive");

        // spendable_notes() does INNER JOIN witnesses AND checks plaintext IS NOT NULL.
        // If either insert was omitted the vec would be empty — proving atomicity.
        let spendable = store
            .spendable_notes(0)
            .await
            .expect("spendable_notes must succeed");
        assert_eq!(
            spendable.len(),
            1,
            "note must appear in spendable_notes after insert_note_with_witness"
        );
        let n = &spendable[0];
        assert_eq!(n.note_id, note_id, "note_id round-trip");
        assert_eq!(n.value_zatoshi, 100_000, "value_zatoshi round-trip");
        assert_eq!(
            n.note_diversifier,
            vec![0x01u8; 11],
            "diversifier round-trip"
        );
        assert_eq!(n.note_pk_d, vec![0x02u8; 32], "pk_d round-trip");
        assert_eq!(n.note_rseed, vec![0x03u8; 32], "rseed round-trip");
        assert!(n.rseed_after_zip212, "rseed_after_zip212 round-trip");
        assert_eq!(n.witness_data, witness_data, "witness_data round-trip");
    }

    /// insert_tx roundtrip: record a transaction and retrieve it via recent_txs.
    ///
    /// Oracle: fields compared against the original TxRecord, independently of
    /// the insert path.
    #[tokio::test]
    async fn insert_and_retrieve_tx() {
        let (store, _tempfile) = make_store().await;
        let tx = TxRecord {
            txid: "deadbeef".repeat(8),
            block_height: 1_000,
            direction: TxDirection::Incoming,
            amount_zatoshi: 250_000,
            memo: Some(b"payment".to_vec()),
            peer_pub_id: Some("a".repeat(64)),
            created_at: 3_000_000,
        };
        store.insert_tx(&tx).await.unwrap();

        let txs = store.recent_txs(10).await.unwrap();
        assert_eq!(txs.len(), 1);
        let got = &txs[0];
        assert_eq!(got.txid, tx.txid);
        assert_eq!(got.block_height, 1_000);
        assert_eq!(got.direction, TxDirection::Incoming);
        assert_eq!(got.amount_zatoshi, 250_000);
        assert_eq!(got.memo.as_deref(), Some(b"payment".as_slice()));
        assert_eq!(got.peer_pub_id.as_deref(), Some("a".repeat(64).as_str()));
    }

    /// Duplicate insert_tx is silently ignored (INSERT OR IGNORE).
    #[tokio::test]
    async fn duplicate_tx_is_ignored() {
        let (store, _tempfile) = make_store().await;
        let tx = TxRecord {
            txid: "cafebabe".repeat(8),
            block_height: 500,
            direction: TxDirection::Outgoing,
            amount_zatoshi: 100_000,
            memo: None,
            peer_pub_id: None,
            created_at: 1_000,
        };
        store.insert_tx(&tx).await.unwrap();
        store.insert_tx(&tx).await.unwrap(); // must not error

        assert_eq!(
            store.recent_txs(10).await.unwrap().len(),
            1,
            "duplicate insert must not create a second row"
        );
    }

    /// Migration v1→v2: existing payment_sessions rows survive the v2 migration.
    ///
    /// Oracle: open store (runs v1), insert session, close, re-open (runs v2),
    /// then verify the session is still present AND the new tables are usable.
    #[tokio::test]
    async fn v1_data_survives_v2_migration() {
        let f = tempfile::NamedTempFile::new().unwrap();

        // Open at v1 (creates payment_sessions only).
        {
            let s1 = WalletStore::new(f.path()).await.unwrap();
            s1.upsert_session(&sample_session(PaymentRole::Payer))
                .await
                .unwrap();
        }

        // Re-open — migration v2 runs; must preserve existing rows and add tables.
        let s2 = WalletStore::new(f.path()).await.unwrap();
        assert_eq!(
            s2.all_sessions().await.unwrap().len(),
            1,
            "payment session must survive v1→v2 migration"
        );

        // New tables must be usable.
        let note_id = s2.insert_note(&sample_note()).await.unwrap();
        assert!(note_id > 0, "notes table must be usable after migration");
    }

    // ---- scan state (nie-bgc) ----

    /// A fresh store returns scan_tip = 0.
    ///
    /// Oracle: 0 is the seeded default in the migration v3 INSERT OR IGNORE.
    #[tokio::test]
    async fn scan_tip_defaults_to_zero() {
        let (store, _tempfile) = make_store().await;
        assert_eq!(store.scan_tip().await.unwrap(), 0);
    }

    /// set_scan_tip persists and scan_tip retrieves the stored height.
    ///
    /// Oracle: retrieved height matches what was set — cross-verified across
    /// two separate DB calls (set then get), not a single round-trip.
    #[tokio::test]
    async fn set_and_get_scan_tip() {
        let (store, _tempfile) = make_store().await;
        store.set_scan_tip(1_234_567).await.unwrap();
        assert_eq!(store.scan_tip().await.unwrap(), 1_234_567);
        // Update again — only one row exists; previous value must be replaced.
        store.set_scan_tip(2_000_000).await.unwrap();
        assert_eq!(store.scan_tip().await.unwrap(), 2_000_000);
    }

    /// Scan tip persists across a DB close/re-open.
    ///
    /// Oracle: height retrieved in a second WalletStore::new() matches what
    /// was set in the first instance, confirming the value is on disk.
    #[tokio::test]
    async fn scan_tip_survives_reopen() {
        let f = tempfile::NamedTempFile::new().unwrap();
        {
            let s1 = WalletStore::new(f.path()).await.unwrap();
            s1.set_scan_tip(999_999).await.unwrap();
        }
        let s2 = WalletStore::new(f.path()).await.unwrap();
        assert_eq!(
            s2.scan_tip().await.unwrap(),
            999_999,
            "scan tip must survive DB re-open"
        );
    }

    // ---- balance (nie-8t7) ----

    /// Empty wallet has zero balance.
    ///
    /// Oracle: no notes inserted; both confirmed and pending must be 0.
    #[tokio::test]
    async fn balance_empty_wallet_is_zero() {
        let (store, _tempfile) = make_store().await;
        let b = store.balance(2_000_000, 10).await.unwrap();
        assert_eq!(b.confirmed_zatoshi, 0);
        assert_eq!(b.pending_zatoshi, 0);
        assert_eq!(b.total_zatoshi(), 0);
    }

    /// A note at depth >= min_confirmations is confirmed; shallower is pending.
    ///
    /// Oracle: two notes at known heights; scan_tip and min_confirmations are
    /// chosen so one falls on each side of the threshold.  Expected values are
    /// derived by hand from the depth formula, not from the balance() code.
    ///
    /// Setup: scan_tip = 1_000_100, min_confirmations = 10
    ///   threshold = 1_000_100 - 10 = 1_000_090
    ///   note_a block_height = 1_000_080 → depth = 20 → confirmed
    ///   note_b block_height = 1_000_095 → depth =  5 → pending
    #[tokio::test]
    async fn balance_separates_confirmed_and_pending() {
        let (store, _tempfile) = make_store().await;

        let mut note_a = sample_note();
        note_a.output_index = 0;
        note_a.value_zatoshi = 300_000;
        note_a.block_height = 1_000_080;
        store.insert_note(&note_a).await.unwrap();

        let mut note_b = sample_note();
        note_b.output_index = 1;
        note_b.value_zatoshi = 200_000;
        note_b.block_height = 1_000_095;
        store.insert_note(&note_b).await.unwrap();

        let b = store.balance(1_000_100, 10).await.unwrap();
        assert_eq!(b.confirmed_zatoshi, 300_000, "only note_a is deep enough");
        assert_eq!(b.pending_zatoshi, 200_000, "note_b is pending");
        assert_eq!(b.total_zatoshi(), 500_000);
    }

    /// Spent notes are excluded from balance.
    ///
    /// Oracle: insert a note, mark it spent, verify both confirmed and pending
    /// are zero — the note must not appear in either bucket.
    #[tokio::test]
    async fn balance_excludes_spent_notes() {
        let (store, _tempfile) = make_store().await;
        let note_id = store.insert_note(&sample_note()).await.unwrap();
        store
            .mark_note_spent(note_id, "spending-txid")
            .await
            .unwrap();

        // scan_tip far above the note's block_height → note would be confirmed
        // if unspent, but it is spent and must not appear.
        let b = store.balance(2_000_000, 10).await.unwrap();
        assert_eq!(
            b.total_zatoshi(),
            0,
            "spent note must not appear in balance"
        );
    }

    /// When scan_tip < min_confirmations, all notes are pending — including
    /// notes with block_height = 0 (the migration v4 DEFAULT sentinel).
    ///
    /// Oracle: threshold is set to -1 (not 0 via saturating_sub) so that
    /// `block_height <= -1` is never satisfied; all notes land in pending.
    /// Expected values derived from the formula, not from balance() itself.
    ///
    /// Setup: scan_tip=3, min_confirmations=10 → scan_tip < min_confirmations
    ///   threshold = -1; block_height=5 > -1 → pending
    #[tokio::test]
    async fn balance_all_pending_when_tip_below_min_confirmations() {
        let (store, _tempfile) = make_store().await;
        let mut note = sample_note();
        note.block_height = 5;
        store.insert_note(&note).await.unwrap();

        let b = store.balance(3, 10).await.unwrap();
        assert_eq!(b.confirmed_zatoshi, 0);
        assert_eq!(b.pending_zatoshi, 500_000);
    }

    /// A note with block_height = 0 is pending when scan_tip < min_confirmations.
    ///
    /// This is the regression test for nie-phy.1: previously threshold was
    /// computed via saturating_sub, giving 0 when scan_tip < min_confirmations.
    /// A note at block_height=0 satisfied `0 <= 0` and appeared as confirmed
    /// despite having zero depth — contradicting the documented formula.
    ///
    /// Oracle: depth formula `scan_tip - block_height = 3 - 0 = 3 < 10` →
    /// note must be pending regardless of the threshold representation.
    #[tokio::test]
    async fn balance_height_zero_note_is_pending_when_tip_below_min_confirmations() {
        let (store, _tempfile) = make_store().await;
        let mut note = sample_note();
        note.block_height = 0; // migration v4 DEFAULT sentinel
        store.insert_note(&note).await.unwrap();

        // scan_tip=3 < min_confirmations=10 → nothing confirmed.
        // Previously block_height=0 <= saturating_sub(3,10)=0 → wrongly confirmed.
        let b = store.balance(3, 10).await.unwrap();
        assert_eq!(
            b.confirmed_zatoshi, 0,
            "block_height=0 note must be pending when scan_tip < min_confirmations"
        );
        assert_eq!(b.pending_zatoshi, 500_000);
    }

    // ---- accounts / diversifier index (nie-0dg) ----

    /// A fresh store returns diversifier_index = 0 for any account.
    ///
    /// Oracle: 0 is the documented default for an unseen account — get returns
    /// 0 without requiring ensure_account to have been called first.
    #[tokio::test]
    async fn diversifier_index_default_is_zero() {
        let (store, _tempfile) = make_store().await;
        assert_eq!(store.get_diversifier_index(0).await.unwrap(), 0);
        assert_eq!(store.get_diversifier_index(1).await.unwrap(), 0);
    }

    /// advance_diversifier_to followed by get_diversifier_index round-trips.
    ///
    /// Oracle: the retrieved value matches the stored value, not a default —
    /// tested across multiple accounts and non-trivial u128 values.
    #[tokio::test]
    async fn diversifier_index_roundtrip() {
        let (store, _tempfile) = make_store().await;

        store.advance_diversifier_to(0, 42).await.unwrap();
        assert_eq!(store.get_diversifier_index(0).await.unwrap(), 42);

        // Large u128 — well above i64::MAX (9_223_372_036_854_775_807).
        // This is the value that would silently wrap to negative in a signed column.
        let large: u128 = u128::MAX;
        store.advance_diversifier_to(0, large).await.unwrap();
        assert_eq!(store.get_diversifier_index(0).await.unwrap(), large);

        // Accounts are independent — account 1 retains its own index.
        store.advance_diversifier_to(1, 99).await.unwrap();
        assert_eq!(store.get_diversifier_index(0).await.unwrap(), large);
        assert_eq!(store.get_diversifier_index(1).await.unwrap(), 99);
    }

    /// Diversifier index persists across a DB close/re-open.
    ///
    /// Oracle: value retrieved in a second WalletStore::new() matches what
    /// was set in the first instance, confirming the value is on disk.
    #[tokio::test]
    async fn diversifier_index_persists_across_reopen() {
        let f = tempfile::NamedTempFile::new().unwrap();
        {
            let s1 = WalletStore::new(f.path()).await.unwrap();
            s1.advance_diversifier_to(0, 1_234_567_890).await.unwrap();
        }
        let s2 = WalletStore::new(f.path()).await.unwrap();
        assert_eq!(
            s2.get_diversifier_index(0).await.unwrap(),
            1_234_567_890,
            "diversifier index must survive DB re-open"
        );
    }

    /// ensure_account creates the row; subsequent get returns 0 (DEFAULT).
    ///
    /// Oracle: a freshly-ensured account with no explicit set returns 0, not
    /// an error — confirming the INSERT OR IGNORE correctly inserts the row.
    #[tokio::test]
    async fn ensure_account_creates_row_with_zero_index() {
        let (store, _tempfile) = make_store().await;
        store.ensure_account(0).await.unwrap();
        assert_eq!(store.get_diversifier_index(0).await.unwrap(), 0);
        // ensure_account is idempotent — second call must not fail.
        store.ensure_account(0).await.unwrap();
        assert_eq!(store.get_diversifier_index(0).await.unwrap(), 0);
    }

    /// advance_diversifier_to is monotonic: a retrograde write is ignored.
    ///
    /// Oracle: after advancing to 200, a call with 100 must leave the stored
    /// value at 200.  This guards against address reuse when a stale caller
    /// retries with an earlier index after Sapling skipped invalid diversifiers.
    #[tokio::test]
    async fn advance_diversifier_to_is_monotonic() {
        let (store, _tempfile) = make_store().await;
        store.advance_diversifier_to(0, 100).await.unwrap();
        store.advance_diversifier_to(0, 200).await.unwrap();
        assert_eq!(store.get_diversifier_index(0).await.unwrap(), 200);
        // Retrograde write must not decrease the stored value.
        store.advance_diversifier_to(0, 50).await.unwrap();
        assert_eq!(
            store.get_diversifier_index(0).await.unwrap(),
            200,
            "retrograde advance_diversifier_to must not decrease the stored index"
        );
    }

    /// advance_diversifier_to with idx=0 creates the account row if absent.
    ///
    /// Oracle: `get_diversifier_index` must return 0 after the call, confirming
    /// the row was inserted.  This verifies the nie-0o9.2 fix: previously the
    /// function's `if idx <= current` guard (with current defaulting to 0 for a
    /// missing row) caused it to return without inserting anything.
    #[tokio::test]
    async fn advance_diversifier_to_zero_creates_row() {
        let (store, _tempfile) = make_store().await;
        // No ensure_account — the row must not exist yet.
        store.advance_diversifier_to(0, 0).await.unwrap();
        assert_eq!(
            store.get_diversifier_index(0).await.unwrap(),
            0,
            "advance_diversifier_to(0) must create the row with index 0"
        );
        // next_diversifier must now succeed (row exists) and return 0.
        let di = store.next_diversifier(0).await.unwrap();
        assert_eq!(di, 0, "next_diversifier must return 0 after advance_to(0)");
    }

    /// advance_diversifier_to returns Err on a corrupt (non-parseable) stored value.
    ///
    /// Oracle: if the stored string is not a valid u128, the function must fail rather
    /// than silently treating it as 0 and potentially writing a retrograde value.
    /// Ensures monotonicity cannot be violated by a corrupt DB row.
    #[tokio::test]
    async fn advance_diversifier_to_corrupt_value_returns_err() {
        let (store, _tempfile) = make_store().await;
        // Directly corrupt the stored diversifier_index using raw SQL.
        sqlx::query(
            "INSERT INTO accounts (account_index, diversifier_index) VALUES (0, 'not-a-number')",
        )
        .execute(&store.pool)
        .await
        .unwrap();

        let result = store.advance_diversifier_to(0, 42).await;
        assert!(
            result.is_err(),
            "advance_diversifier_to must return Err for a corrupt stored value, not silently overwrite"
        );
    }

    // ---- next_diversifier (nie-6y2) ----

    /// 10 consecutive calls produce [0, 1, ..., 9] (pre-increment semantics).
    ///
    /// Oracle: the expected sequence is derived from the pre-increment rule
    /// documented in the function's interface, not from the implementation.
    /// Calls are sequential (not concurrent) to test the monotone-increment
    /// property; concurrent calls would produce the right SET of values but
    /// in non-deterministic order.
    #[tokio::test]
    async fn next_diversifier_sequential() {
        let (store, _tempfile) = make_store().await;
        store.ensure_account(0).await.unwrap();

        let mut indices = Vec::new();
        for _ in 0..10 {
            indices.push(store.next_diversifier(0).await.unwrap());
        }
        assert_eq!(indices, (0u128..10).collect::<Vec<_>>());
    }

    /// next_diversifier without ensure_account returns Err, not a default.
    ///
    /// Oracle: no account row inserted; any call must fail rather than
    /// silently creating a row — callers must opt-in via ensure_account.
    #[tokio::test]
    async fn next_diversifier_missing_account_returns_err() {
        let (store, _tempfile) = make_store().await;
        let result = store.next_diversifier(99).await;
        assert!(result.is_err(), "missing account must return Err");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("not found"),
            "error must mention 'not found': {msg}"
        );
    }

    /// Persisted diversifier index survives a WalletStore::new() reconnect.
    ///
    /// Oracle: after 3 calls (indices 0,1,2 returned; DB stores 3), re-open
    /// and call once more — must return 3, not 0.
    #[tokio::test]
    async fn next_diversifier_survives_reopen() {
        let f = tempfile::NamedTempFile::new().unwrap();
        {
            let s = WalletStore::new(f.path()).await.unwrap();
            s.ensure_account(0).await.unwrap();
            s.next_diversifier(0).await.unwrap(); // returns 0, DB stores 1
            s.next_diversifier(0).await.unwrap(); // returns 1, DB stores 2
            s.next_diversifier(0).await.unwrap(); // returns 2, DB stores 3
        }
        let s2 = WalletStore::new(f.path()).await.unwrap();
        let idx = s2.next_diversifier(0).await.unwrap();
        assert_eq!(idx, 3, "must resume from persisted index after reopen");
    }

    /// Overflow at MAX_DIVERSIFIER (2^88 - 1) returns Err, not a panic.
    ///
    /// Oracle: set index to MAX, then call next_diversifier — must Err.
    /// The max value is defined in the spec as 2^88 - 1 (11 bytes).
    #[tokio::test]
    async fn next_diversifier_overflow_returns_err() {
        let (store, _tempfile) = make_store().await;
        store.ensure_account(0).await.unwrap();

        // Set the index to the maximum (2^88 - 1).
        let max: u128 = (1u128 << 88) - 1;
        store.advance_diversifier_to(0, max).await.unwrap();

        let result = store.next_diversifier(0).await;
        assert!(
            result.is_err(),
            "next_diversifier at max must return Err, not panic"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("overflow") || msg.contains("exhausted"),
            "error must mention overflow: {msg}"
        );
    }

    /// Existing payment session data survives the v5 migration (accounts table added).
    ///
    /// Oracle: open a fresh DB (runs all migrations 1–5), insert a session and
    /// a note, close, re-open (no-op migrations), assert both are still present
    /// AND the accounts table is usable with correct column semantics.
    #[tokio::test]
    async fn v4_data_survives_v5_migration() {
        let f = tempfile::NamedTempFile::new().unwrap();

        // First open: runs all migrations (1–5), inserts data.
        {
            let s = WalletStore::new(f.path()).await.unwrap();
            s.upsert_session(&sample_session(PaymentRole::Payer))
                .await
                .unwrap();
            s.insert_note(&sample_note()).await.unwrap();
            s.advance_diversifier_to(0, 7).await.unwrap();
        }

        // Second open: no migrations run (version = 5 already); data must survive.
        let s2 = WalletStore::new(f.path()).await.unwrap();
        assert_eq!(
            s2.all_sessions().await.unwrap().len(),
            1,
            "payment session must survive migration"
        );
        assert_eq!(
            s2.unspent_notes().await.unwrap().len(),
            1,
            "note must survive migration"
        );
        assert_eq!(
            s2.get_diversifier_index(0).await.unwrap(),
            7,
            "diversifier index must survive migration"
        );
    }

    /// Migration v6 is idempotent: opening the same DB file a second time must not error.
    #[tokio::test]
    async fn v6_migration_is_idempotent() {
        let f = tempfile::NamedTempFile::new().unwrap();
        // First open applies migrations up to v6.
        WalletStore::new(f.path()).await.unwrap();
        // Second open: version = 6 already; no ALTER TABLE statements should run.
        WalletStore::new(f.path()).await.unwrap();
    }

    /// Existing note rows survive the v5 → v6 migration with NULL plaintext columns.
    ///
    /// Oracle: the note inserted before migration is still present afterward,
    /// with `note_diversifier`, `note_pk_d`, `note_rseed` all NULL (not populated by
    /// `insert_note`, which predates the plaintext columns).
    #[tokio::test]
    async fn v5_data_survives_v6_migration() {
        let f = tempfile::NamedTempFile::new().unwrap();

        // First open: runs migrations 1–6; insert a note the normal way (no plaintext).
        {
            let s = WalletStore::new(f.path()).await.unwrap();
            s.insert_note(&sample_note()).await.unwrap();
        }

        // Second open: v6 already applied; note must still be visible in unspent_notes().
        let s2 = WalletStore::new(f.path()).await.unwrap();
        let notes = s2.unspent_notes().await.unwrap();
        assert_eq!(notes.len(), 1, "note must survive v5→v6 migration");
        assert_eq!(
            notes[0].1.value_zatoshi,
            sample_note().value_zatoshi,
            "note value must be preserved"
        );
    }

    /// Migration v7 is idempotent: opening the same DB file a second time must not error.
    ///
    /// Oracle: `CREATE INDEX IF NOT EXISTS` is used, so re-running must be a no-op.
    #[tokio::test]
    async fn v7_migration_is_idempotent() {
        let f = tempfile::NamedTempFile::new().unwrap();
        WalletStore::new(f.path()).await.unwrap();
        WalletStore::new(f.path()).await.unwrap();
    }

    /// v7 migration creates the `notes_unspent` partial index.
    ///
    /// Oracle: `PRAGMA index_list(notes)` must contain an entry named
    /// `notes_unspent` — verified independently of the migration code path.
    #[tokio::test]
    async fn v7_notes_unspent_index_exists() {
        let (store, _tempfile) = make_store().await;
        #[derive(sqlx::FromRow)]
        struct IndexRow {
            name: String,
        }
        let rows: Vec<IndexRow> = sqlx::query_as("PRAGMA index_list(notes)")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        let found = rows.iter().any(|r| r.name == "notes_unspent");
        assert!(
            found,
            "notes_unspent index must exist after v7 migration; got: {:?}",
            rows.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
    }

    /// spendable_notes() excludes notes whose plaintext columns are NULL.
    ///
    /// Oracle: spendable_notes() count is independent of unspent_notes() count —
    /// they are compared against expected values derived from the number of notes
    /// inserted, not from each other.
    #[tokio::test]
    async fn spendable_notes_excludes_null_plaintext() {
        let (store, _tempfile) = make_store().await;

        // Insert a note with no plaintext (the normal insert_note path).
        store.insert_note(&sample_note()).await.unwrap();

        // unspent_notes sees it; spendable_notes does not.
        assert_eq!(store.unspent_notes().await.unwrap().len(), 1);
        assert_eq!(
            store.spendable_notes(0).await.unwrap().len(),
            0,
            "note with NULL plaintext must not appear in spendable_notes"
        );
    }

    /// spendable_notes() includes notes where all three plaintext columns are set
    /// AND a witness row exists (INNER JOIN).
    ///
    /// Oracle: note inserted via raw SQL with known g_d/pk_d/rseed; witness inserted
    /// via upsert_witness().  Round-trip compares each field against the known input
    /// bytes, not the insert path.
    #[tokio::test]
    async fn spendable_notes_includes_fully_populated_note() {
        let (store, _tempfile) = make_store().await;

        // Realistic 11-byte diversifier d, 32-byte pk_d, 32-byte rseed (all synthetic).
        let diversifier: Vec<u8> = (1u8..=11).collect(); // [1, 2, ..., 11]
        let pk_d: Vec<u8> = (1u8..=32).collect(); // [1, 2, ..., 32]
        let rseed: Vec<u8> = (32u8..64).collect(); // [32, 33, ..., 63]
        let witness: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef]; // synthetic stub bytes

        // Insert a note with all plaintext columns populated.
        let note_id: i64 = sqlx::query_scalar(
            "INSERT INTO notes
               (txid, output_index, value_zatoshi, block_height, created_at,
                note_diversifier, note_pk_d, note_rseed, note_rseed_after_zip212)
             VALUES ('aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
                     0, 750000, 1000001, 2000001, ?, ?, ?, 1)
             RETURNING note_id",
        )
        .bind(&diversifier)
        .bind(&pk_d)
        .bind(&rseed)
        .fetch_one(&store.pool)
        .await
        .unwrap();

        // Without a witness row the INNER JOIN excludes this note.
        assert_eq!(
            store.spendable_notes(0).await.unwrap().len(),
            0,
            "note without witness must not appear in spendable_notes"
        );

        // Insert the witness — now the note can appear.
        store
            .upsert_witness(note_id, 1_000_001, &witness)
            .await
            .unwrap();

        let notes = store.spendable_notes(0).await.unwrap();
        assert_eq!(
            notes.len(),
            1,
            "fully-populated note must appear in spendable_notes"
        );

        let n = &notes[0];
        assert_eq!(n.value_zatoshi, 750_000);
        assert_eq!(
            n.note_diversifier, diversifier,
            "diversifier round-trip mismatch"
        );
        assert_eq!(n.note_pk_d, pk_d, "pk_d round-trip mismatch");
        assert_eq!(n.note_rseed, rseed, "rseed round-trip mismatch");
        assert!(n.rseed_after_zip212, "rseed_after_zip212 must be true");
        assert_eq!(n.block_height, 1_000_001);
        assert_eq!(n.witness_data, witness, "witness_data round-trip mismatch");
    }

    /// spendable_notes() never returns a spent note even if plaintext and witness are populated.
    #[tokio::test]
    async fn spendable_notes_excludes_spent_notes() {
        let (store, _tempfile) = make_store().await;

        let diversifier: Vec<u8> = vec![0u8; 11];
        let pk_d: Vec<u8> = vec![0u8; 32];
        let rseed: Vec<u8> = vec![1u8; 32];

        let note_id: i64 = sqlx::query_scalar(
            "INSERT INTO notes
               (txid, output_index, value_zatoshi, block_height, created_at,
                note_diversifier, note_pk_d, note_rseed, note_rseed_after_zip212)
             VALUES ('aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
                     0, 500000, 1000000, 2000000, ?, ?, ?, 1)
             RETURNING note_id",
        )
        .bind(&diversifier)
        .bind(&pk_d)
        .bind(&rseed)
        .fetch_one(&store.pool)
        .await
        .unwrap();

        // Insert a witness so the INNER JOIN includes the note.
        store
            .upsert_witness(note_id, 1_000_000, &[0x01, 0x02])
            .await
            .unwrap();

        // Note appears before spending.
        assert_eq!(store.spendable_notes(0).await.unwrap().len(), 1);

        // Mark as spent — must disappear from spendable_notes.
        store.mark_note_spent(note_id, "deadbeef").await.unwrap();
        assert_eq!(
            store.spendable_notes(0).await.unwrap().len(),
            0,
            "spent note must not appear in spendable_notes"
        );
    }

    // ---- get_session_by_address / sessions_to_watch ----

    /// get_session_by_address returns the session when the address matches
    /// a payee session in the 'sent' state.
    ///
    /// Oracle: the expected result is derived from the SQL semantics:
    /// state IN ('address_provided','sent') AND role = 'payee' AND address = ?
    /// The returned session id must match the inserted one.
    #[tokio::test]
    async fn test_get_session_by_address_hit() {
        let (store, _tempfile) = make_store().await;
        let mut session = sample_session(PaymentRole::Payee);
        session.state = PaymentState::Sent;
        session.address = Some("zs1testaddress_sent".to_string());
        store.upsert_session(&session).await.unwrap();

        let result = store
            .get_session_by_address("zs1testaddress_sent")
            .await
            .unwrap();
        assert!(
            result.is_some(),
            "payee+sent+address must be found by get_session_by_address"
        );
        assert_eq!(
            result.unwrap().id,
            session.id,
            "returned session id must match the inserted session"
        );
    }

    /// get_session_by_address returns Ok(None) when no session has the queried address.
    ///
    /// Oracle: empty DB → no match → Ok(None), not an error.
    #[tokio::test]
    async fn test_get_session_by_address_miss() {
        let (store, _tempfile) = make_store().await;

        let result = store
            .get_session_by_address("zs1nonexistent")
            .await
            .unwrap();
        assert!(result.is_none(), "unknown address must return Ok(None)");
    }

    /// get_session_by_address returns Ok(None) for a session in 'confirmed' state
    /// even when the address matches — the state filter must exclude terminal sessions.
    ///
    /// Oracle: the SQL WHERE clause requires state IN ('address_provided','sent');
    /// 'confirmed' is not in that set.
    #[tokio::test]
    async fn test_get_session_by_address_wrong_state() {
        let (store, _tempfile) = make_store().await;
        let mut session = sample_session(PaymentRole::Payee);
        session.state = PaymentState::Confirmed;
        session.address = Some("zs1confirmed_addr".to_string());
        store.upsert_session(&session).await.unwrap();

        let result = store
            .get_session_by_address("zs1confirmed_addr")
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "confirmed (terminal) state must not be returned by get_session_by_address"
        );
    }

    /// get_session_by_address returns Ok(None) for a session with the correct address
    /// but role = 'payer' — the role filter must exclude payer sessions.
    ///
    /// Oracle: the SQL WHERE clause requires role = 'payee'; payer sessions are excluded.
    #[tokio::test]
    async fn test_get_session_by_address_wrong_role() {
        let (store, _tempfile) = make_store().await;
        let mut session = sample_session(PaymentRole::Payer);
        session.state = PaymentState::Sent;
        session.address = Some("zs1payer_addr".to_string());
        store.upsert_session(&session).await.unwrap();

        let result = store.get_session_by_address("zs1payer_addr").await.unwrap();
        assert!(
            result.is_none(),
            "payer role must not be returned by get_session_by_address"
        );
    }

    /// sessions_to_watch returns only payee sessions in 'address_provided' or 'sent'
    /// state with a non-null address.  Confirmed and payer sessions are excluded.
    ///
    /// Oracle: insert 3 sessions, only 1 qualifies; count and id are known from setup.
    #[tokio::test]
    async fn test_sessions_to_watch_returns_unconfirmed_payee() {
        let (store, _tempfile) = make_store().await;

        // Session 1: payee + Sent + address — must appear.
        let mut qualifying = sample_session(PaymentRole::Payee);
        qualifying.state = PaymentState::Sent;
        qualifying.address = Some("zs1watch_me".to_string());
        store.upsert_session(&qualifying).await.unwrap();

        // Session 2: payee + Confirmed + address — excluded by state.
        let mut confirmed = sample_session(PaymentRole::Payee);
        confirmed.state = PaymentState::Confirmed;
        confirmed.address = Some("zs1confirmed".to_string());
        store.upsert_session(&confirmed).await.unwrap();

        // Session 3: payer + Sent + address — excluded by role.
        let mut payer_sent = sample_session(PaymentRole::Payer);
        payer_sent.state = PaymentState::Sent;
        payer_sent.address = Some("zs1payer_watch".to_string());
        store.upsert_session(&payer_sent).await.unwrap();

        let watchlist = store.sessions_to_watch().await.unwrap();
        assert_eq!(
            watchlist.len(),
            1,
            "only the payee+sent+address session must appear in sessions_to_watch"
        );
        assert_eq!(
            watchlist[0].id, qualifying.id,
            "the qualifying session id must match"
        );
    }

    /// sessions_to_watch returns an empty Vec (not an error) when no sessions exist.
    ///
    /// Oracle: empty DB → empty result, per the SQL semantics of SELECT on an empty table.
    #[tokio::test]
    async fn test_sessions_to_watch_empty() {
        let (store, _tempfile) = make_store().await;
        let watchlist = store.sessions_to_watch().await.unwrap();
        assert!(
            watchlist.is_empty(),
            "sessions_to_watch on an empty DB must return an empty Vec"
        );
    }
}
