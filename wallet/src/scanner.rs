//! Compact block scanner background task (nie-bgc).
//!
//! Fetches [`CompactBlock`]s from a lightwalletd endpoint and trial-decrypts
//! each Sapling output via a pluggable [`NoteDecryptor`].  Discovered notes
//! are persisted to the [`WalletStore`] and the scan tip is advanced per block.
//!
//! ## IVK injection point
//!
//! [`NoteDecryptor`] is the seam for the Sapling incoming viewing key (IVK).
//! The production implementation (see nie-m91) uses the ZIP-32–derived IVK
//! from `zcash_primitives`.  Until that crate is unblocked, pass a
//! [`NullDecryptor`] — the scanner will advance the scan tip through blocks
//! without actually discovering notes.
//!
//! ## Birthday height
//!
//! A brand-new wallet has `scan_tip = 0`, meaning it would scan from the
//! genesis block.  Callers should call [`WalletStore::set_scan_tip`] with
//! an appropriate "wallet birthday" block height (typically the Sapling
//! activation height, ~280_000 on mainnet) before starting the scanner.
//! Scanning from a height below the wallet's creation date wastes bandwidth
//! without finding any relevant notes.

use std::collections::HashMap;
use std::io::Cursor;
use std::time::Duration;

use anyhow::Result;
use ff::PrimeField;
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use sapling::note_encryption::{
    try_sapling_compact_note_decryption, PreparedIncomingViewingKey, Zip212Enforcement,
};
use sapling::{Rseed, SaplingIvk};
use sqlx;
use tracing::{debug, warn};
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput, COMPACT_NOTE_SIZE};
use zcash_primitives::merkle_tree::{
    read_commitment_tree, read_incremental_witness, write_commitment_tree,
    write_incremental_witness,
};

use crate::client::{CompactBlock, CompactSaplingOutput, CompactTx, LightwalletdClient};
use crate::db::{Note, WalletStore};

// ---- ShieldedOutput adapter ----

/// Adapter wrapping validated `CompactSaplingOutput` field slices for the
/// `try_sapling_compact_note_decryption` API.
///
/// Constructed only after the caller has verified the correct byte lengths,
/// so the array casts below cannot panic.
struct CompactOutputAdapter {
    ephemeral_key: [u8; 32],
    cmu: [u8; 32],
    enc_ciphertext: [u8; COMPACT_NOTE_SIZE],
}

impl ShieldedOutput<sapling::note_encryption::SaplingDomain, COMPACT_NOTE_SIZE>
    for CompactOutputAdapter
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.ephemeral_key)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu
    }

    fn enc_ciphertext(&self) -> &[u8; COMPACT_NOTE_SIZE] {
        &self.enc_ciphertext
    }
}

/// Pluggable Sapling note decryption.
///
/// The production implementation wraps a ZIP-32 Sapling incoming viewing key
/// (IVK) and calls `zcash_primitives` note-decryption primitives.  Pass a
/// [`NullDecryptor`] when no IVK is available (e.g., during unit tests or
/// before nie-m91 is implemented).
pub trait NoteDecryptor: Send {
    /// Attempt to decrypt a Sapling compact output.
    ///
    /// Returns `Some(Note)` if the output belongs to this wallet, `None` if
    /// trial decryption fails (the common case — most outputs are for other
    /// wallets).
    ///
    /// # Parameters
    /// - `block_height`: height of the containing block.
    /// - `block_time`: Unix timestamp of the containing block.
    /// - `txid`: 32-byte transaction identifier (little-endian).
    /// - `output_index`: 0-based index within the transaction's Sapling outputs.
    /// - `output`: the compact output bytes (cmu, ephemeralKey, ciphertext).
    fn try_decrypt_sapling(
        &self,
        block_height: u64,
        block_time: u32,
        txid: &[u8],
        output_index: usize,
        output: &CompactSaplingOutput,
    ) -> Option<Note>;
}

/// A [`NoteDecryptor`] that always returns `None`.
///
/// Used as a placeholder until the ZIP-32 IVK implementation (nie-m91) is
/// available.  The scanner advances the scan tip but discovers no notes.
pub struct NullDecryptor;

impl NoteDecryptor for NullDecryptor {
    fn try_decrypt_sapling(
        &self,
        _block_height: u64,
        _block_time: u32,
        _txid: &[u8],
        _output_index: usize,
        _output: &CompactSaplingOutput,
    ) -> Option<Note> {
        None
    }
}

/// A [`NoteDecryptor`] that trial-decrypts Sapling compact outputs using a
/// Sapling incoming viewing key (IVK).
///
/// Constructed from the raw 32-byte IVK scalar bytes via [`new`].  Stores the
/// validated scalar bytes in a `Zeroizing` wrapper and reconstructs a fresh
/// `SaplingIvk` on each `try_decrypt_sapling` call.
///
/// # Key material
///
/// This struct holds the IVK, which is key material.  It deliberately does
/// not implement `Debug` — see CLAUDE.md §Wallet Security.
///
/// The IVK bytes are zeroized on drop via `zeroize::Zeroizing`.
///
/// [`new`]: SaplingIvkDecryptor::new
pub struct SaplingIvkDecryptor {
    /// Raw 32-byte little-endian scalar representation of the Sapling IVK.
    /// Stored as `Zeroizing` so the bytes are overwritten on drop.
    ivk_bytes: zeroize::Zeroizing<[u8; 32]>,
}

impl SaplingIvkDecryptor {
    /// Create a new decryptor from a raw 32-byte Sapling IVK scalar.
    ///
    /// `ivk_bytes` must be a canonically-encoded `jubjub::Fr` scalar (little-endian).
    /// Returns `None` if the bytes do not represent a valid scalar (out-of-range).
    pub fn new(ivk_bytes: &[u8; 32]) -> Option<Self> {
        // Validate that the bytes encode a canonical jubjub::Fr scalar before storing.
        // jubjub::Fr::from_repr returns CtOption<Fr>; into() converts to Option.
        let fr: Option<jubjub::Fr> = jubjub::Fr::from_repr(*ivk_bytes).into();
        fr.map(|_| Self {
            ivk_bytes: zeroize::Zeroizing::new(*ivk_bytes),
        })
    }
}

impl NoteDecryptor for SaplingIvkDecryptor {
    /// Attempt to decrypt one Sapling compact output.
    ///
    /// Returns `None` on any input validation failure or decryption failure.
    /// Never panics.
    fn try_decrypt_sapling(
        &self,
        block_height: u64,
        block_time: u32,
        txid: &[u8],
        output_index: usize,
        output: &CompactSaplingOutput,
    ) -> Option<Note> {
        // Validate lengths before any array cast.
        if output.cmu.len() != 32 {
            return None;
        }
        if output.ephemeral_key.len() != 32 {
            return None;
        }
        if output.ciphertext.len() != COMPACT_NOTE_SIZE {
            return None;
        }
        if txid.len() != 32 {
            return None;
        }

        // Build the adapter.  The array casts are guaranteed by the length
        // checks above; the expect() calls are unreachable by construction.
        let adapter = CompactOutputAdapter {
            ephemeral_key: output
                .ephemeral_key
                .as_slice()
                .try_into()
                .expect("ephemeral_key length checked to be 32"),
            cmu: output
                .cmu
                .as_slice()
                .try_into()
                .expect("cmu length checked to be 32"),
            enc_ciphertext: output
                .ciphertext
                .as_slice()
                .try_into()
                .expect("ciphertext length checked to be COMPACT_NOTE_SIZE (52)"),
        };

        // Reconstruct the SaplingIvk from the stored bytes on each call.
        // The bytes were validated as a canonical jubjub::Fr in new(), so this
        // conversion is infallible; the expect() is unreachable by construction.
        let fr: jubjub::Fr = jubjub::Fr::from_repr(*self.ivk_bytes)
            .into_option()
            .expect("ivk_bytes validated as canonical Fr in SaplingIvkDecryptor::new");
        let ivk = SaplingIvk(fr);
        let prepared_ivk = PreparedIncomingViewingKey::new(&ivk);

        // Trial decryption.  GracePeriod accepts both pre-ZIP-212 (lead byte 0x01)
        // and post-ZIP-212 (lead byte 0x02) note formats, so the scanner works
        // correctly whether scanning old or new blocks.
        let (sapling_note, recipient) = try_sapling_compact_note_decryption(
            &prepared_ivk,
            &adapter,
            Zip212Enforcement::GracePeriod,
        )?;

        // Txid canonical form: hex of the 32-byte hash with bytes reversed
        // (little-endian on-wire to big-endian display convention).
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(txid);
        txid_bytes.reverse();
        let txid_hex: String = txid_bytes.iter().map(|b| format!("{b:02x}")).collect();

        // Extract diversifier and pk_d from the recipient PaymentAddress.
        // PaymentAddress::to_bytes() returns [d(11) | pk_d(32)].
        let addr_bytes = recipient.to_bytes();
        let note_diversifier: Vec<u8> = addr_bytes[..11].to_vec();
        let note_pk_d: Vec<u8> = addr_bytes[11..].to_vec();

        // Extract rseed bytes and ZIP-212 flag.
        let (note_rseed, rseed_after_zip212) = match sapling_note.rseed() {
            Rseed::BeforeZip212(fr) => (fr.to_repr().to_vec(), false),
            Rseed::AfterZip212(bytes) => (bytes.to_vec(), true),
        };

        Some(Note {
            txid: txid_hex,
            output_index: i64::try_from(output_index).ok()?,
            value_zatoshi: sapling_note.value().inner(),
            memo: None, // compact outputs do not carry the memo field
            block_height,
            created_at: i64::from(block_time),
            note_diversifier: Some(note_diversifier),
            note_pk_d: Some(note_pk_d),
            note_rseed: Some(note_rseed),
            rseed_after_zip212: Some(rseed_after_zip212),
        })
    }
}

/// Scans compact blocks from a lightwalletd endpoint and persists discovered
/// notes to the [`WalletStore`].
///
/// Construct with [`CompactBlockScanner::new`], then call [`scan_to_tip`] in a
/// loop (or use [`spawn_scanner`] to run it as a background tokio task).
///
/// [`scan_to_tip`]: CompactBlockScanner::scan_to_tip
pub struct CompactBlockScanner {
    client: LightwalletdClient,
    store: WalletStore,
    decryptor: Box<dyn NoteDecryptor>,
    /// Set to `true` after the birthday-height warning has been emitted once.
    /// Prevents the warning from repeating every poll cycle when the chain tip
    /// is temporarily unavailable and scan_tip stays at 0.
    birthday_warned: bool,
    /// Incremental Sapling commitment tree.  Maintained by appending every
    /// Sapling output's `cmu` value as a leaf, in chain order.  Persisted to
    /// `scan_state.tree_state` after each block so restarts are O(1) rather
    /// than requiring a full chain replay.
    tree: CommitmentTree<sapling::Node, 32>,
    /// Per-note incremental witnesses, keyed by `note_id`.  Each witness is
    /// forked from `tree` at the moment the note's commitment is appended, then
    /// updated with every subsequent commitment.  Required by the transaction
    /// builder to produce Merkle inclusion proofs.
    witnesses: HashMap<i64, IncrementalWitness<sapling::Node, 32>>,
}

impl CompactBlockScanner {
    /// Create a new scanner.
    ///
    /// `decryptor` is called for each Sapling output in each scanned block.
    /// Pass [`NullDecryptor`] if no IVK is available yet.
    pub fn new(
        client: LightwalletdClient,
        store: WalletStore,
        decryptor: Box<dyn NoteDecryptor>,
    ) -> Self {
        Self {
            client,
            store,
            decryptor,
            birthday_warned: false,
            tree: CommitmentTree::empty(),
            witnesses: HashMap::new(),
        }
    }

    /// Restore `tree` and `witnesses` from DB.
    ///
    /// Must be called before [`scan_to_tip`] on an existing wallet so the
    /// scanner continues from the persisted tree state rather than an empty one.
    /// A brand-new wallet has no snapshot; in that case the empty tree set in
    /// [`new`] is correct and this is a no-op.
    ///
    /// Returns `Err` if the DB contains a commitment tree snapshot that cannot
    /// be deserialized.  Loading witnesses against an empty tree (due to a
    /// silent fallback) would silently produce invalid Merkle proofs, making
    /// notes permanently unspendable.  An explicit error forces the operator to
    /// rescan from a valid checkpoint rather than proceeding with corrupt state.
    ///
    /// Witness deserialization errors are logged and that witness is dropped —
    /// the scanner prefers to continue without a corrupted witness rather than
    /// refusing to start.  The affected note will be unspendable until the
    /// witness is rebuilt by a rescan.
    ///
    /// [`scan_to_tip`]: CompactBlockScanner::scan_to_tip
    /// [`new`]: CompactBlockScanner::new
    pub async fn load_state(&mut self) -> Result<()> {
        // Load global tree snapshot.
        match self.store.load_tree_state().await? {
            Some(bytes) => {
                match read_commitment_tree::<sapling::Node, _, 32>(Cursor::new(&bytes)) {
                    Ok(t) => self.tree = t,
                    Err(e) => {
                        // The DB contains a tree snapshot but it cannot be
                        // deserialized.  Do NOT fall back to an empty tree:
                        // loading witnesses against the wrong tree produces
                        // silently invalid Merkle proofs that make every
                        // already-scanned note permanently unspendable.
                        // Return Err so the caller can halt and the operator
                        // can rescan from a valid checkpoint.
                        return Err(anyhow::anyhow!(
                            "scanner: commitment tree in DB is corrupt and cannot be deserialized ({e}); \
                             rescan required — do not scan with mismatched witnesses"
                        ));
                    }
                }
            }
            None => {
                // Fresh wallet: empty tree is already set in new().
            }
        }

        // Load per-note witnesses for all unspent notes that have a witness row.
        // spendable_notes() returns Ok(vec![]) on an empty or new wallet — it does
        // not return Err in the normal "no notes yet" case.  Any Err here is a real
        // DB error (schema mismatch, I/O failure, etc.) and must be propagated.
        let spendable = self.store.spendable_notes(0).await?;
        for sn in spendable {
            match read_incremental_witness::<sapling::Node, _, 32>(Cursor::new(&sn.witness_data)) {
                Ok(w) => {
                    self.witnesses.insert(sn.note_id, w);
                }
                Err(e) => {
                    warn!(
                        note_id = sn.note_id,
                        "scanner: failed to deserialize witness ({e}); note will be unspendable until rescan"
                    );
                }
            }
        }

        Ok(())
    }

    /// Scan from `scan_tip + 1` to the current chain tip.
    ///
    /// Returns the number of blocks processed.  Returns `Ok(0)` if the wallet
    /// is already at the chain tip.
    ///
    /// The scan tip is advanced one block at a time, so a mid-scan crash will
    /// resume from the last committed block rather than re-scanning from the
    /// start.
    pub async fn scan_to_tip(&mut self) -> Result<u64> {
        let scan_tip = self.store.scan_tip().await?;
        if scan_tip == 0 && !self.birthday_warned {
            // A tip of 0 means no birthday height was set.  The scanner will
            // start from block 1, which downloads the entire chain history —
            // ~2.2 M blocks on mainnet, taking hours.  Call
            // WalletStore::set_scan_tip with the wallet's birthday height (the
            // Sapling activation height or the block at which the wallet was
            // created, whichever is later) before starting the scanner.
            warn!("scanner: scan_tip is 0 — scanning from genesis; call set_scan_tip with wallet birthday height to avoid downloading the full chain");
            self.birthday_warned = true;
        }
        let start = scan_tip.checked_add(1).ok_or_else(|| {
            anyhow::anyhow!("scan_tip ({scan_tip}) is u64::MAX; cannot advance scanner")
        })?;
        let end = self.client.latest_height().await?;
        if start > end {
            // Already at (or ahead of) chain tip.
            return Ok(0);
        }
        let mut stream = self.client.get_block_range(start, end).await?;
        let mut scanned = 0u64;
        let mut prev_height: Option<u64> = None;
        while let Some(block) = stream.message().await? {
            // Verify strict height monotonicity before touching the commitment tree.
            // The Sapling incremental commitment tree relies on commitments being
            // appended in strictly ascending block order; an out-of-order or
            // repeated block would corrupt the tree and all witnesses silently.
            check_block_height_monotonic(block.height, prev_height, start, scan_tip)?;
            prev_height = Some(block.height);
            self.scan_block(&block).await?;
            scanned += 1;
        }
        Ok(scanned)
    }

    /// Process a single compact block: trial-decrypt outputs, then advance tip.
    ///
    /// The tip is advanced only after all transactions in the block have been
    /// processed so a partial failure is recoverable by re-scanning the block.
    async fn scan_block(&mut self, block: &CompactBlock) -> Result<()> {
        // Snapshot in-memory state before mutating it.  If save_block_state
        // fails below we restore from these snapshots so the next invocation
        // of scan_to_tip replays the same block against a consistent tree.
        let tree_snapshot = self.tree.clone();
        let witnesses_snapshot = self.witnesses.clone();

        for tx in &block.vtx {
            if let Err(e) = self.scan_tx(block.height, block.time, tx).await {
                self.tree = tree_snapshot;
                self.witnesses = witnesses_snapshot;
                return Err(anyhow::anyhow!(
                    "scan_tx failed at height {}: {e}",
                    block.height
                ));
            }
        }

        // Serialize the updated commitment tree.
        let mut tree_bytes = Vec::new();
        write_commitment_tree(&self.tree, &mut tree_bytes)
            .map_err(|e| anyhow::anyhow!("tree serialize failed: {e}"))?;

        // Convert block height once for SQLite (i64).
        let block_height_i64 = i64::try_from(block.height).map_err(|_| {
            anyhow::anyhow!(
                "block height {} exceeds i64::MAX; cannot store in SQLite",
                block.height
            )
        })?;

        // Serialize all witnesses.
        let mut witness_rows: Vec<(i64, i64, Vec<u8>)> = Vec::new();
        for (note_id, witness) in &self.witnesses {
            let mut wbytes = Vec::new();
            write_incremental_witness(witness, &mut wbytes)
                .map_err(|e| anyhow::anyhow!("witness serialize failed for note {note_id}: {e}"))?;
            witness_rows.push((*note_id, block_height_i64, wbytes));
        }

        // Persist tree_state, all witnesses, and the new scan tip atomically.
        // A crash between any two of these writes would leave the DB inconsistent
        // (tip advanced but witnesses missing, or witnesses written but tip not).
        // save_block_state wraps all three in a single SQLite transaction.
        if let Err(e) = self
            .store
            .save_block_state(&tree_bytes, &witness_rows, block_height_i64)
            .await
        {
            // Restore in-memory state to the pre-block snapshot so the next
            // scan_to_tip invocation replays this block against a consistent
            // tree rather than double-counting its commitments.
            self.tree = tree_snapshot;
            self.witnesses = witnesses_snapshot;
            return Err(anyhow::anyhow!("scanner: save_block_state failed: {e}"));
        }

        Ok(())
    }

    /// Trial-decrypt all Sapling outputs in one transaction.
    ///
    /// For each output:
    /// 1. Parse the `cmu` into a `sapling::Node`.
    /// 2. Update all existing witnesses with the new commitment.
    /// 3. Append the commitment to the global tree.
    /// 4. Trial-decrypt.  If the output belongs to this wallet, insert the note
    ///    and fork a fresh witness from the current tree state.
    async fn scan_tx(&mut self, block_height: u64, block_time: u32, tx: &CompactTx) -> Result<()> {
        for (idx, output) in tx.outputs.iter().enumerate() {
            // Step 1: Parse cmu into a Node.
            let cmu_bytes: [u8; 32] = output.cmu[..].try_into().map_err(|_| {
                anyhow::anyhow!(
                    "cmu wrong length: {} bytes (expected 32) at height {}",
                    output.cmu.len(),
                    block_height
                )
            })?;
            let node = match sapling::Node::from_bytes(cmu_bytes).into_option() {
                Some(n) => n,
                None => {
                    return Err(anyhow::anyhow!(
                        "scanner: invalid cmu at height {block_height} output {idx}; \
                         cannot skip — would corrupt subsequent witness positions"
                    ));
                }
            };

            // Step 2: Update ALL existing witnesses with this commitment before
            // appending to the global tree.  Order matters: witnesses track nodes
            // that appear after their fork point.
            for (_note_id, witness) in self.witnesses.iter_mut() {
                if witness.append(node).is_err() {
                    return Err(anyhow::anyhow!("Sapling note commitment tree is full"));
                }
            }

            // Step 3: Append to global tree.
            if self.tree.append(node).is_err() {
                return Err(anyhow::anyhow!("Sapling note commitment tree is full"));
            }

            // Step 4: Trial-decrypt.
            let maybe_note =
                self.decryptor
                    .try_decrypt_sapling(block_height, block_time, &tx.hash, idx, output);
            if let Some(note) = maybe_note {
                // Step 5: Fork a witness from the current tree state before inserting
                // (after the note's commitment is already appended to the tree).
                // from_tree returns None only on an empty tree; we just appended so this
                // is unreachable in practice — logged as a warning and the note is skipped.
                let Some(witness) = IncrementalWitness::from_tree(self.tree.clone()) else {
                    warn!(
                        height = block_height,
                        output_index = idx,
                        "scanner: could not create witness (empty tree — unexpected); skipping note"
                    );
                    continue;
                };
                let mut witness_bytes = Vec::new();
                write_incremental_witness(&witness, &mut witness_bytes)
                    .map_err(|e| anyhow::anyhow!("witness serialize failed: {e}"))?;

                // Atomically insert the note and its witness so the note can never
                // exist without a witness row.  A note without a witness is excluded
                // from spendable_notes() by its INNER JOIN and is permanently unspendable.
                match self
                    .store
                    .insert_note_with_witness(&note, block_height, &witness_bytes)
                    .await
                {
                    Ok(note_id) => {
                        debug!(
                            height = block_height,
                            output_index = idx,
                            "scanner: discovered note"
                        );
                        self.witnesses.insert(note_id, witness);
                    }
                    Err(e) if is_unique_constraint(&e) => {
                        // Already indexed — scanner is re-processing a block after a
                        // restart from a tip earlier than the actual last-scanned height.
                        // Fetch the existing note_id so this note's witness is updated
                        // for subsequent blocks; without this the note is unspendable
                        // after a rescan because its witness never advances.
                        debug!(
                            height = block_height,
                            output_index = idx,
                            "scanner: note already in DB"
                        );
                        match self
                            .store
                            .get_note_id_by_output(&note.txid, note.output_index)
                            .await
                        {
                            Ok(Some(existing_id)) => {
                                self.witnesses.insert(existing_id, witness);
                            }
                            Ok(None) => {
                                warn!(
                                    height = block_height,
                                    output_index = idx,
                                    "scanner: note claimed UNIQUE conflict but not found in DB; skipping witness"
                                );
                            }
                            Err(e) => {
                                return Err(anyhow::anyhow!(
                                    "scanner: get_note_id_by_output failed after UNIQUE conflict: {e}"
                                ));
                            }
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }
}

/// Spawn a background tokio task that calls
/// [`CompactBlockScanner::scan_to_tip`] in a loop.
///
/// `poll_interval` is the sleep duration between scan iterations.  A value
/// of ~75 seconds matches the Zcash target block time.
///
/// Scan errors are logged as warnings; the task continues running rather than
/// panicking — a transient lightwalletd outage should not crash the wallet.
///
/// The returned [`JoinHandle`] can be dropped — the task will keep running.
/// Abort it explicitly to stop scanning.
///
/// [`JoinHandle`]: tokio::task::JoinHandle
pub fn spawn_scanner(
    scanner: CompactBlockScanner,
    poll_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut s = scanner;
        // Restore the Sapling commitment tree and per-note witnesses from the
        // DB before entering the scan loop.  Without this, every wallet restart
        // begins with an empty tree: witnesses built for newly-discovered notes
        // are rooted in that empty tree and are therefore invalid — the notes
        // become permanently unspendable.
        if let Err(e) = s.load_state().await {
            warn!("scanner: load_state failed ({e}); refusing to scan with empty tree — restart required");
            return;
        }
        // Exponential backoff state for error recovery.
        // On success the backoff resets; on error it doubles (capped at 60 s).
        let mut backoff = Duration::from_secs(5);
        const MAX_BACKOFF: Duration = Duration::from_secs(60);

        loop {
            match s.scan_to_tip().await {
                Ok(n) if n > 0 => {
                    debug!("scanner: processed {n} new blocks");
                    backoff = Duration::from_secs(5); // reset on success
                    tokio::time::sleep(poll_interval).await;
                }
                Ok(_) => {
                    tokio::time::sleep(poll_interval).await;
                }
                Err(e) => {
                    warn!("scanner: scan error (will retry after {backoff:?}): {e}");
                    tokio::time::sleep(backoff).await;
                    // Double backoff, cap at MAX_BACKOFF.
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    // Reconnect: drop the broken client and open a fresh connection.
                    let url = s.client.url.clone();
                    match LightwalletdClient::connect(&url).await {
                        Ok(new_client) => {
                            s.client = new_client;
                            debug!("scanner: reconnected to {url}");
                        }
                        Err(ce) => {
                            warn!("scanner: reconnect to {url} failed ({ce}); will retry");
                        }
                    }
                }
            }
        }
    })
}

/// Verify that `block_height` is the next expected height in the scan stream.
///
/// Returns `Ok(())` when the height is correct.  Returns `Err` with a
/// descriptive message when the stream delivers a block out of order or
/// repeats a height — both of which would silently corrupt the Sapling
/// incremental commitment tree if processed.
///
/// # Parameters
/// - `block_height`: the height reported by the block just received.
/// - `prev_height`: the height of the previously-processed block, or `None`
///   if this is the first block in the current stream.
/// - `expected_start`: the height that the first block must have
///   (`scan_tip + 1` at the call site).
/// - `scan_tip`: the stored scan tip, included in the error message for
///   context.
fn check_block_height_monotonic(
    block_height: u64,
    prev_height: Option<u64>,
    expected_start: u64,
    scan_tip: u64,
) -> Result<()> {
    let expected = match prev_height {
        None => expected_start,
        Some(h) => h + 1,
    };
    if block_height != expected {
        return Err(anyhow::anyhow!(
            "scanner: block height out of order from lightwalletd: \
             expected {expected}, got {block_height} (scan_tip={scan_tip})"
        ));
    }
    Ok(())
}

/// Returns `true` if `e` is a SQLite UNIQUE constraint violation.
///
/// Used to treat duplicate note inserts as idempotent rather than errors.
/// The scanner may re-process blocks after a restart if the stored scan tip
/// is stale.
fn is_unique_constraint(e: &anyhow::Error) -> bool {
    if let Some(sqlx::Error::Database(db_err)) = e.downcast_ref::<sqlx::Error>() {
        return db_err.is_unique_violation();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Test 1: txid_canonical_form ----
    //
    // The txid displayed to users and stored in the DB is computed from
    // CompactTx.hash (32 bytes, little-endian) by reversing the bytes and
    // hex-encoding the result.  This is the standard Zcash/Bitcoin txid
    // display convention.
    //
    // Oracle: manual computation.
    // Input: hash bytes [0x01, 0x02, ..., 0x20] (bytes 1 through 32 in order).
    // Reversed: [0x20, 0x1f, ..., 0x01].
    // Hex: "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"
    //
    // This helper mirrors what the SaplingIvkDecryptor implementation must do
    // when converting the raw tx.hash blob from the proto into a human-readable
    // txid for storage in the notes table.
    fn txid_from_hash(hash: &[u8]) -> String {
        let mut reversed = hash.to_vec();
        reversed.reverse();
        reversed.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn txid_canonical_form() {
        // Input: bytes 0x01 through 0x20 in order.
        let hash: Vec<u8> = (0x01u8..=0x20u8).collect();
        assert_eq!(hash.len(), 32);

        // Oracle: reverse then hex-encode.
        // Reversed = [0x20, 0x1f, 0x1e, ..., 0x02, 0x01].
        let expected = "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201";

        let got = txid_from_hash(&hash);
        assert_eq!(
            got, expected,
            "txid must be reverse-byte-order hex of CompactTx.hash"
        );
    }

    // ---- Test 2: note_struct_has_plaintext_fields ----
    //
    // The SpendableNote struct carries the three plaintext columns
    // (note_diversifier, note_pk_d, note_rseed) plus the rseed_after_zip212 flag.
    // These are written by the scanner after IVK decryption.
    //
    // This is a compile-time test: if any field is missing the test will fail
    // to compile rather than fail at runtime.
    //
    // Note: the Note struct (returned by unspent_notes) does NOT have these
    // fields — they live on SpendableNote, which is returned by spendable_notes().
    // The scanner's IVK decryptor writes them via insert_spendable_note().
    #[test]
    fn spendable_note_has_plaintext_fields() {
        use crate::db::SpendableNote;

        // Construct a SpendableNote with all plaintext fields set.
        // This is a compile-time check: if any field is removed or renamed,
        // this test will fail to compile.
        let _note = SpendableNote {
            note_id: 1,
            value_zatoshi: 100_000_000,
            note_diversifier: vec![0x01u8; 11],
            note_pk_d: vec![0x02u8; 32],
            note_rseed: vec![0x03u8; 32],
            rseed_after_zip212: true,
            block_height: 1_000_000,
            witness_data: vec![0xffu8; 64],
        };

        assert_eq!(
            _note.note_diversifier.len(),
            11,
            "diversifier must be 11 bytes"
        );
        assert_eq!(_note.note_pk_d.len(), 32, "pk_d must be 32 bytes");
        assert_eq!(_note.note_rseed.len(), 32, "rseed must be 32 bytes");
        assert!(
            _note.rseed_after_zip212,
            "rseed_after_zip212 flag must round-trip"
        );
    }

    // ---- Test 5: insert_note_stores_plaintext (integration) ----
    //
    // Verifies that plaintext columns (note_diversifier, note_pk_d, note_rseed,
    // note_rseed_after_zip212) are durably stored and retrieved correctly.
    //
    // Uses insert_spendable_note (the write path the scanner will use after IVK
    // decryption) and spendable_notes (the read path) to verify round-trip
    // correctness without using one as the oracle for the other.
    //
    // Oracle: the bytes inserted are known constants; the bytes retrieved are
    // compared against those same constants, not re-derived from the write path.
    #[tokio::test]
    async fn insert_note_stores_plaintext() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tempfile.path()).await.unwrap();

        // Known plaintext values — the oracle is the constants themselves.
        let diversifier: Vec<u8> = vec![0x01u8; 11]; // 11 bytes
        let pk_d: Vec<u8> = vec![0x02u8; 32]; // 32 bytes
        let rseed: Vec<u8> = vec![0x03u8; 32]; // 32 bytes
        let rseed_after_zip212 = true;
        let value_zatoshi = 500_000u64;
        let block_height = 1_000_000u64;
        let witness_data = vec![0xffu8; 64];

        let note_id = store
            .insert_spendable_note(
                value_zatoshi,
                block_height,
                &diversifier,
                &pk_d,
                &rseed,
                rseed_after_zip212,
                &witness_data,
            )
            .await
            .expect("insert_spendable_note must succeed");
        assert!(note_id > 0, "insert must return a positive note_id");

        // Retrieve via spendable_notes and verify the plaintext columns
        // round-tripped correctly.
        let notes = store
            .spendable_notes(0)
            .await
            .expect("spendable_notes must succeed");
        assert_eq!(notes.len(), 1, "exactly one spendable note must be present");

        let n = &notes[0];
        assert_eq!(n.value_zatoshi, value_zatoshi, "value_zatoshi round-trip");
        assert_eq!(
            n.note_diversifier, diversifier,
            "note_diversifier round-trip: expected {:?}, got {:?}",
            diversifier, n.note_diversifier
        );
        assert_eq!(
            n.note_pk_d, pk_d,
            "note_pk_d round-trip: expected {:?}, got {:?}",
            pk_d, n.note_pk_d
        );
        assert_eq!(
            n.note_rseed, rseed,
            "note_rseed round-trip: expected {:?}, got {:?}",
            rseed, n.note_rseed
        );
        assert_eq!(
            n.rseed_after_zip212, rseed_after_zip212,
            "rseed_after_zip212 round-trip"
        );
        assert_eq!(n.block_height, block_height, "block_height round-trip");
    }

    /// NullDecryptor always returns None for any output.
    ///
    /// Oracle: the return value is constant — NullDecryptor must never
    /// discover notes regardless of the input bytes.
    #[test]
    fn null_decryptor_returns_none() {
        let d = NullDecryptor;
        let output = CompactSaplingOutput {
            cmu: vec![0u8; 32],
            ephemeral_key: vec![0u8; 32],
            ciphertext: vec![0u8; 52],
        };
        assert!(
            d.try_decrypt_sapling(1_000_000, 1_700_000_000, b"txid", 0, &output)
                .is_none(),
            "NullDecryptor must always return None"
        );
    }

    /// is_unique_constraint returns true for a real SQLite UNIQUE violation.
    ///
    /// Oracle: the error is produced by a real duplicate INSERT into a
    /// temporary SQLite database — not fabricated from a string.  The second
    /// INSERT must fail, and the resulting sqlx::Error must be classified as a
    /// UNIQUE constraint violation by sqlx's is_unique_violation() method.
    #[tokio::test]
    async fn unique_constraint_from_real_insert() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tempfile.path()).await.unwrap();

        let note = Note {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            output_index: 0,
            value_zatoshi: 100_000,
            memo: None,
            block_height: 1_000_000,
            created_at: 1_000_000_000,
            note_diversifier: None,
            note_pk_d: None,
            note_rseed: None,
            rseed_after_zip212: None,
        };

        store
            .insert_note(&note)
            .await
            .expect("first insert must succeed");

        let err = store
            .insert_note(&note)
            .await
            .expect_err("duplicate insert must fail");

        assert!(
            is_unique_constraint(&err),
            "error from duplicate insert must be classified as UNIQUE constraint violation"
        );
    }

    /// is_unique_constraint returns false for non-UNIQUE errors.
    ///
    /// Oracle: plain anyhow errors do not downcast to sqlx::Error, so the
    /// function must return false regardless of the message text.
    #[test]
    fn non_unique_error_returns_false() {
        assert!(!is_unique_constraint(&anyhow::anyhow!("disk full")));
        assert!(!is_unique_constraint(&anyhow::anyhow!(
            "foreign key constraint failed"
        )));
    }

    /// Commitment tree serialization round-trips correctly.
    ///
    /// Oracle: write then read with the same library functions.  This is a
    /// roundtrip test — acceptable here because the invariant under test is
    /// "our serialization wrapper does not truncate or corrupt bytes", not
    /// "the tree algorithm is correct".  The tree algorithm is tested by
    /// zcash_primitives' own test suite.
    #[test]
    fn tree_roundtrip() {
        let mut tree = CommitmentTree::<sapling::Node, 32>::empty();
        let node = Option::from(sapling::Node::from_bytes([0x01; 32])).expect("valid node");
        tree.append(node).expect("append");

        let mut buf = Vec::new();
        write_commitment_tree(&tree, &mut buf).expect("serialize tree");

        let restored = read_commitment_tree::<sapling::Node, _, 32>(Cursor::new(&buf))
            .expect("deserialize tree");

        // Re-serialize and compare bytes — two trees that hold the same leaves
        // produce identical serializations.
        let mut buf2 = Vec::new();
        write_commitment_tree(&restored, &mut buf2).expect("re-serialize tree");
        assert_eq!(buf, buf2, "tree round-trip must be byte-identical");
    }

    /// Witness serialization round-trips correctly.
    ///
    /// Oracle: same rationale as `tree_roundtrip` — testing our wrapper, not
    /// the witness algorithm.
    #[test]
    fn witness_roundtrip() {
        let mut tree = CommitmentTree::<sapling::Node, 32>::empty();
        let node = Option::from(sapling::Node::from_bytes([0x02; 32])).expect("valid node");
        tree.append(node).expect("append");
        let witness = IncrementalWitness::from_tree(tree).expect("non-empty tree");

        let mut buf = Vec::new();
        write_incremental_witness(&witness, &mut buf).expect("serialize witness");

        let restored = read_incremental_witness::<sapling::Node, _, 32>(Cursor::new(&buf))
            .expect("deserialize witness");

        let mut buf2 = Vec::new();
        write_incremental_witness(&restored, &mut buf2).expect("re-serialize witness");
        assert_eq!(buf, buf2, "witness round-trip must be byte-identical");
    }

    /// Node::from_bytes accepts a 32-byte all-zero input without returning None.
    ///
    /// Oracle: the all-zero value is a valid (though non-canonical) node for
    /// the Sapling tree; any valid 32-byte input parses.  This confirms our
    /// `into_option()` conversion path works.
    #[test]
    fn node_from_bytes_parses() {
        // Option::from on CtOption<T> is unambiguous when the result type is named.
        let node: Option<sapling::Node> = Option::from(sapling::Node::from_bytes([0u8; 32]));
        assert!(node.is_some(), "all-zero cmu must parse as a valid Node");
    }

    // ---- Tests for check_block_height_monotonic ----
    //
    // Oracle: the expected height is derived by hand from the inputs — not
    // from the function under test.  Each case names the property being
    // checked so failures are self-diagnosing.

    /// First block with the correct starting height is accepted.
    ///
    /// Oracle: prev_height=None, expected_start=1_000_000, block_height=1_000_000
    /// → expected=1_000_000 == block_height → Ok.
    #[test]
    fn monotonic_first_block_correct_height_is_ok() {
        assert!(
            check_block_height_monotonic(1_000_000, None, 1_000_000, 999_999).is_ok(),
            "first block at the expected start height must be accepted"
        );
    }

    /// First block at the wrong height returns Err.
    ///
    /// Oracle: prev_height=None, expected_start=1_000_000, block_height=999_999
    /// → expected=1_000_000 != 999_999 → Err.
    #[test]
    fn monotonic_first_block_wrong_height_is_err() {
        assert!(
            check_block_height_monotonic(999_999, None, 1_000_000, 999_998).is_err(),
            "first block at a height below expected_start must be rejected"
        );
    }

    /// Consecutive block after a correct previous height is accepted.
    ///
    /// Oracle: prev_height=Some(1_000_000), block_height=1_000_001
    /// → expected=1_000_001 == block_height → Ok.
    #[test]
    fn monotonic_consecutive_block_is_ok() {
        assert!(
            check_block_height_monotonic(1_000_001, Some(1_000_000), 1_000_000, 999_999).is_ok(),
            "block at prev+1 must be accepted"
        );
    }

    /// Repeated height (duplicate block) returns Err.
    ///
    /// Oracle: prev_height=Some(1_000_000), block_height=1_000_000
    /// → expected=1_000_001 != 1_000_000 → Err.
    #[test]
    fn monotonic_repeated_height_is_err() {
        assert!(
            check_block_height_monotonic(1_000_000, Some(1_000_000), 999_999, 999_998).is_err(),
            "repeated block height must be rejected"
        );
    }

    /// Skipped height (gap in sequence) returns Err.
    ///
    /// Oracle: prev_height=Some(1_000_000), block_height=1_000_002
    /// → expected=1_000_001 != 1_000_002 → Err.
    #[test]
    fn monotonic_skipped_height_is_err() {
        assert!(
            check_block_height_monotonic(1_000_002, Some(1_000_000), 999_999, 999_998).is_err(),
            "skipped block height must be rejected"
        );
    }

    /// Backward step (earlier height than previous) returns Err.
    ///
    /// Oracle: prev_height=Some(1_000_005), block_height=1_000_003
    /// → expected=1_000_006 != 1_000_003 → Err.
    #[test]
    fn monotonic_backward_step_is_err() {
        assert!(
            check_block_height_monotonic(1_000_003, Some(1_000_005), 999_999, 999_998).is_err(),
            "out-of-order (backward) block height must be rejected"
        );
    }
}
