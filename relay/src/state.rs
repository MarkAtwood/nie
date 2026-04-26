use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use rand::rngs::OsRng;
use rand::RngCore;

use dashmap::DashMap;
use tokio::sync::{mpsc, Mutex};

use nie_core::identity::PubId;
use nie_wallet::address::{SaplingDiversifiableFvk, ZcashNetwork};

use crate::bus::{BusMessage, MessageBus};
use crate::store::Store;

/// Channel to push pre-serialized JSON-RPC messages into a connected client.
pub type ClientTx = mpsc::Sender<String>;

/// Merchant wallet configuration loaded from env at startup.
///
/// Holds only a diversifiable full viewing key (DFVK) — never a spending key.
/// The relay uses this to derive fresh Sapling payment addresses for subscription
/// invoices.  It cannot spend funds.
pub struct MerchantWallet {
    pub dfvk: SaplingDiversifiableFvk,
    pub network: ZcashNetwork,
}

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<Inner>,
}

pub struct Inner {
    /// Live connections: pub_id → list of (sender channel, connection sequence number).
    /// A single pub_id may have multiple simultaneous connections.
    /// Sequence numbers are assigned monotonically on each connect; the connection
    /// with the lowest sequence is the session admin (first connected this run).
    /// DashMap does not preserve insertion order, so callers that need admin
    /// ordering must sort by sequence number explicitly.
    pub clients: DashMap<String, Vec<(ClientTx, u64)>>,
    /// Monotonically increasing connection counter. Incremented on each connect.
    pub connection_counter: AtomicU64,
    pub store: Store,
    /// How often (seconds) to send a WebSocket Ping to each client.
    pub keepalive_secs: u64,
    /// If true, clients without an active subscription cannot send Broadcast messages.
    pub require_subscription: bool,
    /// Subscription price in zatoshi (1 ZEC = 100_000_000 zatoshi).
    /// Default: 1_000_000 zatoshi (0.01 ZEC).
    pub subscription_price_zatoshi: u64,
    /// How many days a paid subscription lasts. Default: 30.
    pub subscription_days: u64,
    /// Merchant DFVK loaded from MERCHANT_DFVK env var.  Absent when the env
    /// var is not set; relay operates without payment gating in that case.
    merchant: OnceLock<MerchantWallet>,
    /// Per-pub_id broadcast rate limit counters: (message_count, window_start).
    /// Key: pub_id. Value: (count in current window, when window started).
    pub rate_limits: dashmap::DashMap<String, (u32, Instant)>,
    /// Per-pub_id SET_NICKNAME rate limit: records when the identity last changed
    /// its nickname, enforcing the 5-second cooldown across all connections from
    /// the same pub_id.  Keyed by pub_id string.
    pub nickname_rate_limits: dashmap::DashMap<String, Instant>,
    /// Per-pub_id PUBLISH_HPKE_KEY rate limit: records when the identity last
    /// published an HPKE key, enforcing a 5-second cooldown.  Prevents a caller
    /// from rapidly overwriting their own key (which would silently discard any
    /// sealed messages in flight encrypted to the previous key).
    pub hpke_key_rate_limits: dashmap::DashMap<String, Instant>,
    /// Max broadcasts per 60-second window per pub_id. 0 = unlimited.
    pub rate_limit_per_min: u32,
    /// Random 32-byte salt generated at startup.  Never persisted, never logged.
    /// Invalidated on restart (stale tokens become unreplayable because salt changes).
    pub pow_server_salt: [u8; 32],
    /// Required leading zero bits for PoW enrollment.  0 = disabled.
    /// Atomically readable; updated at startup and (optionally) at runtime.
    pub pow_difficulty: AtomicU8,
    /// In-memory replay set: h16 → time-of-acceptance.
    /// Entries older than STALENESS_WINDOW_SECS (600s) are lazily evicted.
    pub pow_replay_set: dashmap::DashMap<[u8; 16], Instant>,
    /// Cross-instance message bus for horizontal scaling.
    /// `LocalBus` (default) is a no-op for single-process deployments.
    /// Swap for `RedisBus` to enable multi-instance delivery.
    pub bus: MessageBus,
    /// Serializes subscription address allocation across concurrent requests.
    ///
    /// `alloc_subscription_address` does next_diversifier → find_address →
    /// advance_diversifier_to.  Two concurrent callers can receive the same
    /// `start` value from `next_diversifier` if `find_address` on either side
    /// skips ahead past the other's starting point, producing a duplicate
    /// Sapling address.  This mutex prevents that race by making the whole
    /// sequence atomic within a single process.
    pub subscription_alloc_lock: Mutex<()>,
}

impl AppState {
    pub async fn new(
        db_url: &str,
        keepalive_secs: u64,
        require_subscription: bool,
        subscription_price_zatoshi: u64,
        subscription_days: u64,
        rate_limit_per_min: u32,
    ) -> anyhow::Result<Self> {
        let store = Store::new(db_url).await?;
        Ok(Self {
            inner: Arc::new(Inner {
                clients: DashMap::new(),
                connection_counter: AtomicU64::new(0),
                store,
                keepalive_secs,
                require_subscription,
                subscription_price_zatoshi,
                subscription_days,
                merchant: OnceLock::new(),
                rate_limits: dashmap::DashMap::new(),
                nickname_rate_limits: dashmap::DashMap::new(),
                hpke_key_rate_limits: dashmap::DashMap::new(),
                rate_limit_per_min,
                pow_server_salt: {
                    let mut salt = [0u8; 32];
                    OsRng.fill_bytes(&mut salt);
                    salt
                },
                pow_difficulty: AtomicU8::new(0),
                pow_replay_set: dashmap::DashMap::new(),
                bus: MessageBus::local(),
                subscription_alloc_lock: Mutex::new(()),
            }),
        })
    }

    /// Store the merchant wallet.  May only be called once; subsequent calls are
    /// silently ignored (startup sets it exactly once before serving requests).
    pub fn set_merchant(&self, wallet: MerchantWallet) {
        // OnceLock::set returns Err if already set; we discard the error
        // because set_merchant is called exactly once at startup.
        let _ = self.inner.merchant.set(wallet);
    }

    /// Return a reference to the merchant wallet, or `None` if not configured.
    pub fn merchant(&self) -> Option<&MerchantWallet> {
        self.inner.merchant.get()
    }

    /// Register a new connection. Assigns a monotonically increasing sequence
    /// number so the DirectoryList can be ordered by session connection order.
    /// Returns `(seq, is_first)`:
    /// - `seq`: the sequence number assigned to this connection.
    /// - `is_first`: true if this is the first active connection for `pub_id`
    ///   (i.e., the pub_id transitioned from 0 to 1 connected devices).
    pub fn connect(&self, pub_id: &PubId, tx: ClientTx) -> (u64, bool) {
        let seq = self
            .inner
            .connection_counter
            .fetch_add(1, Ordering::Relaxed);
        let mut entry = self.inner.clients.entry(pub_id.0.clone()).or_default();
        entry.push((tx, seq));
        let is_first = entry.len() == 1;
        (seq, is_first)
    }

    /// Remove the specific connection identified by `seq` for `pub_id`.
    /// If this was the last connection for that pub_id, also clears rate limit state.
    pub fn disconnect(&self, pub_id: &PubId, seq: u64) {
        let remove_key = {
            let mut entry = match self.inner.clients.get_mut(&pub_id.0) {
                Some(e) => e,
                None => return,
            };
            entry.retain(|(_, s)| *s != seq);
            entry.is_empty()
        };
        if remove_key {
            self.inner.clients.remove(&pub_id.0);
            self.inner.rate_limits.remove(&pub_id.0);
            self.inner.nickname_rate_limits.remove(&pub_id.0);
            self.inner.hpke_key_rate_limits.remove(&pub_id.0);
        }
    }

    /// Returns the minimum session connection sequence number for `pub_id`
    /// across all active connections, or `u64::MAX` if not currently connected.
    /// Lower sequence = connected earlier this session.
    pub fn connection_seq(&self, pub_id: &str) -> u64 {
        self.inner
            .clients
            .get(pub_id)
            .map(|e| e.iter().map(|(_, s)| *s).min().unwrap_or(u64::MAX))
            .unwrap_or(u64::MAX)
    }

    /// Attempt live delivery to all connections for a single client.
    /// Returns true if at least one channel accepted the message.
    pub async fn deliver_live(&self, to: &str, msg: String) -> bool {
        let channels: Vec<ClientTx> = match self.inner.clients.get(to) {
            Some(e) => e.iter().map(|(tx, _)| tx.clone()).collect(),
            None => return false,
        };
        let mut any_ok = false;
        for tx in channels {
            if tx.send(msg.clone()).await.is_ok() {
                any_ok = true;
            }
        }
        any_ok
    }

    /// Fan out a message to a specific set of group members.
    ///
    /// For each member in `members` (excluding `exclude`):
    /// - Attempts live delivery via all of the client's sender channels.
    /// - If ANY channel for a pub_id succeeds, that pub_id is marked delivered.
    /// - If the client is offline (no channels succeed), enqueues via `store.enqueue()`
    ///   only if the member is still in the group (checked atomically per recipient
    ///   to prevent delivery after departure when a member leaves between the caller's
    ///   list-fetch and this enqueue).
    ///
    /// `group_id` is used for the departure check.  Pass `None` to skip the check
    /// (e.g. for non-group fan-outs).
    ///
    /// Never holds the DashMap lock across an await point.
    pub async fn broadcast_to_group(
        &self,
        members: &[String],
        exclude: Option<&str>,
        msg: String,
        group_id: Option<&str>,
    ) {
        // O(1) membership test: convert the member list to a HashSet once before
        // iterating over all connected clients.  Without this, `contains` is O(M)
        // per client, giving O(N*M) total work at 10K clients and 100 members.
        let members_set: std::collections::HashSet<&str> =
            members.iter().map(String::as_str).collect();
        // Collect live channels without holding the lock across awaits.
        let channels: Vec<(String, ClientTx)> = self
            .inner
            .clients
            .iter()
            .flat_map(|entry| {
                let pub_id = entry.key().clone();
                if members_set.contains(pub_id.as_str()) && exclude.is_none_or(|ex| pub_id != ex) {
                    entry
                        .value()
                        .iter()
                        .map(|(tx, _)| (pub_id.clone(), tx.clone()))
                        .collect::<Vec<_>>()
                } else {
                    vec![]
                }
            })
            .collect();

        // Drive live deliveries; track which pub_ids had at least one success.
        //
        // GUARD SYMMETRY: both this live-delivery loop and the offline-enqueue
        // loop below re-check group membership (via is_group_member) when
        // group_id is Some.  The two checks are intentionally symmetric so that
        // a member who departs between the caller's list_group_members fetch and
        // this fan-out receives neither a live message nor an offline-queued one.
        // Any future third delivery path added here MUST include the same guard.
        //
        // We memoize the per-pub_id check result so that multiple connections
        // for the same pub_id only hit the DB once.
        let mut membership_cache: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        let mut delivered: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (pub_id, tx) in channels {
            if let Some(gid) = group_id {
                // Memoize: look up or query membership once per pub_id.
                let is_member = if let Some(&cached) = membership_cache.get(&pub_id) {
                    cached
                } else {
                    let result = match self.inner.store.is_group_member(gid, &pub_id).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                "broadcast_to_group: live membership check failed for {pub_id}: {e}"
                            );
                            false
                        }
                    };
                    membership_cache.insert(pub_id.clone(), result);
                    result
                };
                if !is_member {
                    continue;
                }
            }
            if tx.send(msg.clone()).await.is_ok() {
                delivered.insert(pub_id);
            }
        }

        // Enqueue for offline members, with a membership re-check when a group_id
        // is provided to avoid delivering to members who left after the caller
        // fetched the member list.
        for member in members {
            if exclude.is_none_or(|ex| member != ex) && !delivered.contains(member) {
                // Re-verify membership if a group_id was provided.
                // Reuse the membership_cache built in the live loop to avoid a
                // redundant DB query for members who had live connections (nie-qmwv.9).
                if let Some(gid) = group_id {
                    let is_member = if let Some(&cached) = membership_cache.get(member) {
                        cached
                    } else {
                        let result = match self.inner.store.is_group_member(gid, member).await {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(
                                    "broadcast_to_group: is_group_member check failed for {member}: {e}"
                                );
                                false
                            }
                        };
                        membership_cache.insert(member.to_string(), result);
                        result
                    };
                    if !is_member {
                        continue; // departed between list-fetch and enqueue
                    }
                }
                // SECURITY (nie-qgag.13): do not accumulate offline messages for
                // recipients without an active subscription when the relay enforces
                // subscriptions.  An unsubscribed user cannot retrieve queued
                // messages (they are rejected at auth), so enqueuing wastes storage
                // and can be abused to fill the offline queue without limit.
                if self.inner.require_subscription {
                    match self.inner.store.subscription_expiry(member).await {
                        Ok(Some(_)) => {} // active subscription — proceed
                        Ok(None) => {
                            tracing::debug!(
                                "broadcast_to_group: skipping offline enqueue for \
                                 unsubscribed recipient {member}"
                            );
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "broadcast_to_group: subscription check failed for {member}: {e}"
                            );
                            continue;
                        }
                    }
                }
                if let Err(e) = self.inner.store.enqueue(member, &msg).await {
                    tracing::warn!("broadcast_to_group: enqueue failed for {member}: {e}");
                }
            }
        }
    }

    /// Returns the current PoW difficulty (0 = disabled).
    pub fn pow_difficulty(&self) -> u8 {
        self.inner.pow_difficulty.load(Ordering::Relaxed)
    }

    /// Set the PoW difficulty.  0 = disabled; 20 = default.
    /// Capped at MAX_DIFFICULTY (30) to prevent impossible challenges.
    pub fn set_pow_difficulty(&self, d: u8) {
        use nie_core::pow::MAX_DIFFICULTY;
        if d > MAX_DIFFICULTY {
            tracing::warn!(
                "POW_DIFFICULTY {} exceeds MAX_DIFFICULTY {MAX_DIFFICULTY}, \
                 clamping to {MAX_DIFFICULTY}",
                d
            );
        }
        self.inner
            .pow_difficulty
            .store(d.min(MAX_DIFFICULTY), Ordering::Relaxed);
    }

    /// Return a reference to the server PoW salt.
    /// SECURITY: Never log this value.
    pub fn pow_server_salt(&self) -> &[u8; 32] {
        &self.inner.pow_server_salt
    }

    /// Fan `msg` out to every connected client (all connections for every pub_id).
    ///
    /// `exclude`: pass `Some(pub_id)` to skip the sender; pass `None` to
    /// deliver to all clients including the originator.
    ///
    /// Collects all sender channels before awaiting any sends so we hold the
    /// DashMap lock for the minimum time and never await while holding it.
    ///
    /// Sends are driven concurrently via `join_all` so one slow consumer
    /// (full channel) does not delay delivery to other clients.
    pub async fn broadcast(&self, exclude: Option<&str>, msg: String) {
        let targets: Vec<ClientTx> = self
            .inner
            .clients
            .iter()
            .filter(|entry| exclude.is_none_or(|id| entry.key().as_str() != id))
            .flat_map(|entry| {
                entry
                    .value()
                    .iter()
                    .map(|(tx, _)| tx.clone())
                    .collect::<Vec<_>>()
            })
            .collect();

        futures::future::join_all(targets.into_iter().map(|tx| {
            let m = msg.clone();
            async move {
                let _ = tx.send(m).await;
            }
        }))
        .await;

        // Publish to cross-instance bus so other relay instances can deliver locally.
        let bus_msg = BusMessage::Broadcast {
            exclude: exclude.map(str::to_string),
            payload: msg,
        };
        if let Err(e) = self.inner.bus.publish(&bus_msg).await {
            tracing::warn!("bus publish failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    async fn make_state() -> AppState {
        AppState::new("sqlite::memory:", 30, false, 1_000_000, 30, 120)
            .await
            .unwrap()
    }

    fn make_pub_id(hex: &str) -> PubId {
        PubId(hex.to_string())
    }

    #[tokio::test]
    async fn two_connections_same_pub_id_both_receive() {
        let state = make_state().await;
        let pub_id = make_pub_id("aaaa");

        let (tx1, mut rx1) = mpsc::channel::<String>(8);
        let (tx2, mut rx2) = mpsc::channel::<String>(8);

        let (_, is_first1) = state.connect(&pub_id, tx1);
        let (_, is_first2) = state.connect(&pub_id, tx2);
        assert!(is_first1, "first connect must be flagged is_first");
        assert!(!is_first2, "second connect must not be flagged is_first");

        let delivered = state.deliver_live("aaaa", "hello".to_string()).await;
        assert!(delivered);

        let msg1 = rx1.recv().await.expect("rx1 should receive");
        let msg2 = rx2.recv().await.expect("rx2 should receive");
        assert_eq!(msg1, "hello");
        assert_eq!(msg2, "hello");
    }

    #[tokio::test]
    async fn disconnect_one_leaves_other() {
        let state = make_state().await;
        let pub_id = make_pub_id("bbbb");

        let (tx1, rx1) = mpsc::channel::<String>(8);
        let (tx2, mut rx2) = mpsc::channel::<String>(8);

        let (seq1, _) = state.connect(&pub_id, tx1);
        let (_, _) = state.connect(&pub_id, tx2);

        // Disconnect the first connection by its seq.
        state.disconnect(&pub_id, seq1);

        // The pub_id key must still exist (second connection is live).
        assert!(state.inner.clients.contains_key("bbbb"));

        // rx1 channel has no live sender anymore; rx2 still works.
        drop(rx1); // avoid blocking — sender is gone
        let delivered = state.deliver_live("bbbb", "still here".to_string()).await;
        assert!(delivered);
        let msg = rx2.recv().await.expect("rx2 should still receive");
        assert_eq!(msg, "still here");
    }

    #[tokio::test]
    async fn connection_seq_returns_min() {
        let state = make_state().await;
        let pub_id = make_pub_id("cccc");

        let (tx1, _rx1) = mpsc::channel::<String>(8);
        let (tx2, _rx2) = mpsc::channel::<String>(8);

        let (seq1, _) = state.connect(&pub_id, tx1);
        let (seq2, _) = state.connect(&pub_id, tx2);

        let reported = state.connection_seq("cccc");
        assert_eq!(reported, seq1.min(seq2));
        assert!(reported < u64::MAX);
    }

    #[tokio::test]
    async fn last_disconnect_removes_key() {
        let state = make_state().await;
        let pub_id = make_pub_id("dddd");

        let (tx1, _rx1) = mpsc::channel::<String>(8);
        let (tx2, _rx2) = mpsc::channel::<String>(8);

        let (seq1, _) = state.connect(&pub_id, tx1);
        let (seq2, _) = state.connect(&pub_id, tx2);

        state.disconnect(&pub_id, seq1);
        assert!(
            state.inner.clients.contains_key("dddd"),
            "key still present after first disconnect"
        );

        state.disconnect(&pub_id, seq2);
        assert!(
            !state.inner.clients.contains_key("dddd"),
            "key removed after last disconnect"
        );
    }

    /// Admin election is per-user (pub_id), not per-device-connection.
    ///
    /// Scenario:
    ///   - Alice device 1 connects → seq 0 (admin)
    ///   - Bob connects          → seq 1
    ///   - Alice device 2 connects → seq 2
    ///   → Alice's connection_seq = min(0,2) = 0; she is still admin.
    ///
    ///   Then Alice device 1 disconnects:
    ///   → Alice's connection_seq = 2 (only device 2 remains)
    ///   → Bob's seq = 1 < Alice's seq = 2 → Bob becomes admin.
    ///
    /// Oracle: expected seq values are derived from insertion order, not from
    /// any function under test.  Admin election is min(connection_seq) across users.
    #[tokio::test]
    async fn admin_election_uses_per_user_min_seq() {
        let state = make_state().await;
        let alice = make_pub_id("alice");
        let bob = make_pub_id("bob");

        let (tx_a1, _rx_a1) = mpsc::channel::<String>(8);
        let (tx_bob, _rx_bob) = mpsc::channel::<String>(8);
        let (tx_a2, _rx_a2) = mpsc::channel::<String>(8);

        let (seq_a1, _) = state.connect(&alice, tx_a1);
        let (seq_bob, _) = state.connect(&bob, tx_bob);
        let (seq_a2, _) = state.connect(&alice, tx_a2);

        // Ordering must be monotonically increasing.
        assert!(seq_a1 < seq_bob);
        assert!(seq_bob < seq_a2);

        // Alice's per-user seq = min of both her devices = seq_a1.
        assert_eq!(state.connection_seq("alice"), seq_a1);
        // Alice's seq (seq_a1) < Bob's seq (seq_bob) → Alice is admin.
        assert!(state.connection_seq("alice") < state.connection_seq("bob"));

        // Alice's device 1 disconnects.
        state.disconnect(&alice, seq_a1);

        // Alice's per-user seq is now seq_a2 (only device 2 remains).
        assert_eq!(state.connection_seq("alice"), seq_a2);
        // Bob's seq (seq_bob) < Alice's remaining seq (seq_a2) → Bob is now admin.
        assert!(state.connection_seq("bob") < state.connection_seq("alice"));
    }
}
