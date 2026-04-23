use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use rand::rngs::OsRng;
use rand::RngCore;

use dashmap::DashMap;
use tokio::sync::mpsc;

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
                rate_limit_per_min,
                pow_server_salt: {
                    let mut salt = [0u8; 32];
                    OsRng.fill_bytes(&mut salt);
                    salt
                },
                pow_difficulty: AtomicU8::new(0),
                pow_replay_set: dashmap::DashMap::new(),
                bus: MessageBus::local(),
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
    /// Returns the sequence number assigned to this connection.
    pub fn connect(&self, pub_id: &PubId, tx: ClientTx) -> u64 {
        let seq = self
            .inner
            .connection_counter
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .clients
            .entry(pub_id.0.clone())
            .or_default()
            .push((tx, seq));
        seq
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
    /// - If the client is offline (no channels succeed), enqueues via `store.enqueue()`.
    ///
    /// Never holds the DashMap lock across an await point.
    pub async fn broadcast_to_group(&self, members: &[String], exclude: Option<&str>, msg: String) {
        // Collect live channels without holding the lock across awaits.
        let channels: Vec<(String, ClientTx)> = self
            .inner
            .clients
            .iter()
            .flat_map(|entry| {
                let pub_id = entry.key().clone();
                if members.contains(&pub_id) && exclude.is_none_or(|ex| pub_id != ex) {
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
        let mut delivered: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (pub_id, tx) in channels {
            if tx.send(msg.clone()).await.is_ok() {
                delivered.insert(pub_id);
            }
        }

        // Enqueue for offline members.
        for member in members {
            if exclude.is_none_or(|ex| member != ex) && !delivered.contains(member) {
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
    /// Capped at 30 to prevent impossible challenges.
    pub fn set_pow_difficulty(&self, d: u8) {
        self.inner
            .pow_difficulty
            .store(d.min(30), Ordering::Relaxed);
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

        state.connect(&pub_id, tx1);
        state.connect(&pub_id, tx2);

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

        let seq1 = state.connect(&pub_id, tx1);
        let _seq2 = state.connect(&pub_id, tx2);

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

        let seq1 = state.connect(&pub_id, tx1);
        let seq2 = state.connect(&pub_id, tx2);

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

        let seq1 = state.connect(&pub_id, tx1);
        let seq2 = state.connect(&pub_id, tx2);

        state.disconnect(&pub_id, seq1);
        assert!(state.inner.clients.contains_key("dddd"), "key still present after first disconnect");

        state.disconnect(&pub_id, seq2);
        assert!(!state.inner.clients.contains_key("dddd"), "key removed after last disconnect");
    }
}
