use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use tokio::sync::mpsc;

use nie_core::identity::PubId;
use nie_wallet::address::{SaplingDiversifiableFvk, ZcashNetwork};

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
    /// Live connections: pub_id → (sender channel, connection sequence number).
    /// Sequence number is assigned monotonically on each connect; the client
    /// with the lowest sequence is the session admin (first connected this run).
    /// DashMap does not preserve insertion order, so callers that need admin
    /// ordering must sort by sequence number explicitly.
    pub clients: DashMap<String, (ClientTx, u64)>,
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
}

impl AppState {
    pub async fn new(
        db_url: &str,
        keepalive_secs: u64,
        require_subscription: bool,
        subscription_price_zatoshi: u64,
        subscription_days: u64,
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
    pub fn connect(&self, pub_id: &PubId, tx: ClientTx) {
        let seq = self
            .inner
            .connection_counter
            .fetch_add(1, Ordering::Relaxed);
        self.inner.clients.insert(pub_id.0.clone(), (tx, seq));
    }

    pub fn disconnect(&self, pub_id: &PubId) {
        self.inner.clients.remove(&pub_id.0);
    }

    /// Returns the session connection sequence number for `pub_id`, or `u64::MAX`
    /// if not currently connected. Lower sequence = connected earlier this session.
    pub fn connection_seq(&self, pub_id: &str) -> u64 {
        self.inner
            .clients
            .get(pub_id)
            .map(|e| e.1)
            .unwrap_or(u64::MAX)
    }

    /// Attempt live delivery to a single client. Returns true if delivered.
    pub async fn deliver_live(&self, to: &str, msg: String) -> bool {
        if let Some(entry) = self.inner.clients.get(to) {
            entry.0.send(msg).await.is_ok()
        } else {
            false
        }
    }

    /// Fan out a message to a specific set of group members.
    ///
    /// For each member in `members` (excluding `exclude`):
    /// - Attempts live delivery via the client's sender channel.
    /// - If the client is offline, enqueues via `store.enqueue()`.
    ///
    /// Never holds the DashMap lock across an await point.
    pub async fn broadcast_to_group(&self, members: &[String], exclude: Option<&str>, msg: String) {
        // Collect live channels without holding the lock across awaits.
        let channels: Vec<(String, ClientTx)> = self
            .inner
            .clients
            .iter()
            .filter_map(|entry| {
                let pub_id = entry.key().clone();
                if members.contains(&pub_id) && exclude.is_none_or(|ex| pub_id != ex) {
                    Some((pub_id, entry.value().0.clone()))
                } else {
                    None
                }
            })
            .collect();

        // Drive live deliveries.
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

    /// Fan `msg` out to every connected client.
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
            .map(|entry| entry.value().0.clone())
            .collect();

        futures::future::join_all(targets.into_iter().map(|tx| {
            let m = msg.clone();
            async move {
                let _ = tx.send(m).await;
            }
        }))
        .await;
    }
}
