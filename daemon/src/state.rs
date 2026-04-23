// Methods and fields are used by later beads (relay connector, HTTP handlers).
#![allow(dead_code)]

use crate::store::Store;
use crate::types::{DaemonEvent, UserInfo};
use nie_core::mls::MlsClient;
use nie_core::protocol::JsonRpcRequest;
use nie_wallet::db::WalletStore;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

const BROADCAST_CAPACITY: usize = 256;

#[derive(Debug, Default)]
pub struct DirectoryState {
    pub online: Vec<UserInfo>,
    pub offline: Vec<UserInfo>,
}

struct Inner {
    my_pub_id: String,
    token: String,
    display_name: Option<String>,
    network: String,
    wallet_store: Option<WalletStore>,
    store: Option<Store>,
    relay_tx: Mutex<Option<tokio::sync::mpsc::Sender<JsonRpcRequest>>>,
    mls_client: Mutex<Option<Arc<Mutex<MlsClient>>>>,
    directory: Mutex<DirectoryState>,
    events_tx: broadcast::Sender<DaemonEvent>,
    default_space_id: tokio::sync::OnceCell<String>,
    default_channel_id: tokio::sync::OnceCell<String>,
}

#[derive(Clone)]
pub struct DaemonState(Arc<Inner>);

impl DaemonState {
    pub fn new(
        my_pub_id: String,
        token: String,
        display_name: Option<String>,
        network: String,
        wallet_store: Option<WalletStore>,
        store: Option<Store>,
    ) -> Self {
        let (events_tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        DaemonState(Arc::new(Inner {
            my_pub_id,
            token,
            display_name,
            network,
            wallet_store,
            store,
            relay_tx: Mutex::new(None),
            mls_client: Mutex::new(None),
            directory: Mutex::new(DirectoryState::default()),
            events_tx,
            default_space_id: tokio::sync::OnceCell::new(),
            default_channel_id: tokio::sync::OnceCell::new(),
        }))
    }

    pub fn my_pub_id(&self) -> &str {
        &self.0.my_pub_id
    }

    pub fn token(&self) -> &str {
        &self.0.token
    }

    pub fn display_name(&self) -> Option<&str> {
        self.0.display_name.as_deref()
    }

    pub fn network(&self) -> &str {
        &self.0.network
    }

    /// Return the WalletStore if a wallet has been initialized.
    pub fn wallet_store(&self) -> Option<&WalletStore> {
        self.0.wallet_store.as_ref()
    }

    /// Return the JMAP Chat store if initialized.
    pub fn store(&self) -> Option<&Store> {
        self.0.store.as_ref()
    }

    /// Subscribe to the broadcast channel for daemon events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<DaemonEvent> {
        self.0.events_tx.subscribe()
    }

    /// Broadcast a DaemonEvent to all connected browser WebSocket clients.
    /// If no subscribers, this is a no-op (not an error).
    pub fn broadcast_event(&self, event: DaemonEvent) {
        // send() returns Err if no receivers — that's fine
        let _ = self.0.events_tx.send(event);
    }

    /// Store the MLS client after the relay connection is established.
    pub async fn set_mls_client(&self, client: Arc<Mutex<MlsClient>>) {
        *self.0.mls_client.lock().await = Some(client);
    }

    /// Get the MLS client if the relay has connected and bootstrapped MLS.
    pub async fn mls_client(&self) -> Option<Arc<Mutex<MlsClient>>> {
        self.0.mls_client.lock().await.clone()
    }

    /// Set the relay transmit channel after connection is established.
    pub async fn set_relay_tx(&self, tx: tokio::sync::mpsc::Sender<JsonRpcRequest>) {
        *self.0.relay_tx.lock().await = Some(tx);
    }

    /// Get a clone of the relay transmit channel, if connected.
    pub async fn relay_tx(&self) -> Option<tokio::sync::mpsc::Sender<JsonRpcRequest>> {
        self.0.relay_tx.lock().await.clone()
    }

    /// Update the directory state.
    pub async fn update_directory(&self, online: Vec<UserInfo>, offline: Vec<UserInfo>) {
        let mut dir = self.0.directory.lock().await;
        dir.online = online;
        dir.offline = offline;
    }

    /// Get a snapshot of the current directory.
    pub async fn directory_snapshot(&self) -> DirectoryState {
        let dir = self.0.directory.lock().await;
        DirectoryState {
            online: dir.online.clone(),
            offline: dir.offline.clone(),
        }
    }

    /// Record the bootstrapped default Space ID. No-op if already set.
    pub fn set_default_space_id(&self, id: String) {
        let _ = self.0.default_space_id.set(id);
    }

    /// Return the default Space ID, or None if bootstrap has not yet run.
    pub fn default_space_id(&self) -> Option<&str> {
        self.0.default_space_id.get().map(|s| s.as_str())
    }

    /// Record the bootstrapped default channel ID. No-op if already set.
    pub fn set_default_channel_id(&self, id: String) {
        let _ = self.0.default_channel_id.set(id);
    }

    /// Return the default channel ID, or None if bootstrap has not yet run.
    pub fn default_channel_id(&self) -> Option<&str> {
        self.0.default_channel_id.get().map(|s| s.as_str())
    }
}
