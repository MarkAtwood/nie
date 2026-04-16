// Methods and fields are used by later beads (relay connector, HTTP handlers).
#![allow(dead_code)]

use crate::types::{DaemonEvent, UserInfo};
use nie_core::protocol::JsonRpcRequest;
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
    relay_tx: Mutex<Option<tokio::sync::mpsc::Sender<JsonRpcRequest>>>,
    directory: Mutex<DirectoryState>,
    events_tx: broadcast::Sender<DaemonEvent>,
}

#[derive(Clone)]
pub struct DaemonState(Arc<Inner>);

impl DaemonState {
    pub fn new(my_pub_id: String, token: String, display_name: Option<String>) -> Self {
        let (events_tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        DaemonState(Arc::new(Inner {
            my_pub_id,
            token,
            display_name,
            relay_tx: Mutex::new(None),
            directory: Mutex::new(DirectoryState::default()),
            events_tx,
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
}
