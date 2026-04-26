use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::Result;
use nie_core::messages::ClearMessage;
use nie_core::protocol::{BroadcastParams, DeliverParams, JsonRpcRequest};
use nie_core::transport::{next_request_id, ClientEvent};
use subtle::ConstantTimeEq;

use crate::matrix::{mxid_localpart, MatrixEvent};

/// Maximum size of the sent-IDs deque (prevents unbounded memory growth).
const MAX_SENT_IDS: usize = 1000;

/// Tracks recently-sent nie message IDs to prevent echo loops.
pub struct SentIds {
    deque: VecDeque<String>,
    set: HashSet<String>,
}

impl SentIds {
    pub fn new() -> Self {
        Self {
            deque: VecDeque::with_capacity(MAX_SENT_IDS),
            set: HashSet::new(),
        }
    }

    /// Load from a JSON file produced by [`persist_to_file`].
    ///
    /// Returns an empty `SentIds` if the file does not exist.
    /// Logs a warning and returns empty on any parse error rather than failing startup.
    pub fn load_from_file(path: &Path) -> Self {
        match std::fs::read(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::new(),
            Err(e) => {
                tracing::warn!(
                    "cannot read sent_ids file {}: {e}; starting empty",
                    path.display()
                );
                Self::new()
            }
            Ok(bytes) => {
                let ids: Vec<String> = match serde_json::from_slice(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            "cannot parse sent_ids file {}: {e}; starting empty",
                            path.display()
                        );
                        return Self::new();
                    }
                };
                let mut s = Self::new();
                for id in ids.into_iter().take(MAX_SENT_IDS) {
                    s.set.insert(id.clone());
                    s.deque.push_back(id);
                }
                s
            }
        }
    }

    /// Persist the current ring buffer to `path` atomically via a rename.
    pub fn persist_to_file(&self, path: &Path) {
        let ids: Vec<&str> = self.deque.iter().map(String::as_str).collect();
        let json = match serde_json::to_vec(&ids) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("cannot serialize sent_ids: {e}");
                return;
            }
        };
        let tmp = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, &json) {
            tracing::warn!("cannot write sent_ids tmp {}: {e}", tmp.display());
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            tracing::warn!("cannot rename sent_ids tmp to {}: {e}", path.display());
        }
    }

    /// Record a sent message ID. Evicts the oldest if over capacity.
    pub fn insert(&mut self, id: String) {
        if self.deque.len() >= MAX_SENT_IDS {
            if let Some(old) = self.deque.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(id.clone());
        self.deque.push_back(id);
    }

    /// Returns true if this ID was previously sent by us.
    pub fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }
}

/// Format a nie message for display in the Matrix room.
///
/// Format: `[{prefix}{short_id}] {text}`
/// short_id is the first 8 hex chars of the sender's pub_id.
pub fn format_for_matrix(from_pub_id: &str, text: &str, prefix: Option<&str>) -> String {
    let short = &from_pub_id[..8.min(from_pub_id.len())];
    let prefix = prefix.unwrap_or("nie:");
    format!("[{prefix}{short}] {text}")
}

/// Format a Matrix event for broadcast into the nie room.
///
/// Format: `[Matrix:{localpart}] {text}`
pub fn format_for_nie(event: &MatrixEvent, text: &str) -> ClearMessage {
    let localpart = mxid_localpart(&event.sender);
    ClearMessage::Chat {
        text: format!("[Matrix:{localpart}] {text}"),
    }
}

/// Returns true if the Matrix event came from our own bridge bot sender.
pub fn is_bot_sender(event: &MatrixEvent, bot_localpart: &str, homeserver: &str) -> bool {
    // Homeserver domain from URL: strip http(s):// and any trailing slash.
    let domain = homeserver
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let bot_mxid = format!("@{bot_localpart}:{domain}");
    event.sender == bot_mxid
}

/// State shared between the axum AS handler and the main bridge loop.
#[derive(Clone)]
struct AsState {
    hs_token: String,
    room_id: String,
    tx: tokio::sync::mpsc::Sender<MatrixEvent>,
}

/// Axum handler for Matrix Application Service transaction push.
///
/// PUT /transactions/:txn_id — homeserver pushes events here.
/// Verifies the hs_token from the Authorization header, then forwards
/// each event to the bridge loop via the mpsc channel.
async fn as_transaction(
    axum::extract::State(state): axum::extract::State<AsState>,
    axum::extract::Path(_txn_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(txn): axum::extract::Json<crate::matrix::AsTransaction>,
) -> axum::http::StatusCode {
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let authed = bearer.is_some_and(|token| {
        let expected = state.hs_token.as_bytes();
        let provided = token.as_bytes();
        bool::from(expected.ct_eq(provided))
    });
    if !authed {
        return axum::http::StatusCode::FORBIDDEN;
    }
    for event in txn.events {
        // Filter: only forward events from the configured room.
        if event.room_id != state.room_id {
            tracing::debug!(
                room_id = %event.room_id,
                "Matrix event from unconfigured room; skipped"
            );
            continue;
        }
        // Non-blocking: drop the event if the buffer is full rather than
        // back-pressuring the homeserver.
        let _ = state.tx.try_send(event);
    }
    axum::http::StatusCode::OK
}

/// Handle an incoming nie `deliver` notification: forward plain Chat
/// messages to the Matrix room.
async fn handle_nie_deliver(
    params: Option<serde_json::Value>,
    own_pub_id: &str,
    matrix: &crate::matrix::MatrixClient,
    room_id: &str,
    bridge_prefix: Option<&str>,
) {
    let Some(params) = params else { return };
    let Ok(deliver) = serde_json::from_value::<DeliverParams>(params) else {
        return;
    };
    if deliver.from == own_pub_id {
        return; // skip own echo
    }
    let Ok(msg) = nie_core::messages::unpad(&deliver.payload) else {
        return;
    };
    let Ok(clear) = serde_json::from_slice::<ClearMessage>(&msg) else {
        return;
    };
    let ClearMessage::Chat { text } = clear else {
        return;
    };
    let formatted = format_for_matrix(&deliver.from, &text, bridge_prefix);
    if let Err(e) = matrix.send_text(room_id, &formatted).await {
        tracing::warn!("Matrix send_text failed: {e}");
    }
}

/// Run the bridge loop: connect to the nie relay, start the Matrix AS HTTP
/// server, then forward messages in both directions until the relay drops.
pub async fn run(config: &crate::config::BridgeConfig) -> Result<()> {
    // Extract config fields as owned values (needed across async boundaries).
    let room_id = config.matrix_room_id.clone();
    let bot_localpart = config.bot_localpart.clone();
    let homeserver = config.matrix_homeserver.clone();
    let bridge_prefix: Option<String> = config.bridge_prefix.clone();
    let listen_port = config.listen_port;

    // Load the bridge bot identity (no interactive passphrase for a daemon).
    let identity = nie_core::keyfile::load_identity(&config.keyfile, true)?;
    let own_pub_id = identity.pub_id().0.clone();

    // Connect to the nie relay with transparent reconnection.
    let mut conn =
        nie_core::transport::connect_with_retry(config.relay_url.clone(), identity, false, None);

    // Matrix client for outbound sends.
    let matrix = crate::matrix::MatrixClient::new(&homeserver, &config.as_token);

    // Echo-loop prevention: track event_ids of messages we sent to nie.
    // Persisted alongside the keyfile so dedup survives restarts.
    let sent_ids_path: PathBuf = {
        let kf = Path::new(&config.keyfile);
        let dir = kf.parent().unwrap_or_else(|| Path::new("."));
        dir.join("sent_ids.json")
    };
    let mut sent_ids = SentIds::load_from_file(&sent_ids_path);

    // Channel: axum handler → bridge loop.
    let (matrix_tx, mut matrix_rx) = tokio::sync::mpsc::channel::<MatrixEvent>(64);

    // Start the Matrix Application Service HTTP server.
    {
        let state = AsState {
            hs_token: config.hs_token.clone(),
            room_id: room_id.clone(),
            tx: matrix_tx,
        };
        let app = axum::Router::new()
            .route("/transactions/{txn_id}", axum::routing::put(as_transaction))
            .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{listen_port}")).await?;
        tracing::info!("Matrix AS server listening on :{listen_port}");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("Matrix AS HTTP server error: {e}");
            }
        });
    }

    tracing::info!(
        "nie-bridge-matrix running (pub_id prefix: {})",
        &own_pub_id[..8]
    );

    loop {
        tokio::select! {
            event = conn.rx.recv() => {
                let Some(event) = event else {
                    anyhow::bail!("nie relay connection channel closed");
                };
                if let ClientEvent::Message(notif) = event {
                    if notif.method == nie_core::protocol::rpc_methods::DELIVER {
                        handle_nie_deliver(
                            notif.params,
                            &own_pub_id,
                            &matrix,
                            &room_id,
                            bridge_prefix.as_deref(),
                        )
                        .await;
                    }
                }
            }

            event = matrix_rx.recv() => {
                let Some(event) = event else { break };
                if is_bot_sender(&event, &bot_localpart, &homeserver) {
                    continue;
                }
                if sent_ids.contains(&event.event_id) {
                    continue;
                }
                let Some(text) = crate::matrix::text_body(&event) else { continue };
                let clear = format_for_nie(&event, text);
                // serde_json::to_vec on a derived Serialize cannot fail.
                let payload_bytes = serde_json::to_vec(&clear).unwrap();
                let Ok(padded) = nie_core::messages::pad(&payload_bytes) else {
                    tracing::warn!("Matrix message too large to pad; dropped");
                    continue;
                };
                let req = JsonRpcRequest::new(
                    next_request_id(),
                    nie_core::protocol::rpc_methods::BROADCAST,
                    BroadcastParams { payload: padded },
                )?;
                if conn.tx.send(req).await.is_err() {
                    anyhow::bail!("nie relay send channel closed");
                }
                sent_ids.insert(event.event_id.clone());
                sent_ids.persist_to_file(&sent_ids_path);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_event(sender: &str) -> MatrixEvent {
        crate::matrix::MatrixEvent {
            event_type: "m.room.message".to_string(),
            room_id: "!test:example.com".to_string(),
            sender: sender.to_string(),
            content: json!({"msgtype": "m.text", "body": "hi"}),
            event_id: "$xyz".to_string(),
        }
    }

    #[test]
    fn format_for_matrix_uses_prefix() {
        let result = format_for_matrix("ab12cd34ef567890", "some text", Some("nie:"));
        assert_eq!(result, "[nie:ab12cd34] some text");
    }

    #[test]
    fn format_for_matrix_default_prefix() {
        let result = format_for_matrix("ab12cd34ef567890", "hello", None);
        assert_eq!(result, "[nie:ab12cd34] hello");
    }

    #[test]
    fn format_for_nie_strips_domain() {
        let event = make_event("@alice:example.com");
        let msg = format_for_nie(&event, "hello world");
        let ClearMessage::Chat { text } = msg else {
            panic!("expected Chat variant");
        };
        assert_eq!(text, "[Matrix:alice] hello world");
    }

    #[test]
    fn is_bot_sender_matches_own_mxid() {
        let event = make_event("@niebridge:matrix.example.com");
        assert!(is_bot_sender(
            &event,
            "niebridge",
            "https://matrix.example.com"
        ));
    }

    #[test]
    fn is_bot_sender_rejects_others() {
        let event = make_event("@alice:matrix.example.com");
        assert!(!is_bot_sender(
            &event,
            "niebridge",
            "https://matrix.example.com"
        ));
    }

    #[test]
    fn sent_ids_evicts_oldest_when_full() {
        let mut ids = SentIds::new();
        for i in 0..super::MAX_SENT_IDS {
            ids.insert(format!("id{i}"));
        }
        assert!(ids.contains("id0"));
        // Adding one more should evict id0
        ids.insert("id_new".to_string());
        assert!(!ids.contains("id0"));
        assert!(ids.contains("id_new"));
    }

    #[test]
    fn sent_ids_contains_returns_true_for_inserted() {
        let mut ids = SentIds::new();
        ids.insert("abc".to_string());
        assert!(ids.contains("abc"));
    }

    #[test]
    fn sent_ids_contains_returns_false_for_unknown() {
        let ids = SentIds::new();
        assert!(!ids.contains("unknown"));
    }
}
