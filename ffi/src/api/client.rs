use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use flutter_rust_bridge::frb;
use nie_core::{
    identity::Identity,
    messages::{pad, unpad, ClearMessage},
    protocol::{
        rpc_methods, BroadcastParams, DeliverParams, DirectoryListParams, JsonRpcRequest,
        SetNicknameParams, UserJoinedParams, UserLeftParams, UserNicknameParams,
        WhisperDeliverParams, WhisperParams,
    },
    transport::{self, ClientEvent},
};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

// ---------------------------------------------------------------------------
// Public event type
// ---------------------------------------------------------------------------

/// An event from the relay, delivered to Dart one at a time via
/// `client_next_event`.  Dart wraps repeated calls in an `async*` generator
/// to produce a `Stream<NieEvent>`.
///
/// FRB v2 maps this enum to a Dart sealed class hierarchy.
#[frb]
pub enum NieEvent {
    /// A broadcast chat message was delivered.
    MessageReceived { from: String, text: String },
    /// A direct whisper was delivered.
    WhisperReceived { from: String, text: String },
    /// A peer connected for the first time (pub_id 0→1 active connections).
    UserJoined {
        pub_id: String,
        nickname: Option<String>,
        sequence: u64,
    },
    /// A peer disconnected (pub_id 1→0 active connections).
    UserLeft { pub_id: String },
    /// Authoritative online/offline snapshot from the relay.
    DirectoryUpdated { online: Vec<NieUserEntry> },
    /// A peer changed their display nickname.
    UserNickname { pub_id: String, nickname: String },
    /// The connection was lost; the client will reconnect automatically.
    Reconnecting { delay_secs: u64 },
    /// Successfully reconnected after a previous disconnect.
    Reconnected,
    /// A fatal internal error occurred (e.g. background task panicked).
    ///
    /// `client_next_event` will return this once and then return `None` on the
    /// next call.  Dart should treat this as a terminal condition and stop the
    /// event loop.
    FatalError { message: String },
}

/// An entry in the online user list (inside `NieEvent::DirectoryUpdated`).
#[frb]
pub struct NieUserEntry {
    pub pub_id: String,
    pub nickname: Option<String>,
    /// Relay-assigned monotonic connection sequence; lowest == earliest connected == MLS admin.
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// Opaque client handle
// ---------------------------------------------------------------------------

/// Opaque relay client handle, held by Dart as a Dart object.
///
/// The Dart side calls `client_next_event` in a loop to receive events:
///
/// ```dart
/// Stream<NieEvent> events(NieClient client) async* {
///   while (true) {
///     final e = await clientNextEvent(client: client);
///     if (e == null) break;  // channel closed → client disconnected
///     yield e;
///   }
/// }
/// ```
#[frb(opaque)]
pub struct NieClient {
    tx: mpsc::Sender<JsonRpcRequest>,
    pub_id: String,
    /// Events from the relay arrive here; Dart drains them via `client_next_event`.
    event_rx: Arc<Mutex<mpsc::Receiver<NieEvent>>>,
}

// ---------------------------------------------------------------------------
// FFI free functions
// ---------------------------------------------------------------------------

/// Connect to the relay and authenticate.
///
/// `relay_url`: WebSocket URL, e.g. `wss://relay.example.com/ws`.
/// `secret_b64`: base64-encoded 64-byte identity secret from `generate_identity()`.
/// `accept_invalid_certs`: set `true` only for local dev with self-signed certs.
///
/// Spawns a background connection manager that reconnects on disconnect.
/// Returns a `NieClient` handle immediately — no initial connection is awaited
/// here; connection events arrive via `client_next_event`.
pub async fn client_connect(
    relay_url: String,
    secret_b64: String,
    accept_invalid_certs: bool,
) -> Result<NieClient> {
    let bytes = B64
        .decode(&secret_b64)
        .map_err(|e| anyhow!("base64 decode error: {e}"))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow!("keyfile corrupt: expected 64 bytes"))?;
    let identity = Identity::from_secret_bytes(&arr)?;
    let pub_id = identity.pub_id().0.clone();

    // Synchronous — spawns the background manager, returns channel pair.
    let conn = transport::connect_with_retry(relay_url, identity, accept_invalid_certs, None);

    // Bridge: translate ClientEvent → NieEvent and deliver to the event channel.
    let (event_tx, event_rx) = mpsc::channel::<NieEvent>(256);
    let mut transport_rx = conn.rx;
    let own_pub_id_for_task = pub_id.clone();
    let event_tx_panic = event_tx.clone();
    let task_handle = tokio::spawn(async move {
        while let Some(event) = transport_rx.recv().await {
            let nie_event = match event {
                ClientEvent::Reconnecting { delay_secs } => {
                    Some(NieEvent::Reconnecting { delay_secs })
                }
                ClientEvent::Reconnected => Some(NieEvent::Reconnected),
                ClientEvent::Response(_) => None,
                ClientEvent::Message(notif) => map_notification(notif, &own_pub_id_for_task),
                ClientEvent::Disconnected => None,
            };
            if let Some(ev) = nie_event {
                if event_tx.send(ev).await.is_err() {
                    break; // Dart dropped the client
                }
            }
        }
    });
    // Watch the background task: if it panics, the channel sender side is dropped
    // and `client_next_event` would block forever.  Send a terminal FatalError
    // event so Dart receives an error instead of hanging.
    tokio::spawn(async move {
        if let Err(join_err) = task_handle.await {
            if join_err.is_panic() {
                let _ = event_tx_panic
                    .send(NieEvent::FatalError {
                        message: "background event task panicked".to_string(),
                    })
                    .await;
            }
        }
    });

    Ok(NieClient {
        tx: conn.tx,
        pub_id,
        event_rx: Arc::new(Mutex::new(event_rx)),
    })
}

/// Wait for and return the next relay event.
///
/// Returns `None` when the client has been disconnected and the event channel
/// is closed, signalling the Dart `async*` loop to exit.
///
/// This function suspends (does not busy-wait) until an event arrives.
pub async fn client_next_event(client: &NieClient) -> Option<NieEvent> {
    client.event_rx.lock().await.recv().await
}

/// Return this client's public ID (64 lowercase hex chars).
pub fn client_pub_id(client: &NieClient) -> String {
    client.pub_id.clone()
}

/// Broadcast a chat message to all online peers (fire-and-forget).
pub async fn client_send_message(client: &NieClient, text: String) -> Result<()> {
    let payload = encode_chat_payload(&text)?;
    let req = JsonRpcRequest::new(
        transport::next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams { payload },
    )
    .map_err(|e| anyhow!("serialize broadcast: {e}"))?;
    client
        .tx
        .send(req)
        .await
        .map_err(|_| anyhow!("relay channel closed"))
}

/// Send a whisper (direct message) to a specific peer (fire-and-forget).
///
/// `to` is the recipient's pub_id (64 hex chars).
pub async fn client_send_whisper(client: &NieClient, to: String, text: String) -> Result<()> {
    let payload = encode_chat_payload(&text)?;
    let req = JsonRpcRequest::new(
        transport::next_request_id(),
        rpc_methods::WHISPER,
        WhisperParams { to, payload },
    )
    .map_err(|e| anyhow!("serialize whisper: {e}"))?;
    client
        .tx
        .send(req)
        .await
        .map_err(|_| anyhow!("relay channel closed"))
}

/// Set the display nickname visible to other peers.
pub async fn client_set_nickname(client: &NieClient, nickname: String) -> Result<()> {
    let req = JsonRpcRequest::new(
        transport::next_request_id(),
        rpc_methods::SET_NICKNAME,
        SetNicknameParams { nickname },
    )
    .map_err(|e| anyhow!("serialize set_nickname: {e}"))?;
    client
        .tx
        .send(req)
        .await
        .map_err(|_| anyhow!("relay channel closed"))
}

/// Disconnect from the relay.
///
/// Drops the `tx` channel, signalling the connection manager to exit.
/// `client_next_event` will return `None` once the event queue drains.
pub fn client_disconnect(_client: NieClient) {
    // Moving the client here drops it → drops tx → connection manager exits.
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn encode_chat_payload(text: &str) -> Result<Vec<u8>> {
    // ClearMessage::Chat is a derived Serialize with a single String field;
    // serde_json::to_vec on it is infallible by construction.
    let bytes = serde_json::to_vec(&ClearMessage::Chat {
        text: text.to_string(),
    })
    .expect("ClearMessage::Chat serializes infallibly");
    pad(&bytes).map_err(|e| anyhow!("pad error: {e}"))
}

fn decode_payload_text(payload: &[u8]) -> String {
    let plaintext = match unpad(payload) {
        Ok(p) => p,
        Err(_) => return "(invalid padded payload)".to_string(),
    };
    if let Ok(ClearMessage::Chat { text }) = serde_json::from_slice::<ClearMessage>(&plaintext) {
        return text;
    }
    String::from_utf8(plaintext).unwrap_or_else(|_| "(binary payload)".to_string())
}

fn map_notification(
    notif: nie_core::protocol::JsonRpcNotification,
    own_pub_id: &str,
) -> Option<NieEvent> {
    let params = notif.params.unwrap_or(serde_json::Value::Null);
    match notif.method.as_str() {
        rpc_methods::DELIVER => {
            let p: DeliverParams = serde_json::from_value(params).ok()?;
            if p.from == own_pub_id {
                return None; // skip own broadcast echo
            }
            Some(NieEvent::MessageReceived {
                from: p.from,
                text: decode_payload_text(&p.payload),
            })
        }
        rpc_methods::WHISPER_DELIVER => {
            let p: WhisperDeliverParams = serde_json::from_value(params).ok()?;
            Some(NieEvent::WhisperReceived {
                from: p.from,
                text: decode_payload_text(&p.payload),
            })
        }
        rpc_methods::USER_JOINED => {
            let p: UserJoinedParams = serde_json::from_value(params).ok()?;
            Some(NieEvent::UserJoined {
                pub_id: p.pub_id,
                nickname: p.nickname,
                sequence: p.sequence,
            })
        }
        rpc_methods::USER_LEFT => {
            let p: UserLeftParams = serde_json::from_value(params).ok()?;
            Some(NieEvent::UserLeft { pub_id: p.pub_id })
        }
        rpc_methods::USER_NICKNAME => {
            let p: UserNicknameParams = serde_json::from_value(params).ok()?;
            Some(NieEvent::UserNickname {
                pub_id: p.pub_id,
                nickname: p.nickname,
            })
        }
        rpc_methods::DIRECTORY_LIST => {
            let p: DirectoryListParams = serde_json::from_value(params).ok()?;
            let online = p
                .online
                .into_iter()
                .map(|u| NieUserEntry {
                    pub_id: u.pub_id,
                    nickname: u.nickname,
                    sequence: u.sequence,
                })
                .collect();
            Some(NieEvent::DirectoryUpdated { online })
        }
        _ => None,
    }
}
