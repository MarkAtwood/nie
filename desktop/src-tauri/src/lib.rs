//! nie desktop app — Tauri backend.
//!
//! Exposes three Tauri commands to the frontend:
//! - `init_identity`  — load or create an Ed25519 identity
//! - `connect_relay`  — connect to a nie relay and start the message loop
//! - `send_chat`      — broadcast an encrypted Chat message (MLS+HPKE when group
//!   is active, plain BROADCAST before group is established)
//!
//! Incoming `deliver` events are forwarded to the frontend as
//! `"nie://message"` Tauri events carrying a `ChatMessage` JSON payload.

use nie_core::messages::{pad, unpad, ClearMessage};
use nie_core::mls::MlsClient;
use nie_core::protocol::{
    rpc_methods, BroadcastParams, DeliverParams, JsonRpcRequest, SealedBroadcastParams,
};
use nie_core::transport::{next_request_id, ClientEvent};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};

// ---- Shared app state ----

/// Mutable relay connection state, guarded by a Mutex.
struct RelayState {
    /// Channel for sending JSON-RPC requests to the relay.
    tx: Option<tokio::sync::mpsc::Sender<JsonRpcRequest>>,
    /// The local identity's public ID (hex string).
    pub_id: Option<String>,
    /// Per-session MLS client. Initialized on connect, replaced on reconnect.
    mls_client: Option<MlsClient>,
    /// True once this client has joined (or created) the MLS group.
    /// Until then, `send_chat` falls back to plain BROADCAST.
    mls_active: bool,
    /// Room HPKE public key derived from the current MLS epoch.
    /// Set when `mls_active` becomes true; cleared on reconnect.
    room_hpke_pub: Option<[u8; 32]>,
}

// ---- Chat message type emitted to the frontend ----

/// A single chat message delivered from the nie relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Short hex prefix of the sender's public ID (first 8 chars).
    pub from: String,
    /// Message text.
    pub text: String,
}

// ---- Tauri commands ----

/// Load or create a nie identity in `data_dir`.
///
/// Returns the public ID (64-char hex string) on success.
/// Creates a new identity if none exists at the given path.
#[tauri::command]
async fn init_identity(data_dir: String) -> Result<String, String> {
    let path = std::path::Path::new(&data_dir).join("identity.key");
    // `load_identity(path, interactive=false)` loads if exists, creates if not.
    let identity = nie_core::keyfile::load_identity(path.to_str().unwrap_or(&data_dir), false)
        .map_err(|e| e.to_string())?;
    Ok(identity.pub_id().0.clone())
}

/// Connect to a nie relay.
///
/// Starts a background task that maintains the relay connection and emits
/// `"nie://message"` events to the frontend for every received Chat message.
#[tauri::command]
async fn connect_relay(
    relay_url: String,
    data_dir: String,
    state: State<'_, Mutex<RelayState>>,
    app: AppHandle,
) -> Result<(), String> {
    let path = std::path::Path::new(&data_dir).join("identity.key");
    let identity = nie_core::keyfile::load_identity(path.to_str().unwrap_or(&data_dir), false)
        .map_err(|e| e.to_string())?;

    let pub_id = identity.pub_id().0.clone();

    let conn = nie_core::transport::connect_with_retry(relay_url, identity, false, None);

    // Store the send channel and a fresh MLS client in shared state.
    // mls_active and room_hpke_pub reset to false/None so the group
    // lifecycle starts fresh on every reconnect (matches TUI behaviour).
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.tx = Some(conn.tx.clone());
        s.pub_id = Some(pub_id.clone());
        s.mls_active = false;
        s.room_hpke_pub = None;
        match MlsClient::new(&pub_id) {
            Ok(client) => s.mls_client = Some(client),
            Err(e) => tracing::warn!("MlsClient::new failed on connect: {e}"),
        }
    }

    // Spawn the receive loop.
    tokio::spawn(async move {
        let mut rx = conn.rx;
        loop {
            let Some(event) = rx.recv().await else { break };
            match event {
                ClientEvent::Message(notif) if notif.method == rpc_methods::DELIVER => {
                    if let Some(msg) = decode_deliver(notif.params, &pub_id) {
                        if app.emit("nie://message", &msg).is_err() {
                            break;
                        }
                    }
                }
                ClientEvent::Reconnecting { delay_secs } => {
                    tracing::info!("relay reconnecting in {delay_secs}s");
                    let _ = app.emit("nie://status", format!("Reconnecting in {delay_secs}s…"));
                }
                ClientEvent::Disconnected => {
                    tracing::warn!("relay disconnected");
                    let relay_state = app.state::<Mutex<RelayState>>();
                    let mut s = relay_state.lock().unwrap_or_else(|e| e.into_inner());
                    s.tx = None;
                    break;
                }
                _ => {}
            }
        }
        let _ = app.emit("nie://status", "Disconnected.");
    });

    Ok(())
}

/// Broadcast a Chat message to the relay.
///
/// When the MLS group is active the message is encrypted with MLS and then
/// HPKE-sealed before being sent as a `sealed_broadcast`.  This matches the
/// TUI implementation in `tui/src/event.rs`.
///
/// When MLS is not yet active (no group established) the message is sent as a
/// plain `broadcast` — the relay can read it, but this only occurs before the
/// MLS handshake completes.
#[tauri::command]
async fn send_chat(text: String, state: State<'_, Mutex<RelayState>>) -> Result<(), String> {
    // Snapshot everything we need under the lock so we don't hold it across awaits.
    let (tx, mls_active, room_hpke_pub, mls_ciphertext_result) = {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        let tx = s.tx.clone().ok_or("not connected")?;

        // serde_json serialization of a derived type cannot fail.
        let plain = serde_json::to_vec(&ClearMessage::Chat { text: text.clone() })
            .expect("ClearMessage::Chat serialization cannot fail");

        let mls_ciphertext_result: Option<Result<Vec<u8>, String>> = if s.mls_active {
            Some(
                s.mls_client
                    .as_mut()
                    .ok_or_else(|| "mls_active but no MlsClient".to_string())
                    .and_then(|c| c.encrypt(&plain).map_err(|e| e.to_string())),
            )
        } else {
            None
        };

        (tx, s.mls_active, s.room_hpke_pub, mls_ciphertext_result)
    };

    if mls_active {
        let mls_ciphertext = mls_ciphertext_result
            .expect("mls_active implies Some(result)")
            .map_err(|e| format!("MLS encryption failed: {e}"))?;

        let padded = pad(&mls_ciphertext).map_err(|e| format!("payload padding failed: {e}"))?;

        let pub_key = room_hpke_pub.ok_or("MLS active but room HPKE key not yet available")?;
        let room_pub_id = nie_core::hpke::room_hpke_pub_id(&pub_key);
        let sealed = nie_core::hpke::seal_message(&pub_key, &room_pub_id, &padded)
            .map_err(|e| format!("HPKE seal failed: {e}"))?;

        let rpc = JsonRpcRequest::new(
            next_request_id(),
            rpc_methods::SEALED_BROADCAST,
            SealedBroadcastParams { sealed },
        )
        .map_err(|e| e.to_string())?;
        tx.send(rpc).await.map_err(|e| e.to_string())?;
    } else {
        // MLS group not yet established — send plain BROADCAST.
        // The relay can read this, but it only occurs before the MLS handshake
        // completes (matching TUI behaviour for the pre-group phase).
        let plain = serde_json::to_vec(&ClearMessage::Chat { text })
            .expect("ClearMessage::Chat serialization cannot fail");
        let rpc = JsonRpcRequest::new(
            next_request_id(),
            rpc_methods::BROADCAST,
            BroadcastParams { payload: plain },
        )
        .map_err(|e| e.to_string())?;
        tx.send(rpc).await.map_err(|e| e.to_string())?;
    }

    Ok(())
}

// ---- Helpers ----

/// Decode a `deliver` notification params into a `ChatMessage`, or return
/// `None` if the message is not a Chat or is from ourselves.
fn decode_deliver(params: Option<serde_json::Value>, own_pub_id: &str) -> Option<ChatMessage> {
    let params = params?;
    let deliver = serde_json::from_value::<DeliverParams>(params).ok()?;
    if deliver.from == own_pub_id {
        return None; // skip own echo
    }
    let raw = unpad(&deliver.payload).ok()?;
    let clear = serde_json::from_slice::<ClearMessage>(&raw).ok()?;
    let ClearMessage::Chat { text } = clear else {
        return None;
    };
    let short_id = deliver.from[..deliver.from.len().min(8)].to_string();
    Some(ChatMessage {
        from: short_id,
        text,
    })
}

// ---- App entry point ----

/// Called from `main.rs`.
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("nie_desktop_lib=info".parse().unwrap()),
        )
        .init();

    tauri::Builder::default()
        .manage(Mutex::new(RelayState {
            tx: None,
            pub_id: None,
            mls_client: None,
            mls_active: false,
            room_hpke_pub: None,
        }))
        .invoke_handler(tauri::generate_handler![
            init_identity,
            connect_relay,
            send_chat,
        ])
        .run(tauri::generate_context!())
        .expect("nie desktop app failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use serde_json::json;

    fn make_deliver_params(from: &str, text: &str) -> serde_json::Value {
        // Build a ClearMessage::Chat, pad it, base64-encode for DeliverParams.
        let payload = serde_json::to_vec(&ClearMessage::Chat {
            text: text.to_string(),
        })
        .unwrap();
        let padded = pad(&payload).unwrap();
        json!({
            "from": from,
            "payload": B64.encode(&padded)
        })
    }

    #[test]
    fn decode_deliver_returns_chat_message() {
        let params = make_deliver_params("abcdef1234567890", "hello");
        let msg = decode_deliver(Some(params), "other_pub_id").unwrap();
        assert_eq!(msg.from, "abcdef12");
        assert_eq!(msg.text, "hello");
    }

    #[test]
    fn decode_deliver_skips_own_echo() {
        let params = make_deliver_params("abcdef1234567890", "hello");
        let msg = decode_deliver(Some(params), "abcdef1234567890");
        assert!(msg.is_none());
    }

    #[test]
    fn decode_deliver_returns_none_for_no_params() {
        let msg = decode_deliver(None, "any_pub_id");
        assert!(msg.is_none());
    }
}
