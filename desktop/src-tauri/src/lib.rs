//! nie desktop app — Tauri backend.
//!
//! Exposes three Tauri commands to the frontend:
//! - `init_identity`  — load or create an Ed25519 identity
//! - `connect_relay`  — connect to a nie relay and start the message loop
//! - `send_chat`      — broadcast a plaintext Chat message
//!
//! Incoming `deliver` events are forwarded to the frontend as
//! `"nie://message"` Tauri events carrying a `ChatMessage` JSON payload.

use nie_core::messages::{pad, unpad, ClearMessage};
use nie_core::protocol::{rpc_methods, BroadcastParams, DeliverParams, JsonRpcRequest};
use nie_core::transport::{next_request_id, ClientEvent};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};

// ---- Shared app state ----

/// Mutable relay connection state, guarded by a Mutex.
struct RelayState {
    /// Channel for sending JSON-RPC requests to the relay.
    tx: Option<tokio::sync::mpsc::Sender<JsonRpcRequest>>,
    /// The local identity's public ID (hex string).
    pub_id: Option<String>,
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

    // Store the send channel in shared state.
    {
        let mut s = state.lock().unwrap();
        s.tx = Some(conn.tx.clone());
        s.pub_id = Some(pub_id.clone());
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
                _ => {}
            }
        }
        let _ = app.emit("nie://status", "Disconnected.");
    });

    Ok(())
}

/// Broadcast a plain-text Chat message to the relay.
#[tauri::command]
async fn send_chat(text: String, state: State<'_, Mutex<RelayState>>) -> Result<(), String> {
    let tx = {
        let s = state.lock().unwrap();
        s.tx.clone().ok_or("not connected")?
    };
    let payload = serde_json::to_vec(&ClearMessage::Chat { text }).map_err(|e| e.to_string())?;
    let padded = pad(&payload).map_err(|e| e.to_string())?;
    let rpc = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams { payload: padded },
    )
    .map_err(|e| e.to_string())?;
    tx.send(rpc).await.map_err(|e| e.to_string())?;
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
