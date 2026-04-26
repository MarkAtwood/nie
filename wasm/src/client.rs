use std::cell::RefCell;
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures::channel::oneshot;
use js_sys::Function;
use nie_core::{
    auth,
    identity::Identity,
    messages::{pad, unpad, ClearMessage},
    protocol::UserInfo,
};
use serde_json::Value;
use wasm_bindgen::prelude::*;

pub struct NieRelayClient {
    identity: Identity,
    /// Shared handle to the WebSocket transport.
    ///
    /// Stored as `Rc<WasmTransport>` so async callers can clone a cheap pointer
    /// out of the outer `RefCell` before awaiting, rather than holding the borrow
    /// across a yield point.
    transport: Rc<crate::transport::WasmTransport>,
    /// Online user list, sorted ascending by `sequence` (lowest = earliest connected).
    /// Shared with the persistent notify callback so it can be kept up to date.
    online_users: Rc<RefCell<Vec<UserInfo>>>,
}

impl Clone for NieRelayClient {
    /// Clone produces a second handle to the same underlying connection:
    /// all Rc fields share the same allocations.  Identity is value-copied
    /// (it is a small keypair).
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            transport: Rc::clone(&self.transport),
            online_users: Rc::clone(&self.online_users),
        }
    }
}

impl NieRelayClient {
    /// Connect to the relay, perform the challenge-response auth handshake,
    /// and return a ready client.
    pub async fn connect(relay_url: &str, identity: Identity) -> Result<NieRelayClient, String> {
        // 1. Open the WebSocket.
        let (transport, open_rx) = crate::transport::WasmTransport::connect(relay_url)
            .map_err(|e| format!("transport error: {e}"))?;

        // 2. Wait for the WebSocket to complete its opening handshake.
        open_rx
            .await
            .map_err(|_| "WebSocket open channel dropped".to_string())??;

        // 3. Install a temporary notify callback that extracts the challenge nonce.
        //    The relay sends a "challenge" notification immediately after the
        //    TCP+WS handshake.  We capture the nonce via a oneshot channel.
        let (challenge_tx, challenge_rx) = oneshot::channel::<Result<String, String>>();
        let challenge_tx_cell = Rc::new(RefCell::new(Some(challenge_tx)));
        let challenge_tx_for_cb = Rc::clone(&challenge_tx_cell);

        // Pure Rust callback — transport now holds Box<dyn FnMut(Value)> directly,
        // so no JS interop or second JSON parse is needed here.
        transport.set_notify_callback(Box::new(move |v: Value| {
            if v["method"].as_str() == Some("challenge") {
                if let Some(nonce) = v["params"]["nonce"].as_str() {
                    if let Some(tx) = challenge_tx_for_cb.borrow_mut().take() {
                        // Ignore send error — receiver already gone.
                        let _ = tx.send(Ok(nonce.to_string()));
                    }
                }
            }
        }));

        // 4. Await the challenge nonce.
        let nonce = challenge_rx
            .await
            .map_err(|_| "challenge channel dropped before nonce arrived".to_string())??;

        // Clear the challenge callback — the Rust closure is dropped by replacing it
        // with a no-op.  No JS lifetime ordering is required.
        transport.set_notify_callback(Box::new(|_| {}));

        // 5. Sign the nonce with our Ed25519 identity.
        //    sign_challenge signs nonce.as_bytes() (raw UTF-8) — never encode first.
        let (pub_key_b64, sig_b64) = auth::sign_challenge(&identity, &nonce);

        // 6. Send the "authenticate" request.
        let auth_result = transport
            .send_request(
                "authenticate",
                serde_json::json!({
                    "pub_key": pub_key_b64,
                    "nonce": nonce,
                    "signature": sig_b64,
                }),
            )
            .await?;

        // 7. Verify the relay's returned pub_id matches our computed pub_id.
        //    Any mismatch is a protocol error — reject hard.
        let relay_pub_id = auth_result["pub_id"]
            .as_str()
            .ok_or("auth response missing pub_id field")?;
        let our_pub_id = identity.pub_id().0.clone();
        if relay_pub_id != our_pub_id {
            return Err(format!(
                "pub_id mismatch: relay says {relay_pub_id}, we computed {our_pub_id}"
            ));
        }

        Ok(NieRelayClient {
            identity,
            transport: Rc::new(transport),
            online_users: Rc::new(RefCell::new(Vec::new())),
        })
    }

    /// Register a JS callback that receives client-side events as JS objects.
    ///
    /// The callback is called as `cb(eventObject)` for each relay notification.
    /// Event objects have a `"type"` field. Possible types: `message_received`,
    /// `whisper_received`, `user_joined`, `user_left`, `directory_updated`,
    /// `user_nickname`, `key_package_ready`.
    ///
    /// Replaces any previously registered callback.
    pub fn set_event_callback(&mut self, js_cb: Function) {
        let online_users = Rc::clone(&self.online_users);
        let own_pub_id = self.identity.pub_id().0.clone();

        // Transport now delivers the already-parsed Value — no second JSON parse.
        let notify_cb = Box::new(move |v: Value| {
            let method = match v["method"].as_str() {
                Some(m) => m,
                None => return,
            };

            let event: Value = match method {
                "deliver" => {
                    let from = v["params"]["from"].as_str().unwrap_or("").to_string();
                    if from == own_pub_id {
                        return; // skip own broadcast echo
                    }
                    let payload_b64 = v["params"]["payload"].as_str().unwrap_or("");
                    let text = decode_payload_text(payload_b64);
                    serde_json::json!({
                        "type": "message_received",
                        "from": from,
                        "text": text,
                    })
                }
                "whisper_deliver" => {
                    let from = v["params"]["from"].as_str().unwrap_or("").to_string();
                    let payload_b64 = v["params"]["payload"].as_str().unwrap_or("");
                    let text = decode_payload_text(payload_b64);
                    serde_json::json!({
                        "type": "whisper_received",
                        "from": from,
                        "text": text,
                    })
                }
                "directory_list" => {
                    // Update our online list from the authoritative snapshot.
                    // The relay sends this sorted ascending by sequence — online[0]
                    // is the MLS group admin candidate.
                    if let Ok(users) =
                        serde_json::from_value::<Vec<UserInfo>>(v["params"]["online"].clone())
                    {
                        *online_users.borrow_mut() = users;
                    }
                    serde_json::json!({
                        "type": "directory_updated",
                        "online": v["params"]["online"],
                        "offline": v["params"]["offline"],
                    })
                }
                "user_joined" => {
                    // Insert into the online list at the position that keeps it
                    // sorted ascending by sequence, so online_users[0] is always
                    // the earliest-connected peer (MLS admin election invariant).
                    let pub_id = v["params"]["pub_id"].as_str().unwrap_or("").to_string();
                    let nickname: Option<String> =
                        v["params"]["nickname"].as_str().map(|s| s.to_string());
                    // u64::MAX fallback: a peer with unknown sequence sorts last in the admin
                    // election, ensuring known-sequenced peers are preferred as MLS group admin.
                    let sequence = v["params"]["sequence"].as_u64().unwrap_or(u64::MAX);
                    let new_user = UserInfo {
                        pub_id: pub_id.clone(),
                        nickname: nickname.clone(),
                        sequence,
                    };
                    let mut users = online_users.borrow_mut();
                    let pos = users.partition_point(|u| u.sequence < sequence);
                    users.insert(pos, new_user);
                    serde_json::json!({
                        "type": "user_joined",
                        "pub_id": pub_id,
                        "nickname": nickname,
                        "sequence": sequence,
                    })
                }
                "user_left" => {
                    let pub_id = v["params"]["pub_id"].as_str().unwrap_or("").to_string();
                    online_users.borrow_mut().retain(|u| u.pub_id != pub_id);
                    serde_json::json!({
                        "type": "user_left",
                        "pub_id": pub_id,
                    })
                }
                "user_nickname" => {
                    let pub_id = v["params"]["pub_id"].as_str().unwrap_or("").to_string();
                    let nickname = v["params"]["nickname"].as_str().unwrap_or("").to_string();
                    // Update the cached nickname for this peer.
                    for user in online_users.borrow_mut().iter_mut() {
                        if user.pub_id == pub_id {
                            user.nickname = Some(nickname.clone());
                            break;
                        }
                    }
                    serde_json::json!({
                        "type": "user_nickname",
                        "pub_id": pub_id,
                        "nickname": nickname,
                    })
                }
                "key_package_ready" => {
                    let pub_id = v["params"]["pub_id"].as_str().unwrap_or("").to_string();
                    serde_json::json!({
                        "type": "key_package_ready",
                        "pub_id": pub_id,
                    })
                }
                other => {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "nie-wasm: unrecognised relay notification method: {other}"
                    )));
                    return;
                }
            };

            // serde_json::to_string on a serde_json::Value is infallible.
            let event_str =
                serde_json::to_string(&event).expect("serde_json::Value serializes infallibly");
            // Parse the JSON string into a native JS object so JS receives an
            // object directly rather than a string (nie-7bv6.4).
            // If parse fails, skip this event rather than delivering null/undefined
            // to the callback, which would look like a valid (but empty) event.
            let event_jsval = match js_sys::JSON::parse(&event_str) {
                Ok(obj) => obj,
                Err(_) => {
                    web_sys::console::warn_1(&JsValue::from_str(
                        "nie-wasm: failed to convert event to JS object; skipping",
                    ));
                    return;
                }
            };
            if let Err(err) = js_cb.call1(&JsValue::NULL, &event_jsval) {
                web_sys::console::error_1(&err);
            }
        });

        self.transport.set_notify_callback(notify_cb);
    }

    /// Broadcast a chat message to all online users.
    ///
    /// Serializes the text as a `ClearMessage::Chat` JSON payload (this is the
    /// MLS insertion point — when MLS lands, the payload bytes get encrypted
    /// before base64 encoding). Returns the relay-assigned message ID.
    pub async fn send_message(&self, text: &str) -> Result<String, String> {
        let result = self
            .transport
            .send_request(
                "broadcast",
                serde_json::json!({ "payload": build_payload(text)? }),
            )
            .await?;

        let message_id = result["message_id"]
            .as_str()
            .ok_or("broadcast response missing message_id")?
            .to_string();
        Ok(message_id)
    }

    /// Send a whisper (direct message) to a specific peer.
    ///
    /// `to` is the recipient's pub_id (64 hex chars). Returns the message ID.
    pub async fn send_whisper(&self, to: &str, text: &str) -> Result<String, String> {
        let result = self
            .transport
            .send_request(
                "whisper",
                serde_json::json!({ "to": to, "payload": build_payload(text)? }),
            )
            .await?;

        let message_id = result["message_id"]
            .as_str()
            .ok_or("whisper response missing message_id")?
            .to_string();
        Ok(message_id)
    }

    /// Set a display nickname on the relay.
    pub async fn set_nickname(&self, nick: &str) -> Result<(), String> {
        self.transport
            .send_request("set_nickname", serde_json::json!({ "nickname": nick }))
            .await?;
        Ok(())
    }

    /// Return a snapshot of the currently-online user list.
    ///
    /// The list is sorted ascending by `sequence` (relay-assigned monotonic
    /// connection counter). `online_users()[0]` is the MLS group admin.
    pub fn online_users(&self) -> Vec<UserInfo> {
        self.online_users.borrow().clone()
    }

    /// The caller's pub_id (64 lowercase hex chars).
    pub fn pub_id(&self) -> String {
        self.identity.pub_id().0.clone()
    }

    /// Close the WebSocket connection.
    pub fn close(&self) {
        self.transport.close();
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Serialize `text` as a `ClearMessage::Chat`, pad for traffic-analysis resistance,
/// and base64-encode the result.
///
/// This is the MLS insertion point: when MLS lands, replace the plaintext
/// `serde_json::to_vec` with an MLS encrypt call. The base64 encoding and
/// `"payload"` key in the JSON-RPC params stay the same.
fn build_payload(text: &str) -> Result<String, String> {
    let msg = ClearMessage::Chat {
        text: text.to_string(),
    };
    // ClearMessage::Chat is a derived Serialize with a single String field — infallible.
    let payload_bytes = serde_json::to_vec(&msg).expect("ClearMessage::Chat serializes infallibly");
    let padded = pad(&payload_bytes).map_err(|e| e.to_string())?;
    Ok(B64.encode(padded))
}

/// Decode a base64-encoded payload string into a human-readable text.
///
/// If the bytes are valid UTF-8 and the content is a `ClearMessage::Chat`,
/// return the chat text. Otherwise fall back to the raw UTF-8 string, and if
/// that fails too, signal "(binary payload)".
///
/// This function lives in the client layer (not the relay layer) — the relay
/// never deserialises payload bytes; only clients do.
fn decode_payload_text(payload_b64: &str) -> String {
    let bytes = match B64.decode(payload_b64) {
        Ok(b) => b,
        Err(_) => return "(invalid base64 payload)".to_string(),
    };

    let plaintext = match unpad(&bytes) {
        Ok(p) => p,
        Err(_) => return "(invalid padded payload)".to_string(),
    };

    // Attempt to parse as ClearMessage::Chat.
    if let Ok(ClearMessage::Chat { text }) = serde_json::from_slice::<ClearMessage>(&plaintext) {
        return text;
    }

    // Fall back to raw UTF-8 if it isn't a Chat variant (e.g. Payment, Ack).
    String::from_utf8(plaintext).unwrap_or_else(|_| "(binary payload)".to_string())
}
