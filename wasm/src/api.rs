use std::cell::RefCell;
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use js_sys::Function;
use nie_core::identity::Identity;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Generate a fresh Ed25519 + X25519 identity.
///
/// Returns a base64-encoded 64-byte secret blob: Ed25519_seed(32) || X25519_seed(32).
/// This value is sensitive — the caller must store it securely (e.g. via `save_identity`).
/// Never log the return value.
#[wasm_bindgen]
pub fn generate_identity() -> String {
    let identity = Identity::generate();
    B64.encode(identity.to_secret_bytes_64())
}

/// Derive the public ID from a base64-encoded 64-byte secret.
///
/// The public ID is 64 lowercase hex characters: hex(SHA-256(ed25519_verifying_key)).
/// Returns `Err(JsValue)` if the input is not valid base64 or is not exactly 64 bytes.
#[wasm_bindgen]
pub fn pub_id_from_secret(secret_b64: &str) -> Result<String, JsValue> {
    let bytes = B64
        .decode(secret_b64)
        .map_err(|e| JsValue::from_str(&format!("base64 decode error: {e}")))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| JsValue::from_str("keyfile corrupt: expected 64 bytes"))?;
    let identity = Identity::from_secret_bytes(&arr);
    Ok(identity.pub_id().0)
}

/// Save the identity secret to IndexedDB.
///
/// `secret_b64`: base64-encoded 64-byte secret from `generate_identity()`.
/// Returns a `Promise` that resolves to `undefined` on success, or rejects with
/// an error string. Never logs key material.
#[wasm_bindgen]
pub fn save_identity(secret_b64: String) -> js_sys::Promise {
    future_to_promise(async move {
        let bytes = B64
            .decode(&secret_b64)
            .map_err(|e| JsValue::from_str(&format!("base64 decode error: {e}")))?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| JsValue::from_str("keyfile corrupt: expected 64 bytes"))?;
        crate::storage::save_identity(&arr)
            .await
            .map_err(|e| JsValue::from_str(&e))?;
        Ok(JsValue::UNDEFINED)
    })
}

/// Load the identity secret from IndexedDB.
///
/// Returns a `Promise` that resolves to:
/// - A base64-encoded 64-byte secret string if an identity is stored.
/// - `null` (`JsValue::NULL`) if no identity has been stored yet.
/// Rejects with an error string on storage failure.
#[wasm_bindgen]
pub fn load_identity() -> js_sys::Promise {
    future_to_promise(async move {
        match crate::storage::load_identity().await {
            Ok(Some(arr)) => Ok(JsValue::from_str(&B64.encode(arr))),
            Ok(None) => Ok(JsValue::NULL),
            Err(e) => Err(JsValue::from_str(&e)),
        }
    })
}

// ---------------------------------------------------------------------------
// NieClient — JavaScript-facing relay client
// ---------------------------------------------------------------------------

/// JavaScript-facing relay client.
///
/// Typical usage:
/// ```js
/// const client = new NieClient();
/// const pubId = await client.connect("wss://relay.example.com/ws", secretB64);
/// client.on_event((event) => { /* handle */ });
/// await client.send_message("hello");
/// client.disconnect();
/// ```
///
/// The inner `NieRelayClient` is stored behind `Rc<RefCell<Option<_>>>` so
/// `&self` methods can observe and mutate the connection state without needing
/// `&mut self`.  Async methods clone the client (cheap Rc clones on all its
/// fields) out of the `RefCell` before awaiting, preventing the borrow from
/// spanning the yield point (which would violate the `await_holding_refcell_ref`
/// rule).
#[wasm_bindgen]
pub struct NieClient {
    inner: Rc<RefCell<Option<crate::client::NieRelayClient>>>,
}

impl Default for NieClient {
    fn default() -> Self {
        Self::new()
    }
}

impl NieClient {
    /// Clone the `NieRelayClient` out of the `RefCell`.
    ///
    /// Returns `Err("not connected")` if `connect` has not been called yet.
    /// Cloning is cheap: all `NieRelayClient` fields are behind `Rc`.
    /// The `RefCell` borrow is dropped immediately — callers can safely pass
    /// the returned value into an `async` block without holding the borrow
    /// across a yield point.
    fn get_client(&self) -> Result<crate::client::NieRelayClient, JsValue> {
        self.inner
            .borrow()
            .as_ref()
            .cloned()
            .ok_or_else(|| JsValue::from_str("not connected"))
    }
}

#[wasm_bindgen]
impl NieClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(None)),
        }
    }

    /// Connect to the relay and authenticate.
    ///
    /// `relay_url`: WebSocket URL (`wss://...`)
    /// `secret_b64`: base64-encoded 64-byte identity secret from `generate_identity()` or `load_identity()`
    ///
    /// Returns a `Promise<string>` resolving to the authenticated pub_id (64 hex chars).
    /// Rejects with an error string on connection or auth failure.
    pub fn connect(&self, relay_url: String, secret_b64: String) -> js_sys::Promise {
        let inner = Rc::clone(&self.inner);
        future_to_promise(async move {
            let bytes = B64
                .decode(&secret_b64)
                .map_err(|e| JsValue::from_str(&format!("base64 decode error: {e}")))?;
            let arr: [u8; 64] = bytes
                .try_into()
                .map_err(|_| JsValue::from_str("keyfile corrupt: expected 64 bytes"))?;
            let identity = Identity::from_secret_bytes(&arr);

            let client = crate::client::NieRelayClient::connect(&relay_url, identity)
                .await
                .map_err(|e| JsValue::from_str(&e))?;

            let pub_id = client.pub_id();
            *inner.borrow_mut() = Some(client);
            Ok(JsValue::from_str(&pub_id))
        })
    }

    /// Register a callback for relay events.
    ///
    /// The callback receives a JS object with a `"type"` field. Possible types:
    /// `message_received`, `whisper_received`, `user_joined`, `user_left`,
    /// `directory_updated`, `user_nickname`, `key_package_ready`.
    ///
    /// Replaces any previously registered callback. Returns `Err` if not connected.
    pub fn on_event(&self, callback: Function) -> Result<(), JsValue> {
        let mut borrow = self.inner.borrow_mut();
        let client = borrow
            .as_mut()
            .ok_or_else(|| JsValue::from_str("not connected"))?;
        client.set_event_callback(callback);
        Ok(())
    }

    /// Broadcast a chat message to all online peers.
    ///
    /// Returns a `Promise<string>` resolving to the relay-assigned message_id UUID.
    /// Rejects with an error string if not connected or on send failure.
    pub fn send_message(&self, text: String) -> js_sys::Promise {
        let client = match self.get_client() {
            Ok(c) => c,
            Err(e) => return future_to_promise(async move { Err(e) }),
        };
        future_to_promise(async move {
            client
                .send_message(&text)
                .await
                .map(|id| JsValue::from_str(&id))
                .map_err(|e| JsValue::from_str(&e))
        })
    }

    /// Set the display nickname visible to other peers.
    ///
    /// Returns a `Promise<undefined>`. Rejects if not connected or on failure.
    pub fn set_nickname(&self, nick: String) -> js_sys::Promise {
        let client = match self.get_client() {
            Ok(c) => c,
            Err(e) => return future_to_promise(async move { Err(e) }),
        };
        future_to_promise(async move {
            client
                .set_nickname(&nick)
                .await
                .map(|_| JsValue::UNDEFINED)
                .map_err(|e| JsValue::from_str(&e))
        })
    }

    /// Send a whisper (direct message) to a specific peer.
    ///
    /// `to` is the recipient's pub_id (64 hex chars).
    /// Returns a `Promise<string>` resolving to the relay-assigned message_id UUID.
    /// Rejects with an error string if not connected or on send failure.
    pub fn send_whisper(&self, to: String, text: String) -> js_sys::Promise {
        let client = match self.get_client() {
            Ok(c) => c,
            Err(e) => return future_to_promise(async move { Err(e) }),
        };
        future_to_promise(async move {
            client
                .send_whisper(&to, &text)
                .await
                .map(|id| JsValue::from_str(&id))
                .map_err(|e| JsValue::from_str(&e))
        })
    }

    /// Return a snapshot of currently-online users as a JS value (array of objects).
    ///
    /// Each element has `pub_id: string`, `nickname: string | null`, `sequence: number`.
    /// Returns `JsValue::NULL` if not connected.
    pub fn online_users(&self) -> JsValue {
        let borrow = self.inner.borrow();
        let client = match borrow.as_ref() {
            Some(c) => c,
            None => return JsValue::NULL,
        };
        let users = client.online_users();
        // serde_json::to_string on a Vec<UserInfo> with derived Serialize cannot fail
        let json_str = serde_json::to_string(&users).unwrap();
        // js_sys::JSON::parse converts a JSON string into a native JS value.
        js_sys::JSON::parse(&json_str).unwrap_or(JsValue::NULL)
    }

    /// The caller's pub_id (64 lowercase hex chars).
    ///
    /// Returns `None` if not yet connected.
    pub fn pub_id(&self) -> Option<String> {
        self.inner.borrow().as_ref().map(|client| client.pub_id())
    }

    /// Close the relay WebSocket connection.
    ///
    /// Idempotent — safe to call when already disconnected.
    pub fn disconnect(&self) {
        if let Some(client) = self.inner.borrow().as_ref() {
            client.close();
        }
    }
}
