//! Integration test: raw JSON-RPC 2.0 protocol exercised at the WebSocket level.
//!
//! This test verifies the protocol sequence the WASM client will use, without
//! going through the `nie_core::transport` library.  Every frame is built and
//! parsed as raw JSON so the assertions reflect what a WASM consumer actually sees.
//!
//! Tests:
//!   - `auth_success_returns_pub_id`   — auth handshake returns the correct pub_id
//!   - `auth_rejected_wrong_signature` — bogus signature yields error code -32001
//!   - `broadcast_deliver_round_trip`  — broadcast fan-out; payload is byte-for-byte identical
//!
//! Oracle: JSON-RPC 2.0 specification and the nie wire protocol spec in CLAUDE.md.

use axum::{routing::get, Router};
use base64::Engine;
use futures::{SinkExt, StreamExt};
use nie_core::{
    auth::sign_challenge,
    identity::Identity,
    protocol::{rpc_errors, rpc_methods, BroadcastParams},
};
use nie_relay::{state::AppState, ws::ws_handler};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

// ---------------------------------------------------------------------------
// Relay spawn helper (identical pattern to stress.rs and e2e_jsonrpc.rs)
// ---------------------------------------------------------------------------

async fn spawn_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let db_file = tempfile::NamedTempFile::new().unwrap();
    let db_url = format!("sqlite:{}?mode=rwc", db_file.path().display());

    let state = AppState::new(&db_url, 60, false, 1_000_000, 30, 120u32)
        .await
        .unwrap();
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    tokio::spawn(async move {
        let _db_file = db_file;
        axum::serve(listener, app).await.unwrap();
    });

    format!("ws://127.0.0.1:{port}/ws")
}

// ---------------------------------------------------------------------------
// Raw WebSocket helper
// ---------------------------------------------------------------------------

/// A thin raw WebSocket client that speaks JSON-RPC 2.0 frames directly.
///
/// Notifications have no `id` field; responses have one.  The recv_* methods
/// skip frames that don't match the expected shape, up to a limit, then panic.
struct RawWsClient {
    sink: futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    stream: futures::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
}

impl RawWsClient {
    async fn connect(url: &str) -> Self {
        let (ws, _) = connect_async(url).await.expect("raw ws connect");
        let (sink, stream) = ws.split();
        Self { sink, stream }
    }

    /// Read frames until we get a text frame, then parse it as JSON.
    /// Skips Ping/Pong frames (the relay sends keepalive pings).
    /// Panics after 5 seconds.
    async fn recv_frame(&mut self) -> Value {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), self.stream.next()).await {
                Ok(Some(Ok(Message::Text(t)))) => {
                    return serde_json::from_str(&t).expect("relay frame must be valid JSON");
                }
                Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {
                    // keepalive — skip
                }
                Ok(Some(Ok(other))) => {
                    panic!("unexpected ws frame: {other:?}");
                }
                Ok(Some(Err(e))) => panic!("ws error: {e}"),
                Ok(None) => panic!("relay closed the connection"),
                Err(_) => panic!("timed out waiting for a frame from the relay"),
            }
        }
    }

    /// Receive the next notification (a frame without an `id` field).
    /// Skips responses (frames with `id`), up to 20 frames, then panics.
    async fn recv_notification(&mut self) -> Value {
        for _ in 0..20 {
            let frame = self.recv_frame().await;
            if frame.get("id").is_none() {
                return frame;
            }
            // It is a response — skip it.
        }
        panic!("did not receive a notification within 20 frames");
    }

    /// Receive the response for the given request `id`.
    /// Skips notifications (frames without `id`) and responses for other ids,
    /// up to 20 frames, then panics.
    async fn recv_response(&mut self, expected_id: u64) -> Value {
        for _ in 0..20 {
            let frame = self.recv_frame().await;
            match frame.get("id").and_then(|v| v.as_u64()) {
                Some(id) if id == expected_id => return frame,
                _ => {} // notification or response for a different id — skip
            }
        }
        panic!("did not receive response for id={expected_id} within 20 frames");
    }

    /// Send a JSON-RPC 2.0 request frame.
    async fn send_request(&mut self, id: u64, method: &str, params: Value) {
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });
        self.sink
            .send(Message::Text(serde_json::to_string(&req).unwrap().into()))
            .await
            .expect("send request");
    }

    /// Perform the full auth handshake: read challenge, sign, send authenticate,
    /// read auth response.  Returns the `pub_id` string from the relay's response.
    async fn authenticate(&mut self, identity: &Identity) -> String {
        // The relay sends a challenge notification immediately on connect.
        let challenge = self.recv_notification().await;
        assert_eq!(
            challenge["method"].as_str().unwrap(),
            rpc_methods::CHALLENGE,
            "first notification must be a challenge"
        );
        let nonce = challenge["params"]["nonce"]
            .as_str()
            .expect("challenge must have nonce")
            .to_string();

        let (pub_key_b64, sig_b64) = sign_challenge(identity, &nonce);

        self.send_request(
            1,
            rpc_methods::AUTHENTICATE,
            json!({
                "pub_key": pub_key_b64,
                "nonce": nonce,
                "signature": sig_b64
            }),
        )
        .await;

        let resp = self.recv_response(1).await;
        assert!(
            resp.get("error").is_none(),
            "auth must succeed, got error: {}",
            resp["error"]
        );
        resp["result"]["pub_id"]
            .as_str()
            .expect("auth response must contain pub_id")
            .to_string()
    }

    /// Drain notifications until we see a `directory_list`.  This confirms the
    /// client is fully registered as online before we start sending messages.
    async fn wait_for_directory_list(&mut self) {
        for _ in 0..20 {
            let frame = self.recv_frame().await;
            if frame.get("id").is_none()
                && frame["method"].as_str() == Some(rpc_methods::DIRECTORY_LIST)
            {
                return;
            }
        }
        panic!("did not receive directory_list within 20 frames");
    }
}

/// Scan up to 20 frames from `client` looking for a `deliver` notification.
/// Skips user_joined, directory_list, and any other non-deliver notifications.
async fn recv_deliver(client: &mut RawWsClient) -> Value {
    for _ in 0..20 {
        let frame = client.recv_frame().await;
        if frame.get("id").is_none() && frame["method"].as_str() == Some(rpc_methods::DELIVER) {
            return frame;
        }
    }
    panic!("did not receive a deliver notification within 20 frames");
}

// ---------------------------------------------------------------------------
// Test 1: auth_success_returns_pub_id
// ---------------------------------------------------------------------------

/// The relay must return the correct `pub_id` (hex(SHA-256(verifying_key)))
/// in the `authenticate` response result.
#[tokio::test]
async fn auth_success_returns_pub_id() {
    let relay_url = spawn_relay().await;
    let mut client = RawWsClient::connect(&relay_url).await;
    let identity = Identity::generate();

    let returned_pub_id = client.authenticate(&identity).await;

    assert_eq!(
        returned_pub_id,
        identity.pub_id().0,
        "relay must echo back pub_id = hex(SHA-256(verifying_key))"
    );
    assert_eq!(
        returned_pub_id.len(),
        64,
        "pub_id must be 64 hex chars (SHA-256)"
    );
}

// ---------------------------------------------------------------------------
// Test 2: auth_rejected_wrong_signature
// ---------------------------------------------------------------------------

/// A bogus signature must be rejected with JSON-RPC error code -32001 (AUTH_FAILED).
#[tokio::test]
async fn auth_rejected_wrong_signature() {
    let relay_url = spawn_relay().await;
    let mut client = RawWsClient::connect(&relay_url).await;

    let challenge = client.recv_notification().await;
    assert_eq!(
        challenge["method"].as_str().unwrap(),
        rpc_methods::CHALLENGE
    );
    let nonce = challenge["params"]["nonce"]
        .as_str()
        .expect("challenge must have nonce")
        .to_string();

    let identity = Identity::generate();
    let (pub_key_b64, _) = sign_challenge(&identity, &nonce);

    // 64 zero bytes base64-encoded — a syntactically valid but cryptographically wrong signature.
    let bogus_sig = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);

    client
        .send_request(
            1,
            rpc_methods::AUTHENTICATE,
            json!({
                "pub_key": pub_key_b64,
                "nonce": nonce,
                "signature": bogus_sig
            }),
        )
        .await;

    let resp = client.recv_response(1).await;

    assert!(
        resp.get("error").is_some(),
        "bogus signature must be rejected, got: {resp}"
    );
    assert_eq!(
        resp["error"]["code"].as_i64().unwrap(),
        rpc_errors::AUTH_FAILED as i64,
        "auth failure must use error code {}, got: {}",
        rpc_errors::AUTH_FAILED,
        resp["error"]["code"]
    );
}

// ---------------------------------------------------------------------------
// Test 3: broadcast_deliver_round_trip
// ---------------------------------------------------------------------------

/// client1 broadcasts a message; client2 receives it.
///
/// Asserts:
///   - The relay's `SendAck` (BroadcastResult) contains a 36-character hyphenated UUID.
///   - The `deliver` notification carries `from` == client1's pub_id.
///   - The `deliver` payload is byte-for-byte identical to what client1 sent
///     (the relay must not modify the opaque payload).
#[tokio::test]
async fn broadcast_deliver_round_trip() {
    let relay_url = spawn_relay().await;

    let mut client1 = RawWsClient::connect(&relay_url).await;
    let mut client2 = RawWsClient::connect(&relay_url).await;

    let identity1 = Identity::generate();
    let identity2 = Identity::generate();

    // Auth both clients.  client2 may receive a user_joined for client1 during
    // its handshake; recv_response skips notifications so this is handled.
    let pub_id1 = client1.authenticate(&identity1).await;
    let _pub_id2 = client2.authenticate(&identity2).await;

    // Wait for both to receive directory_list — this guarantees both are fully
    // registered as online before client1 broadcasts.
    client1.wait_for_directory_list().await;
    client2.wait_for_directory_list().await;

    // Build the broadcast payload via BroadcastParams so we get the canonical
    // serde_with Base64 encoding.  This is exactly what a WASM client would do.
    let raw_payload: Vec<u8> = b"hello from wasm protocol test".to_vec();
    let broadcast_params = BroadcastParams {
        payload: raw_payload.clone(),
    };
    let params_value =
        serde_json::to_value(&broadcast_params).expect("BroadcastParams must serialize");
    // Extract the base64 string so we can compare it against the deliver payload.
    let payload_b64 = params_value["payload"]
        .as_str()
        .expect("BroadcastParams.payload must serialize as a base64 string")
        .to_string();

    client1
        .send_request(2, rpc_methods::BROADCAST, params_value)
        .await;

    // Receive the BroadcastResult ack on client1.
    let ack = client1.recv_response(2).await;
    assert!(
        ack.get("error").is_none(),
        "broadcast must succeed, got error: {}",
        ack["error"]
    );
    let message_id = ack["result"]["message_id"]
        .as_str()
        .expect("BroadcastResult must contain message_id");
    assert_eq!(
        message_id.len(),
        36,
        "message_id must be a 36-char hyphenated UUID, got: {message_id}"
    );

    // client2 receives the deliver notification.
    let deliver = recv_deliver(&mut client2).await;

    assert_eq!(
        deliver["method"].as_str().unwrap(),
        rpc_methods::DELIVER,
        "notification method must be 'deliver'"
    );
    assert_eq!(
        deliver["params"]["from"].as_str().unwrap(),
        pub_id1,
        "relay must stamp 'from' as client1's authenticated pub_id"
    );

    // CRITICAL: payload must be byte-for-byte identical.  The relay is an
    // opaque pipe — it must never modify the payload.
    assert_eq!(
        deliver["params"]["payload"].as_str().unwrap(),
        payload_b64,
        "relay must not modify the opaque payload; base64 strings must be identical"
    );
}
