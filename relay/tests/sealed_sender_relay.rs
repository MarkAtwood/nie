//! Integration tests for the sealed-sender relay handlers (nie-rwr7.9).
//!
//! These tests cover: SEALED_BROADCAST → SEALED_DELIVER fan-out, SEALED_WHISPER →
//! SEALED_WHISPER_DELIVER point-to-point, PUBLISH_HPKE_KEY store, and GET_HPKE_KEY
//! retrieve.
//!
//! Oracle: bead spec nie-rwr7 plus CLAUDE.md §sealed sender architecture:
//! - sealed_deliver has no `from` field (relay cannot name the sender)
//! - sealed bytes forwarded unchanged (opaque relay principle — invariant #3)
//! - publish/get: 32-byte key stored and retrieved exactly
//! - wrong-size key: relay rejects before storing (validated input)

use std::time::Duration;

use axum::{routing::get, Router};
use nie_core::{
    identity::Identity,
    protocol::{
        rpc_methods, BroadcastResult, GetHpkeKeyParams, GetHpkeKeyResult, JsonRpcNotification,
        JsonRpcRequest, JsonRpcResponse, OkResult, PublishHpkeKeyParams, SealedBroadcastParams,
        SealedDeliverParams, SealedWhisperDeliverParams, SealedWhisperParams,
    },
    transport::{self, next_request_id, ClientEvent},
};
use nie_relay::{state::AppState, ws::ws_handler};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Start an in-process relay on a random OS-assigned port.
/// Returns the WebSocket URL.  Each call gets its own temp SQLite file so
/// parallel test runs never collide.
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
        let _db_file = db_file; // keep temp file alive for the relay's lifetime
        axum::serve(listener, app).await.unwrap();
    });

    format!("ws://127.0.0.1:{port}/ws")
}

/// Drain incoming events until a DirectoryList notification arrives,
/// confirming auth succeeded and the client is registered as online.
async fn wait_for_directory_list(rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>) {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(ClientEvent::Message(notif)))
                if notif.method == rpc_methods::DIRECTORY_LIST =>
            {
                return;
            }
            Ok(Some(_)) => {} // AuthOk response, UserJoined, etc. — keep waiting
            Ok(None) => panic!("relay channel closed before DirectoryList"),
            Err(_) => panic!("timed out waiting for DirectoryList"),
        }
    }
}

/// Drain events until a `Response` arrives, then return it.
async fn wait_for_response(rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>) -> JsonRpcResponse {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(ClientEvent::Response(resp))) => return resp,
            Ok(Some(_)) => {} // notifications — keep draining
            Ok(None) => panic!("relay channel closed before Response"),
            Err(_) => panic!("timed out waiting for Response"),
        }
    }
}

/// Check for a notification matching `method` within the timeout.
/// Returns Some(notification) if found, None if timeout expires without one.
async fn poll_for_notification(
    rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>,
    method: &str,
    timeout: Duration,
) -> Option<JsonRpcNotification> {
    loop {
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(ClientEvent::Message(notif))) if notif.method == method => {
                return Some(notif);
            }
            Ok(Some(ClientEvent::Response(_))) | Ok(Some(ClientEvent::Message(_))) => {
                // Other notifications or responses — keep draining
            }
            Ok(Some(ClientEvent::Reconnecting { .. })) | Ok(Some(ClientEvent::Reconnected)) => {}
            Ok(None) | Err(_) => return None,
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: sealed_broadcast_forwarded_opaque
//
// Alice sends sealed_broadcast with known bytes; Bob receives sealed_deliver
// with those same bytes and no from field.  Alice receives a BroadcastResult
// response with a message_id.
//
// Oracle:
//   - sealed bytes are an external constant (not derived from the code under
//     test) — relay must forward them unchanged.
//   - sealed_deliver has no `from` field (bead spec §Relay behavior).
//   - relay set message_id is a UUID string (non-empty).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sealed_broadcast_forwarded_opaque() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_pub_id = alice.pub_id().0.clone();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut alice_rx = alice_conn.rx;

    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    wait_for_directory_list(&mut alice_rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    // A known byte sequence as the sealed ciphertext blob — external constant,
    // not derived from any function under test.
    let sealed_bytes: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::SEALED_BROADCAST,
        SealedBroadcastParams {
            sealed: sealed_bytes.clone(),
        },
    )
    .expect("SealedBroadcastParams must serialize");

    alice_conn.tx.send(req).await.expect("alice send");

    // Bob waits for the sealed_deliver notification.
    let deliver_notif = loop {
        match tokio::time::timeout(Duration::from_secs(5), bob_conn.rx.recv()).await {
            Ok(Some(ClientEvent::Message(notif)))
                if notif.method == rpc_methods::SEALED_DELIVER =>
            {
                break notif;
            }
            Ok(Some(_)) => {} // UserJoined, other notifications
            Ok(None) => panic!("bob channel closed before sealed_deliver"),
            Err(_) => panic!("timed out waiting for sealed_deliver notification"),
        }
    };

    // Assert: the raw JSON notification does NOT contain alice's pub_id anywhere.
    // The relay must be blind to sender identity.  Serialize before consuming params.
    let raw_json = serde_json::to_string(&deliver_notif).unwrap();
    assert!(
        !raw_json.contains(&alice_pub_id),
        "sealed_deliver notification must not leak alice's pub_id; raw JSON: {raw_json}"
    );

    // Parse the sealed_deliver params — this type has only `sealed`, no `from`.
    let params: SealedDeliverParams = serde_json::from_value(
        deliver_notif
            .params
            .expect("sealed_deliver notification must have params"),
    )
    .expect("SealedDeliverParams must deserialize");

    assert_eq!(
        params.sealed, sealed_bytes,
        "sealed bytes forwarded to bob must exactly match what alice sent"
    );

    // Alice must receive a BroadcastResult response with a non-empty message_id.
    let resp = wait_for_response(&mut alice_rx).await;
    assert!(
        resp.is_success(),
        "alice must receive a success response for sealed_broadcast, got: {resp:?}"
    );
    let result: BroadcastResult =
        serde_json::from_value(resp.result.expect("result must be present"))
            .expect("BroadcastResult must deserialize");
    assert!(
        !result.message_id.is_empty(),
        "message_id in BroadcastResult must be non-empty"
    );
}

// ---------------------------------------------------------------------------
// Test 2: sealed_broadcast_not_self
//
// The relay must NOT echo a sealed_broadcast back to the sender.
//
// Oracle: existing broadcast behavior (relay excludes sender) extended to
// sealed variant.  We wait a short window and assert no sealed_deliver arrives.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sealed_broadcast_not_self() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut alice_rx = alice_conn.rx;

    // Bob connects to make the room non-empty (so the relay has someone to send to).
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    wait_for_directory_list(&mut alice_rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::SEALED_BROADCAST,
        SealedBroadcastParams {
            sealed: b"self-exclude-check".to_vec(),
        },
    )
    .expect("SealedBroadcastParams must serialize");

    alice_conn.tx.send(req).await.expect("alice send");

    // Drain alice's channel for 300 ms; she must not receive sealed_deliver.
    let self_deliver = poll_for_notification(
        &mut alice_rx,
        rpc_methods::SEALED_DELIVER,
        Duration::from_millis(300),
    )
    .await;

    assert!(
        self_deliver.is_none(),
        "sender must not receive their own sealed_deliver; got: {self_deliver:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: sealed_whisper_forwarded_opaque
//
// Alice sends sealed_whisper to Bob.  Bob receives sealed_whisper_deliver with
// the correct `to` field and matching sealed bytes.  The notification has no
// `from` field.
//
// Oracle:
//   - sealed bytes forwarded unchanged (opaque relay principle)
//   - sealed_whisper_deliver has no `from` field (bead spec §Relay behavior)
//   - `to` field carries bob's pub_id as specified by alice (DM addressing is
//     visible to the relay — that is intentional per the epic design)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sealed_whisper_forwarded_opaque() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let bob_pub_id = bob.pub_id().0.clone();
    let alice_pub_id = alice.pub_id().0.clone();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut alice_rx = alice_conn.rx;
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    wait_for_directory_list(&mut alice_rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    let sealed_bytes: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0x10, 0x20, 0x30, 0x40];

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::SEALED_WHISPER,
        SealedWhisperParams {
            to: bob_pub_id.clone(),
            sealed: sealed_bytes.clone(),
        },
    )
    .expect("SealedWhisperParams must serialize");

    alice_conn.tx.send(req).await.expect("alice send");

    // Bob waits for the sealed_whisper_deliver notification.
    let deliver_notif = loop {
        match tokio::time::timeout(Duration::from_secs(5), bob_conn.rx.recv()).await {
            Ok(Some(ClientEvent::Message(notif)))
                if notif.method == rpc_methods::SEALED_WHISPER_DELIVER =>
            {
                break notif;
            }
            Ok(Some(_)) => {} // UserJoined, other notifications
            Ok(None) => panic!("bob channel closed before sealed_whisper_deliver"),
            Err(_) => panic!("timed out waiting for sealed_whisper_deliver notification"),
        }
    };

    let params: SealedWhisperDeliverParams = serde_json::from_value(
        deliver_notif
            .params
            .clone()
            .expect("sealed_whisper_deliver notification must have params"),
    )
    .expect("SealedWhisperDeliverParams must deserialize");

    assert_eq!(
        params.sealed, sealed_bytes,
        "sealed bytes in sealed_whisper_deliver must match what alice sent"
    );

    assert_eq!(
        params.to, bob_pub_id,
        "sealed_whisper_deliver.to must be bob's pub_id"
    );

    // Assert: raw notification JSON does NOT contain alice's pub_id.
    let raw_json = serde_json::to_string(&deliver_notif).unwrap();
    assert!(
        !raw_json.contains(&alice_pub_id),
        "sealed_whisper_deliver must not leak alice's pub_id; raw JSON: {raw_json}"
    );

    // Alice receives OkResult for the whisper send.
    let resp = wait_for_response(&mut alice_rx).await;
    assert!(
        resp.is_success(),
        "alice must receive a success response for sealed_whisper, got: {resp:?}"
    );
    let result: OkResult = serde_json::from_value(resp.result.expect("result must be present"))
        .expect("OkResult must deserialize");
    assert!(result.ok, "OkResult.ok must be true");
}

// ---------------------------------------------------------------------------
// Test 4: publish_and_get_hpke_key
//
// Alice publishes a 32-byte HPKE public key.  Bob retrieves it and gets back
// exactly the same bytes.
//
// Oracle:
//   - 32-byte key is the X25519 / HPKE key size (external constant)
//   - round-trip: store then retrieve — the stored bytes must match verbatim
//   - GetHpkeKeyResult carries pub_id + public_key (both present when found)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_and_get_hpke_key() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_pub_id = alice.pub_id().0.clone();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut alice_rx = alice_conn.rx;
    wait_for_directory_list(&mut alice_rx).await;

    // 32-byte HPKE public key — a known external constant (X25519 public key size).
    // Value chosen to be recognizable and not all-zeros (all-zeros is an invalid
    // X25519 point, so using it here would conflate "wrong value" with "invalid key").
    let alice_hpke_key: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    // Alice publishes her HPKE key.
    let pub_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::PUBLISH_HPKE_KEY,
        PublishHpkeKeyParams {
            public_key: alice_hpke_key.to_vec(),
        },
    )
    .expect("PublishHpkeKeyParams must serialize");

    alice_conn
        .tx
        .send(pub_req)
        .await
        .expect("alice publish send");

    let pub_resp = wait_for_response(&mut alice_rx).await;
    assert!(
        pub_resp.is_success(),
        "publish_hpke_key must return a success response, got: {pub_resp:?}"
    );
    let ok: OkResult = serde_json::from_value(pub_resp.result.expect("result must be present"))
        .expect("OkResult must deserialize");
    assert!(ok.ok, "publish_hpke_key OkResult.ok must be true");

    // Bob connects and retrieves alice's key.
    let bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");
    let mut bob_rx = bob_conn.rx;
    wait_for_directory_list(&mut bob_rx).await;

    let get_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::GET_HPKE_KEY,
        GetHpkeKeyParams {
            pub_id: alice_pub_id.clone(),
        },
    )
    .expect("GetHpkeKeyParams must serialize");

    bob_conn.tx.send(get_req).await.expect("bob get send");

    let get_resp = wait_for_response(&mut bob_rx).await;
    assert!(
        get_resp.is_success(),
        "get_hpke_key must return a success response, got: {get_resp:?}"
    );
    let result: GetHpkeKeyResult =
        serde_json::from_value(get_resp.result.expect("result must be present"))
            .expect("GetHpkeKeyResult must deserialize");

    assert_eq!(
        result.pub_id, alice_pub_id,
        "GetHpkeKeyResult.pub_id must match alice's pub_id"
    );
    assert_eq!(
        result.public_key,
        Some(alice_hpke_key.to_vec()),
        "GetHpkeKeyResult.public_key must exactly match what alice published"
    );
}

// ---------------------------------------------------------------------------
// Test 5: publish_hpke_key_wrong_size
//
// Alice sends publish_hpke_key with a 16-byte key (wrong size; X25519 requires
// 32 bytes).  The relay must return an error response, not OkResult.
//
// Oracle: 32 bytes is the HPKE X25519 public key size (RFC 9180 §4.1).
// A 16-byte key is structurally invalid; the relay must reject it.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_hpke_key_wrong_size() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut alice_rx = alice_conn.rx;
    wait_for_directory_list(&mut alice_rx).await;

    // 16-byte key — wrong size; relay must reject.
    let bad_key: Vec<u8> = vec![
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a,
    ];

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::PUBLISH_HPKE_KEY,
        PublishHpkeKeyParams {
            public_key: bad_key,
        },
    )
    .expect("PublishHpkeKeyParams must serialize");

    alice_conn.tx.send(req).await.expect("alice send");

    let resp = wait_for_response(&mut alice_rx).await;
    assert!(
        resp.error.is_some(),
        "publish_hpke_key with wrong-size key must return an error, got: {resp:?}"
    );
    let error = resp.error.unwrap();
    assert!(
        error.code < 0,
        "error code must be negative (JSON-RPC convention), got: {}",
        error.code
    );
}

// ---------------------------------------------------------------------------
// Test 6: get_hpke_key_not_found
//
// Bob requests the HPKE key for a pub_id that has never published one.
// The relay must return a success response with public_key = None (not an error).
//
// Oracle: absence of a key is not an error — it means the user has not yet
// published their HPKE key.  Returning None lets callers distinguish "not found"
// from "relay error".
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_hpke_key_not_found() {
    let relay_url = spawn_relay().await;

    let bob = Identity::generate();
    let bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");
    let mut bob_rx = bob_conn.rx;
    wait_for_directory_list(&mut bob_rx).await;

    // Query for a pub_id that has never published an HPKE key.
    // 64 hex chars of zeros is a structurally valid pub_id format (SHA-256 hash),
    // but refers to nobody who has ever connected to this relay instance.
    let phantom_pub_id = "0".repeat(64);

    let get_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::GET_HPKE_KEY,
        GetHpkeKeyParams {
            pub_id: phantom_pub_id.clone(),
        },
    )
    .expect("GetHpkeKeyParams must serialize");

    bob_conn.tx.send(get_req).await.expect("bob send");

    let get_resp = wait_for_response(&mut bob_rx).await;
    assert!(
        get_resp.is_success(),
        "get_hpke_key for unknown pub_id must return success (not error), got: {get_resp:?}"
    );
    let result: GetHpkeKeyResult =
        serde_json::from_value(get_resp.result.expect("result must be present"))
            .expect("GetHpkeKeyResult must deserialize");

    assert_eq!(
        result.pub_id, phantom_pub_id,
        "GetHpkeKeyResult.pub_id must echo back the requested pub_id"
    );
    assert_eq!(
        result.public_key, None,
        "GetHpkeKeyResult.public_key must be None for an unknown pub_id"
    );
}

// ---------------------------------------------------------------------------
// Test 7: sealed_deliver_has_no_from_field_in_raw_json
//
// Confirms the "no from field" invariant at the raw JSON level, not just by
// deserializing into SealedDeliverParams.  This catches a regression where
// the relay adds a `from` field that the struct silently ignores.
//
// Oracle: bead spec nie-rwr7 §Relay behavior — relay no longer learns who
// sent any message.  The wire format of sealed_deliver MUST NOT include `from`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sealed_deliver_has_no_from_field_in_raw_json() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_pub_id = alice.pub_id().0.clone();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut alice_rx = alice_conn.rx;
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    wait_for_directory_list(&mut alice_rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::SEALED_BROADCAST,
        SealedBroadcastParams {
            sealed: b"from-field-probe".to_vec(),
        },
    )
    .expect("SealedBroadcastParams must serialize");

    alice_conn.tx.send(req).await.expect("alice send");

    // Receive the raw JSON string before deserializing.
    let deliver_notif = loop {
        match tokio::time::timeout(Duration::from_secs(5), bob_conn.rx.recv()).await {
            Ok(Some(ClientEvent::Message(notif)))
                if notif.method == rpc_methods::SEALED_DELIVER =>
            {
                break notif;
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("bob channel closed before sealed_deliver"),
            Err(_) => panic!("timed out waiting for sealed_deliver"),
        }
    };

    let raw_json = serde_json::to_string(&deliver_notif).unwrap();

    // The raw wire JSON must not contain the string "from" as a key.
    // We check for `"from"` (with quotes) to avoid false-positives on values.
    assert!(
        !raw_json.contains("\"from\""),
        "sealed_deliver wire JSON must not contain a 'from' field; raw JSON: {raw_json}"
    );

    // Must not contain alice's pub_id (identity leak check).
    assert!(
        !raw_json.contains(&alice_pub_id),
        "sealed_deliver wire JSON must not contain alice's pub_id; raw JSON: {raw_json}"
    );
}

// ---------------------------------------------------------------------------
// Test 8: sealed_broadcast_reaches_all_others
//
// With three clients (alice, bob, carol), alice's sealed_broadcast must be
// delivered to both bob and carol.
//
// Oracle: fan-out semantics derived from plain broadcast behavior, applied to
// sealed variant.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sealed_broadcast_reaches_all_others() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let carol = Identity::generate();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut alice_rx = alice_conn.rx;
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");
    let mut carol_conn = transport::connect(&relay_url, &carol, false, None)
        .await
        .expect("carol connect");

    wait_for_directory_list(&mut alice_rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;
    wait_for_directory_list(&mut carol_conn.rx).await;

    let sealed_bytes: Vec<u8> = vec![0x11, 0x22, 0x33, 0x44];

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::SEALED_BROADCAST,
        SealedBroadcastParams {
            sealed: sealed_bytes.clone(),
        },
    )
    .expect("SealedBroadcastParams must serialize");

    alice_conn.tx.send(req).await.expect("alice send");

    // Both bob and carol must receive the sealed_deliver notification.
    let bob_notif = loop {
        match tokio::time::timeout(Duration::from_secs(5), bob_conn.rx.recv()).await {
            Ok(Some(ClientEvent::Message(n))) if n.method == rpc_methods::SEALED_DELIVER => {
                break n;
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("bob channel closed before sealed_deliver"),
            Err(_) => panic!("timed out waiting for bob's sealed_deliver"),
        }
    };

    let carol_notif = loop {
        match tokio::time::timeout(Duration::from_secs(5), carol_conn.rx.recv()).await {
            Ok(Some(ClientEvent::Message(n))) if n.method == rpc_methods::SEALED_DELIVER => {
                break n;
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("carol channel closed before sealed_deliver"),
            Err(_) => panic!("timed out waiting for carol's sealed_deliver"),
        }
    };

    let bob_params: SealedDeliverParams =
        serde_json::from_value(bob_notif.params.unwrap()).expect("bob SealedDeliverParams");
    let carol_params: SealedDeliverParams =
        serde_json::from_value(carol_notif.params.unwrap()).expect("carol SealedDeliverParams");

    assert_eq!(
        bob_params.sealed, sealed_bytes,
        "bob's sealed bytes must match alice's original"
    );
    assert_eq!(
        carol_params.sealed, sealed_bytes,
        "carol's sealed bytes must match alice's original"
    );
}
