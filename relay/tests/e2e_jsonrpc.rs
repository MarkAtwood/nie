//! End-to-end integration tests for the JSON-RPC 2.0 wire protocol.
//!
//! Each test spawns an in-process relay on a random port, runs real WebSocket
//! connections through the full auth handshake, and asserts on the wire-level
//! JSON-RPC messages exchanged.
//!
//! Oracle: the JSON-RPC 2.0 specification and the nie wire protocol spec in
//! CLAUDE.md.  Tests observe actual relay output, not roundtrips through the
//! same code paths.

use std::time::Duration;

use axum::{routing::get, Router};
use futures::{SinkExt, StreamExt};
use nie_core::{
    identity::Identity,
    protocol::{
        rpc_errors, rpc_methods, BroadcastParams, DeliverParams, GroupAddParams, GroupCreateParams,
        GroupCreateResult, GroupDeliverParams, GroupSendParams, GroupSendResult,
        JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PublishKeyPackageParams,
        SetNicknameParams, SubscribeInvoiceResult, SubscribeRequestParams,
    },
    transport::{self, next_request_id, ClientEvent},
};
use nie_relay::{
    state::{AppState, MerchantWallet},
    ws::ws_handler,
};
use nie_wallet::address::{SaplingExtendedSpendingKey, ZcashNetwork};
use tokio_tungstenite::{connect_async, tungstenite::Message};

// ---------------------------------------------------------------------------
// Shared helper
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
        // Keep db_file alive for the relay's lifetime.
        let _db_file = db_file;
        axum::serve(listener, app).await.unwrap();
    });

    format!("ws://127.0.0.1:{port}/ws")
}

/// Drain incoming events on a `RelayConn` until a `DirectoryList` notification
/// arrives, confirming auth succeeded and the client is registered as online.
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

// ---------------------------------------------------------------------------
// Test 1: two_client_message_delivery
// ---------------------------------------------------------------------------

/// Alice sends a broadcast; bob receives a deliver notification whose payload
/// exactly matches what alice sent.
#[tokio::test]
async fn two_client_message_delivery() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    // Wait until both clients have their DirectoryList — guarantees each is
    // registered as online before alice broadcasts.
    let mut alice_rx = alice_conn.rx;
    wait_for_directory_list(&mut alice_rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    let original_payload: Vec<u8> = b"hello from alice".to_vec();

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams {
            payload: original_payload.clone(),
        },
    )
    .expect("BroadcastParams must serialize");

    alice_conn.tx.send(req).await.expect("alice send");

    // Bob waits for the deliver notification.
    let deliver_notif = loop {
        match tokio::time::timeout(Duration::from_secs(5), bob_conn.rx.recv()).await {
            Ok(Some(ClientEvent::Message(notif))) if notif.method == rpc_methods::DELIVER => {
                break notif;
            }
            Ok(Some(_)) => {} // UserJoined, etc.
            Ok(None) => panic!("bob channel closed before deliver"),
            Err(_) => panic!("timed out waiting for deliver notification"),
        }
    };

    let params: DeliverParams = serde_json::from_value(
        deliver_notif
            .params
            .expect("deliver notification must have params"),
    )
    .expect("DeliverParams must deserialize");

    assert_eq!(
        params.payload, original_payload,
        "bob's deliver payload must match what alice sent"
    );
}

// ---------------------------------------------------------------------------
// Test 2: from_field_is_alice_pub_id
// ---------------------------------------------------------------------------

/// The relay stamps `DeliverParams.from` from the authenticated sender's
/// pub_id — never from anything the client provides.  Verify bob's deliver
/// notification carries alice's exact pub_id.
#[tokio::test]
async fn from_field_is_alice_pub_id() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_pub_id = alice.pub_id().0.clone();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    let mut alice_rx = alice_conn.rx;
    wait_for_directory_list(&mut alice_rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams {
            payload: b"identify yourself".to_vec(),
        },
    )
    .expect("BroadcastParams must serialize");

    alice_conn.tx.send(req).await.expect("alice send");

    let deliver_notif = loop {
        match tokio::time::timeout(Duration::from_secs(5), bob_conn.rx.recv()).await {
            Ok(Some(ClientEvent::Message(notif))) if notif.method == rpc_methods::DELIVER => {
                break notif;
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("bob channel closed before deliver"),
            Err(_) => panic!("timed out waiting for deliver notification"),
        }
    };

    let params: DeliverParams = serde_json::from_value(
        deliver_notif
            .params
            .expect("deliver notification must have params"),
    )
    .expect("DeliverParams must deserialize");

    assert_eq!(
        params.from, alice_pub_id,
        "DeliverParams.from must equal alice's pub_id (relay-set, not client-provided)"
    );
}

// ---------------------------------------------------------------------------
// Test 3: old_format_client_gets_error
// ---------------------------------------------------------------------------

/// A client that sends the old RelayMessage wire format ({"type":"authenticate",...})
/// instead of JSON-RPC 2.0 must receive a JSON-RPC error response.
///
/// The relay parses the first post-challenge frame as `JsonRpcRequest`.
/// The old format has no `jsonrpc`, `id`, or `method` fields, so deserialization
/// fails and the relay responds with PARSE_ERROR (-32700).
#[tokio::test]
async fn old_format_client_gets_error() {
    let relay_url = spawn_relay().await;

    let (ws, _) = connect_async(&relay_url).await.expect("raw ws connect");
    let (mut sink, mut stream) = ws.split();

    // Receive the challenge notification.
    let challenge_text = loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => break t.to_string(),
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {}
            Ok(other) => panic!("unexpected frame waiting for challenge: {other:?}"),
            Err(_) => panic!("timed out waiting for challenge"),
        }
    };

    // Decode the nonce so we can produce a syntactically plausible old-format message.
    let challenge: JsonRpcNotification =
        serde_json::from_str(&challenge_text).expect("challenge must be valid JSON-RPC");
    let nonce = challenge
        .params
        .as_ref()
        .and_then(|p| p.get("nonce"))
        .and_then(|v| v.as_str())
        .expect("challenge must carry a nonce")
        .to_string();

    // Build the OLD wire format (pre-JSON-RPC), using a freshly generated key
    // and a valid signature.  The format itself is what the relay rejects — the
    // crypto correctness does not matter for this test.
    let id = Identity::generate();
    use base64::Engine;
    let pub_key_b64 = id.pub_key_b64();
    let sig_bytes = id.sign(nonce.as_bytes()).to_bytes();
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes);

    // Old RelayMessage format: tag-based, no jsonrpc/id fields.
    let old_format = serde_json::json!({
        "type": "authenticate",
        "pub_key": pub_key_b64,
        "nonce": nonce,
        "signature": sig_b64
    });
    let old_format_text = serde_json::to_string(&old_format).unwrap();

    sink.send(Message::Text(old_format_text.into()))
        .await
        .expect("send old-format message");

    // The relay must respond with a JSON-RPC error (parse error or invalid request).
    let response_text = loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => break t.to_string(),
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {}
            Ok(Some(Ok(Message::Close(_)))) => {
                panic!("relay closed connection instead of sending error response")
            }
            Ok(other) => panic!("unexpected frame waiting for error response: {other:?}"),
            Err(_) => panic!("timed out waiting for error response"),
        }
    };

    let resp: JsonRpcResponse =
        serde_json::from_str(&response_text).expect("relay error must be valid JSON-RPC response");

    assert!(
        resp.error.is_some(),
        "relay must return an error for old-format messages, got: {response_text}"
    );

    let error = resp.error.unwrap();
    assert!(
        error.code < 0,
        "JSON-RPC error code must be negative, got: {}  (full response: {response_text})",
        error.code
    );

    // The relay sends PARSE_ERROR (-32700) specifically when JsonRpcRequest
    // deserialization fails.  Verify the exact code.
    assert_eq!(
        error.code,
        rpc_errors::PARSE_ERROR,
        "old-format message must trigger PARSE_ERROR (-32700), got: {}",
        error.code
    );
}

// ---------------------------------------------------------------------------
// Test 4: subscribe_request_returns_invoice
// ---------------------------------------------------------------------------

/// Start an in-process relay configured with a test merchant DFVK derived from
/// an all-zero 64-byte seed (testnet, account 0).
///
/// The DFVK is a viewing key only — the relay cannot spend funds.
async fn spawn_relay_with_merchant() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let db_file = tempfile::NamedTempFile::new().unwrap();
    let db_url = format!("sqlite:{}?mode=rwc", db_file.path().display());

    let state = AppState::new(&db_url, 60, false, 1_000_000, 30, 120u32)
        .await
        .unwrap();

    // Derive a DFVK from a fixed all-zero test seed (testnet, account 0).
    // This seed is an external test vector — it is not derived from nor equal
    // to any identity key, satisfying the key-separation invariant.
    let seed = [0u8; 64];
    let dfvk = SaplingExtendedSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 0).to_dfvk();
    state.set_merchant(MerchantWallet {
        dfvk,
        network: ZcashNetwork::Testnet,
    });

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    tokio::spawn(async move {
        let _db_file = db_file;
        axum::serve(listener, app).await.unwrap();
    });

    format!("ws://127.0.0.1:{port}/ws")
}

/// Drain incoming events, returning the first `ClientEvent::Response`.
///
/// Skips notifications (DirectoryList, UserJoined, etc.) which arrive before
/// the response.  Panics after a 5-second timeout.
async fn wait_for_response(rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>) -> JsonRpcResponse {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(ClientEvent::Response(resp))) => return resp,
            Ok(Some(_)) => {} // notifications — keep waiting
            Ok(None) => panic!("relay channel closed before response arrived"),
            Err(_) => panic!("timed out waiting for JSON-RPC response"),
        }
    }
}

/// A client that authenticates successfully and sends `subscribe_request` for
/// 30 days receives a `SubscribeInvoiceResult` with a Sapling testnet address.
///
/// Oracles:
/// - Sapling testnet addresses start with "ztestsapling" — Zcash protocol spec,
///   not derived from the code under test.
/// - `amount_zatoshi` matches the configured constant 1_000_000 passed to
///   `AppState::new`.
/// - `expires_at` must be in SQLite datetime format "YYYY-MM-DD HH:MM:SS"
///   (see CLAUDE.md §SQLite datetime invariant).
#[tokio::test]
async fn subscribe_request_returns_invoice() {
    let relay_url = spawn_relay_with_merchant().await;

    let alice = Identity::generate();
    let mut alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");

    wait_for_directory_list(&mut alice_conn.rx).await;

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::SUBSCRIBE_REQUEST,
        SubscribeRequestParams { duration_days: 30 },
    )
    .expect("SubscribeRequestParams must serialize");
    let req_id = req.id;

    alice_conn
        .tx
        .send(req)
        .await
        .expect("alice send subscribe_request");

    let resp = wait_for_response(&mut alice_conn.rx).await;

    assert_eq!(resp.id, req_id, "response id must match request id");
    assert!(
        resp.error.is_none(),
        "subscribe_request must not return an error, got: {:?}",
        resp.error
    );

    let result_val = resp
        .result
        .expect("subscribe_request response must have a result");
    let result: SubscribeInvoiceResult = serde_json::from_value(result_val)
        .expect("result must deserialize as SubscribeInvoiceResult");

    assert!(
        !result.invoice_id.is_empty(),
        "invoice_id must be a non-empty string"
    );

    // Oracle: Sapling testnet bech32 addresses start with "ztestsapling".
    // Source: ZIP-316 and the Zcash protocol specification.
    assert!(
        result.address.starts_with("ztestsapling"),
        "expected a Sapling testnet address starting with 'ztestsapling', got: {}",
        result.address
    );

    // Oracle: amount matches the 1_000_000 zatoshi constant passed to AppState::new.
    assert_eq!(
        result.amount_zatoshi, 1_000_000,
        "amount_zatoshi must match the configured subscription price"
    );

    // Oracle: expires_at must be "YYYY-MM-DD HH:MM:SS" — no 'T' separator, no 'Z'.
    // See CLAUDE.md §SQLite datetime invariant.
    assert!(
        !result.expires_at.is_empty(),
        "expires_at must be a non-empty datetime string"
    );
    assert!(
        !result.expires_at.contains('T'),
        "expires_at must be SQLite datetime format (no 'T'), got: {}",
        result.expires_at
    );
    assert!(
        !result.expires_at.contains('Z'),
        "expires_at must be SQLite datetime format (no 'Z'), got: {}",
        result.expires_at
    );
}

// ---------------------------------------------------------------------------
// Test 5: subscribe_request_without_merchant_returns_error
// ---------------------------------------------------------------------------

/// A client that sends `subscribe_request` when no merchant DFVK is configured
/// receives a METHOD_NOT_FOUND (-32601) error.
///
/// Oracle: JSON-RPC 2.0 spec §5 and the nie wire protocol spec which states
/// that -32601 is returned when subscription payments are not configured.
#[tokio::test]
async fn subscribe_request_without_merchant_returns_error() {
    let relay_url = spawn_relay().await; // no merchant wallet

    let alice = Identity::generate();
    let mut alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");

    wait_for_directory_list(&mut alice_conn.rx).await;

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::SUBSCRIBE_REQUEST,
        SubscribeRequestParams { duration_days: 30 },
    )
    .expect("SubscribeRequestParams must serialize");
    let req_id = req.id;

    alice_conn
        .tx
        .send(req)
        .await
        .expect("alice send subscribe_request");

    let resp = wait_for_response(&mut alice_conn.rx).await;

    assert_eq!(resp.id, req_id, "response id must match request id");
    assert!(
        resp.result.is_none(),
        "error response must not have a result field, got: {:?}",
        resp.result
    );

    let error = resp
        .error
        .expect("subscribe_request without merchant must return an error");

    assert_eq!(
        error.code,
        rpc_errors::METHOD_NOT_FOUND,
        "expected METHOD_NOT_FOUND (-32601) when merchant not configured, got: {}",
        error.code
    );
}

// ---------------------------------------------------------------------------
// Test 6: group_create_add_send_deliver
// ---------------------------------------------------------------------------

/// Alice creates a group, adds Bob, Bob sends a message, Alice receives it.
/// Carol (non-member) attempts GROUP_SEND and receives NOT_A_MEMBER (-32012).
///
/// Oracle:
/// - GroupCreateResult.group_id is a non-empty relay-assigned UUID string
/// - GROUP_DELIVER.from equals Bob's authenticated pub_id (relay-set, not client-provided)
/// - GROUP_DELIVER.group_id matches the created group_id
/// - GROUP_DELIVER.payload bytes are identical to what Bob sent (relay must not transform)
/// - Carol's GROUP_SEND error code is exactly -32012 (rpc_errors::NOT_A_MEMBER)
#[tokio::test]
async fn group_create_add_send_deliver() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let bob_pub_id = bob.pub_id().0.clone();

    let mut alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    wait_for_directory_list(&mut alice_conn.rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    // Step 1: Alice creates a group.
    let create_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::GROUP_CREATE,
        GroupCreateParams {
            name: "test-group".to_string(),
        },
    )
    .expect("GroupCreateParams must serialize");
    let create_id = create_req.id;
    alice_conn
        .tx
        .send(create_req)
        .await
        .expect("alice send GROUP_CREATE");

    let create_resp = wait_for_response(&mut alice_conn.rx).await;
    assert_eq!(
        create_resp.id, create_id,
        "response id must match request id"
    );
    let group_create: GroupCreateResult = serde_json::from_value(
        create_resp
            .result
            .expect("GROUP_CREATE must return a result"),
    )
    .expect("GroupCreateResult must deserialize");
    assert!(
        !group_create.group_id.is_empty(),
        "group_id must be non-empty"
    );
    let group_id = group_create.group_id;

    // Step 2: Alice adds Bob.
    let add_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::GROUP_ADD,
        GroupAddParams {
            group_id: group_id.clone(),
            member_pub_id: bob_pub_id.clone(),
        },
    )
    .expect("GroupAddParams must serialize");
    alice_conn
        .tx
        .send(add_req)
        .await
        .expect("alice send GROUP_ADD");
    let add_resp = wait_for_response(&mut alice_conn.rx).await;
    assert!(add_resp.result.is_some(), "GROUP_ADD must succeed");
    assert!(
        add_resp.error.is_none(),
        "GROUP_ADD must not return an error"
    );

    // Step 3: Bob sends a message to the group.
    let original_payload: Vec<u8> = b"hello from bob".to_vec();
    let send_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::GROUP_SEND,
        GroupSendParams {
            group_id: group_id.clone(),
            payload: original_payload.clone(),
        },
    )
    .expect("GroupSendParams must serialize");
    let send_id = send_req.id;
    bob_conn
        .tx
        .send(send_req)
        .await
        .expect("bob send GROUP_SEND");

    // Bob receives a GroupSendResult ack.
    let send_resp = wait_for_response(&mut bob_conn.rx).await;
    assert_eq!(send_resp.id, send_id, "ack id must match send request id");
    let send_result: GroupSendResult =
        serde_json::from_value(send_resp.result.expect("GROUP_SEND must return a result"))
            .expect("GroupSendResult must deserialize");
    assert!(
        !send_result.message_id.is_empty(),
        "message_id must be non-empty"
    );

    // Step 4: Alice receives GROUP_DELIVER.
    let deliver_notif = loop {
        match tokio::time::timeout(Duration::from_secs(5), alice_conn.rx.recv()).await {
            Ok(Some(ClientEvent::Message(notif))) if notif.method == rpc_methods::GROUP_DELIVER => {
                break notif;
            }
            Ok(Some(_)) => {} // other notifications — keep waiting
            Ok(None) => panic!("alice channel closed before GROUP_DELIVER"),
            Err(_) => panic!("timed out waiting for GROUP_DELIVER"),
        }
    };

    let deliver: GroupDeliverParams = serde_json::from_value(
        deliver_notif
            .params
            .expect("GROUP_DELIVER must have params"),
    )
    .expect("GroupDeliverParams must deserialize");

    assert_eq!(
        deliver.from, bob_pub_id,
        "GROUP_DELIVER.from must be Bob's relay-authenticated pub_id"
    );
    assert_eq!(
        deliver.group_id, group_id,
        "GROUP_DELIVER.group_id must match the created group"
    );
    assert_eq!(
        deliver.payload, original_payload,
        "GROUP_DELIVER.payload must be identical to what Bob sent — relay must not transform"
    );

    // Step 5: Carol (non-member) is rejected with NOT_A_MEMBER.
    let carol = Identity::generate();
    let mut carol_conn = transport::connect(&relay_url, &carol, false, None)
        .await
        .expect("carol connect");
    wait_for_directory_list(&mut carol_conn.rx).await;

    let carol_send = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::GROUP_SEND,
        GroupSendParams {
            group_id: group_id.clone(),
            payload: b"intruder!".to_vec(),
        },
    )
    .expect("GroupSendParams must serialize");
    let carol_id = carol_send.id;
    carol_conn
        .tx
        .send(carol_send)
        .await
        .expect("carol send GROUP_SEND");

    let carol_resp = wait_for_response(&mut carol_conn.rx).await;
    assert_eq!(
        carol_resp.id, carol_id,
        "response id must match carol's request id"
    );
    assert!(
        carol_resp.result.is_none(),
        "non-member GROUP_SEND must not return a result"
    );
    let carol_err = carol_resp
        .error
        .expect("non-member GROUP_SEND must return an error");
    assert_eq!(
        carol_err.code,
        rpc_errors::NOT_A_MEMBER,
        "expected NOT_A_MEMBER (-32012), got: {}",
        carol_err.code
    );
}

// ---------------------------------------------------------------------------
// Test 7: padded_broadcast_roundtrip
// ---------------------------------------------------------------------------

/// Verifies that the relay forwards padded payloads unchanged, and that the
/// pad/unpad roundtrip correctly recovers the original bytes.
///
/// Oracle: `nie_core::messages::pad` and `unpad` specifications:
///   - pad(N bytes) → 256-byte bucket when 4 + N ≤ 256
///   - unpad(padded) → original N bytes
///   - relay forwards BroadcastParams.payload without transformation (CLAUDE.md §3)
#[tokio::test]
async fn padded_broadcast_roundtrip() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    let mut alice_rx = alice_conn.rx;
    wait_for_directory_list(&mut alice_rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    // Simulate what the CLI does after MLS encrypt: pad the ciphertext before
    // putting it in BroadcastParams.  Use a recognizable fake ciphertext so
    // the oracle is independent of the actual MLS layer.
    let fake_ciphertext: Vec<u8> = b"fake_mls_ciphertext_for_padding_test".to_vec();
    let padded =
        nie_core::messages::pad(&fake_ciphertext).expect("pad must succeed for small payload");

    // Padded output must land in the 256-byte bucket (4 + 36 = 40 < 256).
    assert_eq!(
        padded.len(),
        256,
        "pad must produce 256-byte output for 36-byte input (smallest bucket)"
    );

    // The padded bytes must not be valid UTF-8 JSON — they start with a u32le
    // length prefix, so serde_json must reject them.
    assert!(
        serde_json::from_slice::<serde_json::Value>(&padded).is_err(),
        "padded payload must not be valid JSON (starts with binary length prefix)"
    );

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams {
            payload: padded.clone(),
        },
    )
    .expect("BroadcastParams must serialize");

    alice_conn
        .tx
        .send(req)
        .await
        .expect("alice send padded broadcast");

    // Bob receives the DELIVER notification.
    let deliver_notif = loop {
        match tokio::time::timeout(Duration::from_secs(5), bob_conn.rx.recv()).await {
            Ok(Some(ClientEvent::Message(notif))) if notif.method == rpc_methods::DELIVER => {
                break notif;
            }
            Ok(Some(_)) => {} // UserJoined, etc.
            Ok(None) => panic!("bob channel closed before deliver"),
            Err(_) => panic!("timed out waiting for padded deliver notification"),
        }
    };

    let params: DeliverParams = serde_json::from_value(
        deliver_notif
            .params
            .expect("deliver notification must have params"),
    )
    .expect("DeliverParams must deserialize");

    // Relay must forward the padded bytes unchanged (CLAUDE.md §3: relay never
    // transforms payload).
    assert_eq!(
        params.payload, padded,
        "relay must forward padded payload unchanged"
    );

    // Unpad to recover the original fake ciphertext.  Oracle: the result must
    // be bit-exact equal to what alice padded.
    let recovered = nie_core::messages::unpad(&params.payload)
        .expect("unpad must succeed on relay-forwarded padded payload");

    assert_eq!(
        recovered, fake_ciphertext,
        "unpad(relay_forwarded(pad(x))) must equal x"
    );
}

// ---------------------------------------------------------------------------
// Test 8: display_name_canonicalization
// ---------------------------------------------------------------------------

/// Verifies display-name canonicalization at the wire level:
///
/// 1. SET_NICKNAME with a Right-to-Left Override (U+202E) is rejected with an
///    INVALID_REQUEST error whose message contains "bidirectional".
/// 2. GROUP_CREATE with a Zero Width Space (U+200B) succeeds; the relay strips
///    the ZWS and the GroupCreateResult.name equals the stripped string.
///
/// Oracle:
/// - Unicode UAX #9: U+202E (RIGHT-TO-LEFT OVERRIDE) is a bidirectional
///   formatting control character; the relay rejects all bidi controls.
/// - Unicode UCD: U+200B (ZERO WIDTH SPACE) is a format character (Cf) with
///   no visual width; the relay strips it silently.
/// - rpc_errors::INVALID_REQUEST == -32600 (JSON-RPC 2.0 spec §5).
#[tokio::test]
async fn display_name_canonicalization() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let mut alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");

    wait_for_directory_list(&mut alice_conn.rx).await;

    // --- Part 1: RTL override in SET_NICKNAME must be rejected ---

    let rtl_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::SET_NICKNAME,
        SetNicknameParams {
            nickname: "group\u{202E}x".to_string(),
        },
    )
    .expect("SetNicknameParams must serialize");
    let rtl_req_id = rtl_req.id;

    alice_conn
        .tx
        .send(rtl_req)
        .await
        .expect("alice send SET_NICKNAME with RTL override");

    let rtl_resp = wait_for_response(&mut alice_conn.rx).await;

    assert_eq!(
        rtl_resp.id, rtl_req_id,
        "response id must match SET_NICKNAME request id"
    );
    assert!(
        !rtl_resp.is_success(),
        "SET_NICKNAME with RTL override must not succeed"
    );

    let rtl_err = rtl_resp
        .error
        .expect("SET_NICKNAME with RTL override must return an error");

    assert_eq!(
        rtl_err.code,
        rpc_errors::INVALID_REQUEST,
        "RTL override in SET_NICKNAME must yield INVALID_REQUEST (-32600), got: {}",
        rtl_err.code
    );

    assert!(
        rtl_err.message.contains("bidirectional"),
        "error message must contain \"bidirectional\", got: \"{}\"",
        rtl_err.message
    );

    // --- Part 2: ZWS in GROUP_CREATE must be stripped silently ---

    let zws_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::GROUP_CREATE,
        GroupCreateParams {
            name: "test\u{200B}room".to_string(),
        },
    )
    .expect("GroupCreateParams must serialize");
    let zws_req_id = zws_req.id;

    alice_conn
        .tx
        .send(zws_req)
        .await
        .expect("alice send GROUP_CREATE with ZWS");

    let zws_resp = wait_for_response(&mut alice_conn.rx).await;

    assert_eq!(
        zws_resp.id, zws_req_id,
        "response id must match GROUP_CREATE request id"
    );
    assert!(
        zws_resp.is_success(),
        "GROUP_CREATE with ZWS must succeed (ZWS should be stripped), got error: {:?}",
        zws_resp.error
    );

    let result: GroupCreateResult =
        serde_json::from_value(zws_resp.result.expect("GROUP_CREATE must return a result"))
            .expect("GroupCreateResult must deserialize");

    assert_eq!(
        result.name, "testroom",
        "relay must strip ZWS from group name: expected \"testroom\", got \"{}\"",
        result.name
    );

    assert!(
        !result.group_id.is_empty(),
        "group_id must be non-empty after ZWS-stripped GROUP_CREATE"
    );
}

// ---------------------------------------------------------------------------
// Test 9: publish_key_package_rejects_malformed_device_id
// ---------------------------------------------------------------------------

/// PUBLISH_KEY_PACKAGE with a malformed device_id must receive an
/// INVALID_REQUEST error, not a success response.
///
/// Oracle:
/// - rpc_errors::INVALID_REQUEST == -32600 (JSON-RPC 2.0 spec §5)
/// - A valid device_id is exactly 64 lowercase hex characters; "notvalidhex"
///   fails both length and character constraints.
/// - The relay must return an error response (resp.error.is_some()) rather
///   than ok: true.
#[tokio::test]
async fn publish_key_package_rejects_malformed_device_id() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let mut alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");

    wait_for_directory_list(&mut alice_conn.rx).await;

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::PUBLISH_KEY_PACKAGE,
        PublishKeyPackageParams {
            device_id: "notvalidhex".to_string(),
            data: vec![1, 2, 3],
        },
    )
    .expect("PublishKeyPackageParams must serialize");
    let req_id = req.id;

    alice_conn
        .tx
        .send(req)
        .await
        .expect("alice send PUBLISH_KEY_PACKAGE with malformed device_id");

    let resp = wait_for_response(&mut alice_conn.rx).await;

    assert_eq!(resp.id, req_id, "response id must match request id");
    assert!(
        resp.result.is_none(),
        "error response must not have a result field, got: {:?}",
        resp.result
    );

    let error = resp
        .error
        .expect("PUBLISH_KEY_PACKAGE with malformed device_id must return an error");

    assert_eq!(
        error.code,
        rpc_errors::INVALID_REQUEST,
        "malformed device_id must yield INVALID_REQUEST (-32600), got: {}",
        error.code
    );
}
