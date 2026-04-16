//! Integration tests for DM (whisper) delivery — live and offline.
//!
//! Test 1 (test_dm_live_delivery): Alice and Bob are both connected.  Alice
//! sends a whisper to Bob.  Bob receives a whisper_deliver notification
//! immediately.  Alice receives an OkResult response.
//!
//! Test 2 (test_dm_offline_delivery): Bob disconnects before Alice sends.
//! The relay enqueues the DM.  When Bob reconnects and authenticates, the
//! relay drains the queue and delivers the queued whisper_deliver notification.
//!
//! Oracle: the expected payload bytes are constructed independently of the
//! whisper code path using serde_json::to_vec(&ClearMessage::Chat{...}).
//! This is the specification of what the payload must contain — not derived
//! from the DM send/receive path under test.

use std::time::Duration;

use axum::{routing::get, Router};
use nie_core::{
    identity::Identity,
    messages::ClearMessage,
    protocol::{
        rpc_methods, JsonRpcRequest, JsonRpcResponse, OkResult, WhisperDeliverParams, WhisperParams,
    },
    transport::{self, next_request_id, ClientEvent},
};
use nie_relay::{state::AppState, ws::ws_handler};

// ---------------------------------------------------------------------------
// Shared helpers (pattern mirrors sealed_sender_relay.rs and e2e_jsonrpc.rs)
// ---------------------------------------------------------------------------

/// Start an in-process relay on a random OS-assigned port.
/// Each call gets its own temp SQLite file so parallel test runs never collide.
async fn spawn_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let db_file = tempfile::NamedTempFile::new().unwrap();
    let db_url = format!("sqlite:{}?mode=rwc", db_file.path().display());

    let state = AppState::new(&db_url, 60, false, 1_000_000, 30)
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
            Ok(Some(_)) => {} // AuthOk response, UserJoined, etc.
            Ok(None) => panic!("relay channel closed before DirectoryList"),
            Err(_) => panic!("timed out waiting for DirectoryList"),
        }
    }
}

/// Drain incoming events until a JsonRpcResponse arrives, then return it.
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

/// Drain incoming events until a whisper_deliver notification arrives.
async fn wait_for_whisper_deliver(
    rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>,
) -> WhisperDeliverParams {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(ClientEvent::Message(notif)))
                if notif.method == rpc_methods::WHISPER_DELIVER =>
            {
                let params: WhisperDeliverParams = serde_json::from_value(
                    notif
                        .params
                        .expect("whisper_deliver notification must have params"),
                )
                .expect("WhisperDeliverParams must deserialize");
                return params;
            }
            Ok(Some(_)) => {} // UserJoined, DirectoryList, other notifications
            Ok(None) => panic!("relay channel closed before whisper_deliver"),
            Err(_) => panic!("timed out waiting for whisper_deliver notification"),
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: test_dm_live_delivery
//
// Alice and Bob are both connected.  Alice whispers to Bob.  The relay
// delivers the notification to Bob immediately (live path).
//
// Oracle: expected payload bytes derived from the ClearMessage spec
// (serde_json::to_vec of a known ClearMessage::Chat value), not from
// the DM send/receive code path under test.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dm_live_delivery() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_pub_id = alice.pub_id().0.clone();
    let bob_pub_id = bob.pub_id().0.clone();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut alice_rx = alice_conn.rx;

    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    // Wait until both clients are registered online before sending.
    wait_for_directory_list(&mut alice_rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    // Oracle: the payload is independently constructed from the spec.
    // ClearMessage::Chat with text "hello dm" must serialize to this exact byte sequence.
    // Verified externally: {"type":"chat","text":"hello dm"}
    let oracle_payload: Vec<u8> = serde_json::to_vec(&ClearMessage::Chat {
        text: "hello dm".to_string(),
    })
    .unwrap();

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::WHISPER,
        WhisperParams {
            to: bob_pub_id,
            payload: oracle_payload.clone(),
        },
    )
    .expect("WhisperParams must serialize");

    alice_conn.tx.send(req).await.expect("alice send whisper");

    // Alice must receive a success OkResult response.
    let resp = wait_for_response(&mut alice_rx).await;
    assert!(
        resp.is_success(),
        "alice must receive a success response for whisper, got: {resp:?}"
    );
    let ok: OkResult = serde_json::from_value(resp.result.expect("result must be present"))
        .expect("OkResult must deserialize");
    assert!(ok.ok, "OkResult.ok must be true");

    // Bob must receive the whisper_deliver notification.
    let params = wait_for_whisper_deliver(&mut bob_conn.rx).await;

    assert_eq!(
        params.from, alice_pub_id,
        "whisper_deliver.from must be alice's pub_id (relay-set, not client-provided)"
    );
    assert_eq!(
        params.payload, oracle_payload,
        "whisper_deliver.payload must exactly match the payload alice sent"
    );

    // Confirm the payload decodes to the expected ClearMessage.
    let decoded: ClearMessage =
        serde_json::from_slice(&params.payload).expect("payload must deserialize to ClearMessage");
    let ClearMessage::Chat { text } = decoded else {
        panic!("expected ClearMessage::Chat, got a different variant");
    };
    assert_eq!(text, "hello dm", "decoded chat text must match oracle");
}

// ---------------------------------------------------------------------------
// Test 2: test_dm_offline_delivery
//
// Bob disconnects before Alice sends the DM.  The relay enqueues the message.
// When Bob reconnects with the same identity, the relay drains the queue and
// delivers the whisper_deliver notification.
//
// Oracle: same independently-constructed payload as test 1.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dm_offline_delivery() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_pub_id = alice.pub_id().0.clone();
    let bob_pub_id = bob.pub_id().0.clone();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut alice_rx = alice_conn.rx;

    {
        // Bob connects, authenticates, then disconnects.
        let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
            .await
            .expect("bob initial connect");
        wait_for_directory_list(&mut alice_rx).await;
        wait_for_directory_list(&mut bob_conn.rx).await;
        // bob_conn drops here: the transport sends a WS Close frame, and the
        // relay will remove Bob from the live map once it processes the close.
    }

    // Give the relay time to process Bob's WS close frame and remove him from
    // the live client map before Alice sends.  Without this yield, the whisper
    // could arrive while Bob is still registered as live.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Oracle: payload bytes derived from spec, not from the DM code path.
    let oracle_payload: Vec<u8> = serde_json::to_vec(&ClearMessage::Chat {
        text: "hello dm".to_string(),
    })
    .unwrap();

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::WHISPER,
        WhisperParams {
            to: bob_pub_id.clone(),
            payload: oracle_payload.clone(),
        },
    )
    .expect("WhisperParams must serialize");

    alice_conn.tx.send(req).await.expect("alice send whisper");

    // Alice must receive OkResult (relay enqueued for offline recipient).
    let resp = wait_for_response(&mut alice_rx).await;
    assert!(
        resp.is_success(),
        "alice must receive a success response for whisper to offline bob, got: {resp:?}"
    );
    let ok: OkResult = serde_json::from_value(resp.result.expect("result must be present"))
        .expect("OkResult must deserialize");
    assert!(
        ok.ok,
        "OkResult.ok must be true even when recipient is offline"
    );

    // Bob reconnects with the same identity.  The relay will drain the queue
    // and deliver the queued whisper_deliver notification.
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob reconnect");

    let params = tokio::time::timeout(
        Duration::from_secs(5),
        wait_for_whisper_deliver(&mut bob_conn.rx),
    )
    .await
    .expect("timed out waiting for queued whisper_deliver after bob reconnect");

    assert_eq!(
        params.from, alice_pub_id,
        "queued whisper_deliver.from must be alice's pub_id"
    );
    assert_eq!(
        params.payload, oracle_payload,
        "queued whisper_deliver.payload must exactly match the payload alice sent"
    );

    // Confirm the payload decodes to the expected ClearMessage.
    let decoded: ClearMessage =
        serde_json::from_slice(&params.payload).expect("payload must deserialize to ClearMessage");
    let ClearMessage::Chat { text } = decoded else {
        panic!("expected ClearMessage::Chat, got a different variant");
    };
    assert_eq!(text, "hello dm", "decoded chat text must match oracle");
}
