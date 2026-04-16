//! E2E integration test proving the relay is blind to sealed sender identity
//! (nie-rwr7.11).
//!
//! The test sets up a real two-client MLS session through the relay, then sends
//! a SEALED_BROADCAST whose plaintext carries alice's pub_id prepended to an MLS
//! application message.  After bob unseals and decrypts, we assert:
//!
//! 1. The raw wire JSON of SEALED_DELIVER contains no `from` field and no trace
//!    of alice's pub_id — the relay is demonstrably blind.
//! 2. Bob recovers alice's pub_id and the plaintext message by unsealing and
//!    running the MLS application message through `process_incoming`.
//!
//! Oracle: the relay cannot add information it does not possess.  Alice's pub_id
//! and plaintext are external constants supplied by the test; they are not
//! derived from any code path under test.

use std::time::Duration;

use axum::{routing::get, Router};
use nie_core::{
    identity::Identity,
    mls::MlsClient,
    protocol::{
        rpc_methods, BroadcastParams, DeliverParams, GetKeyPackageParams, GetKeyPackageResult,
        JsonRpcRequest, JsonRpcResponse, PublishKeyPackageParams, SealedBroadcastParams,
        SealedDeliverParams, WhisperDeliverParams, WhisperParams,
    },
    transport::{self, next_request_id, ClientEvent},
};
use nie_relay::{state::AppState, ws::ws_handler};

// ---------------------------------------------------------------------------
// Shared helpers (copied from sealed_sender_relay.rs / e2e_jsonrpc.rs)
// ---------------------------------------------------------------------------

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
        let _db_file = db_file;
        axum::serve(listener, app).await.unwrap();
    });

    format!("ws://127.0.0.1:{port}/ws")
}

async fn wait_for_directory_list(rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>) {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(ClientEvent::Message(notif)))
                if notif.method == rpc_methods::DIRECTORY_LIST =>
            {
                return;
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("relay channel closed before DirectoryList"),
            Err(_) => panic!("timed out waiting for DirectoryList"),
        }
    }
}

async fn wait_for_notification(
    rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>,
    method: &str,
) -> nie_core::protocol::JsonRpcNotification {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(ClientEvent::Message(n))) if n.method == method => return n,
            Ok(Some(_)) => {}
            Ok(None) => panic!("channel closed waiting for {method}"),
            Err(_) => panic!("timed out waiting for {method}"),
        }
    }
}

async fn wait_for_response(rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>) -> JsonRpcResponse {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(ClientEvent::Response(r))) => return r,
            Ok(Some(_)) => {}
            Ok(None) => panic!("channel closed waiting for response"),
            Err(_) => panic!("timed out waiting for response"),
        }
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// Proves the relay is blind to the sealed sender's identity end-to-end.
///
/// Alice and Bob establish an MLS group through the relay.  Alice sends a
/// SEALED_BROADCAST whose ciphertext is HPKE-sealed with the shared room key
/// and whose plaintext is `alice_pub_id (64 bytes) || MLS_app_ciphertext`.
///
/// Oracle for relay-blindness assertion: we serialize the raw SEALED_DELIVER
/// notification and assert that alice's pub_id does not appear anywhere in the
/// wire JSON.  The relay never learned alice's identity; it only saw opaque bytes.
///
/// Oracle for recovery assertion: bob unseals with the same room secret, recovers
/// alice's pub_id from the prefix, and decrypts the MLS ciphertext to
/// `b"hello from alice"`.  Both values are external constants, not roundtrip probes.
#[tokio::test]
async fn sealed_broadcast_relay_blind_and_recipient_recovers_sender() {
    let relay_url = spawn_relay().await;

    // Alice connects first → lower connection_seq → admin (online[0]).
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_pub_id = alice.pub_id();
    let bob_pub_id = bob.pub_id();

    let alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut alice_rx = alice_conn.rx;

    let bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");
    let mut bob_rx = bob_conn.rx;

    // Wait until both clients have received DirectoryList with 2 online users.
    wait_for_directory_list(&mut alice_rx).await;
    wait_for_directory_list(&mut bob_rx).await;

    // -----------------------------------------------------------------------
    // MLS group setup
    // -----------------------------------------------------------------------

    let mut alice_mls = MlsClient::new(&alice_pub_id.0).expect("alice MlsClient");
    let mut bob_mls = MlsClient::new(&bob_pub_id.0).expect("bob MlsClient");

    // Step 4a: Bob publishes his key package.
    let bob_kp_bytes = bob_mls.key_package_bytes().expect("bob key_package_bytes");
    let pub_kp_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::PUBLISH_KEY_PACKAGE,
        PublishKeyPackageParams { data: bob_kp_bytes },
    )
    .expect("PublishKeyPackageParams must serialize");
    bob_conn.tx.send(pub_kp_req).await.expect("bob publish kp");

    // Step 4b: Wait for Alice to receive KeyPackageReady.
    wait_for_notification(&mut alice_rx, rpc_methods::KEY_PACKAGE_READY).await;

    // Step 4c: Alice sends GET_KEY_PACKAGE for Bob.
    let get_kp_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::GET_KEY_PACKAGE,
        GetKeyPackageParams {
            pub_id: bob_pub_id.0.clone(),
        },
    )
    .expect("GetKeyPackageParams must serialize");
    alice_conn.tx.send(get_kp_req).await.expect("alice get kp");

    // Step 4d: Wait for Alice's GET_KEY_PACKAGE response; extract Bob's KP bytes.
    let get_kp_resp = wait_for_response(&mut alice_rx).await;
    assert!(
        get_kp_resp.is_success(),
        "GET_KEY_PACKAGE must succeed; got: {get_kp_resp:?}"
    );
    let kp_result: GetKeyPackageResult =
        serde_json::from_value(get_kp_resp.result.expect("result must be present"))
            .expect("GetKeyPackageResult must deserialize");
    let bob_kp = kp_result.data.expect("bob's key package must be present");

    // Step 4e: Alice creates the group and adds Bob.
    alice_mls.create_group().expect("alice create_group");
    let (commit_bytes, welcome_bytes) = alice_mls.add_member(&bob_kp).expect("alice add_member");

    // Step 4f: Alice broadcasts the commit.
    let commit_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams {
            payload: commit_bytes,
        },
    )
    .expect("BroadcastParams must serialize");
    alice_conn
        .tx
        .send(commit_req)
        .await
        .expect("alice broadcast commit");

    // Step 4g: Alice whispers the Welcome to Bob.
    let whisper_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::WHISPER,
        WhisperParams {
            to: bob_pub_id.0.clone(),
            payload: welcome_bytes,
        },
    )
    .expect("WhisperParams must serialize");
    alice_conn
        .tx
        .send(whisper_req)
        .await
        .expect("alice whisper welcome");

    // Step 4h: Bob loops until WHISPER_DELIVER (Welcome), processing any DELIVER
    // (commit) notifications encountered along the way.  The commit arrives before
    // the welcome because it is broadcast first.  Bob has no group yet when the
    // commit arrives, so process_incoming will return Err — that is expected and
    // intentional; we discard the result.
    loop {
        match tokio::time::timeout(Duration::from_secs(5), bob_rx.recv()).await {
            Ok(Some(ClientEvent::Message(n))) if n.method == rpc_methods::WHISPER_DELIVER => {
                let params: WhisperDeliverParams =
                    serde_json::from_value(n.params.expect("whisper_deliver must have params"))
                        .expect("WhisperDeliverParams must deserialize");
                bob_mls
                    .join_from_welcome(&params.payload)
                    .expect("bob join_from_welcome");
                break;
            }
            Ok(Some(ClientEvent::Message(n))) if n.method == rpc_methods::DELIVER => {
                let params: DeliverParams =
                    serde_json::from_value(n.params.expect("deliver must have params"))
                        .expect("DeliverParams must deserialize");
                // Bob has no group yet — process_incoming returns Err.  Discard.
                let _ = bob_mls.process_incoming(&params.payload);
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("bob channel closed waiting for welcome"),
            Err(_) => panic!("timed out waiting for welcome"),
        }
    }

    // -----------------------------------------------------------------------
    // Both clients now have an active MLS group at the same epoch.
    // Derive the shared room HPKE keypair.
    // -----------------------------------------------------------------------

    let (alice_room_sk, alice_room_pk) = alice_mls
        .room_hpke_keypair()
        .expect("alice room_hpke_keypair");
    let (bob_room_sk, bob_room_pk) = bob_mls.room_hpke_keypair().expect("bob room_hpke_keypair");

    // Sanity check: both sides derived the same secret (same MLS epoch).
    assert_eq!(
        alice_room_sk, bob_room_sk,
        "alice and bob must derive the same room HPKE secret at the same epoch"
    );
    assert_eq!(
        alice_room_pk, bob_room_pk,
        "same MLS epoch must yield identical room HPKE public key"
    );

    // -----------------------------------------------------------------------
    // Step 6: Alice sends a sealed broadcast.
    //
    // Plaintext format: alice_pub_id (64 UTF-8 bytes) || MLS app ciphertext.
    // The relay receives only opaque bytes; it cannot read alice's pub_id.
    // -----------------------------------------------------------------------

    let mls_ct = alice_mls
        .encrypt(b"hello from alice")
        .expect("alice encrypt");

    let mut sealed_plaintext = Vec::with_capacity(64 + mls_ct.len());
    sealed_plaintext.extend_from_slice(alice_pub_id.0.as_bytes());
    sealed_plaintext.extend_from_slice(&mls_ct);

    let sealed =
        nie_core::hpke::seal_message(&alice_room_pk, &sealed_plaintext).expect("seal_message");

    let sealed_broadcast_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::SEALED_BROADCAST,
        SealedBroadcastParams {
            sealed: sealed.clone(),
        },
    )
    .expect("SealedBroadcastParams must serialize");

    alice_conn
        .tx
        .send(sealed_broadcast_req)
        .await
        .expect("alice sealed broadcast send");

    // -----------------------------------------------------------------------
    // Step 7: Bob waits for SEALED_DELIVER.
    // -----------------------------------------------------------------------

    let sealed_deliver_notif =
        wait_for_notification(&mut bob_rx, rpc_methods::SEALED_DELIVER).await;

    // -----------------------------------------------------------------------
    // Step 8: Assert relay blindness — raw wire JSON must not leak alice's identity.
    // -----------------------------------------------------------------------

    let raw_json = serde_json::to_string(&sealed_deliver_notif).unwrap();

    assert_eq!(
        sealed_deliver_notif.method,
        rpc_methods::SEALED_DELIVER,
        "notification method must be sealed_deliver"
    );
    assert!(
        !raw_json.contains("\"from\""),
        "relay must not add a 'from' field to sealed_deliver; raw JSON: {raw_json}"
    );
    assert!(
        !raw_json.contains(alice_pub_id.0.as_str()),
        "relay must not expose alice's pub_id in sealed_deliver; raw JSON: {raw_json}"
    );

    // -----------------------------------------------------------------------
    // Step 9: Bob unseals and verifies sender identity and message content.
    // -----------------------------------------------------------------------

    let params: SealedDeliverParams = serde_json::from_value(
        sealed_deliver_notif
            .params
            .expect("sealed_deliver must have params"),
    )
    .expect("SealedDeliverParams must deserialize");

    let plaintext =
        nie_core::hpke::unseal_message(&bob_room_sk, &params.sealed).expect("bob unseal_message");

    assert_eq!(
        plaintext.len(),
        64 + mls_ct.len(),
        "unsealed plaintext must be 64 (pub_id) + MLS ciphertext bytes"
    );

    assert_eq!(
        &plaintext[..64],
        alice_pub_id.0.as_bytes(),
        "sealed sender identity must be alice's pub_id"
    );

    let mls_ct_from_wire = &plaintext[64..];
    let decrypted = bob_mls
        .process_incoming(mls_ct_from_wire)
        .expect("bob process_incoming")
        .expect("sealed_deliver payload must be an MLS application message");

    assert_eq!(
        decrypted, b"hello from alice",
        "decrypted MLS plaintext must match alice's original message"
    );
}
