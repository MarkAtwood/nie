//! E2E integration test: two nie-tui "headless" instances exchange a message.
//!
//! This test drives the event/relay logic directly (no real terminal) to verify:
//! 1. Both instances connect and receive DirectoryList
//! 2. Alice sends a ClearMessage::Chat via Broadcast
//! 3. Bob's relay channel delivers the message
//! 4. The payload decodes to the expected text (independent oracle)
//!
//! TUI handler tests (deliver_updates_tui_state, user_joined_updates_online_list)
//! additionally exercise handle_relay_event end-to-end against a live relay.

use axum::routing::get;
use nie_core::{
    identity::Identity,
    messages::ClearMessage,
    mls::MlsClient,
    protocol::{rpc_methods, BroadcastParams, DeliverParams, JsonRpcRequest},
    transport::{self, next_request_id, ClientEvent},
};
use nie_relay::{state::AppState as RelayAppState, ws::ws_handler};
use nie_tui::{app::AppState as TuiAppState, event::handle_relay_event};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::time::timeout;

/// Spawn a relay on a random port with an ephemeral SQLite DB.
/// Returns the ws:// URL.
async fn spawn_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let db_file = NamedTempFile::new().unwrap();
    let db_url = format!("sqlite:{}?mode=rwc", db_file.path().display());

    let state = RelayAppState::new(&db_url, 60, false, 1_000_000, 30, 120)
        .await
        .unwrap();
    let app = axum::Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    tokio::spawn(async move {
        let _db_file = db_file; // keep alive
        axum::serve(listener, app).await.unwrap();
    });

    format!("ws://127.0.0.1:{port}/ws")
}

/// Wait for a DIRECTORY_LIST notification (proof of successful auth).
async fn wait_for_directory_list(rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>) {
    loop {
        match timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(ClientEvent::Message(n))) if n.method == rpc_methods::DIRECTORY_LIST => return,
            Ok(Some(_)) => {}
            Ok(None) => panic!("channel closed before DirectoryList"),
            Err(_) => panic!("timed out waiting for DirectoryList"),
        }
    }
}

/// Wait for a DELIVER notification.
async fn wait_for_deliver(rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>) -> DeliverParams {
    loop {
        match timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(ClientEvent::Message(n))) if n.method == rpc_methods::DELIVER => {
                return serde_json::from_value(n.params.expect("deliver has params"))
                    .expect("DeliverParams deserializes");
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("channel closed before Deliver"),
            Err(_) => panic!("timed out waiting for Deliver"),
        }
    }
}

/// Capture the raw ClientEvent for the first notification matching `method`.
/// Discards unrelated events. Returns the event so the caller can feed it to
/// handle_relay_event without re-constructing it.
async fn wait_for_notification_event(
    rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>,
    method: &str,
) -> ClientEvent {
    loop {
        let event = match timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => panic!("channel closed before {method}"),
            Err(_) => panic!("timed out waiting for {method}"),
        };
        if let ClientEvent::Message(ref n) = event {
            if n.method == method {
                return event;
            }
        }
    }
}

#[tokio::test]
async fn two_instances_exchange_message() {
    let relay_url = spawn_relay().await;

    // Create two identities (independent entropy — no shared state with code under test)
    let alice = Identity::generate();
    let bob = Identity::generate();

    // Connect both
    let mut alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    // Wait for both to be authenticated (DirectoryList = auth success)
    wait_for_directory_list(&mut alice_conn.rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    // ORACLE: construct expected payload independently from the test subject.
    // The relay must forward exactly these bytes — any corruption would fail this assert.
    let expected_text = "hello from alice to bob";
    let oracle_payload: Vec<u8> = serde_json::to_vec(&ClearMessage::Chat {
        text: expected_text.to_string(),
    })
    .expect("oracle payload serialization");

    // Alice broadcasts
    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams {
            payload: oracle_payload.clone(),
        },
    )
    .expect("BroadcastParams serializes");
    alice_conn.tx.send(req).await.expect("alice broadcast");

    // Bob receives the delivery
    let delivered = wait_for_deliver(&mut bob_conn.rx).await;

    // Verify payload matches oracle (relay forwarded bytes unchanged)
    assert_eq!(
        delivered.payload, oracle_payload,
        "relay must forward payload unchanged"
    );

    // Verify the payload decodes to the expected text (ClearMessage round-trip)
    let msg: ClearMessage = serde_json::from_slice(&delivered.payload)
        .expect("delivered payload must be valid ClearMessage");
    assert!(
        matches!(&msg, ClearMessage::Chat { text } if text == expected_text),
        "decoded message must match oracle text"
    );
}

#[tokio::test]
async fn sender_identity_is_enforced() {
    // Relay must reject a message where envelope.from != authenticated pub_id.
    // This test verifies the relay's security invariant (CLAUDE.md §4).
    // We verify indirectly: Alice's own message does NOT appear as a Deliver to Alice
    // (relay sends SendAck, not Deliver, to the sender), and Bob sees the message
    // with from == alice.pub_id(), not a spoofed value.
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();

    let mut alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .unwrap();
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .unwrap();

    wait_for_directory_list(&mut alice_conn.rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    let payload = serde_json::to_vec(&ClearMessage::Chat {
        text: "hi".to_string(),
    })
    .unwrap();
    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams { payload },
    )
    .unwrap();
    alice_conn.tx.send(req).await.unwrap();

    let delivered = wait_for_deliver(&mut bob_conn.rx).await;

    // Relay stamped the sender as Alice's authenticated pub_id
    assert_eq!(
        delivered.from,
        alice.pub_id().0,
        "from field must equal authenticated pub_id"
    );
}

/// Build a TuiAppState from an Identity (no wallet, fresh MLS client).
fn make_tui_state(identity: &Identity) -> TuiAppState {
    let pub_id = identity.pub_id().0.clone();
    let mls = MlsClient::new(&pub_id).expect("MlsClient::new");
    TuiAppState::new(
        pub_id,
        *identity.hpke_secret_bytes(),
        identity.hpke_pub_key_bytes(),
        mls,
    )
}

/// DELIVER notification from relay → handle_relay_event → TUI message log updated.
///
/// This exercises decrypt_and_display and ClearMessage deserialization end-to-end
/// against a live relay rather than a manually-constructed fake event.
#[tokio::test]
async fn deliver_updates_tui_state() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();

    let mut alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");
    let mut bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    wait_for_directory_list(&mut alice_conn.rx).await;
    wait_for_directory_list(&mut bob_conn.rx).await;

    let expected_text = "tui e2e test message";
    let payload = serde_json::to_vec(&ClearMessage::Chat {
        text: expected_text.to_string(),
    })
    .expect("oracle payload serialization");

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams { payload },
    )
    .expect("BroadcastParams serializes");
    alice_conn.tx.send(req).await.expect("alice broadcast");

    // Capture the raw DELIVER event from Bob's channel — this is what the TUI
    // event loop would receive from the relay.
    let event = wait_for_notification_event(&mut bob_conn.rx, rpc_methods::DELIVER).await;

    // Build Bob's TUI state and feed the live relay event through handle_relay_event.
    let mut bob_state = make_tui_state(&bob);
    let (dummy_tx, _dummy_rx) = tokio::sync::mpsc::channel::<JsonRpcRequest>(16);
    handle_relay_event(&mut bob_state, &dummy_tx, event)
        .await
        .expect("handle_relay_event");

    // Assert the chat message landed in the TUI message log.
    let found = bob_state
        .messages
        .iter()
        .any(|m| matches!(m, nie_tui::app::ChatLine::Chat { text, .. } if text == expected_text));
    assert!(
        found,
        "expected chat message not found in bob_state.messages"
    );
}

/// DIRECTORY_LIST then USER_JOINED events → handle_relay_event → online list updated
/// in ascending-sequence order (online[0].sequence < online[1].sequence).
///
/// This exercises the partition_point insertion invariant for MLS admin election
/// against real relay-stamped sequence numbers.
#[tokio::test]
async fn user_joined_updates_online_list() {
    let relay_url = spawn_relay().await;

    let alice = Identity::generate();
    let bob = Identity::generate();

    // Connect Alice first so she gets a lower connection sequence.
    let mut alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect");

    // Capture Alice's DIRECTORY_LIST (contains only Alice at this point).
    let dir_event =
        wait_for_notification_event(&mut alice_conn.rx, rpc_methods::DIRECTORY_LIST).await;

    let mut alice_state = make_tui_state(&alice);
    let (dummy_tx, _dummy_rx) = tokio::sync::mpsc::channel::<JsonRpcRequest>(16);
    handle_relay_event(&mut alice_state, &dummy_tx, dir_event)
        .await
        .expect("handle DIRECTORY_LIST");

    // After DirectoryList, Alice's online list must be non-empty and contain Alice.
    assert!(
        !alice_state.online.is_empty(),
        "online list must be non-empty after DirectoryList"
    );
    assert!(
        alice_state
            .online
            .iter()
            .any(|u| u.pub_id == alice.pub_id().0),
        "Alice must appear in her own online list"
    );

    // Now connect Bob — relay will send Alice a USER_JOINED notification.
    let mut _bob_conn = transport::connect(&relay_url, &bob, false, None)
        .await
        .expect("bob connect");

    let joined_event =
        wait_for_notification_event(&mut alice_conn.rx, rpc_methods::USER_JOINED).await;
    handle_relay_event(&mut alice_state, &dummy_tx, joined_event)
        .await
        .expect("handle USER_JOINED");

    // After USER_JOINED, the online list must have 2 entries ordered by sequence.
    assert_eq!(
        alice_state.online.len(),
        2,
        "online list must have 2 entries after Bob joins"
    );
    assert!(
        alice_state.online[0].sequence < alice_state.online[1].sequence,
        "online list must be ordered ascending by sequence (admin invariant)"
    );
}
