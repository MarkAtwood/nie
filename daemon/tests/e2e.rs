//! End-to-end test: two daemon instances exchange a message via a shared relay.
//!
//! Alice sends via her daemon's REST API; Bob receives via his daemon's WebSocket.
//! Exercises the full stack: POST /api/send → nie-daemon → relay → nie-daemon → /ws/events.
//!
//! Run with:
//!   cargo test -p nie-daemon e2e -- --ignored

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use futures_util::StreamExt;
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use nie_daemon::{api, state::DaemonState, token, ws_events};

// ---------------------------------------------------------------------------
// Relay helper — in-process relay on a random OS-assigned port
// ---------------------------------------------------------------------------

async fn spawn_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let db_file = tempfile::NamedTempFile::new().unwrap();
    let db_url = format!("sqlite:{}?mode=rwc", db_file.path().display());

    let relay_state = nie_relay::state::AppState::new(&db_url, 60, false, 1_000_000, 30, 120)
        .await
        .unwrap();
    let app = axum::Router::new()
        .route("/ws", axum::routing::get(nie_relay::ws::ws_handler))
        .with_state(relay_state);

    tokio::spawn(async move {
        let _db_file = db_file; // keep temp file alive for relay lifetime
        axum::serve(listener, app).await.unwrap();
    });

    format!("ws://127.0.0.1:{port}/ws")
}

// ---------------------------------------------------------------------------
// Daemon helper — HTTP server backed by a DaemonState (no relay connected yet)
// ---------------------------------------------------------------------------

async fn start_daemon(pub_id: String, tok: String) -> (SocketAddr, DaemonState) {
    let state = DaemonState::new(pub_id, tok.clone(), None, "mainnet".to_string(), None, None);

    let api_router = Router::new()
        .route("/api/whoami", get(api::handle_whoami))
        .route("/api/users", get(api::handle_users))
        .route("/api/send", post(api::handle_send))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            token::require_token,
        ));

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ws/events", get(ws_events::handle_ws_events))
        .merge(api_router)
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, state)
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

// ---------------------------------------------------------------------------
// E2E test
// ---------------------------------------------------------------------------

/// Alice sends a chat message via her daemon's REST API; Bob receives it via
/// his daemon's WebSocket /ws/events.
///
/// Full stack exercised:
///   Alice POST /api/send  →  nie-daemon  →  relay BROADCAST→DELIVER  →  nie-daemon  →  Bob WS
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_two_daemon_message_exchange() {
    // 1. Relay
    let relay_url = spawn_relay().await;
    // Small pause to let the relay's accept loop start.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2. Identities + keyfiles in temp directories.
    let alice_id = nie_core::identity::Identity::generate();
    let bob_id = nie_core::identity::Identity::generate();

    let alice_tmpdir = tempfile::TempDir::new().unwrap();
    let bob_tmpdir = tempfile::TempDir::new().unwrap();

    let alice_keyfile = alice_tmpdir.path().join("identity.key");
    let bob_keyfile = bob_tmpdir.path().join("identity.key");

    std::fs::write(&alice_keyfile, alice_id.to_secret_bytes_64()).unwrap();
    std::fs::write(&bob_keyfile, bob_id.to_secret_bytes_64()).unwrap();

    let alice_pub_id = alice_id.pub_id().0.clone();
    let bob_pub_id = bob_id.pub_id().0.clone();

    // 3. Daemon HTTP servers.
    let alice_token = "alice-e2e-token-11111".to_string();
    let bob_token = "bob-e2e-token-22222".to_string();

    let (alice_addr, alice_state) = start_daemon(alice_pub_id.clone(), alice_token.clone()).await;
    let (bob_addr, bob_state) = start_daemon(bob_pub_id.clone(), bob_token.clone()).await;

    // 4. Connect both daemons to the relay (returns immediately; auth is async).
    nie_daemon::relay::start_relay_connector(
        alice_keyfile.to_str().unwrap(),
        &relay_url,
        false,
        None,
        alice_state,
    )
    .await
    .unwrap();

    nie_daemon::relay::start_relay_connector(
        bob_keyfile.to_str().unwrap(),
        &relay_url,
        false,
        None,
        bob_state,
    )
    .await
    .unwrap();

    // 5. Wait until Alice's daemon sees Bob in /api/users (both relay connections
    //    are authenticated and the relay has delivered directory events).
    let client = http_client();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let res = client
            .get(format!("http://{}/api/users", alice_addr))
            .header("Authorization", format!("Bearer {}", alice_token))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = res.json().await.unwrap();
        let online = body["online"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        if online
            .iter()
            .any(|u| u["pub_id"].as_str() == Some(bob_pub_id.as_str()))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timeout: Alice's daemon did not see Bob in /api/users within 10s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 6. Bob subscribes to his daemon's WebSocket event stream.
    let (mut bob_ws, _) = tokio_tungstenite::connect_async(format!(
        "ws://{}/ws/events?token={}",
        bob_addr, bob_token
    ))
    .await
    .expect("Bob WS connect failed");

    // Give the WS handler time to subscribe to the daemon's broadcast channel.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 7. Alice sends a message.
    let send_res = client
        .post(format!("http://{}/api/send", alice_addr))
        .header("Authorization", format!("Bearer {}", alice_token))
        .json(&serde_json::json!({ "text": "hello from alice" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        send_res.status(),
        200,
        "Alice /api/send failed with status {}",
        send_res.status()
    );

    // 8. Bob's WS must deliver a message_received event within 10 seconds.
    //    Loop over frames to skip any WebSocket-level Ping/Pong frames.
    let text_payload = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = bob_ws
                .next()
                .await
                .expect("Bob's WS stream closed unexpectedly")
                .expect("Bob's WS receive error");
            match frame {
                Message::Text(t) => break t.to_string(),
                Message::Ping(_) | Message::Pong(_) => continue,
                other => panic!("unexpected WS frame type: {other:?}"),
            }
        }
    })
    .await
    .expect("timeout: Bob did not receive a WS event within 10s");

    // 9. Validate the event.
    let event: serde_json::Value =
        serde_json::from_str(&text_payload).expect("event is not valid JSON");

    assert_eq!(
        event["type"].as_str().unwrap_or(""),
        "message_received",
        "unexpected event type; full event: {event}"
    );
    assert_eq!(
        event["text"].as_str().unwrap_or(""),
        "hello from alice",
        "text mismatch; full event: {event}"
    );

    let from = event["from"].as_str().unwrap_or("");
    assert_eq!(from.len(), 64, "from must be 64 hex chars, got: {from:?}");
    assert!(
        from.chars().all(|c| c.is_ascii_hexdigit()),
        "from must be lowercase hex, got: {from:?}"
    );
    assert_eq!(
        from, alice_pub_id,
        "from must equal Alice's pub_id; got: {from:?}"
    );

    let _ = bob_ws.close(None).await;
}
