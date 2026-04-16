//! Integration tests for nie-daemon HTTP API and WebSocket events.
//!
//! Each test starts a real axum server on a random OS-assigned port with a
//! fresh DaemonState and verifies the HTTP/WS interface end-to-end.
//!
//! These tests exercise the full axum middleware stack — including the
//! require_token middleware on /api/* routes and the in-handler auth check
//! on /ws/events.  No relay connection is needed; send returns 503 when the
//! relay is not connected, and that path is tested explicitly.

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;

use nie_daemon::{api, state::DaemonState, token, web, ws_events};

// ---------------------------------------------------------------------------
// Test server helper
// ---------------------------------------------------------------------------

struct TestDaemon {
    addr: SocketAddr,
    token: String,
}

async fn start_test_daemon() -> TestDaemon {
    let token = "test-integration-token-abc123".to_string();
    let pub_id = "a".repeat(64);
    let state = DaemonState::new(pub_id, token.clone(), Some("TestUser".to_string()));

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
        .route("/", get(web::handle_index))
        .merge(api_router)
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestDaemon { addr, token }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

// ---------------------------------------------------------------------------
// /health — no auth required
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_health_no_auth_required() {
    let d = start_test_daemon().await;
    let res = http_client()
        .get(format!("http://{}/health", d.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

// ---------------------------------------------------------------------------
// /api/whoami — auth enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_whoami_no_token_rejected() {
    let d = start_test_daemon().await;
    let res = http_client()
        .get(format!("http://{}/api/whoami", d.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        401,
        "expected 401 without Authorization header"
    );
}

#[tokio::test]
async fn test_whoami_wrong_token_rejected() {
    let d = start_test_daemon().await;
    let res = http_client()
        .get(format!("http://{}/api/whoami", d.addr))
        .header("Authorization", "Bearer wrong-token-xyz")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "expected 401 with wrong token");
}

#[tokio::test]
async fn test_whoami_ok() {
    let d = start_test_daemon().await;
    let res = http_client()
        .get(format!("http://{}/api/whoami", d.addr))
        .header("Authorization", format!("Bearer {}", d.token))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    let pub_id = body["pub_id"].as_str().expect("pub_id missing");
    assert_eq!(pub_id.len(), 64, "pub_id must be 64 chars: {pub_id}");
    assert!(
        pub_id.chars().all(|c| c.is_ascii_hexdigit()),
        "pub_id must be lowercase hex: {pub_id}"
    );
}

// ---------------------------------------------------------------------------
// /api/send — auth enforcement and relay-unavailable path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_send_no_auth_rejected() {
    let d = start_test_daemon().await;
    let res = http_client()
        .post(format!("http://{}/api/send", d.addr))
        .json(&serde_json::json!({ "text": "hello" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn test_send_empty_text_rejected() {
    let d = start_test_daemon().await;
    let res = http_client()
        .post(format!("http://{}/api/send", d.addr))
        .header("Authorization", format!("Bearer {}", d.token))
        .json(&serde_json::json!({ "text": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["code"].as_str().unwrap(), "invalid_request");
}

#[tokio::test]
async fn test_send_relay_unavailable_returns_503() {
    // Without a relay connected, /api/send must return 503 relay_unavailable.
    let d = start_test_daemon().await;
    let res = http_client()
        .post(format!("http://{}/api/send", d.addr))
        .header("Authorization", format!("Bearer {}", d.token))
        .json(&serde_json::json!({ "text": "hello integration test" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 503, "expected 503 when relay not connected");
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(
        body["code"].as_str().unwrap(),
        "relay_unavailable",
        "unexpected error code: {body}"
    );
}

// ---------------------------------------------------------------------------
// Static index page
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_static_index_served() {
    let d = start_test_daemon().await;
    let res = http_client()
        .get(format!("http://{}/", d.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let ct = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/html"),
        "content-type must be text/html, got: {ct}"
    );
}

// ---------------------------------------------------------------------------
// /ws/events — auth enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ws_no_token_rejected() {
    let d = start_test_daemon().await;
    let url = format!("ws://{}/ws/events", d.addr);
    let result = tokio_tungstenite::connect_async(&url).await;
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("401") || msg.contains("HTTP error"),
                "expected 401 rejection, got: {msg}"
            );
        }
        Ok(_) => panic!("WS connection without token must be rejected"),
    }
}

#[tokio::test]
async fn test_ws_wrong_token_rejected() {
    let d = start_test_daemon().await;
    let url = format!("ws://{}/ws/events?token=wrong-token", d.addr);
    let result = tokio_tungstenite::connect_async(&url).await;
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("401") || msg.contains("HTTP error"),
                "expected 401 rejection, got: {msg}"
            );
        }
        Ok(_) => panic!("WS connection with wrong token must be rejected"),
    }
}

#[tokio::test]
async fn test_ws_query_token_connects() {
    let d = start_test_daemon().await;
    let url = format!("ws://{}/ws/events?token={}", d.addr, d.token);
    let result = tokio_tungstenite::connect_async(&url).await;
    assert!(
        result.is_ok(),
        "WS connect with valid query token failed: {:?}",
        result.err()
    );
    let (mut ws, _) = result.unwrap();
    let _ = ws.close(None).await;
}

#[tokio::test]
async fn test_ws_bearer_header_connects() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let d = start_test_daemon().await;
    let url = format!("ws://{}/ws/events", d.addr);
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", d.token).parse().unwrap(),
    );
    let result = tokio_tungstenite::connect_async(req).await;
    assert!(
        result.is_ok(),
        "WS connect with Bearer header failed: {:?}",
        result.err()
    );
    let (mut ws, _) = result.unwrap();
    let _ = ws.close(None).await;
}

// ---------------------------------------------------------------------------
// /ws/events — event delivery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ws_connection_stays_open_with_no_events() {
    use futures_util::StreamExt;
    use tokio::time::{timeout, Duration};

    let d = start_test_daemon().await;
    let url = format!("ws://{}/ws/events?token={}", d.addr, d.token);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("WS connect failed");

    // With no events broadcast, the connection must stay open (no spontaneous Close).
    let recv_result = timeout(Duration::from_millis(200), ws.next()).await;
    assert!(
        recv_result.is_err(),
        "WS must stay open with no events, but received: {:?}",
        recv_result.ok()
    );

    let _ = ws.close(None).await;
}

#[tokio::test]
async fn test_ws_receives_broadcast_event() {
    use futures_util::StreamExt;
    use nie_daemon::DaemonEvent;
    use tokio::time::{timeout, Duration};
    use tokio_tungstenite::tungstenite::Message;

    // Build a DaemonState we hold onto so we can broadcast.
    let token_str = "test-broadcast-event-token".to_string();
    let pub_id = "b".repeat(64);
    let state = DaemonState::new(pub_id, token_str.clone(), None);

    let api_router = Router::new()
        .route("/api/whoami", get(api::handle_whoami))
        .route("/api/users", get(api::handle_users))
        .route("/api/send", post(api::handle_send))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            token::require_token,
        ));

    let app = Router::new()
        .route("/ws/events", get(ws_events::handle_ws_events))
        .merge(api_router)
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Connect WS client.
    let url = format!("ws://{}/ws/events?token={}", addr, token_str);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("WS connect failed");

    // Small yield to let the WS handler subscribe to the broadcast channel
    // before we send the event.
    tokio::task::yield_now().await;

    // Broadcast an event via DaemonState.
    state.broadcast_event(DaemonEvent::MessageReceived {
        from: "a".repeat(64),
        from_display_name: "Alice".to_string(),
        text: "hello integration test".to_string(),
        timestamp: "2026-04-19T00:00:00Z".to_string(),
        message_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
    });

    // WS client must receive the event within 2 seconds.
    let frame = timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("timed out waiting for WS event")
        .expect("WS stream closed")
        .expect("WS receive error");

    let text = match frame {
        Message::Text(t) => t.to_string(),
        other => panic!("expected Text frame, got: {other:?}"),
    };

    let json: serde_json::Value = serde_json::from_str(&text).expect("event not valid JSON");
    assert_eq!(
        json["type"].as_str().unwrap(),
        "message_received",
        "unexpected event type: {json}"
    );
    assert_eq!(
        json["text"].as_str().unwrap(),
        "hello integration test",
        "unexpected text: {json}"
    );

    let _ = ws.close(None).await;
}
