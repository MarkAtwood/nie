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

use nie_daemon::{api, jmap, state::DaemonState, token, web, ws_events};

// ---------------------------------------------------------------------------
// Test server helper
// ---------------------------------------------------------------------------

struct TestDaemon {
    addr: SocketAddr,
    token: String,
    pub_id: String,
}

async fn start_test_daemon() -> TestDaemon {
    let token = "test-integration-token-abc123".to_string();
    let pub_id = "a".repeat(64);
    let state = DaemonState::new(
        pub_id.clone(),
        token.clone(),
        Some("TestUser".to_string()),
        "mainnet".to_string(),
        None,
        None,
    );

    let api_router = Router::new()
        .route("/api/whoami", get(api::handle_whoami))
        .route("/api/users", get(api::handle_users))
        .route("/api/send", post(api::handle_send))
        .route("/.well-known/jmap", get(jmap::handle_jmap_session))
        .route("/jmap", post(jmap::handle_jmap_request))
        .route(
            "/jmap/upload/{account_id}",
            post(jmap::handle_jmap_upload),
        )
        .route(
            "/jmap/download/{account_id}/{blob_id}/{name}",
            get(jmap::handle_jmap_download),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            token::require_token,
        ));

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ws/events", get(ws_events::handle_ws_events))
        .route("/jmap/eventsource/", get(jmap::handle_jmap_eventsource))
        .route("/", get(web::handle_index))
        .merge(api_router)
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestDaemon { addr, token, pub_id }
}

async fn start_test_daemon_with_store() -> TestDaemon {
    let token = "test-store-token-xyz".to_string();
    let pub_id = "c".repeat(64);
    let store = nie_daemon::store::Store::new("sqlite::memory:")
        .await
        .expect("in-memory store");
    let state = DaemonState::new(
        pub_id.clone(),
        token.clone(),
        Some("StoreUser".to_string()),
        "mainnet".to_string(),
        None,
        Some(store),
    );

    let api_router = Router::new()
        .route("/api/whoami", get(api::handle_whoami))
        .route("/.well-known/jmap", get(jmap::handle_jmap_session))
        .route("/jmap", post(jmap::handle_jmap_request))
        .route(
            "/jmap/upload/{account_id}",
            post(jmap::handle_jmap_upload),
        )
        .route(
            "/jmap/download/{account_id}/{blob_id}/{name}",
            get(jmap::handle_jmap_download),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            token::require_token,
        ));

    let app = Router::new()
        .merge(api_router)
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestDaemon { addr, token, pub_id }
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
    let state = DaemonState::new(
        pub_id,
        token_str.clone(),
        None,
        "mainnet".to_string(),
        None,
        None,
    );

    let api_router = Router::new()
        .route("/api/whoami", get(api::handle_whoami))
        .route("/api/users", get(api::handle_users))
        .route("/api/send", post(api::handle_send))
        .route("/.well-known/jmap", get(jmap::handle_jmap_session))
        .route("/jmap", post(jmap::handle_jmap_request))
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

// ---------------------------------------------------------------------------
// JMAP Core endpoints (nie-8b1t)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_jmap_session_no_auth_rejected() {
    let d = start_test_daemon().await;
    let res = http_client()
        .get(format!("http://{}/.well-known/jmap", d.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        401,
        "/.well-known/jmap without token must be 401"
    );
}

#[tokio::test]
async fn test_jmap_session_returns_session_object() {
    let d = start_test_daemon().await;
    let res = http_client()
        .get(format!("http://{}/.well-known/jmap", d.addr))
        .header("Authorization", format!("Bearer {}", d.token))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["@type"].as_str().unwrap(), "Session");
    assert!(
        body["capabilities"]
            .as_object()
            .unwrap()
            .contains_key("urn:ietf:params:jmap:chat"),
        "session must advertise jmap:chat capability"
    );
    assert!(
        body["apiUrl"].as_str().unwrap().ends_with("/jmap"),
        "apiUrl must end with /jmap"
    );
}

#[tokio::test]
async fn test_jmap_post_no_auth_rejected() {
    let d = start_test_daemon().await;
    let res = http_client()
        .post(format!("http://{}/jmap", d.addr))
        .json(&serde_json::json!({
            "using": ["urn:ietf:params:jmap:chat"],
            "methodCalls": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "/jmap POST without token must be 401");
}

#[tokio::test]
async fn test_jmap_post_unknown_method_returns_error() {
    let d = start_test_daemon().await;
    let res = http_client()
        .post(format!("http://{}/jmap", d.addr))
        .header("Authorization", format!("Bearer {}", d.token))
        .json(&serde_json::json!({
            "using": ["urn:ietf:params:jmap:chat"],
            "methodCalls": [["Foo/unknownVerb", {}, "c0"]]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(
        body["sessionState"].as_str().is_some(),
        "sessionState must be present"
    );
    let responses = body["methodResponses"].as_array().unwrap();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0][0].as_str().unwrap(), "error");
    assert_eq!(responses[0][1]["type"].as_str().unwrap(), "unknownMethod");
    assert_eq!(responses[0][2].as_str().unwrap(), "c0");
}

#[tokio::test]
async fn test_jmap_post_empty_batch() {
    let d = start_test_daemon().await;
    let res = http_client()
        .post(format!("http://{}/jmap", d.addr))
        .header("Authorization", format!("Bearer {}", d.token))
        .json(&serde_json::json!({
            "using": ["urn:ietf:params:jmap:chat"],
            "methodCalls": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(
        body["methodResponses"].as_array().unwrap().len(),
        0,
        "empty batch must return empty methodResponses"
    );
}

// ---------------------------------------------------------------------------
// /jmap/eventsource/ — SSE push channel
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_eventsource_no_auth_rejected() {
    let d = start_test_daemon().await;
    let res = http_client()
        .get(format!(
            "http://{}/jmap/eventsource/?types=*&closeafter=no&ping=0",
            d.addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "EventSource without token must be 401");
}

#[tokio::test]
async fn test_eventsource_query_token_accepted() {
    let d = start_test_daemon().await;
    let res = http_client()
        .get(format!(
            "http://{}/jmap/eventsource/?types=*&closeafter=no&ping=0&token={}",
            d.addr, d.token
        ))
        // Keep the connection short: we just want the 200 + content-type header.
        .timeout(std::time::Duration::from_millis(300))
        .send()
        .await;
    // A timeout on an open SSE stream is expected — the important thing is that
    // the server accepted the connection (not 401) and sent text/event-stream.
    match res {
        Ok(r) => {
            assert_eq!(r.status(), 200);
            let ct = r
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert!(
                ct.starts_with("text/event-stream"),
                "content-type must be text/event-stream, got: {ct}"
            );
        }
        // Timeout means server kept the stream open — connection was accepted.
        Err(e) if e.is_timeout() => {}
        Err(e) => panic!("unexpected error: {e}"),
    }
}

// ---------------------------------------------------------------------------
// /jmap/upload + /jmap/download — blob store (RFC 8620 §6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_blob_upload_and_download_roundtrip() {
    let d = start_test_daemon_with_store().await;
    let content = b"hello blob world";
    let content_type = "text/plain";

    // Upload
    let upload_url = format!("http://{}/jmap/upload/{}", d.addr, d.pub_id);
    let res = http_client()
        .post(&upload_url)
        .header("Authorization", format!("Bearer {}", d.token))
        .header("Content-Type", content_type)
        .body(content.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "upload must return 201 Created");
    let body: serde_json::Value = res.json().await.unwrap();
    let blob_id = body["blobId"].as_str().expect("blobId in response").to_string();
    assert_eq!(body["type"].as_str().unwrap(), content_type);
    assert_eq!(body["size"].as_u64().unwrap(), content.len() as u64);

    // Download
    let download_url = format!(
        "http://{}/jmap/download/{}/{}/hello.txt",
        d.addr, d.pub_id, blob_id
    );
    let res = http_client()
        .get(&download_url)
        .header("Authorization", format!("Bearer {}", d.token))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "download must return 200");
    let ct = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.starts_with(content_type), "content-type must match: {ct}");
    let bytes = res.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), content);
}

#[tokio::test]
async fn test_blob_download_not_found() {
    let d = start_test_daemon_with_store().await;
    let res = http_client()
        .get(format!(
            "http://{}/jmap/download/{}/nonexistent/file.bin",
            d.addr, d.pub_id
        ))
        .header("Authorization", format!("Bearer {}", d.token))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn test_blob_upload_wrong_account_rejected() {
    let d = start_test_daemon_with_store().await;
    let wrong_id = "z".repeat(64);
    let res = http_client()
        .post(format!("http://{}/jmap/upload/{}", d.addr, wrong_id))
        .header("Authorization", format!("Bearer {}", d.token))
        .header("Content-Type", "text/plain")
        .body(b"data".as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "wrong accountId must be 403");
}

#[tokio::test]
async fn test_blob_upload_deduplicates_same_content() {
    let d = start_test_daemon_with_store().await;
    let url = format!("http://{}/jmap/upload/{}", d.addr, d.pub_id);
    let auth = format!("Bearer {}", d.token);

    // Upload same content twice
    let r1 = http_client()
        .post(&url)
        .header("Authorization", &auth)
        .header("Content-Type", "application/octet-stream")
        .body(b"dup-content".as_slice())
        .send()
        .await
        .unwrap();
    let r2 = http_client()
        .post(&url)
        .header("Authorization", &auth)
        .header("Content-Type", "application/octet-stream")
        .body(b"dup-content".as_slice())
        .send()
        .await
        .unwrap();

    assert_eq!(r1.status(), 201);
    assert_eq!(r2.status(), 201);
    let id1 = r1.json::<serde_json::Value>().await.unwrap()["blobId"]
        .as_str()
        .unwrap()
        .to_string();
    let id2 = r2.json::<serde_json::Value>().await.unwrap()["blobId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(id1, id2, "same content must produce same blobId");
}
