//! End-to-end integration test: nie client connects to relay via SOCKS5 proxy.
//!
//! No external network or Tor required.  The SOCKS5 proxy is an in-process
//! forwarder defined in socks5_helper.rs.
//!
//! Oracle: transport::connect() returning Ok(RelayConn) proves the full
//! stack worked — TCP → SOCKS5 handshake → relay WebSocket upgrade →
//! JSON-RPC challenge-response auth — all in one unbroken chain.

mod socks5_helper;

use std::time::Duration;

use axum::{routing::get, Router};
use nie_core::{identity::Identity, transport};
use nie_relay::{state::AppState, ws::ws_handler};

/// Start an in-process relay on a random OS-assigned port.
/// Returns `(ws_url, relay_host_port)`.
/// Each call gets its own temp SQLite file so parallel test runs never collide.
async fn spawn_relay() -> (String, String) {
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

    let ws_url = format!("ws://127.0.0.1:{port}/ws");
    let host_port = format!("127.0.0.1:{port}");
    (ws_url, host_port)
}

/// A nie client connects to the relay through a minimal in-process SOCKS5
/// proxy.  The test asserts:
///
/// 1. `transport::connect()` returns `Ok(RelayConn)` — auth handshake
///    succeeded end-to-end through the proxy.
/// 2. The proxy task received a SOCKS5 CONNECT command — the client
///    actually used the proxy rather than dialing the relay directly.
#[tokio::test]
async fn connect_via_socks5_proxy() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (relay_url, relay_host_port) = spawn_relay().await;

        let (proxy_port, connect_rx) = socks5_helper::run_socks5_proxy(relay_host_port).await;

        let proxy_url = format!("socks5h://127.0.0.1:{proxy_port}");
        let identity = Identity::generate();

        let result = transport::connect(&relay_url, &identity, false, Some(proxy_url)).await;

        assert!(
            result.is_ok(),
            "transport::connect via SOCKS5 proxy must succeed; got: {:?}",
            result.err()
        );

        // Verify the proxy received the CONNECT command with a tight timeout.
        // The connect() call already returned Ok, so the CONNECT must have
        // already fired — this recv() is nearly instantaneous.
        match tokio::time::timeout(Duration::from_secs(2), connect_rx).await {
            Ok(Ok(())) => {} // proxy confirmed CONNECT was received
            Ok(Err(_)) => panic!("SOCKS5 proxy task dropped the oneshot sender"),
            Err(_) => panic!("timed out waiting for proxy CONNECT confirmation"),
        }
    })
    .await
    .expect("test must complete within 10 seconds");
}
