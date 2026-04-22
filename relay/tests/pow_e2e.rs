//! E2E integration tests for the PoW enrollment gate (nie-967x.7).
//!
//! Oracles:
//! - rpc_errors::POW_REQUIRED / POW_STALE / POW_REPLAYED are the wire-stable
//!   error codes defined in nie_core::protocol::rpc_errors.  They are checked
//!   against the relay's actual response, not the implementation under test.
//! - A successful auth is witnessed by receiving a DirectoryList notification,
//!   which the relay only sends after the client is fully registered as online.
//!   This is an independent, observable relay behaviour that cannot be faked by
//!   the PoW or auth code paths.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{routing::get, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures::{SinkExt, StreamExt};
use nie_core::{
    identity::Identity,
    protocol::{
        rpc_errors, rpc_methods, AuthenticateParams, ChallengeParams, JsonRpcNotification,
        JsonRpcRequest, JsonRpcResponse,
    },
    transport::{self, ClientEvent},
};
use nie_relay::{state::AppState, ws::ws_handler};
use tokio_tungstenite::{connect_async, tungstenite::Message};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawn an in-process relay with PoW enabled at the given difficulty.
/// Returns the WebSocket URL.
async fn spawn_relay_with_pow(difficulty: u8) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let db_file = tempfile::NamedTempFile::new().unwrap();
    let db_url = format!("sqlite:{}?mode=rwc", db_file.path().display());

    let state = AppState::new(&db_url, 60, false, 1_000_000, 30, 120u32)
        .await
        .unwrap();

    state.set_pow_difficulty(difficulty);

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    tokio::spawn(async move {
        let _db_file = db_file;
        axum::serve(listener, app).await.unwrap();
    });

    format!("ws://127.0.0.1:{port}/ws")
}

/// Drain incoming events until a DirectoryList notification arrives.
/// Proves that auth succeeded and the client is registered as online.
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

/// Receive the next text frame from a raw WebSocket stream, skipping ping/pong.
async fn recv_text_frame(
    stream: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin),
    waiting_for: &str,
) -> String {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => return t.to_string(),
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {}
            Ok(other) => panic!("unexpected frame waiting for {waiting_for}: {other:?}"),
            Err(_) => panic!("timed out waiting for {waiting_for}"),
        }
    }
}

/// Parse ChallengeParams out of a raw challenge notification text frame.
fn parse_challenge(text: &str) -> ChallengeParams {
    let notif: JsonRpcNotification =
        serde_json::from_str(text).expect("challenge must be valid JSON-RPC notification");
    assert_eq!(
        notif.method,
        rpc_methods::CHALLENGE,
        "expected challenge notification"
    );
    serde_json::from_value(notif.params.expect("challenge must have params"))
        .expect("ChallengeParams must deserialize")
}

/// Build and serialize an AuthenticateParams JSON-RPC request.
fn build_authenticate_request(id: &Identity, nonce: &str, pow_token: Option<String>) -> String {
    let sig_bytes = id.sign(nonce.as_bytes()).to_bytes();
    let signature = B64.encode(sig_bytes);
    let params = AuthenticateParams {
        pub_key: id.pub_key_b64(),
        nonce: nonce.to_string(),
        signature,
        pow_token,
    };
    let req = JsonRpcRequest::new(1u64, rpc_methods::AUTHENTICATE, params)
        .expect("AuthenticateParams must serialize");
    serde_json::to_string(&req).expect("request must serialize")
}

// ---------------------------------------------------------------------------
// Test 1: Normal connect with valid mined token succeeds
// ---------------------------------------------------------------------------

/// `transport::connect()` auto-mines a PoW token when the relay signals
/// difficulty > 0.  A successful DirectoryList proves auth completed.
///
/// Oracle: DirectoryList is only sent after the relay registers the client as
/// online.  Its arrival is evidence that auth — including PoW verification —
/// succeeded.  The relay implementation is the system under test; the
/// observation is purely from the client side.
#[tokio::test]
async fn pow_gate_allows_valid_mined_token() {
    let relay_url = spawn_relay_with_pow(1).await;

    let alice = Identity::generate();
    let mut alice_conn = transport::connect(&relay_url, &alice, false, None)
        .await
        .expect("alice connect with auto-mined PoW token");

    // DirectoryList proves auth succeeded.
    wait_for_directory_list(&mut alice_conn.rx).await;
}

// ---------------------------------------------------------------------------
// Test 2: Missing token when difficulty > 0 returns POW_REQUIRED
// ---------------------------------------------------------------------------

/// Sending AuthenticateParams with pow_token: None when the relay requires PoW
/// must return an error with code POW_REQUIRED (-32030).
///
/// Oracle: rpc_errors::POW_REQUIRED is the wire-stable error code from
/// nie_core::protocol::rpc_errors, defined independently of ws.rs.
#[tokio::test]
async fn pow_gate_rejects_missing_token() {
    let relay_url = spawn_relay_with_pow(1).await;

    let (ws, _) = connect_async(&relay_url).await.expect("raw WS connect");
    let (mut sink, mut stream) = ws.split();

    let challenge_text = recv_text_frame(&mut stream, "challenge").await;
    let challenge = parse_challenge(&challenge_text);

    let alice = Identity::generate();
    // Deliberately omit pow_token (None) even though difficulty > 0.
    let auth_json = build_authenticate_request(&alice, &challenge.nonce, None);
    sink.send(Message::Text(auth_json.into()))
        .await
        .expect("send auth");

    let response_text = recv_text_frame(&mut stream, "POW_REQUIRED error response").await;
    let resp: JsonRpcResponse =
        serde_json::from_str(&response_text).expect("response must be valid JSON-RPC");

    assert!(
        resp.error.is_some(),
        "relay must return an error when pow_token is missing; got: {response_text}"
    );
    let err = resp.error.unwrap();
    assert_eq!(
        err.code,
        rpc_errors::POW_REQUIRED,
        "missing token must produce POW_REQUIRED (-32030), got: {} (response: {response_text})",
        err.code
    );
}

// ---------------------------------------------------------------------------
// Test 3: Stale token (ts_floor > 10 minutes old) returns POW_STALE
// ---------------------------------------------------------------------------

/// Mining a token with a ts_floor that is 11 minutes in the past and submitting
/// it must return POW_STALE (-32032).
///
/// Oracle: rpc_errors::POW_STALE is the wire-stable error code.  The staleness
/// window is ±10 minutes (600 seconds); 11 minutes is outside it.  The check is
/// implemented in nie_core::pow::verify_token and enforced in ws.rs.  The test
/// observes the wire-level error code, not the library internals.
#[tokio::test]
async fn pow_gate_rejects_stale_token() {
    let relay_url = spawn_relay_with_pow(1).await;

    let (ws, _) = connect_async(&relay_url).await.expect("raw WS connect");
    let (mut sink, mut stream) = ws.split();

    let challenge_text = recv_text_frame(&mut stream, "challenge").await;
    let challenge = parse_challenge(&challenge_text);

    // Decode server_salt from the challenge.
    let salt_bytes = B64
        .decode(&challenge.server_salt)
        .expect("server_salt must be valid base64");
    assert_eq!(salt_bytes.len(), 32, "server_salt must be 32 bytes");
    let mut server_salt = [0u8; 32];
    server_salt.copy_from_slice(&salt_bytes);

    let alice = Identity::generate();
    let pub_key_bytes: [u8; 32] = alice.verifying_key().to_bytes();

    // Compute ts_floor that is 11 minutes in the past — outside the ±10 min window.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let stale_ts_floor = ((now_secs / 60) - 11) as u32;

    let stale_token = nie_core::pow::mine_token(&pub_key_bytes, &server_salt, 1, stale_ts_floor);

    let auth_json = build_authenticate_request(&alice, &challenge.nonce, Some(stale_token));
    sink.send(Message::Text(auth_json.into()))
        .await
        .expect("send auth");

    let response_text = recv_text_frame(&mut stream, "POW_STALE error response").await;
    let resp: JsonRpcResponse =
        serde_json::from_str(&response_text).expect("response must be valid JSON-RPC");

    assert!(
        resp.error.is_some(),
        "relay must return an error for a stale token; got: {response_text}"
    );
    let err = resp.error.unwrap();
    assert_eq!(
        err.code,
        rpc_errors::POW_STALE,
        "stale token must produce POW_STALE (-32032), got: {} (response: {response_text})",
        err.code
    );
}

// ---------------------------------------------------------------------------
// Test 4: Replayed token (same h16 submitted twice) returns POW_REPLAYED
// ---------------------------------------------------------------------------

/// Submitting the same PoW token on a second connection (same h16) must return
/// POW_REPLAYED (-32033).
///
/// Procedure:
/// 1. Open WS 1 for alice; receive Challenge 1 and its server_salt.
/// 2. Mine token T1 using Challenge 1's server_salt + alice's pub_key + diff=1.
/// 3. Sign Challenge 1's nonce; send AuthenticateParams with T1 → success.
/// 4. Open WS 2 for alice; receive Challenge 2 (same server_salt — relay unchanged).
/// 5. Sign Challenge 2's nonce; send T1 again (same h16) → POW_REPLAYED.
///
/// Oracle: rpc_errors::POW_REPLAYED is the wire-stable error code.  The relay
/// tracks h16 values across connections in its in-memory replay set.  The same
/// h16 from the same token string must be rejected on the second use regardless
/// of which nonce was signed.
#[tokio::test]
async fn pow_gate_rejects_replayed_token() {
    let relay_url = spawn_relay_with_pow(1).await;

    let alice = Identity::generate();
    let pub_key_bytes: [u8; 32] = alice.verifying_key().to_bytes();

    // --- Connection 1: mine and submit T1, expect success ---

    let (ws1, _) = connect_async(&relay_url).await.expect("raw WS connect 1");
    let (mut sink1, mut stream1) = ws1.split();

    let challenge1_text = recv_text_frame(&mut stream1, "challenge 1").await;
    let challenge1 = parse_challenge(&challenge1_text);

    let salt_bytes = B64
        .decode(&challenge1.server_salt)
        .expect("server_salt must be valid base64");
    assert_eq!(salt_bytes.len(), 32, "server_salt must be 32 bytes");
    let mut server_salt = [0u8; 32];
    server_salt.copy_from_slice(&salt_bytes);

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ts_floor = (now_secs / 60) as u32;

    // Mine T1 — this is the token we will replay on connection 2.
    let token_t1 = nie_core::pow::mine_token(&pub_key_bytes, &server_salt, 1, ts_floor);

    let auth1_json = build_authenticate_request(&alice, &challenge1.nonce, Some(token_t1.clone()));
    sink1
        .send(Message::Text(auth1_json.into()))
        .await
        .expect("send auth 1");

    // Read frames until we see the JSON-RPC response to the AUTHENTICATE request.
    // A successful auth response has "result" and no "error".
    let auth1_resp: JsonRpcResponse = loop {
        let text = recv_text_frame(&mut stream1, "auth1 response").await;
        // Notifications (challenge, directory_list) lack an "id" at the top level
        // matching a response.  Parse as JsonRpcResponse and skip if it's a
        // notification (no "id" key at the JSON object level that maps to a u64).
        if let Ok(r) = serde_json::from_str::<JsonRpcResponse>(&text) {
            break r;
        }
        // If it didn't parse as JsonRpcResponse (e.g. it's a notification), keep reading.
    };

    assert!(
        auth1_resp.error.is_none(),
        "first auth with T1 must succeed; got error: {:?} (response: {:?})",
        auth1_resp.error,
        auth1_resp
    );

    // --- Connection 2: replay T1, expect POW_REPLAYED ---

    let (ws2, _) = connect_async(&relay_url).await.expect("raw WS connect 2");
    let (mut sink2, mut stream2) = ws2.split();

    let challenge2_text = recv_text_frame(&mut stream2, "challenge 2").await;
    let challenge2 = parse_challenge(&challenge2_text);

    // Sign challenge 2's nonce with alice's key, but reuse T1 (same h16).
    let auth2_json = build_authenticate_request(&alice, &challenge2.nonce, Some(token_t1));
    sink2
        .send(Message::Text(auth2_json.into()))
        .await
        .expect("send auth 2");

    let response2_text = recv_text_frame(&mut stream2, "POW_REPLAYED error response").await;
    let resp2: JsonRpcResponse =
        serde_json::from_str(&response2_text).expect("response must be valid JSON-RPC");

    assert!(
        resp2.error.is_some(),
        "second auth with replayed T1 must return an error; got: {response2_text}"
    );
    let err2 = resp2.error.unwrap();
    assert_eq!(
        err2.code,
        rpc_errors::POW_REPLAYED,
        "replayed token must produce POW_REPLAYED (-32033), got: {} (response: {response2_text})",
        err2.code
    );
}
