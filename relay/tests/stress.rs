//! Integration stress test: 16 concurrent clients, random message exchange.
//!
//! Starts an in-process relay (random port, temp SQLite file), connects
//! N clients via `nie_core::transport`, and has each send random messages at
//! human-speed intervals.  Two barriers enforce correct counting:
//!
//! 1. `start_barrier` — no client sends until ALL N have received their
//!    `DirectoryList`.  This guarantees every broadcast reaches exactly N−1
//!    recipients, making the final assertion exact.
//!
//! 2. `done_barrier` — no client starts draining until every client has
//!    finished sending.  This prevents a race where a late message arrives
//!    at a peer's channel after that peer has already closed its drain window.
//!
//! This tests relay routing correctness and concurrency.  MLS is omitted —
//! the relay treats payloads as opaque bytes, so plain Broadcast→Deliver
//! is sufficient to exercise message fan-out.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
use nie_core::{
    identity::Identity,
    protocol::{rpc_methods, BroadcastParams, JsonRpcRequest},
    transport::{self, next_request_id, ClientEvent},
};
use nie_relay::{state::AppState, ws::ws_handler};
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use tokio::sync::Barrier;

/// Number of concurrent clients.
const N: usize = 16;

/// How long each client actively sends messages (wall-clock, after all N
/// clients have connected).
const SEND_SECS: u64 = 15;

/// Extra time after the done barrier for in-flight messages to drain through
/// the relay→WebSocket→transport pipeline.  Generous: loopback latency is <1 ms
/// but the pipeline has several async hops and system load varies in CI.
const DRAIN_SECS: u64 = 5;

/// Random word pool for message content.
const WORDS: &[&str] = &[
    "hey",
    "hello",
    "hi",
    "how",
    "are",
    "you",
    "doing",
    "today",
    "great",
    "thanks",
    "see",
    "later",
    "what",
    "time",
    "meet",
    "tomorrow",
    "sounds",
    "good",
    "ok",
    "bye",
    "nice",
    "weather",
    "yeah",
    "lol",
    "omg",
    "wait",
    "back",
    "here",
    "now",
    "just",
    "about",
    "think",
    "know",
    "want",
    "got",
    "get",
    "going",
    "come",
    "look",
    "help",
    "need",
    "work",
    "home",
    "this",
    "that",
    "with",
    "from",
    "have",
    "will",
    "been",
    "they",
    "something",
    "anyone",
    "around",
    "check",
    "update",
    "ready",
    "done",
    "send",
];

/// Start an in-process relay on a random OS-assigned port.
/// Returns the WebSocket URL.
async fn spawn_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Each test run gets its own temp DB so parallel test runs never collide.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sixteen_clients_stress() {
    let relay_url = spawn_relay().await;
    // Brief pause so the relay is ready to accept connections.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let total_sent = Arc::new(AtomicU64::new(0));
    let total_received = Arc::new(AtomicU64::new(0));

    // Barrier 1: no sends begin until every client has received DirectoryList.
    // This ensures every broadcast reaches exactly N−1 recipients, making
    // the `received == sent * (N-1)` assertion exact.
    let start_barrier = Arc::new(Barrier::new(N));

    // Barrier 2: no client starts draining until every client has stopped
    // sending, preventing the boundary race where a late message arrives after
    // a peer has already exited its drain window.
    let done_barrier = Arc::new(Barrier::new(N));

    let mut handles = Vec::with_capacity(N);

    for i in 0..N {
        let url = relay_url.clone();
        let sent_ctr = total_sent.clone();
        let recv_ctr = total_received.clone();
        let start_barrier = start_barrier.clone();
        let done_barrier = done_barrier.clone();

        handles.push(tokio::spawn(async move {
            // Distinct seed per client → different cadence and message content.
            let mut rng = StdRng::seed_from_u64(0xdead_beef_cafe ^ (i as u64 * 0x9e37_79b9));

            let id = Identity::generate();
            let conn = transport::connect_with_retry(url, id, false, None);
            let tx = conn.tx;
            let mut rx = conn.rx;

            // Stagger connections: spread initial connections over 0–2 s so
            // 16 clients don't all hit the relay in the same millisecond.
            let jitter_ms: u64 = rng.gen_range(0..=2000);
            tokio::time::sleep(Duration::from_millis(jitter_ms)).await;

            // Wait for DirectoryList which confirms auth succeeded and the
            // relay has registered us as online.
            loop {
                match rx.recv().await {
                    Some(ClientEvent::Message(notif))
                        if notif.method == rpc_methods::DIRECTORY_LIST =>
                    {
                        break;
                    }
                    Some(_) => {}
                    None => return, // relay shut down unexpectedly
                }
            }

            // ── Start barrier ───────────────────────────────────────────────
            // Every client waits here until all N have connected.  After this
            // point every Broadcast is guaranteed to reach exactly N−1 clients.
            start_barrier.wait().await;

            let send_until = tokio::time::Instant::now() + Duration::from_secs(SEND_SECS);
            // Fire the first send immediately; subsequent sends after a random delay.
            let mut next_send = tokio::time::Instant::now();

            // ── Send phase ──────────────────────────────────────────────────
            loop {
                let now = tokio::time::Instant::now();
                if now >= send_until {
                    break;
                }
                let remaining = send_until - now;
                let until_send = next_send.saturating_duration_since(now);

                tokio::select! {
                    event = rx.recv() => {
                        match event {
                            Some(ClientEvent::Message(notif))
                                if notif.method == rpc_methods::DELIVER =>
                            {
                                recv_ctr.fetch_add(1, Ordering::Relaxed);
                            }
                            // UserJoined/Left, Reconnecting, AuthOk, KeyPackageReady,
                            // Reconnected — none of these are Deliver, skip them.
                            Some(_) => {}
                            None => return, // relay shut down unexpectedly
                        }
                    }
                    _ = tokio::time::sleep(until_send) => {
                        let word_count = rng.gen_range(1usize..=8);
                        let words: Vec<&str> = (0..word_count)
                            .map(|_| *WORDS.choose(&mut rng).unwrap())
                            .collect();
                        let payload = words.join(" ").into_bytes();

                        let req = JsonRpcRequest::new(
                            next_request_id(),
                            rpc_methods::BROADCAST,
                            BroadcastParams { payload },
                        )
                        .expect("BroadcastParams must serialize");
                        if tx.send(req).await.is_ok() {
                            sent_ctr.fetch_add(1, Ordering::Relaxed);
                        }

                        // Next message in 300 ms – 3 000 ms (human typing cadence).
                        let delay_ms: u64 = rng.gen_range(300..=3000);
                        next_send = tokio::time::Instant::now()
                            + Duration::from_millis(delay_ms);
                    }
                    _ = tokio::time::sleep(remaining) => break,
                }
            }

            // ── Done barrier ────────────────────────────────────────────────
            // Wait until every client has stopped sending.  Once all N reach
            // here, no further Broadcast messages will enter the relay.
            done_barrier.wait().await;

            // ── Drain phase ─────────────────────────────────────────────────
            // Flush messages that were in the relay→WebSocket→transport pipeline
            // at the barrier point.  5 s is very conservative for loopback.
            let drain_until = tokio::time::Instant::now() + Duration::from_secs(DRAIN_SECS);
            loop {
                let now = tokio::time::Instant::now();
                if now >= drain_until {
                    break;
                }
                let remaining = drain_until - now;
                match tokio::time::timeout(remaining, rx.recv()).await {
                    Ok(Some(ClientEvent::Message(notif)))
                        if notif.method == rpc_methods::DELIVER =>
                    {
                        recv_ctr.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Some(_)) => {}
                    // Channel closed or timeout with empty channel → done.
                    Ok(None) | Err(_) => break,
                }
            }
        }));
    }

    for handle in handles {
        handle.await.expect("client task panicked");
    }

    let sent = total_sent.load(Ordering::Relaxed);
    let received = total_received.load(Ordering::Relaxed);
    let expected = sent * (N as u64 - 1);

    eprintln!("[stress] clients={N}  sent={sent}  received={received}  expected={expected}");

    assert_eq!(
        received,
        expected,
        "relay routing mismatch — {sent} messages × {} recipients = {expected} expected, \
         got {received}  (delta {})",
        N - 1,
        expected as i64 - received as i64,
    );
}
